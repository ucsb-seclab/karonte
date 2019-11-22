import angr
import claripy
import logging
import simuvex
import random
import capstone
import signal
import os
from random import shuffle

from utils import *

angr.loggers.disable_root_logger()
log = logging.getLogger("CoreTaint")
log.setLevel("DEBUG")

GLOB_TAINT_DEP_KEY = 'taint_deps'
UNTAINT_DATA = 'untainted_data'
UNTAINTED_VARS = 'untainted_vars'
SEEN_MASTERS = 'seen_masters'


class MyFileHandler(object):

    def __init__(self, filename, handlerFactory, **kw):
        kw['filename'] = filename
        self._handler = handlerFactory(**kw)

    def __getattr__(self, n):
        if hasattr(self._handler, n):
            return getattr(self._handler, n)
        raise AttributeError, n


class TimeOutException(Exception):
    def __init__(self, message):
        super(TimeOutException, self).__init__(message)


class CoreTaint:
    """
    Perform a symbolic-execution-based taint analysis on a given binary to find whether
    it exists a tainted path between a source and a sink.
    """

    def __init__(self, p, interfunction_level=0, log_path='/tmp/coretaint.out',
                 smart_call=True, follow_unsat=False, try_thumb=False, white_calls=[], black_calls=[], not_follow_any_calls=False,
                 default_log=True, exit_on_decode_error=True, concretization_strategy=None, force_paths=False,
                 taint_returns_unfollowed_calls=False, taint_arguments_unfollowed_calls=False, allow_untaint=True,
                 only_follow_near_calls=False, logger_obj=None):
        """
        Initialialization function

        :param p: angr project
        :param interfunction_level: interfunction level
        :param log_path:  path where the analysis' log is created
        :param smart_call: if True a call is followed only if at least one of its parameters is tainted
        :param follow_unsat: if true unsat successors are also considered during path exploration. In this case
                             the collected constraints up to that point will be dropped.
        :param try_thumb: try to force thumb mode if some decoding error occurred
        :param white_calls: calls to follow in any case
        :param default_log: log info by default
        :param exit_on_decode_error: terminate the analysis in case of error
        :param concretization_strategy: concretization strategy callback
        :param force_paths: force a path to be followed even when some decode errors were found
        :param allow_untaint: allow to untaint variables.
        """
        global log

        self._count_var = 0
        self._back_jumps = {}
        self._N = 1
        self._keep_run = True
        self._timeout_triggered = False
        self._timer = 0
        self._force_exit_after = -1
        self._p = p
        self._taint_buf = "taint_buf"
        self._taint_applied = False
        self._taint_buf_size = 4096 # 1 page
        self._bogus_return = 0x41414141
        self._fully_taint_guard = []
        self._white_calls = white_calls
        self._black_calls = black_calls
        self._taint_returns_unfollowed_calls = taint_returns_unfollowed_calls
        self._taint_arguments_unfollowed_calls = taint_arguments_unfollowed_calls
        self._allow_untaint = allow_untaint
        self._not_follow_any_calls = not_follow_any_calls
        self._only_follow_near_calls = only_follow_near_calls

        self._deref_taint_address = False
        self._deref_instruction = None
        self._deref_addr_expr = None
        self._deref = (None, None)
        self._old_deref = self._deref
        self._old_deref_taint_address = self._deref_taint_address
        self._old_deref_addr_expr = self._deref_addr_expr

        self._interfunction_level = interfunction_level
        self._smart_call = smart_call
        self._follow_unsat = follow_unsat

        self._concretizations = {}
        self._summarized_f = {}

        self._fp = open(log_path, 'w')
        self._interesing_path = {'sink': [], 'deref': [], 'loop': []}
        self._try_thumb = try_thumb
        self._force_paths = force_paths

        self._default_log = default_log

        self._exit_on_decode_error = exit_on_decode_error
        self._concretization_strategy = self._default_concretization_strategy if concretization_strategy is None else \
            concretization_strategy

        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        fileh = MyFileHandler(log_path + '._log', logging.FileHandler)
        fileh.setFormatter(formatter)
        log.addHandler(fileh)

    def handler(self, signum, frame):
        """
        Timeout handler

        :param signum: signal number
        :param frame:  frame
        :return:
        """

        log.info("Timeout triggered, %s left...." % str(self._force_exit_after))
        self._keep_run = False
        self._timeout_triggered = True
        # time to stop this non-sense!
        self._force_exit_after -= 1
        self.set_alarm(self._timer, self._force_exit_after)
        if self._force_exit_after <= 0:
            raise TimeOutException("Hard timeout triggered")

    def _get_bb(self, addr):
        try:
            bl = self._p.factory.block(addr)
        except:
            bl = None

        if bl is None or bl.vex.jumpkind == 'Ijk_NoDecode':
            try:
                bl = self._p.factory.block(addr, thumb=True)
            except:
                bl = None

        return bl

    def _save_taint_flag(self):
        """
        Save the tainting related flags

        :return:
        """

        self._old_deref = self._deref
        self._old_deref_taint_address = self._deref_taint_address
        self._old_deref_addr_expr = self._deref_addr_expr

    def _restore_taint_flags(self):
        """
        Restiore the tainting related flags

        :return:
        """

        self._deref = self._old_deref
        self._deref_taint_address = self._old_deref_taint_address
        self._deref_addr_expr = self._old_deref_addr_expr

    @property
    def bogus_return(self):
        return self._bogus_return

    @property
    def taint_buf(self):
        return self._taint_buf

    @property
    def taint_buf_size(self):
        return self._taint_buf_size

    @property
    def taint_applied(self):
        return self._taint_applied

    @property
    def p(self):
        return self._p

    def safe_load(self, path, addr, size=None, unconstrained=False):
        """
        Loads bytes from memory, saving and restoring taint info

        :param path: path
        :param addr:  address
        :return: the content in memory at address addr
        """

        self._save_taint_flag()
        if not size:
            size = self._p.arch.bits / 8
        state = path.active[0] if not unconstrained else path.unconstrained[0]
        mem_cnt = state.memory.load(addr, size)
        self._restore_taint_flags()
        return mem_cnt

    def safe_store(self, path, addr, thing):
        """
        Stores bytes in memory, saving and restoring taint info

        :param path: path
        :param addr: address
        :param thing: thing to store
        :return:
        """

        self._save_taint_flag()
        path.active[0].memory.store(addr, thing)
        self._restore_taint_flags()

    def get_sym_val(self, **args):
        return self._get_sym_val(**args)

    def _set_deref_bounds(self, ast_node):
        """
        Check an ast node and if  contains a dereferenced address, it sets
        its bounds
        :param ast_node: ast node
        :return: None
        """
        lb = self._deref[0]
        ub = self._deref[1]

        if hasattr(ast_node, 'op') and ast_node.op == 'Extract' \
                and self.is_tainted(ast_node.args[2]):
            m = min(ast_node.args[0], ast_node.args[1])
            lb = m if lb is None or m < lb else lb
            m = max(ast_node.args[0], ast_node.args[1])
            ub = m if ub is None or m > ub else ub
            self._deref = (lb, ub)
        elif hasattr(ast_node, 'args'):
            for a in ast_node.args:
                self._set_deref_bounds(a)
        elif self.is_tainted(ast_node):
            self._deref = (0, 0)

    def addr_concrete_after(self, state):
        """
        Hook for address concretization
        :param state: Program state
        """

        addr_expr = state.inspect.address_concretization_expr
        state.inspect.address_concretization_result = [self._get_target_concretization(addr_expr, state)]

        # a tainted buffer's location is used as address
        if self.is_tainted(addr_expr, state=state):
            self._set_deref_bounds(addr_expr)
            self._deref_taint_address = True
            self._deref_addr_expr = addr_expr
            self._deref_instruction = state.ip.args[0]

            if state.inspect.address_concretization_action == 'load':
                # new fresh var
                name = "cnt_pt_by(" + self._taint_buf + '[' + str(self._deref[0]) + ', ' + str(self._deref[1]) + ']' + ")"
                bits = state.inspect.mem_read_length
                if type(bits) not in (long, int) and hasattr(bits, 'symbolic'):
                    bits = state.se.max_int(bits)
                var = self._get_sym_val(name=name, bits=bits)
                state.memory.store(state.inspect.address_concretization_result[0], var)

    def _check_taint(self, state, reg, history):
        """
        Check whther a path is completely tainted
        :param state: current state
        :param reg: Register used to pass the argument to the sink call
        :return: True if reg has is still tainted before the sink's call, False otherwise
        """

        self._bounds = [None, None]

        def _find_extract_bounds(ast_node):
            if ast_node.op == 'Extract':
                a, b = ast_node.args[0], ast_node.args[1]
                if a < b:
                    return a, b
                return b, a

            for a in ast_node.args:
                if hasattr(a, 'args'):
                    a, b = _find_extract_bounds(a)
                    if self._bounds[0] is None or (a is not None and a <= self._bounds[0]):
                        self._bounds[0] = a
                    if self._bounds[1] is None or (b is not None and b >= self._bounds[1]):
                        self._bounds[1] = b
            return self._bounds[0], self._bounds[1]

        def _find_name(ast_node):
            if type(ast_node) == claripy.ast.BV and \
                            ast_node.op == 'BVS':
                return ast_node.args[0]
            elif hasattr(ast_node, 'args'):
                for a in ast_node.args:
                    name = _find_name(a)
                    if name:
                        return name
            return None

        def _check_guards(tainted_var, history):
            self._bounds = [None, None]
            lb, ub = _find_extract_bounds(tainted_var)
            tainted_buff_name = _find_name(tainted_var)

            for a, g in history:
                if self.is_tainted(g):
                    # scan the path's guards and collect those relative to
                    # the tainted portion of memory

                    t_op = g.args[0] if self.is_tainted(g.args[0]) else g.args[1]
                    sec_op = g.args[1] if self.is_tainted(g.args[0]) else g.args[0]

                    if not self.is_tainted(sec_op):
                        name_op = _find_name(t_op)

                        if name_op != tainted_buff_name:
                            # we consider only the conditions relative
                            # to the tainted variable which reached the sink
                            continue

                        # the condition untaints part of the tainted buffer
                        # get the portion of untainted buffer
                        self._bounds = [None, None]
                        lb_op, ub_op = _find_extract_bounds(t_op)

                        if lb_op is None:
                            log.error("The whole buffer seem to be untainted, check me!")
                            return False

                        if lb >= lb_op:
                            lb = lb_op
                        if ub <= ub_op:
                            ub = ub_op

                        if lb >= ub:
                            return False

                    else:
                        # both operands involved in the guard are tainted
                        self._fully_taint_guard.append((a, g))
            return True

        self._fully_taint_guard = []

        if hasattr(state.regs, reg):
            ast = getattr(state.regs, reg)

            if self.is_tainted(ast):
                # TODO: check also below part?
                if _check_guards(ast, history):
                    return True

            # save taint flags, the following load may change them
            self._save_taint_flag()

            # the function will dereference the argument
            # resulting in a read from our tainting location
            tmp_s = state.copy()
            try:
                cnt = tmp_s.memory.load(ast, 1)
            except TimeOutException as t:
                raise t
            except Exception:
                log.warning("Unable to concretize %s" % hex(ast))
                return False

            # the load might have set some flags, let's restore them
            self._restore_taint_flags()

            if self.is_tainted(cnt):
                # the variable reaching the sink is tainted
                return _check_guards(cnt, history)

            return False
        raise Exception("Architecture %s has no register %s" % (self._p.arch.name, reg))

    def _save_sink_info(self, path, reg, sink_address):
        """
        Dump the info about a tainted sink into the log file
        :param path: path found to be tainted
        :param reg: register pointing to the tainted buffer
        :param sink_address: sink address
        :return:
        """

        if not self._default_log:
            return

        f = self._fp
        reg_cnt = getattr(self.get_state(path).regs, str(reg))
        mem_cnt = None
        is_addr = False
        tmp_s = self.get_state(path).copy()

        if not self.is_tainted(reg_cnt, path=path):
            is_addr = True
            self._save_taint_flag()
            mem_cnt = tmp_s.memory.load(reg_cnt)
            self._restore_taint_flags()

        key_path = (str(mem_cnt), str(reg_cnt), str(reg))
        if key_path in self._interesing_path['sink']:
            return

        self._interesing_path['sink'].append(key_path)

        f.write("===================== Start Info path =====================\n")
        f.write("Sink address: %s\n" % hex(sink_address))

        if is_addr:
            f.write("\nReason: sink accepts %s which points to the location of memory %s.\n" % (str(reg), reg_cnt))
            f.write("\nContent of %s: %s\n" % (str(reg_cnt), str(mem_cnt)))
        else:
            f.write("\nReason: sink accepts parameter %s which is tainted.\n" % (str(reg)))
            f.write("\nContent of %s: %s\n" % (str(reg), str(reg_cnt)))

        f.write("\n\nPath \n----------------\n")
        path = ' -> '.join([hex(a) for a in self.get_state(path).history.bbl_addrs])
        f.write(path + '\n\n')

        f.write("Fully tainted conditions \n----------------\n")
        if not self._fully_taint_guard:
            f.write('None\n')
        else:
            for fc in self._fully_taint_guard:
                f.write(fc[0] + ': ')
                f.write(str(fc[1]) + '\n\n')

        f.write("===================== End Info path =====================\n\n\n")

    def _save_deref_info(self, path, addr_expr):
        """
        Dump the dereference of tainted address information into the log file
        :param path: path found to be tainted
        :return:
        """
        if not self._default_log:
            return

        f = self._fp
        code_addr = self.get_addr(path)

        key_path = (str(code_addr), str(addr_expr))
        if key_path in self._interesing_path['deref']:
            return

        self._interesing_path['deref'].append(key_path)

        f.write("===================== Start Info path =====================\n")
        f.write("Dereference address at: %s\n" % hex(code_addr))
        f.write("\nReason: at location %s a tainted variable is dereferenced and used as address.\n" % hex(code_addr))
        f.write("\nContent of the tainted variable: %s\n" % str(addr_expr))
        f.write("\n\nTainted Path \n----------------\n")
        path = ' -> '.join([hex(a) for a in self.get_state(path).history.bbl_addrs])
        f.write(path + '\n\n')
        f.write("===================== End Info path =====================\n\n\n")

    def _save_loop_info(self, path, addr, cond):
        """
        Dump the info about a tainted variable guarding a loop
        :param path: path found to be tainted
        :return:
        """

        if not self._default_log:
            return

        f = self._fp

        key_path = (str(addr), str(cond))
        if key_path in self._interesing_path['loop']:
            return

        self._interesing_path['loop'].append(key_path)

        f.write("===================== Start Info path =====================\n")
        f.write("Dangerous loop condition at address %s\n" % hex(addr))
        f.write("\nReason: a tainted variable is used in the guard of a loop condition\n")
        f.write("\nCondition: %s\n" % cond)
        f.write("\n\nTainted Path \n----------------\n")
        path = ' -> '.join([hex(a) for a in self.get_state(path).history.bbl_addrs])
        f.write(path + '\n\n')
        f.write("===================== End Info path =====================\n\n\n")

    def _default_concretization_strategy(self, state, cnt):#, extra_constraints=()):
        extra_constraints = state.inspect.address_concretization_extra_constraints
        if not extra_constraints:
            extra_constraints = tuple()
        concs = state.se.any_n_int(cnt, 50, extra_constraints=extra_constraints)
        return random.choice(concs)

    def _get_target_concretization(self, var, state):
        """
        Concretization must be done carefully in order to perform
        a precise taint analysis. We concretize according the following
        strategy:
        * every symbolic leaf of an ast node is concretized to unique value, according on its name.

        In this way we obtain the following advantages:
        a = get_pts();
        b = a

        c = a + 2
        d = b + 1 + 1

        d = get_pts()

        conc(a) = conc(b)
        conc(c) = conc(d)
        conc(d) != any other concretizations

        :param var: ast node
        :param state: current state
        :return: concretization value
        """

        def get_key_cnt(x):
            # angr by default create a unique id for every new symbolic variable.
            # as in karonte we often have to copy the state, step and check some
            # quantities before step() with the current state, two identical variables might assume
            # two different names. Therefore, we should not consider the unique _id_ added to symbolic variables
            # created by angr
            ret = str(x)
            if '_' in str(x) and not self.is_tainted(x):
                splits = str(x).split('_')
                idx = splits[-2]

                if not idx.isdigit():
                    log.error("get_key_cnt: Symbolic ID parsing failed, using the whole id: %s" % ret)
                    return ret

                ret = '_'.join(splits[:-2]) + '_'
                ret += '_'.join(splits[-1:])
            return ret

        # chek if uncontrained
        state_cp = state.copy()
        se = state_cp.se
        leafs = [l for l in var.recursive_leaf_asts]

        if not leafs:
            conc = self._concretization_strategy(state_cp, var)

            if not se.solution(var, conc):
                conc = se.any_int(var)
            key_cnt = get_key_cnt(var)
            self._concretizations[key_cnt] = conc
            return conc

        for cnt in leafs:
            key_cnt = get_key_cnt(cnt)
            # concretize all unconstrained children
            if cnt.symbolic:
                # first check whether the value is already constrained
                if key_cnt in self._concretizations.keys():
                    conc = self._concretizations[key_cnt]
                    if state_cp.se.solution(cnt, conc):
                        state_cp.add_constraints(cnt == conc)
                        continue

                conc = self._concretization_strategy(state_cp, cnt)
                self._concretizations[key_cnt] = conc
                state_cp.add_constraints(cnt == conc)

        val = state_cp.se.any_int(var)
        return val

    def is_tainted(self, var, path=None, state=None, unconstrained=False):
        def is_untaint_constraint_present(v, untaint_var_strs):
            for u in untaint_var_strs:
                # get argument name
                if v.args[0] in u:
                    # variable is untainted
                    return True
            # no untaint found, var is tainted!
            return False

        # Nothing is tainted
        if self._taint_buf not in str(var):
            return False

        #
        # something is tainted
        #

        if not self._allow_untaint or (not path and not state):
            return True

        # get contraints
        if path:
            state = path.active[0] if not unconstrained else path.unconstrained[0]

        untaint_var_strs = state.globals[UNTAINT_DATA][UNTAINTED_VARS]
        if not untaint_var_strs:
            return True

        taint_leafs = list(set([l for l in var.recursive_leaf_asts if self._taint_buf in str(l)]))
        taints = set()

        for l in taint_leafs:
            if l in taints:
                continue
            # search an untaint constraint for this taint variable
            if not is_untaint_constraint_present(l, untaint_var_strs):
                return True
            taints.add(l)
        return False

    def add_taint_glob_dep(self, master, slave, path):
        """
        Add a taint dependency: if master gets untainted, slave should be untainted
        :param master: master expression
        :param slave: slave expression
        :param path: path
        :return:
        """

        if not self.is_tainted(master):
            return
        leafs = list(set([l for l in master.recursive_leaf_asts if self.is_tainted(l)]))
        key = tuple(map(str, leafs))
        if key not in self.get_state(path).globals[GLOB_TAINT_DEP_KEY]:
            self.get_state(path).globals[GLOB_TAINT_DEP_KEY][key] = []
        self.get_state(path).globals[GLOB_TAINT_DEP_KEY][key].append(slave)

    def _do_recursive_untaint_core(self, dst, path):
        # given an expression to untaint, we untaint every single tainted variable in it.
        # E.g., given (taint_x + taint_y) to untaint, both variables gets untainted as
        # they cannot assume no longer arbitrary values down this path.
        if not self._allow_untaint:
            return

        state = self.get_state(path)
        leafs = list(set([l for l in dst.recursive_leaf_asts if self.is_tainted(l)]))

        # then we use the collected untainted variables
        # and check whether we should untaint some other variables
        state.globals[UNTAINT_DATA][UNTAINTED_VARS] += map(str, leafs)
        deps = dict(state.globals[GLOB_TAINT_DEP_KEY])
        i = 0
        while i < len(deps.keys()):
            master, salve = deps.items()[i]

            # if not already untainted, let's consider it
            if master not in state.globals[UNTAINT_DATA][SEEN_MASTERS]:
                untainted_vars = set(state.globals[UNTAINT_DATA][UNTAINTED_VARS])
                set_master = set(master)

                # we can not untaint it
                if set_master.intersection(untainted_vars) == set_master:
                    state.globals[UNTAINT_DATA][SEEN_MASTERS].append(master)
                    for entry in deps[master]:
                        self._do_recursive_untaint_core(entry, path)
                    # restart!
                    i = 0
                    continue

            i += 1

    def do_recursive_untaint(self, dst, path):
        return self._do_recursive_untaint_core(dst, path)

    def apply_taint(self, current_path, addr, taint_id, bit_size=None):
        self._save_taint_flag()
        bit_size = bit_size if bit_size else self._taint_buf_size
        t = self._get_sym_val(name=self._taint_buf + '_' + taint_id + '_', bits=bit_size).reversed
        self.get_state(current_path).memory.store(addr, t)
        self._restore_taint_flags()
        self._taint_applied = True

    def _check_if_sink_or_source(self, current_path, guards_info, _, sinks_info=(), sources_info=()):
        """
        Check if a tainted sink is present in the current block of a path
        :param current_path: current path
        :param guards_info: info about the guards in the current path
        :param sinks_info: sinks' information: ((sinks), reg)
        :param sources_info: sources' information ((source), reg)
        :return: True if the sink is tainted, false otherwise
        """

        current_cp = current_path.copy(copy_states=True)
        succ = current_cp.step()

        # get the successor state
        if not succ.active:
            # check if it was un unconstrained call.
            # somtimes angr fucks it up
            bl = self._get_bb(self.get_addr(current_path))
            if bl.vex.jumpkind != 'Ijk_Call':
                # Heuristic: if not a function call, we do not consider dereference
                # of tainted locations, since it is unlikely to be used as address
                return False
            suc_state = current_cp.unconstrained[0]
            succ.active = [suc_state]

        suc_state = self.get_state(succ)

        # SOURCES:
        # look for sources:

        for source, reg_source in sources_info:
            bb = self._get_bb(self.get_addr(current_path))

            # the bb contains the call to the source
            if any([x for x in bb.vex.statements if x.tag == 'Ist_IMark' and x.addr == source]):
                #  time to taint
                if reg_source == 'RETURN':
                    addr_to_taint = self._get_sym_val(name='reg_ret_', inc=False)
                else:
                    addr_to_taint = getattr(suc_state.regs, reg_source)

                # check whether is tainted first! A tainted address passed to a source
                # might overwrite sensible data.
                if self.is_tainted(addr_to_taint):
                    self._save_deref_info(current_path, addr_to_taint)
                t = self._get_sym_val(name=self._taint_buf, bits=self._taint_buf_size).reversed
                self._save_taint_flag()
                self.get_state(current_path).memory.store(addr_to_taint, t)
                self._restore_taint_flags()
                self._taint_applied = True

        # SINKS:
        # look for sinks (only if we have successors. A sink is a function!):
        succ_addr = self.get_addr(succ)
        found = False
        for sink, reg_sink in sinks_info:
            if succ_addr == sink:
                if self._check_taint(suc_state, reg_sink, guards_info):
                    log.info("HOOOORAY:  Detected a possibly tainted path")
                    self._save_sink_info(succ, reg_sink, sink)
                    found = True
        if found:
            return True

        # or if a tainted address is dereferenced
        if self._deref_taint_address:
            self._deref_taint_address = False

            bl = self._get_bb(self._deref_instruction)
            if bl.vex.jumpkind == 'Ijk_Call':
                log.info("Dereferenced tainted address")
                self._save_deref_info(current_path, self._deref_addr_expr)
                # self._keep_run = False

        # eventually if we are in a loop guarded by a tainted variable
        if len(succ.active) > 1 and any([a for a in succ.active if a.addr in [t for t in self.get_state(current_path).history.bbl_addrs]]):
            cond_guard = [g for g in self.get_state(succ).guards][-1]
            for node in cond_guard.recursive_leaf_asts:
                if self.is_tainted(node):
                    self._save_loop_info(current_path, self.get_addr(current_path), cond_guard)
                    return True

        return False

    def _get_sym_val(self, name='x_', bits=None, inc=True, explicit=False):
        if bits is None:
            bits = self._p.arch.bits

        if explicit:
            var = claripy.BVS(name=name, size=bits, explicit_name=True)
        else:
            var = claripy.BVS(name=(name + '_' + str(self._count_var) + '_' + str(self._p.arch.bits)), size=bits,
                              explicit_name=True)
            if inc:
                self._count_var += 1
        return var

    def get_addr(self, run):
        return run.active[0].ip.args[0]

    def get_state(self, run):
        return run.active[0]

    def is_or_points_to_tainted_data(self, x, path, unconstrained=False):
        return self.is_tainted(x, path=path, unconstrained=unconstrained) or \
                self.is_tainted(self.safe_load(path, x, unconstrained=unconstrained), path=path, unconstrained=unconstrained)

    def _set_fake_ret_succ(self, path, state, addr, ret):
        """
        Create a fake ret successors of a given path.
        :param path: current path
        :param: state: state to set in the new succ
        :param addr: address where the fake ret block will return
        :param ret: return of the current function
        :return: angr path
        """
        new_s = state.copy()
        new_s.history.jumpkind = "Ijk_FakeRet"

        # check whether any of the function parameters are tainted
        nargs = get_arity(self._p, self.get_addr(path))
        next_cp = path.copy(copy_states=True).step()
        to_taint = False
        ord_arg_tainted = -1

        for i in xrange(nargs):
            name = self._p.arch.register_names[ordered_agument_regs[self._p.arch.name][i]]
            try:
                val_arg = getattr(self.get_state(next_cp).regs, name)
            except:
                break
            if self.is_or_points_to_tainted_data(val_arg, next_cp):
                to_taint = True
                ord_arg_tainted = i
                break

        # return value
        name = 'reg_ret_'
        if self._taint_returns_unfollowed_calls and to_taint:
            name = self._taint_buf + '_' + name

        ret_reg = return_regs[self._p.arch.name]
        link_reg = link_regs[self._p.arch.name]

        new_s.regs.pc = addr
        setattr(new_s.regs, self._p.arch.register_names[link_reg], ret)
        setattr(new_s.regs, self._p.arch.register_names[ret_reg], self._get_sym_val(name=name))

        # function arguments
        if to_taint and self._taint_arguments_unfollowed_calls:
            for i in xrange(nargs):
                if i == ord_arg_tainted:
                    continue

                name_reg = self._p.arch.register_names[ordered_agument_regs[self._p.arch.name][i]]
                addr = getattr(new_s.regs, name_reg)
                if addr.concrete and addr.args[0] < self.p.loader.main_object.min_addr:
                        continue
                taint_name = self._taint_buf + '_' + name_reg
                new_s.memory.store(addr, self._get_sym_val(name=taint_name, bits=self._taint_buf_size))

        return path.copy(
            stashes={'active': [new_s], 'unsat': [], 'pruned': [], 'unconstrained': [], 'deadended': []})

    def _is_summarized(self, prev_path, suc_path, current_depth):
        # first check if function is summarized
        addr = self.get_addr(suc_path)

        if self._summarized_f:
            for s_addr in self._summarized_f.keys():
                if addr == s_addr:
                    self._summarized_f[s_addr](self, prev_path, suc_path)
                    return True
        return False

    def _follow_call(self, prev_path, suc_path, current_depth):
        """
        Checks if a call should be followed or not: if any of its parameters is tainted
        and the current depth of transitive closure allows it yes, otherwise no.

        :param prev_path: previous path
        :param suc_path: successive path
        :param current_depth: current depth of transitive closure
        :return: True if call should be followed, false otherwise
        """

        if self._not_follow_any_calls:
            return False

        # first check if function is summarized
        prev_addr = self.get_addr(prev_path)
        addr = self.get_addr(suc_path)

        if self._only_follow_near_calls:
            try:
                plt = self.p.loader.main_object.reverse_plt
                if addr in plt:
                    return False
            except:
                pass

        if addr in self._black_calls or prev_addr in self._black_calls:
            return False

        # check if call falls within bound binary
        if addr > self._p.loader.max_addr or addr < self._p.loader.min_addr:
            return False

        # if the function is summarized by angr, we follow it
        if self._p._should_use_sim_procedures:
            # consider also next addr in case th current one is a trampoline (eg., plt)
            trp = suc_path.copy(copy_states=True)
            trp.step()
            trp_addr = self.get_addr(trp)
            if self._p.is_hooked(addr) or self._p.is_hooked(trp_addr):
                return True

        if addr in self._white_calls:
            return True

        if current_depth <= 0:
            return False

        if not self._smart_call:
            return True

        if not self._taint_applied:
            return False

        bl = self._get_bb(self.get_addr(prev_path))
        puts = [s for s in bl.vex.statements if s.tag == 'Ist_Put']

        expected = 0
        index = 0
        set_regs = []

        # type of regs we are looking for
        reg_ty = 'r' if self._p.arch.bits == 32 else 'x'

        while True:
            if index >= len(puts):
                break

            p = puts[index]

            if self._p.arch.register_names[p.offset] == reg_ty + str(expected):
                set_regs.append(reg_ty + str(expected))
                expected += 1
                index = 0
                continue

            index += 1

        self._save_taint_flag()

        for r in set_regs:
            reg_cnt = getattr(self.get_state(suc_path).regs, r)
            # check if it is pointing to a tainted location
            tmp_s = self.get_state(suc_path).copy()
            try:
                mem_cnt = tmp_s.memory.load(reg_cnt, 50)  # FIXME set this N to a meaningful value
            except TimeOutException as t:
                raise t
            except Exception as e:
                # state is unconstrained
                log.warning("Tried to defererence a non pointer!")
                continue

            # we might have dereferenced wrongly a tainted variable during the tests before
            if (self.is_tainted(reg_cnt) or self.is_tainted(mem_cnt)) and current_depth > 0:
                self._restore_taint_flags()
                return True

        self._restore_taint_flags()
        return False

    def _follow_back_jump(self, current_path, next_path, guards_info):
        """
        Check if a back jump (probably a loop) should be followed.

        :param current_path:  current path
        :param next_path: next path
        :param guards_info:  guards information
        :return:  true if should back jump, false otherwise
        """
        key = hash(''.join(sorted(list(set([x[0] for x in guards_info])))))
        bj = (key, self.get_addr(next_path), self.get_addr(current_path))
        if bj not in self._back_jumps.keys():
            self._back_jumps[bj] = 1
        elif self._back_jumps[bj] > self._N:
            # we do not want to follow the same back jump infinite times
            return False
        else:
            self._back_jumps[bj] += 1
        return True

    def _check_sat_state(self, current_path, current_guards):
        # just try to concretize any variable
        cp_state = current_path.active[0].copy()
        try:
            reg_name = self._p.arch.register_names[return_regs[self._p.arch.name]]
            reg = getattr(cp_state.regs, reg_name)
            cp_state.se.any_int(reg)
            self.last_sat = (current_path.copy(copy_states=True), current_guards)
        except TimeOutException as t:
            raise t
        except Exception as e:
            print str(e)
            return False
        return True

    def _vex_fucked_up(self, current_path, next_path):
        current_path_addr = current_path.active[0].ip.args[0]
        next_path_addr = next_path.active[0].ip.args[0]

        bl = self._get_bb(current_path_addr)
        puts = [p for p in bl.vex.statements if p.tag == 'Ist_Put']

        lr = self._p.arch.register_names[link_regs[self._p.arch.name]]

        for p in puts:
            if self._p.arch.register_names[p.offset] == lr:
                break
        else:
            return False

        if next_path_addr == self._next_inst(bl):
            log.warning(" VEX fucked up big time!")
            return True
        return False

    def _drop_constraints(self, path):
        self.get_state(path).release_plugin('solver_engine')
        self.get_state(path).downsize()

    #FIXME: change offset according arch.
    def _next_inst(self, bl):
        return bl.instruction_addrs[-1] + 4

    def _flat_explore(self, current_path, check_path_fun, guards_info, current_depth, **kwargs):
        """
        Find a tainted path between a source and a sink
        :param current_path: current path
        :param check_path_fun: function to call for every block in the path
        :param guards_info: current info about the guards in the current path
        :param kwargs: additional arguments to pass to check_path_fun
        :return: the tainted path between the source and the sink, if any
        """

        if not self._keep_run:
            log.debug("Backtracking due to stop")
            return

        current_path_addr = self.get_addr(current_path)

        log.debug("%s: Analyzing block %s", self._p.filename.split('/')[-1], hex(current_path_addr))

        if not self._check_sat_state(current_path, guards_info) and not self._timeout_triggered:
            log.error("State got messed up!")
            raise Exception("State became UNSAT")

        # check whether we reached a sink
        try:
            check_path_fun(current_path, guards_info, current_depth, **kwargs)
        except Exception as e:
            if not self._keep_run:
                return
            log.error("'Function check path errored out: %s" % str(e))


        try:
            succ_path = current_path.copy(copy_states=True).step()
        except Exception as e:
            print("ERROR: %s" % str(e))
            return

        # try thumb
        if succ_path and succ_path.errored and self._try_thumb and not self._force_paths:
            succ_path = current_path.copy(copy_states=True).step(thumb=True)

        if succ_path and succ_path.errored and self._try_thumb and not self._force_paths:
            if self._exit_on_decode_error:
                self._keep_run = False
            return

        succ_states_unsat = succ_path.unsat if self._follow_unsat else []
        succ_states_sat = succ_path.active

        if succ_path.deadended and not succ_states_sat and not succ_states_unsat:
            log.debug("Backtracking from dead path")
            return

        if not succ_states_sat:
            # check if it was un unconstrained call.
            # sometimes angr fucks it up
            bl = self._get_bb(current_path_addr)
            if not bl:
                return
            if bl.vex.jumpkind == 'Ijk_Call':
                # create a fake successors
                # which should have been created
                # before.
                # FIXME: I should use get_below_block
                # but as of now I don;t want to use CFG
                unc_state = succ_path.unconstrained[0]
                ret_addr = self._next_inst(bl)
                link_reg = self._p.arch.register_names[link_regs[self._p.arch.name]]
                ret_func = getattr(self.get_state(current_path).regs, link_reg)
                tmp_path = self._set_fake_ret_succ(current_path, unc_state, ret_addr, ret_func)
                succ_states_sat = [self.get_state(tmp_path)]

        # register sat and unsat information so that later we can drop the constraints
        for s in succ_states_sat:
            s.sat = True
        for s in succ_states_unsat:
            s.sat = False

        # collect and prepare the successors to be analyzed
        #shuffle(succ_states_sat)
        succ_states = succ_states_sat + succ_states_unsat

        for next_state in succ_states:
            if hasattr(next_state.ip, 'symbolic') and next_state.ip.symbolic:
                if next_state.sat:
                    continue
                log.warning("Got a symbolic IP, perhaps a non-handled switch statement? FIX ME... ")
                continue

            next_path = succ_path.copy(stashes={'active': [next_state.copy()], 'unsat': [], 'pruned': [], 'unconstrained': [], 'deadended': []})
            if not next_state.sat:
                # unsat successors, drop the constraints
                self._drop_constraints(next_path)

            next_depth = current_depth

            # First, let's see if we can follow the calls
            try:
                if self.get_state(next_path).history.jumpkind == 'Ijk_Call' and not self._vex_fucked_up(current_path, next_path):
                    if not self._is_summarized(current_path, next_path, current_depth):
                        if not self._follow_call(current_path, next_path, current_depth):
                            # if there is not fake ret we create one
                            if not any(s.history.jumpkind == "Ijk_FakeRet" for s in succ_states):
                                state = self.get_state(next_path)
                                link_reg = self._p.arch.register_names[link_regs[self._p.arch.name]]
                                ret_addr = getattr(state.regs, link_reg)
                                ret_func = getattr(self.get_state(current_path).regs, link_reg)
                                next_path = self._set_fake_ret_succ(current_path, state, ret_addr, ret_func)
                            else:
                                # the fake ret is already present, therefore we just skip
                                # the call
                                continue
                        else:
                            log.debug("Following function call to %s" % hex(self.get_addr(next_path)))
                            next_depth = current_depth - 1
            except Exception as e:
                log.error("ERROR: %s" % str(e))
                return

            try:
                if self.get_state(next_path).history.jumpkind == 'Ijk_Ret':
                    next_depth = current_depth + 1
            except:
                continue


            # we have a back jump
            if self.get_state(next_path).history.jumpkind == 'Ijk_Boring' and \
               self.get_addr(next_path) <= self.get_addr(current_path) and \
               not self._follow_back_jump(current_path, next_path, guards_info):
                    log.debug("breaking loop")
                    continue

            # the successor leads out of the function, we do not want to follow it
            if self.get_addr(next_path) == self._bogus_return:
                log.debug("hit a return")
                continue

            # save the info about the guards of this path
            new_guards_info = list(guards_info)
            current_guards = [g for g in self.get_state(next_path).guards]
            if current_guards and len(new_guards_info) < len(current_guards):
                new_guards_info.append([hex(self.get_addr(current_path)), current_guards[-1]])

            # next step!
            self._flat_explore(next_path, check_path_fun, new_guards_info, next_depth, **kwargs)
            log.debug("Back to block %s", hex(self.get_addr(current_path)))
        log.debug("Backtracking")

    def set_project(self, p):
        """
        Set the project
        :param p: angr project
        :return:
        """
        self._p = p

    def stop_run(self):
        """
        Stop the taint analysis
        :return:
        """
        self._keep_run = False

    def flat_explore(self, state, check_path_fun, guards_info, force_thumb=False, **kwargs):
        self._keep_run = True
        initial_path = self._p.factory.path(state)
        initial_path = self._p.factory.simgr(initial_path, save_unconstrained=True, save_unsat=True)
        current_depth = self._interfunction_level

        if force_thumb:
            # set thumb mode
            initial_path = initial_path.step(thumb=True)[0]
        self._flat_explore(initial_path, check_path_fun, guards_info, current_depth, **kwargs)

    def start_logging(self):
        if not self._default_log:
            return

        self._fp.write("Log Start \n"
                       "Binary: " +
                       self._p.filename + '\n'
                       "=================================\n\n")

    def log(self, msg):
        self._fp.write(msg)

    def stop_logging(self):
        if self._default_log:
            log.info("Done.")
            log.info("Results in " + self._fp.name)
        self._fp.close()

    def _init_bss(self, state):
        bss = [s for s in self._p.loader.main_bin.sections if s.name == '.bss']
        if not bss:
            return

        bss = bss[0]
        min_addr = bss.min_addr
        max_addr = bss.max_addr

        for a in range(min_addr, max_addr + 1):
            var = self._get_sym_val(name="bss_", bits=8)
            state.memory.store(a, var)

    def set_alarm(self, timer, n_tries=0):
        # setup a consistent initial state
        signal.signal(signal.SIGALRM, self.handler)
        signal.alarm(timer)
        self._force_exit_after = n_tries
        self._timer = timer

    def unset_alarm(self):
        signal.alarm(0)

    def run(self, state, sinks_info, sources_info, summarized_f={}, init_bss=True,
            check_func=None, force_thumb=False, use_smart_concretization=True):

        if use_smart_concretization:
            state.inspect.b(
                'address_concretization',
                simuvex.BP_AFTER,
                action=self.addr_concrete_after
            )

        state.globals[GLOB_TAINT_DEP_KEY] = {}
        state.globals[UNTAINT_DATA] = {UNTAINTED_VARS:[], SEEN_MASTERS: []}

        self._count_var = 0
        self._back_jumps = {}
        self._keep_run = True
        self._taint_applied = False
        self._fully_taint_guard = []
        self._deref_taint_address = False
        self._deref_addr_expr = None
        self._deref = (None, None)
        self._old_deref = self._deref
        self._old_deref_taint_address = self._deref_taint_address
        self._old_deref_addr_expr = self._deref_addr_expr
        self._concretizations = {}
        self._summarized_f = summarized_f
        self._timeout_triggered = False

        check_func = self._check_if_sink_or_source if check_func is None else check_func

        if init_bss:
            log.info("init .bss")
            self._init_bss(state)
        try:
            self.flat_explore(state,  check_func, [], force_thumb=force_thumb, sinks_info=sinks_info,
                              sources_info=sources_info)
        except TimeOutException:
            log.warning("Hard timeout triggered")

        if self._timeout_triggered:
            self.log("\nTimed out...\n")
            log.debug("Timeout triggered")
