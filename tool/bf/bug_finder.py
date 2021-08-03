import logging
import os
import time

import angr
from claripy import pickle

from bbf.utils import NETWORK_KEYWORDS
from loggers import bar_logger
from bdg.binary_dependency_graph import BinaryDependencyGraph, RoleInfo, Role
from bdg.utils import get_ord_arguments_call, get_any_arguments_call, are_parameters_in_registers, \
    get_mem_string, STR_LEN, get_dyn_sym_addr, find_memcpy_like, get_reg_used, get_addrs_similar_string, \
    prepare_function_summaries, get_string
from bf import sinks
from bf.utils import TIMEOUT_TAINT, TIMEOUT_TRIES, SINK_FUNCS
from taint_analysis.coretaint import TimeOutException, CoreTaint
from taint_analysis.utils import arg_reg_id, get_initial_state, arg_reg_name, \
    get_arguments_call_with_instruction_address, arg_reg_names, get_arity

angr.loggers.disable_root_logger()
angr.logging.disable(logging.ERROR)

log = logging.getLogger("BugFinder")
log.setLevel("DEBUG")


class BugFinder:
    def __init__(self, config, bdg, analyze_parents=True, analyze_children=True, logger_obj=None):
        global log

        if logger_obj:
            log = logger_obj

        self._config = config
        self._bdg = bdg
        self._ct = None
        self._current_seed_addr = None
        self._current_p = None
        self._current_role_info = {
            RoleInfo.ROLE: Role.UNKNOWN,
            RoleInfo.DATAKEY: '',
            RoleInfo.CPF: None,
            RoleInfo.X_REF_FUN: None,
            RoleInfo.CALLER_BB: None,
            RoleInfo.ROLE_FUN: None,
            RoleInfo.ROLE_INS: None,
            RoleInfo.ROLE_INS_IDX: None,
            RoleInfo.COMM_BUFF: None,
            RoleInfo.PAR_N: None
        }

        self._analyze_parents = analyze_parents
        self._analyze_children = analyze_children
        self._analysis_starting_time = None
        self._taint_names_applied = []
        self._sink_addrs = []
        self._current_cfg = None
        self._raised_alert = False
        self._report_alert_fun = None

        # stats
        self._stats = {}
        self._visited_bb = 0
        self._current_cpf_name = Role.UNKNOWN.name
        self._start_time = None
        self._end_time = None
        self._report_stats_fun = None

    def _apply_taint(self, addr, current_path, next_state, taint_key=False, data_key_reg=None):
        """
        Applies the taint to the role function call

        :param addr: address of the role function
        :param current_path: current angr's path
        :param next_state: state at the entry of the function
        :param taint_key: taint the used data key
        :return:
        """

        def is_arg_key(arg):
            return hasattr(arg, 'args') and isinstance(arg.args[0], int) and arg.args[0] == self._current_seed_addr

        p = self._current_p
        ins_args = get_ord_arguments_call(p, addr)
        if not ins_args:
            ins_args = get_any_arguments_call(p, addr)

        if not are_parameters_in_registers(p):
            raise Exception("Parameters not in registers: Implement me")

        for stmt in ins_args:
            reg_name = p.arch.register_names[stmt.offset]
            val_arg = getattr(next_state.regs, reg_name)
            size = None
            if is_arg_key(val_arg):
                if not taint_key:
                    continue
                n_bytes = p.loader.memory.load(val_arg.args[0], STR_LEN)
                size = len(get_mem_string(n_bytes)) * 8
            if val_arg.concrete and val_arg.args[0] < p.loader.main_object.min_addr:
                continue

            log.info(f"taint applied to {reg_name}:{str(val_arg)}")

            # if size is none, it will be estimated in apply_taint
            if reg_name == data_key_reg:
                reg_addr = getattr(next_state.regs, reg_name)
                loaded = self._ct.safe_load(current_path, reg_addr, size=int(size / 8))

            tainted_var = self._ct.apply_taint(current_path, val_arg, reg_name, size)

            # constrain this register if it is the data key
            if reg_name == data_key_reg:
                # load the contents of the register
                current_path.active[0].add_constraints(loaded == tainted_var)

    def _find_sink_addresses(self):
        """
        Sets the sink addresses in the current binary's project

        :return: None
        """

        p = self._current_p

        self._sink_addrs = [(get_dyn_sym_addr(p, func[0]), func[1]) for func in SINK_FUNCS]
        self._sink_addrs += [(m, sinks.memcpy) for m in find_memcpy_like(p)]

    def _jump_in_sink(self, current_path, next_path):
        """
        Checks whether a basic block contains a jump into a sink

        :param current_path: angr current path
        :param next_path: angr next path
        :return: True if the basic block contains a jump into a sink, and the Sink. False and None otherwise
        """
        if self._current_p.loader.find_object_containing(current_path.active[0].addr) != \
                self._current_p.loader.main_object:
            return False, None

        try:
            for entry in self._sink_addrs:
                if next_path.active[0].addr == entry[0]:
                    return True, entry[1]
        except Exception as e:
            log.error(
                f"Unable to find successors for {hex(current_path.active[0].addr)}, perhaps unconstrained call?")
        return False, None

    def _is_sink_and_tainted(self, current_path, next_path):
        """
        Checks if the current basic block is a sink

        :param current_path: angr current path
        :param next_path: angr next path
        :return: The sink if the basic block contains a call to a sink and uses tainted data, False otherwise
        """

        p = self._current_p

        is_sink, check_taint_func = self._jump_in_sink(current_path, next_path)
        if not is_sink:
            return []

        # check if the sink is tainted and collect necessary information
        return check_taint_func(p, self._ct, next_path)

    def _discover_http_strings(self, strs):
        """
        Discover the HTTP strings in the binaries of a BDG
        :param strs: HTTP strings
        :return: None
        """

        for n in self._bdg.nodes:
            old_role_info_callers = [role[RoleInfo.CALLER_BB] for roles in n.role_info.values() for role in roles]
            n.clear_role_info()
            log.info(f"Discovering HTTP strings for {str(n)}")
            BugFinder.find_ref_http_strings(n, strs, old_role_info_callers)
            log.info("Done.")

    def _vuln_analysis(self, bdg_node, seed_addr, info):
        """
        Run the analysis for children (i.e, slave binaries)

        :param bdg_node:  BDG node
        :param seed_addr: address of the seed of taint
        :param info: binary's info
        :return:
        """

        self._current_p = bdg_node.p
        self._current_cfg = bdg_node.cfg
        self._current_cpf_name = bdg_node.find_cpf_data_key(info[RoleInfo.DATAKEY]).name
        self._current_seed_addr = seed_addr
        self._current_role_info = info
        self._taint_names_applied = []
        self._visited_bb = 0

        ana_start_time = time.time()
        if bdg_node.bin not in self._stats:
            self._stats[bdg_node.bin] = {
                'n_paths': 0,
                'ana_time': 0,
                'visited_bb': 0,
                'n_runs': 0,
                'to': 0,
            }

        # prepare the under-constrained-based initial state
        self._ct = CoreTaint(self._current_p, interfunction_level=1, smart_call=True,
                             follow_unsat=True, black_calls=(info[RoleInfo.ROLE_FUN],),
                             try_thumb=True, shuffle_sat=True,
                             exit_on_decode_error=True, force_paths=True,
                             taint_returns_unfollowed_calls=True, allow_untaint=True,
                             logger_obj=log)

        try:
            summarized_f = prepare_function_summaries(self._current_p)
            s = get_initial_state(self._current_p, self._ct, info[RoleInfo.X_REF_FUN])
            self._find_sink_addresses()

            self._ct.set_alarm(TIMEOUT_TAINT, n_tries=TIMEOUT_TRIES)

            self._ct.run(s, (), (), summarized_f=summarized_f, force_thumb=False, check_func=self._check_sink,
                         init_bss=False)
        except TimeOutException:
            log.warning("Hard timeout triggered")
        except Exception as e:
            log.error(f"Coretaint: Something went terribly wrong: {str(e)}")

        self._ct.unset_alarm()

        # stats
        self._stats[bdg_node.bin]['to'] += 1 if self._ct.triggered_to() else 0
        self._stats[bdg_node.bin]['visited_bb'] += self._visited_bb
        self._stats[bdg_node.bin]['n_paths'] += self._ct.n_paths
        self._stats[bdg_node.bin]['ana_time'] += (time.time() - ana_start_time)
        self._stats[bdg_node.bin]['n_runs'] += 1

    @staticmethod
    def find_ref_http_strings(n, keywords, caller_nodes_to_skip=None):
        """
        Finds HTTP related strings

        :param n: BDG node
        :param keywords: keywords to look for
        :param caller_nodes_to_skip a list of caller nodes that we should skip (to prevent duplicates from BDG)
        :return: None
        """

        cfg = n.cfg
        p = n.p

        found_references = []

        # discover the locations of all keys
        key_addrs = []
        for key_string in keywords:
            key_addrs.extend(get_addrs_similar_string(p, key_string))
        key_addrs = list(set(key_addrs))

        for func_addr, func in cfg.kb.functions.items():
            call_sites = func.get_call_sites()
            for call_site in call_sites:
                basic_block = p.factory.block(call_site)
                if basic_block:
                    for inst_addr, put_statement in get_arguments_call_with_instruction_address(p,
                                                                                                basic_block.addr):
                        # check for possible xrefs
                        xrefs = cfg.kb.xrefs.get_xrefs_by_ins_addr(inst_addr)
                        for xref in xrefs:
                            if xref.dst not in key_addrs:
                                continue
                            found_references.append((xref.block_addr, xref.ins_addr, xref.dst))
                        # or the string might be referenced as a constant
                        if hasattr(put_statement.data, 'con') and put_statement.data.con.value in key_addrs:
                            # append the entry
                            found_references.append((basic_block.addr, inst_addr, put_statement.data.con.value))

        for block_addr, inst_addr, key_addr in set(found_references):
            if not BinaryDependencyGraph.is_call(p.factory.block(block_addr)):
                continue

            if are_parameters_in_registers(p):
                reg_used = get_reg_used(p, inst_addr)
                if not reg_used:
                    continue

                # in this way we filter out sub-functions (angr's mistakes)
                x_ref_fun = min([f for f in cfg.functions.values() if
                                 min(f.block_addrs) <= block_addr <= max(f.block_addrs)],
                                key=lambda x: x.addr)

                c_string = get_string(p, key_addr, extended=False)
                if not c_string:
                    raise Exception("find_ref_http_string: Could not retrieve string. DEBUG ME!")

                if caller_nodes_to_skip and block_addr in caller_nodes_to_skip:
                    continue

                info = {
                    RoleInfo.ROLE: n.role,
                    RoleInfo.DATAKEY: c_string,
                    RoleInfo.CPF: None,
                    RoleInfo.X_REF_FUN: x_ref_fun.addr,
                    RoleInfo.CALLER_BB: block_addr,
                    RoleInfo.ROLE_FUN: cfg.model.get_any_node(block_addr).successors[0].addr,
                    RoleInfo.ROLE_INS: None,
                    RoleInfo.ROLE_INS_IDX: None,
                    RoleInfo.COMM_BUFF: None,
                    RoleInfo.PAR_N: arg_reg_id(p, reg_used)
                }
                n.add_role_info(key_addr, info)
            else:
                log.error("_find_ref_http_strings: arch doesn't use registers "
                          "to set function parameters. Implement me!")

    @staticmethod
    def _register_next_elaboration():
        """
        Register next elaboration with the bar logger
        :return:
        """
        if log.__class__ == bar_logger.BarLogger:
            log.new_elaboration()

    def _setup_progress_bar(self):
        """
        Setup the bar logger with the total number of analysis to perform
        :return:
        """
        if log.__class__ == bar_logger.BarLogger:
            tot_dk = sum([len(x.role_data_keys) for x in self._bdg.nodes])
            etc = tot_dk * TIMEOUT_TAINT * TIMEOUT_TRIES / 2
            log.set_etc(etc)
            log.set_tot_elaborations(tot_dk)

    def _analyze(self):
        """
        Runs the actual vulnerability detection analysis

        :return:
        """
        # roots = [f for f, c in self._bdg.graph.items() if len(c) != 0]
        roots = [x for x in self._bdg.nodes if x.root]
        worklist = roots
        analyzed_dk = {}

        # setup the loading bar
        self._setup_progress_bar()
        self._analysis_starting_time = time.time()

        index = 0

        # connected graph
        while index < len(worklist):
            parent = worklist[index]
            index += 1

            if parent not in analyzed_dk:
                analyzed_dk[parent] = []

            parent_strings = parent.role_data_keys

            # analyze parents
            if self._analyze_parents:
                log.info(f"Analyzing {os.path.basename(parent.bin)}")
                for s_addr, s_refs_info in parent.role_info.items():
                    for info in s_refs_info:
                        if info in analyzed_dk[parent]:
                            continue

                        analyzed_dk[parent].append(info)
                        self._register_next_elaboration()
                        log.info(f"New string: {info[RoleInfo.DATAKEY]}")
                        self._vuln_analysis(parent, s_addr, info)
                self._report_stats_fun(parent, self._stats)

            if self._analyze_children:
                # analyze children
                for child in self._bdg.graph[parent]:
                    log.info(f"Analyzing {os.path.basename(child.bin)}")

                    if child not in worklist:
                        worklist.append(child)
                    if child not in analyzed_dk:
                        analyzed_dk[child] = []
                    for s_addr, s_refs_info in child.role_info.items():
                        for info in s_refs_info:
                            if info in analyzed_dk[child]:
                                continue

                            if info[RoleInfo.DATAKEY] in parent_strings or parent.could_be_generated(
                                    info[RoleInfo.DATAKEY]):
                                # update the loading bar
                                self._register_next_elaboration()
                                analyzed_dk[child].append(info)
                                log.info(f"New string: {info[RoleInfo.DATAKEY]}")
                                self._vuln_analysis(child, s_addr, info)
                    self._report_stats_fun(child, self._stats)

        if self._analyze_children:
            # orphans
            log.info("Analyzing orphan nodes")
            for n in self._bdg.orphans:
                log.info(f"Analyzing {os.path.basename(n.bin)}")
                if n not in analyzed_dk:
                    analyzed_dk[n] = []

                for s_addr, s_refs_info in n.role_info.items():
                    for info in s_refs_info:
                        if info in analyzed_dk[n]:
                            continue
                        if 'only_string' in self._config and self._config['only_string'].lower() == 'true':
                            if info[RoleInfo.DATAKEY] != self._config['data_keys'][0][1]:
                                continue
                        analyzed_dk[n].append(info)

                        # update the loading bar
                        self._register_next_elaboration()
                        log.info(f"New string: {info[RoleInfo.DATAKEY]}")
                        self._vuln_analysis(n, s_addr, info)
                self._report_stats_fun(n, self._stats)

    def analysis_time(self):
        if not self._end_time or self._start_time:
            return 0
        return self._end_time - self._start_time

    def _check_sink(self, current_path, guards_info, *_, **__):
        """
        Checks whether the taint propagation analysis lead to a sink, and performs the necessary actions
        :param current_path: angr current path
        :param guards_info:  guards (ITE) information
        :return: None
        """

        try:
            current_state = current_path.active[0]
            current_addr = current_state.addr
            cfg = self._current_cfg

            self._visited_bb += 1

            next_path = current_path.copy(deep=True).step()
            info = self._current_role_info
            # check constant comparisons and untaint if necessary
            bounded, var = self._is_any_taint_var_bounded(guards_info)
            if bounded:
                self._ct.do_recursive_untaint(var, current_path)

            # If the taint is not applied yet, apply it
            if not self._ct.taint_applied and current_addr == info[RoleInfo.CALLER_BB]:
                next_state = next_path.active[0]
                self._apply_taint(current_addr, current_path, next_state, taint_key=True,
                                  data_key_reg=arg_reg_name(self._current_p, info[RoleInfo.PAR_N]))
            try:
                if 'eg_source_addr' in self._config and len(next_path.active) and self._config['eg_source_addr']:
                    if next_path.active[0].addr == int(self._config['eg_source_addr'], 16):
                        next_state = next_path.active[0]
                        self._apply_taint(current_addr, current_path, next_state, taint_key=True)
            except TimeOutException as to:
                raise to
            except Exception as e:
                pass

            if self._is_sink_and_tainted(current_path, next_path):
                delta_t = time.time() - self._analysis_starting_time
                self._raised_alert = True
                name_bin = self._ct.p.loader.main_object.binary
                log.info("Found a tainted sink! Reporting alert!")
                self._report_alert_fun('sink', name_bin, current_path, current_addr,
                                       self._current_role_info[RoleInfo.DATAKEY],
                                       pl_name=self._current_cpf_name, report_time=delta_t)

            # tainted call address and tainted parameters
            bl = self._current_p.factory.block(current_addr)
            if not len(next_path.active) and len(next_path.unconstrained) and bl.vex.jumpkind == 'Ijk_Call':
                cap = bl.capstone.insns[-1]
                vb = bl.vex
                reg_jump = cap.insn.op_str
                val_jump_reg = getattr(next_path.unconstrained[0].regs, reg_jump)
                if not hasattr(vb.next, 'tmp'):
                    return
                val_jump_tmp = next_path.unconstrained[0].scratch.temps[vb.next.tmp]

                if not self.is_tainted_by_us(val_jump_reg) and not self.is_tainted_by_us(val_jump_tmp):
                    if self._ct.is_or_points_to_tainted_data(val_jump_reg, next_path, unconstrained=True):
                        nargs = get_arity(self._current_p, current_path.active[0].addr)
                        for reg_name in arg_reg_names(self._current_p, nargs):
                            if reg_name == reg_jump:
                                continue

                            reg_val = getattr(next_path.unconstrained[0].regs, reg_name)
                            if self._ct.is_or_points_to_tainted_data(reg_val, next_path, unconstrained=True) \
                                    and self.is_address(reg_val):
                                delta_t = time.time() - self._analysis_starting_time
                                self._raised_alert = True
                                name_bin = self._ct.p.loader.main_object.binary
                                log.info("Found a tainted call with tainted parameters! Reporting alert!")
                                self._report_alert_fun('sink', name_bin, current_path, current_addr,
                                                       self._current_role_info[RoleInfo.DATAKEY],
                                                       pl_name=self._current_cpf_name, report_time=delta_t)

                        next_state = next_path.unconstrained[0]
                        hash_val = self.bv_to_hash(val_jump_tmp)
                        self._taint_names_applied.append(hash_val)
                        hash_val = self.bv_to_hash(val_jump_reg)
                        self._taint_names_applied.append(hash_val)
                        self._apply_taint(current_addr, current_path, next_state)

            # eventually if we are in a loop guarded by a tainted variable
            next_active = next_path.active
            if len(next_active) > 1:
                history_addrs = [t for t in current_state.history.bbl_addrs]
                seen_addr = [a.addr for a in next_active if a.addr in history_addrs]

                if len(seen_addr) == 0:
                    return

                back_jumps = [a for a in seen_addr if a < current_addr]
                if len(back_jumps) == 0:
                    return

                bj = back_jumps[0]
                node_s = cfg.model.get_any_node(bj)
                node_f = cfg.model.get_any_node(current_addr)

                if not node_s or not node_f:
                    return

                fun_s = node_s.function_address
                fun_f = node_f.function_address

                if fun_s != fun_f:
                    return

                idx_s = history_addrs.index(bj)
                for a in history_addrs[idx_s:]:
                    n = cfg.model.get_any_node(a)
                    if not n:
                        continue

                    if n.function_address != fun_s:
                        return

                # if we have a back-jump satisfying all the conditions
                cond_guard = [g for g in next_active[0].history.jump_guards][-1]

                for node in cond_guard.recursive_leaf_asts:
                    if self._ct._taint_buf in str(node):
                        log.info("Found a loop guarded by a tainted variable. Reporting Alert!")
                        delta_t = time.time() - self._analysis_starting_time
                        self._raised_alert = True
                        name_bin = self._ct.p.loader.main_object.binary
                        self._report_alert_fun('loop', name_bin, current_path, current_addr, cond_guard,
                                               pl_name=self._current_cpf_name, report_time=delta_t)
            # clean up the copied state to prevent possible memory leaks
            for state in next_path.active + next_path.unconstrained:
                state.history.trim()
                state.downsize()
                state.release_plugin('solver')
        except TimeOutException as to:
            raise to
        except Exception as e:
            log.error(f"Something went terribly wrong: {str(e)}")

    def _is_any_taint_var_bounded(self, guards_info):
        """
        Checks whether tainted data is bounded

        :param guards_info: guards info (ITE)
        :return: True if bounded (False otherwise), and the tainted data.
        """
        if not guards_info:
            return False, None

        bounded = False
        tainted = None
        last_guard = guards_info[-1][1]
        if last_guard.op in ('__eq__', '__le__', '__ne__', 'SLE', 'SGT', '__ge__'):
            op1 = last_guard.args[0]
            op2 = last_guard.args[1]
            if (self._ct.is_tainted(op1) and not self._ct.is_tainted(op2)) or \
                    (self._ct.is_tainted(op2) and not self._ct.is_tainted(op1)):

                # First check if the var si a constant and NULL, as they are mostly used to check whether an address
                # is not NUll.

                if self._ct.is_tainted(op1):
                    tainted = op1
                    var = op2
                else:
                    tainted = op2
                    var = op1

                if last_guard.op in ('__eq__', '__ne__') and var.concrete and var.args[0] == 0:
                    return False, None

                # Then check whether is un-tainting the whole memory region or just a part of it
                # FIXME: do something better
                bounded = True
                for c in tainted.recursive_children_asts:
                    if self._ct.is_tainted(c):
                        if c.op == 'BVS':
                            break
                        if c.op == 'Extract':
                            bounded = False
                            break
        return bounded, tainted

    def is_address(self, val):
        """
        Checks if value is a valid address.
        :param val: value
        :return:  True if value is a valid address
        """
        p = self._current_p
        if val.concrete and val.args[0] < p.loader.main_object.min_addr:
            return False
        return True

    @staticmethod
    def bv_to_hash(v):
        """
        Calculates the hash of a bitvector
        :param v: bit vector
        :return: hash
        """

        args_str = map(str, v.recursive_leaf_asts)
        new_v_str = ''
        for a_str in args_str:
            if '_' in a_str:
                splits = a_str.split('_')
                a_str = '_'.join(splits[:-2] + splits[-1:])
                new_v_str += a_str
        return new_v_str

    def is_tainted_by_us(self, tainted_val):
        """
        Checks if a variable is tainted by us, or the results of the taint propagation
        :param tainted_val: variable
        :return: True if tainted by us, False otherwise
        """

        hash_val = self.bv_to_hash(tainted_val)
        if hash_val in self._taint_names_applied:
            return True
        return False

    @property
    def stats(self):
        return self._stats

    def run(self, report_alert=None, report_stats=None):
        """
        Runs the bug Finder module
        :return:
        """

        def default_report(*args):
            return print(args)

        self._start_time = time.time()
        self._report_alert_fun = default_report if report_alert is None else report_alert
        self._report_stats_fun = default_report if report_stats is None else report_stats

        is_multi_bin = True
        fathers = [f for f, c in self._bdg.graph.items() if len(c) != 0]
        orphans = [n for n in self._bdg.nodes if n.orphan]

        # FIXME: do this in a cleaner way. Perhaps move it into karonte.py?
        if not fathers and not orphans:
            # Single bin case:
            # let's consider common network strings too
            is_multi_bin = False
            self._discover_http_strings(NETWORK_KEYWORDS)
            for node in self._bdg.nodes:
                node.set_orphan()

        self._analyze()

        # also run for all other possible keywords
        if not self._raised_alert and is_multi_bin:
            log.info("Attempting to discover new data keys:")
            # let's consider other possible data-keys too
            self._discover_http_strings(NETWORK_KEYWORDS)
            self._analyze()

        self._end_time = time.time()
