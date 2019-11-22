import angr
from __init__ import Plugin
from binary_dependency_graph.utils import *
from binary_dependency_graph.bdp_enum import *
from taint_analysis.utils import *
import itertools

INDEXING_OPS = ('add', 'sub')
CMP_FUNCTIONS = ('strcmp', 'strncmp', 'memcmp')
LIB_KEYWORD = 'lib'

class Semantic(Plugin):

    def __init__(self, *kargs, **kwargs):
        Plugin.__init__(self, 'semantic', *kargs, **kwargs)
        self._strings = []
        self._role_strings_info = {}
        self._already_discovered = False
        self._normalized_cfg = None

    # FIXME: use a better way to do this
    def _is_stack(self, addr, state):
        """
        Checks whether an address belongs to the current stack
        :param addr: address
        :param state:  current state
        :return: True if the address belongs to the current stack, False otherwise
        """

        p = self._p

        msbs = (state.callstack.current_stack_pointer & addr & 0x7ff << (p.arch.bits - 12))
        if hasattr(msbs, 'args'):
            msbs = msbs.args[0]
        return msbs == 0x7ff00000

    def _is_heap(self, addr, state):
        """
        Checks whether an address belongs to the heap
        :param addr: address
        :param state:  current state
        :return: True if the address belongs to the heap, False otherwise
        """

        if hasattr(addr, 'args'):
            addr = addr.args[0]
        return state.libc.heap_location >= addr

    def _is_global(self, addr, state):
        return False

    def _taint_used_as_index(self, core_taint, b, s, path):
        """
        Checks whether a tainted variable is used as index within a data structure

        :param b: basic block
        :param s: vex statement where the buffer is referenced
        :param state: program state
        :return: True if the tainted variable is used as index, False otherwise
        """
        s_idx = b.vex.statements.index(s)
        stmts = b.vex.statements[:s_idx]
        state = path.active[0]

        for stmt in stmts:
            try:
                if contains(INDEXING_OPS, stmt.data.op.lower()):
                    for a in stmt.data.args:
                        val = None
                        # tmp
                        if hasattr(a, 'tmp'):
                            val = a.tmp
                        # constant
                        elif hasattr(a, 'con'):
                            val = a.con.value
                        else:
                            print "Implement me!"
                            return False

                        if val is not None and core_taint.is_tainted(state.scratch.temps[val], path=path) or \
                                core_taint.is_tainted(core_taint.safe_load(path, state.scratch.temps[val]),
                                                            path=path):
                            return True

            except:
                continue
        return False

    def _is_memcmp_succ(self, succ):
        if not self._blob:
            return (succ.name and succ.name in CMP_FUNCTIONS or (succ.addr in self._p.loader.main_bin.reverse_plt
                                                      and succ.successors[0].name and succ.successors[0].name in CMP_FUNCTIONS))
        else:
            return succ.addr in self._memcmp_like

    def _indirect_access_search(self, current_path, key_string, key_addr, core_taint, par_name):
        # there must be a loop, a strcmp-like function and the key_string has to be used as key
        history_bbs = [x for x in current_path.active[0].history.bbl_addrs]
        current_addr = current_path.active[0].addr

        next_path = current_path.copy(copy_states=True)

        next_path.step()
        try:
            next_state = next_path.active[0]
        except:
            return False, Role.UNKNOWN

        if self._p.factory.block(current_addr).vex.jumpkind == 'Ijk_Call':
            no = self._cfg.get_any_node(current_addr)
            if no and no.successors:

                for succ in no.successors:
                    if current_addr in history_bbs and self._is_memcmp_succ(succ):

                        # we are calling a strcmp-like function within a loop.
                        if not are_parameters_in_registers(self._p):
                            print "implement me"
                            return False

                        dst_reg = ordered_agument_regs[self._p.arch.name][1]
                        dst_addr = getattr(next_state.regs, self._p.arch.register_names[dst_reg])
                        dst_cnt = current_path.active[0].memory.load(dst_addr)
                        if core_taint.is_tainted(dst_cnt) or (dst_addr.concrete and dst_addr.args[0] == dst_addr):
                            # yup! they are looking for some data indexed by the key string. Understand if for setting
                            # or getting
                            current_function = no.function_address
                            try:
                                pos_call = len(history_bbs) - 1 - history_bbs[::-1].index(current_function)
                            except:
                                pos_call = 0

                            assert pos_call > 0, 'semantic.run: unable to find the calling block'

                            caller_block = history_bbs[pos_call - 1]

                            # Heuristic: if the function's arity is greater than two, we assume
                            # that the third paramenter is the content to store in the shared buffer, making
                            # the function itsels a setter.
                            # FIXME: (limitation) improve this heuristic. One should perform a def-use analysis to see whether
                            # the base pointer used as first argument in the strcmp is used to return a value, or to set
                            # a value
                            nargs = get_arity(self._p, caller_block)
                            if nargs > 2:
                                candidate_role = Role.SETTER
                            else:
                                candidate_role = Role.GETTER

                            no = self._cfg.get_any_node(caller_block)
                            assert no, 'semantic.run: could not get a node :('

                            function_x_ref = no.function_address
                            par_id = ordered_agument_regs[self._p.arch.name].index(self._p.arch.registers[par_name][0])
                            block = self._p.factory.block(no.addr)

                            info = {
                                RoleInfo.ROLE: candidate_role,
                                RoleInfo.STRING: key_string,
                                RoleInfo.X_REF_FUN: function_x_ref,
                                RoleInfo.CALLER_BB: caller_block,
                                RoleInfo.ROLE_FUN: current_function,
                                RoleInfo.ROLE_INS: no.addr,
                                RoleInfo.ROLE_INS_IDX: len(block.vex.statements),
                                RoleInfo.COMM_BUFF: None,
                                RoleInfo.PAR_N: par_id
                            }
                            if key_addr not in self._role_strings_info:
                                self._role_strings_info[key_addr] = []
                            self._role_strings_info[key_addr].append(info)
                            return True, candidate_role

        return False, Role.UNKNOWN

    def _direct_access_search(self, current_path, key_string, key_addr, core_taint, par_name):
        p = self._p

        candidate_role = Role.UNKNOWN
        next_path = current_path.copy(copy_states=True)
        block = p.factory.block(current_path.active[0].addr)

        next_path.step()
        try:
            state = next_path.active[0]
        except:
            return False, Role.UNKNOWN

        ins_addr = None

        for s in block.vex.statements:
            # store in a buffer
            buf_addr = None

            if s.tag == 'Ist_Store':
                # if the memory location to write into depends on the key, is a setter
                # t2 = val
                # t1 = key + x
                # e.g. ST(t1) = t2
                candidate_role = Role.SETTER
                if hasattr(s.addr, 'tmp'):
                    addr_tmp = s.addr.tmp
                    buf_addr = state.scratch.temps[addr_tmp] if addr_tmp and addr_tmp in state.scratch.temps else None
                elif hasattr(s.addr, 'con'):
                    buf_addr = s.addr.con.value
                else:
                    return False, Role.UNKNOWN
            elif s.tag == 'Ist_WrTmp' and s.data.tag == 'Iex_Load':
                # if the memory location to read from depends on the key, is a getter
                # t1 = key + x
                # e.g. t2 = LD(t1)
                candidate_role = Role.GETTER
                if hasattr(s.data.addr, 'tmp'):
                    addr_tmp = s.data.addr
                    buf_addr = state.scratch.temps[addr_tmp] if addr_tmp and addr_tmp in state.scratch.temps else None

                elif hasattr(s.data.addr, 'con'):
                    buf_addr = s.data.addr.con.value
                else:
                    return False, Role.UNKNOWN
            elif s.tag == 'Ist_IMark':
                ins_addr = s.addr

            if buf_addr is not None and (core_taint.is_tainted(buf_addr, path=next_path) or
                                             core_taint.is_tainted(core_taint.safe_load(next_path, buf_addr),
                                                                   path=next_path)):
                if hasattr(buf_addr, 'args'):
                    buf_addr = buf_addr.args[0]

                # check if the key is used as index
                if self._taint_used_as_index(core_taint, block, s, next_path):
                    # check the type of buffer used
                    buf_type = None
                    if self._is_stack(buf_addr, state):
                        buf_type = BuffType.STACK
                    elif self._is_heap(buf_addr, state):
                        buf_type = BuffType.HEAP
                    elif self._is_global(buf_addr, state):
                        buf_type = BuffType.GLOBAL
                    self._strings.append(key_string)

                    addrs = [x for x in current_path.active[0].history.bbl_addrs]
                    current_addr = current_path.active[0].addr

                    no = self._cfg.get_any_node(current_addr)
                    assert no, 'semantic.run: could not get a node :('

                    current_function = no.function_address
                    try:
                        pos_call = len(addrs) - 1 - addrs[::-1].index(current_function)
                    except:
                        pos_call = 0

                    assert pos_call > 0, 'semantic.run: unable to find the calling block'

                    caller_block = addrs[pos_call - 1]
                    no = self._cfg.get_any_node(caller_block)
                    assert no, 'semantic.run: could not get a node :('

                    function_x_ref = no.function_address
                    par_id = ordered_agument_regs[p.arch.name].index(p.arch.registers[par_name][0])

                    info = {
                        RoleInfo.ROLE: candidate_role,
                        RoleInfo.STRING: key_string,
                        RoleInfo.X_REF_FUN: function_x_ref,
                        RoleInfo.CALLER_BB: caller_block,
                        RoleInfo.ROLE_FUN: current_function,
                        RoleInfo.ROLE_INS: ins_addr,
                        RoleInfo.ROLE_INS_IDX: block.vex.statements.index(s),
                        RoleInfo.COMM_BUFF: buf_type,
                        RoleInfo.PAR_N: par_id
                    }
                    if key_addr not in self._role_strings_info:
                        self._role_strings_info[key_addr] = []

                    self._role_strings_info[key_addr].append(info)
                    return True, candidate_role

        return False, Role.UNKNOWN

    def run(self, key_string, key_addr, par_name, core_taint, current_path):
        # we scan for two different semantic setter/getter
        # 1- cases like hash_map['key'] = val or return hash_map['key']
        # 2- while(strcmp(ptr_entry, 'key')){/* .. /*}
        found, role = self._direct_access_search(current_path, key_string, key_addr, core_taint, par_name)
        if found:
            return True, role
        return self._indirect_access_search(current_path, key_string, key_addr, core_taint, par_name)

    def discover_new_binaries(self):
        bins = []

        for _, r_info in self._role_strings_info.items():
            for info in r_info:
                if info[RoleInfo.ROLE] == Role.SETTER:
                    string = info[RoleInfo.STRING]
                    self._log.debug("New string: " + str(string))
                    cmd = "grep -r '" + string + "' " + self._fw_path + " | grep Binary | awk '{print $3}'"
                    o, e = run_command(cmd)
                    candidate_bins = list(set([x for x in o.split('\n') if x]))
                    for b in candidate_bins:
                        if LIB_KEYWORD in b:
                            continue

                        name = b.split('/')[-1]
                        self._log.debug("Adding " + str(name))
                        bins.append(b)

        return list(set(bins))

    def _search_in_bb(self, caller_node, role_function_info):
        p = self._p
        c = caller_node

        block = p.factory.block(c.addr)

        # consider the constants in the calling block
        for con in block.vex.all_constants:
            val = con.value
            # check if a string
            c_string = get_string(p, val)
            if c_string:
                if val not in self._role_strings_info:
                    self._role_strings_info[val] = []

                new_role_info = dict(role_function_info)
                new_role_info[RoleInfo.STRING] = c_string
                new_role_info[RoleInfo.X_REF_FUN] = c.function_address
                new_role_info[RoleInfo.CALLER_BB] = c.addr

                self._role_strings_info[val].append(new_role_info)

    def _run_def_use(self, caller_node, role_function_info):
        if not self._normalized_cfg:
            self._normalized_cfg = self._p.analyses.CFG(normalize=True)

        p = self._p
        cfg = self._normalized_cfg

        c = caller_node
        # Reaching definition analysis
        fun = cfg.functions.function(caller_node.function_address)
        t = (caller_node.instruction_addrs[-1], angr.analyses.reaching_definitions.OP_AFTER)
        rd = p.analyses.ReachingDefinitions(func=fun, observation_points=[t,], init_func=True)
        try:
            results = rd.observed_results[t]
        except:
            return

        if are_parameters_in_registers(p):
            idx = role_function_info[RoleInfo.PAR_N]
            reg_off = ordered_agument_regs[p.arch.name][idx]

            for r_def in results.register_definitions.get_objects_by_offset(reg_off):
                for val in r_def.data.data:
                    if type(val) == angr.analyses.reaching_definitions.undefined.Undefined:
                        continue
                    if type(val) not in (int, long):
                        print("Data value is not what expected. Check me...")
                        return

                    c_string = get_string(p, val)
                    if val not in self._role_strings_info:
                        self._role_strings_info[val] = []

                    new_role_info = dict(role_function_info)
                    new_role_info[RoleInfo.STRING] = c_string
                    new_role_info[RoleInfo.X_REF_FUN] = c.function_address
                    new_role_info[RoleInfo.CALLER_BB] = c.addr

                    self._role_strings_info[val].append(new_role_info)

        else:
            print ("Implement me")
            return

    def _record_role_string(self, caller_node, role_function_info):
        p = self._p
        cfg = self._cfg

        # shortcut: check whether the string is the in the basic block
        # in such a case we avoid to perform a reach-def analysis and just get the
        # string
        idx = role_function_info[RoleInfo.PAR_N]
        reg_off = ordered_agument_regs[p.arch.name][idx]
        block = p.factory.block(caller_node.addr)
        ass_to_reg = [x for x in block.vex.statements if x.tag == 'Ist_Put' and x.offset == reg_off]

        # it might
        if ass_to_reg:
            ass_to_reg = ass_to_reg[-1]
            if hasattr(ass_to_reg, 'tmp'): # nope
                print ("_run_def_use: tmp is assigned to a register, we should find all the defs for this "
                        "tmp rather than the register. Implement me...")
                return

            self._search_in_bb(caller_node, role_function_info)
            return

        self._run_def_use(caller_node, role_function_info)

    @property
    def role_strings_info(self):
        return self._role_strings_info

    def discover_strings(self):
        p = self._p
        cfg = self._cfg

        if self._already_discovered:
            return self._role_strings_info

        role_functions_info = [x for x in itertools.chain.from_iterable(self._role_strings_info.values())]
        self._role_strings_info = {}

        for role_function_info in role_functions_info:
            if role_function_info[RoleInfo.ROLE] == Role.UNKNOWN:
                continue

            role_fun_addr = role_function_info[RoleInfo.ROLE_FUN]

            # all the callers to that function
            callers = cfg.get_any_node(role_fun_addr).predecessors
            for c in callers:
                self._record_role_string(c, role_function_info)

        self._already_discovered = True
        return self._role_strings_info