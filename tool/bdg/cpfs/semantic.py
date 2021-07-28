from bdg.cpfs.__init__ import CPF

import angr
import itertools

from taint_analysis.utils import get_arity, arg_reg_name, arg_reg_id, arg_reg_off
from bdg.bdp_enum import Role, RoleInfo
from bdg.utils import get_string, are_parameters_in_registers, contains
from taint_analysis.coretaint import TimeOutException

INDEXING_OPS = ('add', 'sub')
CMP_FUNCTIONS = ('strcmp', 'strncmp', 'memcmp', 'strcsecmp', 'strncasecmp', 'strstr')
CPY_FUNS = ('sprintf', 'snprintf')


class Semantic(CPF):

    def __init__(self, *kargs, **kwargs):
        CPF.__init__(self, 'semantic', *kargs, **kwargs)
        self._normalized_cfg = None
        self._tainted_calls = []
        self._already_discovered = False

    def taint_used_as_index(self, core_taint, b, s, path):
        """
        Checks whether a tainted variable is used as index within a data structure

        :param core_taint: core taint engine
        :param b: basic block
        :param s: vex statement where the buffer is referenced
        :param path: angr current path
        :return: True if the tainted variable is used as index, False otherwise
        """

        s_idx = b.vex.statements.index(s)
        stmts = b.vex.statements[:s_idx]
        state = path.active[0]

        for stmt in stmts:
            try:
                if contains(INDEXING_OPS, stmt.data.op.lower()):
                    for a in stmt.data.args:
                        # tmp
                        if hasattr(a, 'tmp'):
                            val = state.scratch.temps[a.tmp]
                        # constant
                        elif hasattr(a, 'con'):
                            val = a.con.value
                        else:
                            self._log.error("Semantic: This type of reference is not implemented! Implement me!")
                            continue

                        if val is not None and core_taint.is_tainted(val, path=path) or \
                                core_taint.is_tainted(core_taint.safe_load(path, val), path=path):
                            return True

            except TimeOutException:
                raise
            except:
                continue
        return False

    def _is_memcmp_succ(self, succ):
        if not self._blob:
            return (succ.name and succ.name in CMP_FUNCTIONS or (self._p.loader.find_plt_stub_name(succ.addr)
                                                                 and succ.successors[0].name
                                                                 and succ.successors[0].name in CMP_FUNCTIONS))
        else:
            return succ.addr in self._memcmp_like

    def _is_wrapped(self, history_bbl, current_path):
        """
        Check whether a role function is wrapper by another function.

        :param history_bbl: basic bloc history
        :param current_path: angr current path
        :return: True if it is wrapped, and the wrapper. False, and None otherwise.
        """

        # FIXME: add check to function parameters to define if a function is a wrapper or not
        try:
            faddr = self._cfg.model.get_any_node(current_path.active[0].addr).function_address
            fcallers = [x.function_address for x in self._cfg.model.get_any_node(faddr).predecessors if x]
            found_callers = [a for a in history_bbl if a in fcallers]
            candidate_wrapper = found_callers[-1]
            if candidate_wrapper in self._tainted_calls:
                return True, candidate_wrapper
        except TimeOutException:
            raise
        except:
            pass
        return False, None

    def _indirect_access_search(self, current_path, data_key, key_addr, core_taint, reg_name, next_path):
        """
        Checks whether tainted data is used indirectly (through a loop and memory comparison) to retrieve, or set, data
        into a structure.

        :param current_path: angr current path
        :param data_key: data key value
        :param key_addr: data key address
        :param core_taint: core taint engine
        :param reg_name: register name
        :return:
        """
        current_addr = current_path.active[0].addr

        try:
            next_state = next_path.active[0]
        except TimeOutException:
            raise
        except Exception:
            return False, Role.UNKNOWN

        if self._p.factory.block(current_addr).vex.jumpkind == 'Ijk_Call':
            # there must be a loop, a strcmp-like function and the data_key has to be used as key
            history_bbs = [x for x in current_path.active[0].history.bbl_addrs]
            no = self._cfg.model.get_any_node(current_addr)

            if no and no.successors:

                for succ in no.successors:
                    if current_addr in history_bbs and self._is_memcmp_succ(succ):

                        # we are calling a strcmp-like function within a loop.
                        if not are_parameters_in_registers(self._p):
                            raise Exception("implement me")

                        dst_addr = getattr(next_state.regs, arg_reg_name(self._p, 1))
                        dst_cnt = current_path.active[0].memory.load(dst_addr, self._p.arch.bytes)
                        # eq = int(dst_addr.args[0]) == dst_addr
                        concrete = dst_addr.concrete
                        if core_taint.is_tainted(dst_cnt) or concrete:
                            # yup! they are looking for some data indexed by the key. Understand if for setting
                            # or getting
                            current_function = no.function_address
                            try:
                                pos_call = len(history_bbs) - 1 - history_bbs[::-1].index(current_function)
                            except TimeOutException:
                                raise
                            except:
                                pos_call = 0

                            assert pos_call > 0, 'semantic.run: unable to find the calling block'

                            caller_block = history_bbs[pos_call - 1]

                            # Heuristic: if the function's arity is greater than two, we assume
                            # that the third paramenter is the content to store in the shared buffer, making
                            # the function itsels a setter.
                            # FIXME: (limitation) improve this heuristic. One should perform a def-use analysis to
                            # see whether the base pointer used as first argument in the strcmp is used to return a
                            # value, or to set a value
                            nargs = get_arity(self._p, caller_block)
                            if nargs > 2:
                                candidate_role = Role.SETTER
                            else:
                                candidate_role = Role.GETTER

                            no = self._cfg.model.get_any_node(caller_block)
                            assert no, 'semantic.run: could not get a node :('

                            function_x_ref = no.function_address
                            block = self._p.factory.block(no.addr)
                            is_wrapped, wrapp_addr = self._is_wrapped(history_bbs, current_path)
                            if is_wrapped:
                                last_index = len(history_bbs) - 1 - history_bbs[::-1].index(wrapp_addr)
                                if last_index > 0:
                                    current_function = wrapp_addr
                                    caller_block = history_bbs[last_index - 1]
                                    cno = self._cfg.model.get_any_node(caller_block)
                                    function_x_ref = None
                                    if cno:
                                        function_x_ref = cno.function_address

                            info = {
                                RoleInfo.ROLE: candidate_role,
                                RoleInfo.DATAKEY: data_key,
                                RoleInfo.X_REF_FUN: function_x_ref,
                                RoleInfo.CALLER_BB: caller_block,
                                RoleInfo.ROLE_FUN: current_function,
                                RoleInfo.ROLE_INS: no.addr,
                                RoleInfo.ROLE_INS_IDX: len(block.vex.statements),
                                RoleInfo.COMM_BUFF: None,
                                RoleInfo.PAR_N: arg_reg_id(self._p, reg_name),
                                RoleInfo.CPF: self._name
                            }
                            if key_addr not in self._role_info:
                                self._role_info[key_addr] = []

                            if info not in self._role_info[key_addr]:
                                self._role_info[key_addr].append(info)
                            return True, candidate_role

        return False, Role.UNKNOWN

    def _check_role_function_address(self, addr):
        """
        Checks if addr is the real beginning of a function.
        To do so, we check whether the predecessor is immediately before addr.
        if so, we assume it's not a call and angr messed up.

        :param addr: function address
        :return: the address of the role function
        """

        try:
            fno = self._cfg.model.get_any_node(addr)
            preds = fno.predecessors
            if len(preds) != 1:
                return addr
            pred = preds[0]
            if addr - pred.addr == pred.size:
                # angr messed up. Let's play safe and return the first function getting
                # tainted parameters
                return self._tainted_calls[0]
        except:
            return addr

    def _direct_access_search(self, current_path, data_key, key_addr, core_taint, reg_name, next_path):
        """
        Finds whether the current analyzed function used tainted data as index to retrieve, or set, some data.

        :param current_path: angr current path
        :param data_key:  data key value
        :param key_addr:  data key address
        :param core_taint: core taint engine
        :param reg_name: parameter name (i.e., register name)
        :return:
        """

        p = self._p

        candidate_role = Role.UNKNOWN
        block = p.factory.block(current_path.active[0].addr)

        try:
            state = next_path.active[0]
        except TimeOutException:
            raise
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
                    buf_addr = state.scratch.temps[addr_tmp] if addr_tmp < len(state.scratch.temps) else None
                elif hasattr(s.addr, 'con'):
                    buf_addr = s.addr.con.value
                else:
                    self._log.error("Never seen this case.. check me!")
                    return False, Role.UNKNOWN
            elif s.tag == 'Ist_WrTmp' and s.data.tag == 'Iex_Load':
                # if the memory location to read from depends on the key, is a getter
                # t1 = key + x
                # e.g. t2 = LD(t1)
                candidate_role = Role.GETTER
                if hasattr(s.data.addr, 'tmp'):
                    addr_tmp = s.data.addr.tmp
                    buf_addr = state.scratch.temps[addr_tmp] if addr_tmp < len(state.scratch.temps) else None
                elif hasattr(s.data.addr, 'con'):
                    buf_addr = s.data.addr.con.value
                else:
                    self._log.error("Never seen this case.. check me!")
                    return False, Role.UNKNOWN

            elif s.tag == 'Ist_IMark':
                ins_addr = s.addr

            if buf_addr is not None and (core_taint.is_tainted(buf_addr, path=next_path) or
                                         core_taint.is_tainted(core_taint.safe_load(next_path, buf_addr),
                                                               path=next_path)):

                # check if the key is used as index
                if self.taint_used_as_index(core_taint, block, s, next_path):
                    self._data_keys.append(data_key)

                    addrs = [x for x in current_path.active[0].history.bbl_addrs]
                    current_addr = current_path.active[0].addr

                    no = self._cfg.model.get_any_node(current_addr)
                    assert no, 'semantic.run: could not get a node :('

                    current_function = self._check_role_function_address(no.function_address)
                    try:
                        pos_call = len(addrs) - 1 - addrs[::-1].index(current_function)
                    except TimeOutException:
                        raise
                    except:
                        pos_call = 0

                    assert pos_call > 0, 'semantic.run: unable to find the calling block'

                    caller_block = addrs[pos_call - 1]
                    no = self._cfg.model.get_any_node(caller_block)
                    assert no, 'semantic.run: could not get a node :('
                    function_x_ref = no.function_address

                    is_wrapped, wrapp_addr = self._is_wrapped(addrs, current_path)
                    if is_wrapped:
                        last_index = len(addrs) - 1 - addrs[::-1].index(wrapp_addr)
                        if last_index > 0:
                            current_function = wrapp_addr
                            caller_block = addrs[last_index - 1]
                            cno = self._cfg.model.get_any_node(caller_block)
                            function_x_ref = None
                            if cno:
                                function_x_ref = cno.function_address

                    info = {
                        RoleInfo.ROLE: candidate_role,
                        RoleInfo.DATAKEY: data_key,
                        RoleInfo.X_REF_FUN: function_x_ref,
                        RoleInfo.CALLER_BB: caller_block,
                        RoleInfo.ROLE_FUN: current_function,
                        RoleInfo.ROLE_INS: ins_addr,
                        RoleInfo.ROLE_INS_IDX: block.vex.statements.index(s),
                        RoleInfo.PAR_N: arg_reg_id(p, reg_name),
                        RoleInfo.CPF: self._name,
                    }
                    if key_addr not in self._role_info:
                        self._role_info[key_addr] = []

                    if info not in self._role_info[key_addr]:
                        self._role_info[key_addr].append(info)
                    return True, candidate_role

        return False, Role.UNKNOWN

    def _save_info_preamble(self, current_path, core_taint):
        """
        Save address of function calls that have tainted parameters.
        This is useful to find wrappers to role functions.

        :param current_path: angr current path
        :param core_taint:  core taint engine
        :return:  None
        """

        try:
            no = self._cfg.model.get_any_node(current_path.active[0].addr)
            if not no or no.function_address != no.addr:
                return

            if len(no.predecessors) == 1:
                # check if the current address is just a normal basic block
                # that angr mistaken for a function because it contains a function preamble
                pred = no.predecessors[0]
                if self._p.factory.block(pred.addr).vex.jumpkind != 'Ijk_Call':
                    return

            if no.predecessors:
                arity = get_arity(self._p, no.predecessors[0].addr)
                for narg in range(arity):
                    dst_addr = getattr(current_path.active[0].regs, arg_reg_name(self._p, narg))
                    if core_taint.is_or_points_to_tainted_data(dst_addr, current_path):
                        self._tainted_calls.append(no.addr)
                        break
        except TimeOutException:
            raise
        except:
            return

    def _glbl_data_key_setter(self, current_path, data_key, key_addr, core_taint, reg_name, par_vals, next_path):
        """
        Check whether a data key is copied to global structure. This strategy is usually used to binaries that
        talks to themselves.

        :param current_path: angr current path
        :param data_key: data key value
        :param key_addr: data key address
        :param core_taint: core taint engine
        :param reg_name: parameter name
        :param par_vals: function argument values
        :return: None
        """

        p = self._p
        cfg = self._cfg

        globl = False
        tainted = False
        arg_copied = False

        try:
            current_addr = current_path.active[0].addr
            bl = p.factory.block(current_addr)

            if bl.vex.jumpkind != 'Ijk_Call':
                return False, Role.UNKNOWN

            no = cfg.model.get_any_node(current_addr)
            succ = no.successors[0]

            if not self._p.loader.find_plt_stub_name(succ.addr):
                return False, Role.UNKNOWN

            if not succ.name:
                succ = succ.successors[0]

            if succ.name in CPY_FUNS:
                caller_block_addr = current_addr
                arity = get_arity(p, caller_block_addr)
                for narg in range(arity):
                    dst_reg_cnt = getattr(next_path.active[0].regs, arg_reg_name(p, narg))
                    cnt_buff = current_path.active[0].memory.load(dst_reg_cnt, p.arch.bytes)

                    if core_taint.is_or_points_to_tainted_data(dst_reg_cnt, next_path):
                        tainted = True
                    elif dst_reg_cnt.concrete and any([sec.min_addr <= dst_reg_cnt.args[0] <= sec.max_addr
                                                       for sec in p.loader.main_object.sections
                                                       if sec.name in ('.bss', '.data')]):
                        globl = True
                    elif any([str(cnt_buff) == str(current_path.active[0].memory.load(val, p.arch.bytes))
                              for val in par_vals]):
                        arg_copied = True

                if arg_copied and tainted and globl:
                    current_function = no.function_address
                    addrs = [x for x in current_path.active[0].history.bbl_addrs]

                    try:
                        pos_call = len(addrs) - 1 - addrs[::-1].index(current_function)
                    except TimeOutException:
                        raise
                    except:
                        pos_call = 0

                    assert pos_call > 0, 'semantic.run: unable to find the calling block'

                    caller_block = addrs[pos_call - 1]
                    cno = self._cfg.model.get_any_node(caller_block)
                    assert cno, 'semantic.run: could not get a node :('
                    function_x_ref = cno.function_address

                    info = {
                        RoleInfo.ROLE: Role.SETTER,
                        RoleInfo.DATAKEY: data_key,
                        RoleInfo.X_REF_FUN: function_x_ref,
                        RoleInfo.CALLER_BB: caller_block,
                        RoleInfo.ROLE_FUN: current_function,
                        RoleInfo.ROLE_INS: cno.addr,
                        RoleInfo.ROLE_INS_IDX: len(bl.vex.statements),
                        RoleInfo.COMM_BUFF: None,
                        RoleInfo.PAR_N: arg_reg_id(p, reg_name),
                        RoleInfo.CPF: self._name
                    }
                    if key_addr not in self._role_info:
                        self._role_info[key_addr] = []

                    if info not in self._role_info[key_addr]:
                        self._role_info[key_addr].append(info)
                    return True,  Role.SETTER

        except TimeOutException:
            raise
        except Exception as e:
            self._log.debug(f"Semantic cpf. Error: {str(e)}")

        return False, Role.UNKNOWN

    def run(self, data_key, key_addr, reg_name, core_taint, current_path, par_vals):
        """
        Run the semantic CPF.

        we scan for three different semantic setter/getter
        1- cases like hash_map['key'] = val or return hash_map['key']
        2- if(!strcmp(ptr_entry, 'key')){/* .. /*}
        3- memcpy(GLOBAL_STRUCT_PTR, 'key')

        :param data_key: data key value
        :param key_addr:  data key address
        :param reg_name: parameter name containng the address of the data key
        :param core_taint: core taint engine
        :param current_path: angr current path
        :param par_vals: function parameter values
        :return: True if the semantic CPF matched, False otherwise.
                 The role of the binary is also returned.
        """

        self._save_info_preamble(current_path, core_taint)
        next_path = current_path.copy(deep=True).step()
        found, role = self._direct_access_search(current_path, data_key, key_addr, core_taint, reg_name, next_path)
        if not found:
            found, role = self._indirect_access_search(current_path, data_key, key_addr, core_taint,
                                                       reg_name, next_path)
        if not found:
            found, role = self._glbl_data_key_setter(current_path, data_key, key_addr, core_taint,
                                                     reg_name, par_vals, next_path)
        return found, role


    @property
    def role_info(self):
        return self._role_info

    def discover_data_keys(self):
        """
        Discover new data keys based on the same role functions.

        :return: role information
        """

        cfg = self._cfg

        if self._already_discovered:
            return self._role_info

        role_functions_info = [x for x in itertools.chain.from_iterable(self._role_info.values())]
        bak = dict(self._role_info)
        self._role_info = {}

        # we used the current info, to get more role info
        for role_function_info in role_functions_info:
            if role_function_info[RoleInfo.ROLE] == Role.UNKNOWN:
                continue

            role_fun_addr = role_function_info[RoleInfo.ROLE_FUN]

            # all the callers to that function
            callers = cfg.model.get_any_node(role_fun_addr).predecessors
            for c in callers:
                self._record_role_data_key(c, role_function_info)

        self._already_discovered = True
        if not self._role_info:
            # something went wrong, let's restore what we found
            self._role_info = dict(bak)

        return self._role_info
