from __init__ import CPF, LIB_KEYWORD

import angr
import itertools

from taint_analysis.utils import ordered_argument_regs, get_arity
from binary_dependency_graph.utils import get_string, are_parameters_in_registers, run_command, contains
from binary_dependency_graph.bdp_enum import Role, RoleInfo, BuffType
from taint_analysis.coretaint import TimeOutException

M_SET_KEYWORD = ('set', 'insert', 'add', 'nvram_set')
M_GET_KEYWORD = ('get', 'read', 'nvram_get')


class SetterGetter(CPF):
    """
    This CPF is an extension of the semantic CPF to speed up analysis.
    It does string matching on a function name (when present) and tries to infer whether the function is a role
    function for the pair (data key, current binay)
    """

    def __init__(self, *kargs, **kwargs):
        CPF.__init__(self, 'setter_getter', *kargs, **kwargs)
        self._normalized_cfg = None
        self._already_discovered = False
        self._binaries_strings = {}
        self._name_funs = []

    @staticmethod
    def is_setter(node_name):
        """
        Checks whether the passed function name indicates that the function is a sender candidate.

        :param node_name: function name
        :return: True if the function indicate the binary is a setter, False otherwise
        """

        for s in M_SET_KEYWORD:
            set_candidate = False
            index = node_name.lower().find(s)
            if index == -1:
                continue

            if index + len(s) < len(node_name):
                next_ch = node_name[index + len(s)]
                if next_ch in ('_', '-') or next_ch.isupper():
                    set_candidate = True
            else:
                set_candidate = True

            if index != 0:
                curr_ch = node_name[index]
                prev_ch = node_name[index - 1]
                if prev_ch in ('_', '-') or (curr_ch.isupper() and prev_ch.islower()):
                    set_candidate = True
            else:
                set_candidate = True

            if set_candidate:
                return True

        return False

    @staticmethod
    def is_getter(node_name):
        """
        Checks whether the passed function name indicates that the function is a gender candidate.

        :param node_name: function name
        :return: True if the function indicate the binary is a getter, False otherwise
        """
        for s in M_GET_KEYWORD:
            set_candidate = False
            index = node_name.lower().find(s)
            if index == -1:
                continue

            if index + len(s) < len(node_name):
                next_ch = node_name[index + len(s) + 1]
                if next_ch in ('_', '-') or next_ch.isupper():
                    set_candidate = True
            else:
                set_candidate = True

            if index != 0:
                curr_ch = node_name[index]
                prev_ch = node_name[index - 1]
                if prev_ch in ('_', '-') or (curr_ch.isupper() and prev_ch.islower()):
                    set_candidate = True
            else:
                set_candidate = True

            if set_candidate:
                return True

        return False

    def run(self, data_key, key_addr, reg_name, core_taint, current_path, *kargs, **kwargs):
        """
        Runs this CPF.

        :param data_key: data key value
        :param key_addr: data key address
        :param reg_name: register name
        :param core_taint: core taint engine
        :param current_path: angr current path
        :return: True, and the role if the role for the current binary was found, False and Unknown otherwise.
        """

        p = self._p
        cfg = self._cfg

        path_copy = current_path.copy(copy_states=True)
        addr = current_path.active[0].addr
        node = cfg.get_any_node(addr)
        prev_node = node.predecessors
        if prev_node:
            prev_node = prev_node[0]
        par_n = ordered_argument_regs[p.arch.name].index(p.arch.registers[reg_name][0])

        # we check that + is not in the name as we want to avoid to consider ever single block
        # within a function starting with a get/set keyword
        if node and node.name and '+' not in node.name:
            if are_parameters_in_registers(p):
                reg_cnt = getattr(path_copy.active[0].regs, reg_name)
                tainted = core_taint.is_tainted(reg_cnt)
                if not tainted:
                    tainted = core_taint.is_tainted(core_taint.safe_load(path_copy, reg_cnt), path=path_copy)
            else:
                raise Exception("setter_getter.run: Implement me")

            if (SetterGetter.is_setter(str(node.name)) or SetterGetter.is_getter(str(node.name))) and tainted:
                assert len(current_path.active[0].history.bbl_addrs) >= 1, "setter_getter.run: what's the caller? :("
                block_caller_role_function = current_path.active[0].history.bbl_addrs[-1]
                no = self._cfg.get_any_node(block_caller_role_function)

                assert no, "setter_getter.run: Impossible to find the function address, this is bad.."

                # set_env
                role = Role.GETTER if SetterGetter.is_getter(str(node.name)) else Role.SETTER
                self._name_funs.append(node.name)
                self._data_keys.append(data_key)
                self._roles.append(role)

                plt = self._p.loader.main_bin.reverse_plt
                if addr not in plt and prev_node.addr in plt:
                    addr = prev_node.addr
                    no = prev_node
                    block_caller_role_function = current_path.active[0].history.bbl_addrs[-2]

                info = {
                    RoleInfo.ROLE: role,
                    RoleInfo.DATAKEY: data_key,
                    RoleInfo.CPF: self._name,
                    RoleInfo.X_REF_FUN: no.function_address,
                    RoleInfo.CALLER_BB: block_caller_role_function,
                    RoleInfo.ROLE_FUN: addr,
                    RoleInfo.ROLE_INS: addr,
                    RoleInfo.ROLE_INS_IDX: None,
                    RoleInfo.COMM_BUFF: None,
                    RoleInfo.PAR_N: par_n
                }

                if key_addr not in self._role_info:
                    self._role_info[key_addr] = []
                if info not in self._role_info[key_addr]:
                    self._role_info[key_addr].append(info)
                return True, role

        return False, Role.UNKNOWN

    @property
    def role_info(self):
        return self._role_info

    def _search_data_key_in_bb(self, p, b, caller_node, data_key):
        """
        Finds if the given data key is within the calling basic block.

        :param p: angr project
        :param b: binary
        :param caller_node: calling basic block
        :param data_key: data key value
        :return: True if found, False otherwise
        """

        found = False
        c = caller_node

        block = p.factory.block(c.addr)

        # consider the constants in the calling block
        for con in block.vex.all_constants:
            val = con.value
            # check if a string
            c_string = get_string(p, val)
            self._binaries_strings[b].append(c_string)
            if c_string and c_string == data_key:
                found = True

        return found

    def _is_getter_of(self, b, data_key):
        """
        Checks whether the passed binary is a getter of the current binary for the passed data key

        :param data_key: data key value
        :return: True if the passed binary b is a getter for the current binary
        """

        if b in self._binaries_strings:
            return data_key in self._binaries_strings[b]

        self._binaries_strings[b] = []
        try:
            p = angr.Project(b)
            cfg = p.analyses.CFG()
        except TimeOutException:
            raise
        except Exception as e:
            print e
            return False

        funcs = [x for x in cfg.functions if cfg.functions.function(x).name.startswith(M_GET_KEYWORD)]

        for f in funcs:
            if f not in p.loader.main_object.reverse_plt:
                continue

            no = cfg.get_any_node(f)
            if not no:
                continue
            preds = no.predecessors
            for pred in preds:
                if self._search_data_key_in_bb(p, b, pred, data_key):
                    return True
        return False

    def discover_new_binaries(self):
        """
        Discover new binaries within the firmware sample that have data dependency with the current one.

        :return: a list of binaries
        """

        bins = []
        seen_strs = []
        self._log.debug("Discovering new binaries.. this might take a while.. take a coffee.")

        for role, data_key in zip(self._roles, self._data_keys):
            if role == Role.SETTER and data_key:
                self._log.debug("New data key: " + str(data_key))
                if data_key in seen_strs:
                    continue

                seen_strs.append(data_key)
                for get_f in M_GET_KEYWORD:
                    cmd = "for file in `grep -r '" + data_key + "' " + self._fw_path + \
                          " | grep Binary | awk '{print $3}'`; do grep " + get_f + \
                          " $file | grep Binary | awk '{print $3}'; done;"
                    o, e = run_command(cmd)
                    candidate_bins = list(set([x for x in o.split('\n') if x]))
                    for b in candidate_bins:
                        if LIB_KEYWORD in b:
                            continue
                        if self._is_getter_of(b, data_key):
                            name = b.split('/')[-1]
                            self._log.debug("Adding " + str(name))
                            bins.append(b)

        return list(set(bins))

    def _search_in_bb(self, caller_node, role_function_info):
        """
        Search for a data key in the passed basic block.

        :param caller_node: node calling the role function
        :param role_function_info: role function info
        :return: None
        """

        p = self._p
        c = caller_node

        block = p.factory.block(c.addr)

        # consider the constants in the calling block
        for con in block.vex.all_constants:
            val = con.value
            # check if a string
            c_string = get_string(p, val)
            if c_string:
                if val not in self._role_info:
                    self._role_info[val] = []

                new_role_info = dict(role_function_info)
                new_role_info[RoleInfo.DATAKEY] = c_string
                new_role_info[RoleInfo.X_REF_FUN] = c.function_address
                new_role_info[RoleInfo.CALLER_BB] = c.addr
                new_role_info[RoleInfo.CPF] = self._name

                if new_role_info not in self._role_info[val]:
                    self._role_info[val].append(new_role_info)
                role = self._roles[0]
                self._roles.append(role)
                self._data_keys.append(c_string)
                self._name_funs.append(c.successors[0].name)

    def _run_def_use(self, caller_node, role_function_info):
        """
        Run dev use to find data keys.

        :param caller_node: node calling a role function
        :param role_function_info: role function info
        :return: None
        """

        if not self._normalized_cfg:
            try:
                self._normalized_cfg = self._p.analyses.CFG(normalize=True)
            except:
                self._normalized_cfg = None
                return

        p = self._p
        cfg = self._normalized_cfg

        c = caller_node
        # Reaching definition analysis
        fun = cfg.functions.function(caller_node.function_address)
        t = (caller_node.instruction_addrs[-1], angr.analyses.reaching_definitions.OP_AFTER)

        try:
            rd = p.analyses.ReachingDefinitions(func=fun, observation_points=[t, ], init_func=True)
            results = rd.observed_results[t]
        except TimeOutException:
            raise
        except:
            return

        if are_parameters_in_registers(p):
            idx = role_function_info[RoleInfo.PAR_N]
            reg_off = ordered_argument_regs[p.arch.name][idx]

            for r_def in results.register_definitions.get_objects_by_offset(reg_off):
                for val in r_def.data.data:
                    if type(val) == angr.analyses.reaching_definitions.undefined.Undefined:
                        continue
                    if type(val) not in (int, long):
                        print("Data value is not what expected. Check me...")
                        continue

                    c_string = get_string(p, val)
                    if c_string:
                        if val not in self._role_info:
                            self._role_info[val] = []

                        new_role_info = dict(role_function_info)
                        new_role_info[RoleInfo.DATAKEY] = c_string
                        new_role_info[RoleInfo.X_REF_FUN] = c.function_address
                        new_role_info[RoleInfo.CALLER_BB] = c.addr
                        new_role_info[RoleInfo.CPF] = self._name

                        if new_role_info not in self._role_info[val]:
                            self._role_info[val].append(new_role_info)
                        role = self._roles[0]
                        self._roles.append(role)
                        self._data_keys.append(c_string)
                        self._name_funs.append(c.successors[0].name)

        else:
            raise Exception("Implement me")

    def _record_role_data_key(self, caller_node, role_function_info):
        """
        Record role data key

        :param caller_node: node calling the role function
        :param role_function_info:  role function info
        :return: None

        """

        p = self._p

        # shortcut: check whether the data key is the in the basic block
        # in such a case we avoid to perform a reach-def analysis and just get the
        # data key
        idx = role_function_info[RoleInfo.PAR_N]
        reg_off = ordered_argument_regs[p.arch.name][idx]
        block = p.factory.block(caller_node.addr)
        ass_to_reg = [x for x in block.vex.statements if x.tag == 'Ist_Put' and x.offset == reg_off]

        # it might
        if ass_to_reg:
            ass_to_reg = ass_to_reg[-1]
            if hasattr(ass_to_reg, 'tmp'):
                print ("_run_def_use: tmp is assigned to a register, we should find all the defs for this "
                       "tmp rather than the register. Implement me...")

            self._search_in_bb(caller_node, role_function_info)
            return

        self._run_def_use(caller_node, role_function_info)

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
            callers = cfg.get_any_node(role_fun_addr).predecessors
            for c in callers:
                self._record_role_data_key(c, role_function_info)

        self._already_discovered = True
        if not self._role_info:

            # something went wrong, let's restore what we found
            self._role_info = dict(bak)
        return self._role_info
