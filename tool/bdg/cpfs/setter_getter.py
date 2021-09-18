import os

from bdg.cpfs.__init__ import CPF, LIB_KEYWORD

import angr
import itertools

from taint_analysis.utils import arg_reg_id
from bdg.utils import are_parameters_in_registers, run_command, get_addrs_string
from bdg.bdp_enum import Role, RoleInfo
from taint_analysis.coretaint import TimeOutException


M_SET_KEYWORD = ('set', 'insert', 'add', 'nvram_set')
# M_SET_SKIP_KEYWORDS = ['memset']
M_GET_KEYWORD = ('get', 'read', 'nvram_get')


class SetterGetter(CPF):
    """
    This CPF is an extension of the semantic CPF to speed up analysis.
    It does string matching on a function name (when present) and tries to infer whether the function is a role
    function for the pair (data key, current binary)
    """

    def __init__(self, *kargs, **kwargs):
        CPF.__init__(self, 'setter_getter', *kargs, **kwargs)
        self._normalized_cfg = None
        self._already_discovered = False

    @staticmethod
    def is_setter(node_name):
        """
        Checks whether the passed function name indicates that the function is a sender candidate.

        :param node_name: function name
        :return: True if the function indicate the binary is a setter, False otherwise
        """
        return SetterGetter.is_role_candidate(node_name, M_SET_KEYWORD)  # and node_name not in M_SET_SKIP_KEYWORDS

    @staticmethod
    def is_getter(node_name):
        """
        Checks whether the passed function name indicates that the function is a Getter candidate.

        :param node_name: function name
        :return: True if the function indicate the binary is a getter, False otherwise
        """
        return SetterGetter.is_role_candidate(node_name, M_GET_KEYWORD)

    @staticmethod
    def is_role_candidate(node_name, keyword_list):
        """
        Checks if the node is part of a role in the keyword list

        :param node_name: function name
        :param keyword_list: the list of keywords for this role
        :return: True if the function indicate the binary is part of this role, False otherwise
        """
        for s in keyword_list:
            set_candidate = False
            index = node_name.lower().find(s)
            if index == -1:
                continue

            if index + len(s) < len(node_name):
                # TODO check if it needs to have  + 1 in the id
                # next_ch = node_name[index + len(s) + 1]
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

        path_copy = current_path.copy(deep=True)
        addr = current_path.active[0].addr
        node = cfg.model.get_any_node(addr)
        if not node:
            return False, Role.UNKNOWN
        prev_node = node.predecessors
        if prev_node:
            prev_node = prev_node[0]

        if node and node.name and '+' not in node.name:
            # we check that + is not in the name as we want to avoid to consider ever single block
            # within a function starting with a get/set keyword
            if are_parameters_in_registers(p):
                reg_cnt = getattr(path_copy.active[0].regs, reg_name)
                reg_cnt_loaded = core_taint.safe_load(path_copy, reg_cnt)
                tainted = core_taint.is_tainted(reg_cnt) or core_taint.is_tainted(reg_cnt_loaded, path=path_copy)
            else:
                raise Exception("setter_getter.run: Implement me")
            if (SetterGetter.is_setter(str(node.name)) or SetterGetter.is_getter(str(node.name))) and tainted:
                assert len(current_path.active[0].history.bbl_addrs) >= 1, "setter_getter.run: what's the caller? :("
                block_caller_role_function = current_path.active[0].history.bbl_addrs[-1]
                no = self._cfg.model.get_any_node(block_caller_role_function)

                assert no, "setter_getter.run: Impossible to find the function address, this is bad.."

                # set_env
                role = Role.GETTER if SetterGetter.is_getter(str(node.name)) else Role.SETTER
                self._name_funs.append(node.name)
                self._data_keys.append(data_key)
                self._roles.append(role)

                if not self._p.loader.find_plt_stub_name(addr) and self._p.loader.find_plt_stub_name(prev_node.addr):
                    addr = prev_node.addr
                    block_caller_role_function = current_path.active[0].history.bbl_addrs[-2]
                    no = cfg.model.get_any_node(block_caller_role_function)

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
                    RoleInfo.PAR_N: arg_reg_id(p, reg_name)
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

    def _is_getter_of(self, b, data_key):
        """
        Checks whether the passed binary is a getter of the current binary for the passed data key

        :param data_key: data key value
        :return: True if the passed binary b is a getter for the current binary
        """

        if b in self._binaries_strings and data_key in self._binaries_strings[b]:
            return True

        p = angr.Project(b)

        # optimization to skip binaries that do not have this data key exactly or a relevant function
        funcs = [addr for name, addr in p.loader.main_object.plt.items() if name.startswith(M_GET_KEYWORD)]
        if not funcs or not get_addrs_string(p, data_key):
            return False

        self._binaries_strings[b] = []
        try:
            cfg = p.analyses.CFG()
        except TimeOutException:
            raise
        except:
            return False

        for f in funcs:
            if not p.loader.find_plt_stub_name(f):
                continue

            no = cfg.model.get_any_node(f)
            if not no:
                continue
            preds = no.predecessors
            for pred in preds:
                if self._search_data_key_in_bb(p, cfg, b, pred, data_key):
                    return True
        return False

    def discover_new_binaries(self):
        """
        Discover new binaries within the firmware sample that have data dependency with the current one.

        :return: a list of binaries
        """

        bins = []
        self._log.debug("Discovering new binaries.. this might take a while.. take a coffee.")

        for role, data_key in set(zip(self._roles, self._data_keys)):
            if role == Role.SETTER and data_key:
                if data_key in self._seen_strings:
                    continue
                self._log.debug(f"New data key: {str(data_key)}")
                self._seen_strings.append(data_key)
                candidate_bins = []
                for get_f in M_GET_KEYWORD:
                    cmd = "for file in `grep -r '" + data_key + "' " + self._fw_path + \
                          " | grep Binary | awk '{print $3}'`; do grep " + get_f + \
                          " $file | grep Binary | awk '{print $3}'; done;"
                    o, e = run_command(cmd)
                    candidate_bins += list(set([x for x in o.decode().split('\n') if x]))
                for b in list(set(candidate_bins)):
                    if LIB_KEYWORD in b or b in bins:
                        continue
                    if self._is_getter_of(b, data_key):
                        self._log.debug(f"Adding {os.path.basename(b)}")
                        bins.append(b)

        return list(set(bins))

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
