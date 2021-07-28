import os

from bdg.cpfs.__init__ import CPF, LIB_KEYWORD

import angr
import itertools
import re

from taint_analysis.utils import arg_reg_id
from bdg.utils import are_parameters_in_registers, run_command, get_addrs_string
from bdg.bdp_enum import Role, RoleInfo
from taint_analysis.coretaint import TimeOutException

M_SET_KEYWORD = 'setenv'
M_GET_KEYWORD = 'getenv'


class Environment(CPF):
    """
    Implementation of the environment CPF
    """

    def __init__(self, *kargs, **kwargs):
        CPF.__init__(self, 'environment', *kargs, **kwargs)
        self._normalized_cfg = None
        self._already_discovered = False

    @staticmethod
    def case_sensitive_replace(s, before, after):
        """
        Performs a case sensitive word replacement

        :param s: string
        :param before: list of string to replace
        :param after: list of strings that replace
        :return:
        """

        regex = re.compile(re.escape(before), re.I)
        return regex.sub(lambda x: ''.join(d.upper() if c.isupper() else d.lower()
                                           for c, d in zip(x.group(), after)), s)

    def run(self, data_key, key_addr, reg_name, core_taint, current_path, *kargs, **kwargs):
        """
        Run this CPF

        :param data_key:
        :param key_addr:
        :param reg_name:
        :param core_taint:
        :param current_path:
        :param kargs:
        :param kwargs:
        :return:
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
            if are_parameters_in_registers(p):
                reg_cnt = getattr(path_copy.active[0].regs, reg_name)
                reg_cnt_loaded = core_taint.safe_load(path_copy, reg_cnt)
                tainted = core_taint.is_tainted(reg_cnt) or core_taint.is_tainted(reg_cnt_loaded, path=path_copy)
            else:
                raise Exception("environment.run: Parameters not in registers, implement me")

            if (M_SET_KEYWORD in str(node.name).lower() or M_GET_KEYWORD in str(node.name).lower()) and tainted:

                assert len(current_path.active[0].history.bbl_addrs) >= 1, "environment.run: what's the caller? :("
                block_caller_role_function = current_path.active[0].history.bbl_addrs[-1]
                no = self._cfg.model.get_any_node(block_caller_role_function)

                assert no, "environment.run: Impossible to find the function address, this is bad.."

                # set_env
                role = Role.GETTER if M_GET_KEYWORD in str(node.name).lower() else Role.SETTER
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
                    RoleInfo.X_REF_FUN: no.function_address,
                    RoleInfo.CALLER_BB: block_caller_role_function,
                    RoleInfo.ROLE_FUN: addr,
                    RoleInfo.ROLE_INS: addr,
                    RoleInfo.ROLE_INS_IDX: None,
                    RoleInfo.COMM_BUFF: None,
                    RoleInfo.PAR_N: arg_reg_id(p, reg_name),
                    RoleInfo.CPF: self._name
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
        Determines if the current binary if a getter for b on the given data key

        :param b: binary name
        :param data_key: data key
        :return: True if the current binary is a getter for the binary b
        """
        if b in self._binaries_strings and data_key in self._binaries_strings[b]:
            return True

        p = angr.Project(b)

        # optimization to skip binaries that do not have this data key exactly or a relevant function
        funcs = [addr for name, addr in p.loader.main_object.plt.items() if M_GET_KEYWORD in name.lower()]
        if not funcs or not get_addrs_string(p, data_key):
            return False

        self._binaries_strings[b] = []
        try:
            p = angr.Project(b)
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
        Discovers new binaries within the firmware sample that exchange data through the OS environment with the
        current binary

        :return: a list of binaries
        """

        bins = []
        self._log.debug("Discovering new binaries.. this might take a while.. take a coffee.")
        for role, data_key, name_fun in zip(self._roles, self._data_keys, self._name_funs):
            if data_key in self._seen_strings:
                continue
            if role == Role.SETTER and name_fun and data_key:
                self._log.debug(f"New data key: {str(data_key)}")
                self._seen_strings.append(data_key)
                dual_fun = Environment.case_sensitive_replace(name_fun, M_SET_KEYWORD, M_GET_KEYWORD)
                cmd = "for file in `grep -r '" + data_key + "' " + self._fw_path + \
                      " | grep Binary | awk '{print $3}'`; do grep " + dual_fun + \
                      " $file | grep Binary | awk '{print $3}'; done;"
                o, e = run_command(cmd)
                candidate_bins = list(set([x for x in o.decode().split('\n') if x]))
                for b in candidate_bins:
                    self._log.debug(f"Checking binary {b} ")
                    if LIB_KEYWORD in b or b in bins:
                        continue
                    if self._is_getter_of(b, data_key):
                        self._log.debug(f"Adding {os.path.basename(b)}")
                        bins.append(b)

        return list(set(bins))

    def discover_data_keys(self):
        """
        Discover new data keys based on the same role function.

        :return: None
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
