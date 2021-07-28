import logging
import os

from bdg.utils import run_command, get_string, are_parameters_in_registers
from bdg.bdp_enum import RoleInfo, Role
from taint_analysis.coretaint import TimeOutException
from taint_analysis.utils import get_arguments_call_with_instruction_address, arg_reg_id_by_off, arg_reg_off

from angr.knowledge_plugins.key_definitions.constants import OP_AFTER
from angr.knowledge_plugins.key_definitions.undefined import UNDEFINED

log = logging.getLogger("BinaryDependencyGraph")
log.setLevel("DEBUG")

LIB_KEYWORD = 'lib'


class CPF:
    """
    CPF base class
    """

    def __init__(self, name, p, cfg, fw_path, memcmp_like_functions=None, *kargs, **kwargs):
        """
        Initialization routine

        :param name: CPF name
        :param p:  angr project
        :param cfg: angr CFG
        :param fw_path:  firmware path
        :param memcmp_like_functions: memcmp-like functions within the binary
        :param kargs: kargs
        :param kwargs: kwargs
        """

        global log
        self._role_info = {}
        self._roles = []
        self._data_keys = []
        self._name_funs = []
        self._fw_path = fw_path
        self._cfg = cfg
        self._p = p
        self._log = kwargs['log'] if 'log' in kwargs else log
        self._name = name
        self._memcmp_like = memcmp_like_functions if memcmp_like_functions is not None else []
        self._blob = True if not hasattr(self._p.loader.main_object, 'reverse_plt') else False
        self._binaries_strings = {}
        self._seen_strings = []

    @property
    def name(self):
        return self._name

    def run(self, *kargs, **kwargs):
        raise Exception("You have to implement at least the cpf's run")

    def discover_data_keys(self, *kargs, **kwargs):
        return {}

    @property
    def role_info(self):
        return {}

    def discover_new_binaries(self):
        """
        Find other binaries within the firmware sample that have data dependencies with those associated
        with a CPF object
        :return: a list of binaries
        """

        bins = []
        self._log.debug("Discovering new binaries.. this might take a while.. take a coffee.")
        for _, r_info in self._role_info.items():
            for info in r_info:
                data_key = info[RoleInfo.DATAKEY]
                role = info[RoleInfo.ROLE]
                if role == Role.SETTER and data_key and data_key in self._seen_strings:
                    self._seen_strings.append(data_key)
                    self._log.debug(f"New data key: {str(data_key)}")
                    cmd = "grep -r '" + data_key + "' " + self._fw_path + " | grep Binary | awk '{print $3}'"
                    o, e = run_command(cmd)
                    candidate_bins = list(set([x for x in o.decode().split('\n') if x]))
                    for b in candidate_bins:
                        # optimization: this is handle by angr anyway
                        if LIB_KEYWORD in b or b in bins:
                            continue
                        self._log.debug(f"Adding {os.path.basename(b)}")
                        bins.append(b)

        return list(set(bins))

    def _get_caller_blocks(self, current_path, call_name):
        """
        Get caller blocks.

        :param current_path: angr current path
        :param call_name: call function name
        :return: caller blocks
        """

        cfg = self._cfg
        p = self._p

        no = cfg.model.get_any_node(current_path.active[0].addr)
        fun = cfg.functions[no.function_address]
        blocks = []
        for addr in fun.block_addrs:
            try:
                bb = p.factory.block(addr).vex
                if bb.jumpkind != 'Ijk_Call':
                    continue
                t_no = cfg.model.get_any_node(bb.addr)
                succ = t_no.successors[0]
                if not succ.name:
                    succ = t_no.successors[0]

                if succ.name and call_name in succ.name:
                    blocks.append(bb.addr)
            except TimeOutException:
                raise
            except Exception as e:
                self._log.error(f"_get_caller_blocks: Something went terribly wrong: {str(e)}")
        return blocks

    def _search_data_key_in_bb(self, p, cfg, b, caller_node, data_key):
        """
        Finds if the given data key is within the calling basic block.

        :param p: angr project
        :param b: binary
        :param caller_node: calling basic block
        :param data_key: data key value
        :return: True if found, False otherwise
        """
        # check if one of the registers xrefs a string
        strings_addrs = []
        for inst_addr, put_statement in get_arguments_call_with_instruction_address(p, caller_node.addr):
            xrefs = cfg.kb.xrefs.get_xrefs_by_ins_addr(inst_addr)
            for xref in xrefs:
                strings_addrs.append(xref.dst)
            if hasattr(put_statement.data, 'con'):
                strings_addrs.append(put_statement.data.con.value)

        for strings_addr in set(strings_addrs):
            c_string = get_string(p, strings_addr, extended=False)
            if c_string == data_key:
                return True
        return False

    def _search_in_bb(self, caller_node, role_function_info):
        """
        Search for a data key in the passed basic block.

        :param caller_node: node calling the role function
        :param role_function_info: role function info
        :return: None
        """

        p = self._p
        cfg = self._cfg
        c = caller_node

        block = p.factory.block(c.addr)

        # check if one of the registers xrefs a string
        strings_addrs = []
        for inst_addr, put_statement in get_arguments_call_with_instruction_address(p, block.addr):
            par_n = arg_reg_id_by_off(p, put_statement.offset)
            # skip if this instruction is assigned to a different register to prevent useless strings
            if par_n != role_function_info[RoleInfo.PAR_N]:
                continue

            xrefs = cfg.kb.xrefs.get_xrefs_by_ins_addr(inst_addr)
            for xref in xrefs:
                strings_addrs.append(xref.dst)
            if hasattr(put_statement.data, 'con'):
                strings_addrs.append(put_statement.data.con.value)

        for strings_addr in set(strings_addrs):
            c_string = get_string(p, strings_addr, extended=True)
            if c_string:
                if strings_addr not in self._role_info:
                    self._role_info[strings_addr] = []

                new_role_info = dict(role_function_info)
                new_role_info[RoleInfo.DATAKEY] = c_string
                new_role_info[RoleInfo.X_REF_FUN] = c.function_address
                new_role_info[RoleInfo.CALLER_BB] = c.addr
                new_role_info[RoleInfo.CPF] = self._name

                if new_role_info not in self._role_info[strings_addr]:
                    self._role_info[strings_addr].append(new_role_info)
                self._roles.append(new_role_info[RoleInfo.ROLE])
                self._data_keys.append(c_string)
                self._name_funs.append(c.successors[0].name)

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
        reg_off = arg_reg_off(p, role_function_info[RoleInfo.PAR_N])
        block = p.factory.block(caller_node.addr)
        ass_to_reg = [x for x in block.vex.statements if x.tag == 'Ist_Put' and x.offset == reg_off]

        # it might
        if ass_to_reg:
            self._search_in_bb(caller_node, role_function_info)
            return

        self._run_def_use(caller_node, role_function_info)

    def _run_def_use(self, caller_node, role_function_info):
        """
        Run def-use analysis to find the data-key

        :param caller_node: node calling an environment function
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
        t = (caller_node.instruction_addrs[-1], OP_AFTER)

        try:
            rd = p.analyses.ReachingDefinitions(func=fun, observation_points=[t, ], init_func=True)
            results = rd.observed_results[t]
        except TimeOutException:
            raise
        except:
            return

        if are_parameters_in_registers(p):
            reg_off = arg_reg_off(p, role_function_info[RoleInfo.PAR_N])

            for r_def in results.register_definitions.get_objects_by_offset(reg_off):
                for val in r_def.data.data:
                    if type(val) == UNDEFINED:
                        continue
                    if not isinstance(val, int):
                        self._log.error("Environment: Data value is not what expected. Check me...")
                        continue
                    c_string = get_string(p, val, extended=False)
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
                        self._roles.append(new_role_info[RoleInfo.ROLE])
                        self._data_keys.append(c_string)
                        self._name_funs.append(c.successors[0].name)
        else:
            raise Exception("CPF: Parameters not in registers, implement me")
