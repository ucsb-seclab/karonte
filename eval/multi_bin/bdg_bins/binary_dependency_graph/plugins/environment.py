import angr
from __init__ import Plugin
import sys
from os.path import dirname, abspath

sys.path.append(dirname(dirname(abspath(__file__))))

from taint_analysis.utils import ordered_agument_regs
from binary_dependency_graph.utils import *
from binary_dependency_graph.bdp_enum import *
import itertools
import re

M_SET_KEYWORD = 'setenv'
M_GET_KEYWORD = 'getenv'
LIB_KEYWORD = 'lib'


class Environment(Plugin):

    def __init__(self, *kargs, **kwargs):
        Plugin.__init__(self, 'environment', *kargs, **kwargs)
        self._normalized_cfg = None
        self._strings = []
        self._roles = []
        self._role_strings_info = {}
        self._already_discovered = False
        self._binaries_strings = {}
        self._name_funs = []

    def case_sensitive_replace(self, s, before, after):
        regex = re.compile(re.escape(before), re.I)
        return regex.sub(lambda x: ''.join(d.upper() if c.isupper() else d.lower()
                                               for c, d in zip(x.group(), after)), s)

    def run(self, key_string, key_addr, reg_name, core_taint, current_path):
        p = self._p
        cfg = self._cfg

        path_copy = current_path.copy(copy_states=True)
        addr = current_path.active[0].addr
        node = cfg.get_any_node(addr)
        prev_node = node.predecessors
        if prev_node:
            prev_node = prev_node[0]
        par_n = ordered_agument_regs[p.arch.name].index(p.arch.registers[reg_name][0])

        if node and node.name and '+' not in node.name:
            tainted = False

            if are_parameters_in_registers(p):
                reg_cnt = getattr(path_copy.active[0].regs, reg_name)
                tainted = core_taint.is_tainted(reg_cnt)
                if not tainted:
                    tainted = core_taint.is_tainted(core_taint.safe_load(path_copy, reg_cnt), path=path_copy)
            else:
                print "environment.run: Implement me"
                return

            if (M_SET_KEYWORD in str(node.name).lower() or
                    M_GET_KEYWORD in str(node.name).lower()) and tainted:

                assert len(current_path.active[0].history.bbl_addrs) >= 1, "environment.run: what's the caller? :("
                block_caller_role_function = current_path.active[0].history.bbl_addrs[-1]
                no = self._cfg.get_any_node(block_caller_role_function)

                assert no,"environment.run: Impossible to find the function address, this is bad.."

                # set_env
                role = Role.GETTER if M_GET_KEYWORD in str(node.name).lower() else Role.SETTER
                self._name_funs.append(node.name)
                self._strings.append(key_string)
                self._roles.append(role)

                plt = self._p.loader.main_bin.reverse_plt
                if addr not in plt and prev_node.addr in plt:
                    addr = prev_node.addr
                    no = prev_node
                    block_caller_role_function = current_path.active[0].history.bbl_addrs[-2]

                info = {
                    RoleInfo.ROLE: role,
                    RoleInfo.STRING: key_string,
                    RoleInfo.X_REF_FUN: no.function_address,
                    RoleInfo.CALLER_BB: block_caller_role_function,
                    RoleInfo.ROLE_FUN: addr,
                    RoleInfo.ROLE_INS: addr,
                    RoleInfo.ROLE_INS_IDX: None,
                    RoleInfo.COMM_BUFF: None,
                    RoleInfo.PAR_N: par_n
                }
                if key_addr not in self._role_strings_info:
                    self._role_strings_info[key_addr] = []
                if info not in self._role_strings_info[key_addr]:
                    self._role_strings_info[key_addr].append(info)

                return True, role

        return False, Role.UNKNOWN

    @property
    def role_strings_info(self):
        return self._role_strings_info

    def _search_str_in_bb(self, p, b, caller_node, string):
        found = False
        c = caller_node

        block = p.factory.block(c.addr)

        # consider the constants in the calling block
        for con in block.vex.all_constants:
            val = con.value
            # check if a string
            c_string = get_string(p, val)
            self._binaries_strings[b].append(c_string)
            if c_string and c_string == string:
                found = True

        return found

    def _is_getter_of(self, b, string):
        if b in self._binaries_strings:
            return string in self._binaries_strings[b]
        self._binaries_strings[b] = []
        try:
            p = angr.Project(b)
            cfg = p.analyses.CFG()
        except Exception as e:
            print e
            return False

        funcs = [x for x in cfg.functions if M_GET_KEYWORD in cfg.functions.function(x).name.lower()]

        for f in funcs:
            if f not in p.loader.main_object.reverse_plt:
                continue

            no = cfg.get_any_node(f)
            if not no:
                continue
            preds = no.predecessors
            for pred in preds:
                if self._search_str_in_bb(p, b, pred, string):
                    return True
        return False

    def discover_new_binaries(self):
        bins = []
        self._log.debug("Discovering new binaries.. this might take a while.. take a coffee.")
        for role, string, name_fun in zip(self._roles, self._strings, self._name_funs):
            if role == Role.SETTER and name_fun:
                self._log.debug("New string: " + str(string))
                dual_fun = self.case_sensitive_replace(name_fun, M_SET_KEYWORD, M_GET_KEYWORD)
                cmd = "for file in `grep -r '" + string + "' " + self._fw_path + " | grep Binary | awk '{print $3}'`; do grep " + dual_fun + " $file | grep Binary | awk '{print $3}'; done;"
                o, e = run_command(cmd)
                candidate_bins = list(set([x for x in o.split('\n') if x]))
                for b in candidate_bins:
                    if LIB_KEYWORD in b:
                        continue

                    if self._is_getter_of(b, string):
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
                role = self._roles[0]
                self._roles.append(role)
                self._strings.append(c_string)
                self._name_funs.append(c.successors[0].name)

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
                        continue

                    c_string = get_string(p, val)
                    if val not in self._role_strings_info:
                        self._role_strings_info[val] = []

                    new_role_info = dict(role_function_info)
                    new_role_info[RoleInfo.STRING] = c_string
                    new_role_info[RoleInfo.X_REF_FUN] = c.function_address
                    new_role_info[RoleInfo.CALLER_BB] = c.addr

                    self._role_strings_info[val].append(new_role_info)
                    role = self._roles[0]
                    self._roles.append(role)
                    self._strings.append(c_string)
                    self._name_funs.append(c.successors[0].name)

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

    def discover_strings(self):
        p = self._p
        cfg = self._cfg

        if self._already_discovered:
            return self._role_strings_info

        role_functions_info = [x for x in itertools.chain.from_iterable(self._role_strings_info.values())]
        self._role_strings_info = {}

        # we used the current info, to get more role info
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
