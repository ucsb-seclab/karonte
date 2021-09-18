import itertools
import logging
import os
import time
from typing import Callable

import angr

from claripy import BVV

from bbf.utils import SEPARATOR_CHARS
from bdg.bdp_enum import *
from bdg.cpfs import environment, file, socket, semantic, setter_getter
from bdg.utils import *
from taint_analysis.coretaint import TimeOutException, CoreTaint
from taint_analysis.utils import get_arity, arg_reg_name, arg_reg_names, get_arguments_call_with_instruction_address, \
    get_initial_state

angr.loggers.disable_root_logger()
angr.logging.disable(logging.ERROR)

logging.basicConfig()
log = logging.getLogger("BinaryDependencyGraph")
log.setLevel("DEBUG")


class BdgNode:
    def __init__(self, project, cfg, cpf_used, is_root=False, is_orphan=False, is_leaf=False):
        """
        Initialize a BDG node

        :param project: angr project
        :param cfg: angr cfg
        :param cpf_used: CPF used to infer the role of this binary
        :param is_root: flag representing whether this node is a root node or not
        :param is_orphan: flag representing whether this node is an orphan (i.e. could not find its parents) node or not
        :param is_leaf: flag representing whether this node is a leaf node or not
        """

        self._p = project
        self._bin = project.loader.main_object.binary
        self._role_info = {}

        self._root = is_root
        self._orphan = is_orphan
        self._leaf = is_leaf
        self._cfg = cfg
        self._generator_keys = []
        self._cpfs_used = [p for p in cpf_used if p]

    def clear_role_info(self):
        self._role_info = {}

    def __hash__(self):
        return hash(self._bin)

    def __str__(self):
        return self._bin

    def __repr__(self):
        return f"<BdgNode {self._bin}>"

    def __eq__(self, o):
        return self._bin == o.bin

    def __neq__(self, o):
        return not (self._bin == o.bin)

    def __getstate__(self):
        log.warning("You should never pickle a BDG Node, you will lose some info")
        return self._p, self._bin, self.role_info, self._root, self._generator_keys

    def __setstate__(self, info):
        self._p = info[0]
        self._bin = info[1]
        self._role_info = info[2]
        self._root = info[3]
        self._generator_keys = info[4]
        self._cpfs_used = []

    @property
    def bin(self):
        return self._bin

    @property
    def cfg(self):
        return self._cfg

    @property
    def role(self):
        if self.orphan or self.leaf:
            return Role.GETTER
        if self.root:
            return Role.SETTER

        return Role.SETTER_GETTER

    @property
    def root(self):
        return self._root

    @property
    def leaf(self):
        return self._leaf

    @property
    def orphan(self):
        return self._orphan

    @property
    def cpfs(self):
        return self._cpfs_used

    def set_root(self):
        self._root = True

    def set_orphan(self):
        self._orphan = True

    def set_leaf(self):
        self._leaf = True

    def find_cpf_data_key(self, datakey):
        for pl in self.cpfs:
            if any([info[RoleInfo.DATAKEY] == datakey for elem in pl.role_info.values() for info in elem]):
                return pl
        return Role.UNKNOWN

    @property
    def role_data_keys(self):
        """
        Return the list of the data keys relative to the role of the binary
        :return: list of data keys
        """

        return [s[RoleInfo.DATAKEY] for s in [v for item in self.role_info.values() for v in item]
                if s[RoleInfo.DATAKEY]]

    @property
    def p(self):
        return self._p

    @property
    def generator_keys(self):
        return self._generator_keys

    def _remove_duplicates(self):
        """
        Removes duplicates from role keys
        :return:
        """

        for key in self._role_info:
            self._role_info[key] = \
                [dict(tupleized) for tupleized in set(tuple(item.items()) for item in self._role_info[key])]

    def _remove_unknown(self):
        for key in self._role_info:
            self._role_info[key] = [x for x in self._role_info[key] if x[RoleInfo.ROLE] != Role.UNKNOWN]

    @property
    def role_info(self):
        if not self._cpfs_used:
            return self._role_info

        # get them, clean them and cache them
        if not self._role_info:
            self._role_info = {}
            try:
                roles_info = [pl.role_info for pl in self._cpfs_used]
            except:
                return {}

            for info in roles_info:
                self._role_info.update(info)

            # removing duplicates
            self._remove_duplicates()

            # remove the unknown
            self._remove_unknown()

        return self._role_info

    def _set_data_key_generators(self):
        # could be within a loop and pre-pended to different data and should respect the rule
        # of a setter datakey.

        datakeys = [s[0] for s in get_bin_strings(self._bin)]
        self._generator_keys = [s for s in datakeys if s[-1] in SEPARATOR_CHARS]
        self._generator_keys = list(set(self._generator_keys))

    def could_be_generated(self, s):
        for separator in SEPARATOR_CHARS:
            splits = s.split(separator)
            if splits[0] + separator in self._generator_keys:
                return True
        return False

    def discover_role_data_keys(self):
        """
        Discover the role data keys contained in the binary which are passed to the role function(s)
        :return:  list of data keys
        """

        if not self._cpfs_used:
            return {}

        # we have to refresh everything
        self._role_info = {}

        self._cpfs_used = list(set(self._cpfs_used))
        for pl in self._cpfs_used:
            pl.discover_data_keys()

        # if it could be a setter, check whether it has any
        # data key generator
        if any([j for k, v in self.role_info.items() for j in v if j[RoleInfo.ROLE] == Role.SETTER]):
            self._set_data_key_generators()

        return self.role_info

    def discover_new_binaries(self):
        """
        Using the cpf used to infer the role of this binary, search for new binaries to add to the set
        of analyzed binaries

        :return: list of binaries
        """
        # get new binaries from the discovery cpfs, if any
        if not self._cpfs_used:
            return []
        # remove possible duplicates
        self._cpfs_used = list(set(self._cpfs_used))
        cpfs_bins = [pl.discover_new_binaries() for pl in self._cpfs_used]
        return [item for bins in cpfs_bins for item in bins]

    def add_role_info(self, key_addr, info):
        """
        Add a role information

        :param key_addr: data key address in the binary
        :param info: info
        :return:
        """

        if key_addr not in self._role_info:
            self._role_info[key_addr] = []
        if info not in self._role_info[key_addr]:
            self._role_info[key_addr].append(info)


class BinaryDependencyGraph:
    """
        BDG algorithm: Automatically infers the data flow across binaries of a firmware sample.
    """

    def __init__(self, config, seed_bins, fw_path, init_data_keys=None, cpfs=(), logger_obj=None):
        """
        Initialization routine

        :param config: configuration file
        :param seed_bins: list of starting binary files (paths)
        :param fw_path: unpacked firmware path
        :param init_data_keys: list of initial data keys to look for within the seed binaries
        :param cpfs: set of cpfs used to infer the role of a binary
        :param logger_obj: logger object
        """

        global log

        if logger_obj:
            log = logger_obj

        self._arch = str(config['arch']) if 'arch' in config else None
        self._base_addr = int(config['base_addr'], 16) if 'base_addr' in config else None
        self._keys_to_taint = [[int(x[0], 16), x[1]] for x in config['data_keys']] if 'data_keys' in config else None
        self._arg_to_taint = map(lambda x: int(x, 16), config['glob_var']) if 'glob_var' in config else None
        self._source_addr = int(config['eg_source_addr'], 16) if 'eg_source_addr' in config else None
        self._ignore_bins = config['angr_explode_bins'] if 'angr_explode_bins' in config else []

        self._f_arg_vals = []
        self._seed_bins = seed_bins
        self._graph = {}
        self._current_p = None
        self._current_cfg = None
        self._core_taint = None
        self._current_role = Role.UNKNOWN
        self._current_bin = None
        self._current_f_addr = None
        self._set_f_vals = True
        self._discover_data_keys = True

        self._data_keys = init_data_keys if init_data_keys is not None else []
        self._current_info = None
        self._current_data_key = None
        self._current_key_addr = None
        self._current_par_name = None
        self._candidate_role_function = None
        self._tainted_callsites = []

        self._cpf_used = None
        self._fw_path = fw_path

        self._projects = {}
        self._cfgs = {}
        self._cpfs = {}

        self._enabled_cpfs = cpfs
        if not cpfs:
            self._enabled_cpfs = [environment.Environment, file.File, socket.Socket,
                                  setter_getter.SetterGetter, semantic.Semantic]

        self._seed_bins = self._update_projects(self._seed_bins)
        self._end_time = 0
        self._start_time = 0

    @staticmethod
    def is_call(bb):
        """
        Finds if basic blocks ends with a call.

        :param bb: basic block
        :return: True if bb ends with a call
        """

        if hasattr(bb, 'vex'):
            return bb.vex.jumpkind == 'Ijk_Call'
        if bb.irsb:
            return bb.irsb.jumpkind == 'Ijk_Call'
        return False

    def __getstate__(self):
        log.warning("You should never pickle a BDG graph, you will lose some info")
        return (self._seed_bins,
                self._graph,
                self._data_keys,
                self._projects)

    def __setstate__(self, info):
        self._seed_bins = info[0]
        self._graph = info[1]
        self._data_keys = info[2]
        self._projects = info[3]
        self._cfgs = {}
        self._current_role = Role.UNKNOWN
        self._current_data_key = None
        self._current_key_addr = None
        self._cpf_used = None
        self._current_bin = None
        self._current_p = None

    def _update_projects(self, bins):
        """
        Update the list of projects we consider

        :param bins: paths to binaries
        :return: None
        """

        added_bins = []

        for b in bins:
            bin_name = os.path.basename(b)
            if any([nb in bin_name for nb in self._ignore_bins]):
                continue

            # angr might successfully load keys sometimes. We do not want that.
            if b not in self._projects and not is_pem_key(b):
                try:
                    # we got a blob?
                    if self._arch and self._base_addr:
                        blob = True
                        log.info("We got a blob")
                        load_options = {
                            'main_opts': {
                                'custom_arch': self._arch,
                                'backend': 'blob',
                                'custom_base_addr': self._base_addr
                            }
                        }
                        self._projects[b] = angr.Project(b, auto_load_libs=False, load_options=load_options)
                    else:
                        blob = False
                        self._projects[b] = angr.Project(b, auto_load_libs=False)

                    log.info(f"Building {bin_name} CFG (this may take some time)")
                    self._cfgs[b] = self._projects[b].analyses.CFG(collect_data_references=True,
                                                                   extra_cross_references=True)
                    memcplike = find_memcmp_like(self._projects[b], self._cfgs[b]) if blob else []

                    self._cpfs[b] = []
                    for cpf in self._enabled_cpfs:
                        c = cpf(self._projects[b], self._cfgs[b], self._fw_path,
                                memcmp_like_functions=memcplike, log=log)
                        self._cpfs[b].append(c)
                    added_bins.append(b)
                except Exception as e:
                    log.warning(f"Failed to add {b}")
                    self._ignore_bins.append(bin_name)
        return added_bins

    def _check_key_usage(self, current_path, *_, **__):
        """
        Runs every cpfs on the current path to check whether the role of the binary can be inferred with
        the current info

        :param current_path: current path given by the taint analysis
        :return: None
        """

        # retrieve and save the values of arguments of the function where we start the taint analyis
        if not self._f_arg_vals and self._set_f_vals:
            self._set_f_vals = False
            arity = max(get_arity(self._current_p, self._current_f_addr), DEF_ROLE_ARITY)
            for narg in range(arity):
                dst_cnt = getattr(current_path.active[0].regs, arg_reg_name(self._current_p, narg))
                self._f_arg_vals.append(dst_cnt)

        current_bin = self._current_bin

        for pl in self._cpfs[current_bin]:
            # log.debug(f"Entering cpf {pl.name}")
            try:
                found, role = pl.run(self._current_data_key, self._current_key_addr, self._current_par_name,
                                     self._core_taint, current_path, self._f_arg_vals)

                if found:
                    log.debug(f"Using cpf {pl.name} with role {role}")

                    self._current_role = role
                    self._cpf_used = pl
                    if pl not in (semantic.Semantic, setter_getter.SetterGetter):
                        self._core_taint.stop_run()
                        break
            except Exception as e:
                log.warning(f"Exception CPF {pl.name}: {e}")
                pass

    def _apply_taint(self, state, key_addr, keyword=None):
        """
        Apply the taint to the datakey
        :param state: the current initial state
        :param key_addr: the address of the datakey
        :param keyword: the keyword to taint (if we want to constraint the datakey)
        :return: the new state
        """
        # taint the data key
        if self._discover_data_keys:
            size = len(self._current_data_key)
        else:
            size = self._core_taint.taint_buf_size
        t = self._core_taint.get_sym_val(name=self._core_taint.taint_buf, bits=(size * 8)).reversed
        if keyword:
            # reverse to make it LE
            bvv = BVV(keyword).reversed
            state.add_constraints(t == bvv)
        # we taint the used keyword to trace its use
        state.memory.store(key_addr, t)
        return state

    def _get_role(self, no, key_addr, reg_name, key_name=None):
        """
        Retrieve the role of a binary by inferring whether it is a setter or a getter

        :param no: node containing the call to a set or getter function
        :param key_addr: address of the keyword used to infer the role
        :param reg_name: register containing the key_addr
        :return: The role and the function used to infer it whether the role could be inferred, None and None otherwise
        """

        p = self._current_p

        if not BinaryDependencyGraph.is_call(p.factory.block(no.addr)):
            return None

        # detect the role
        self._cpf_used = None
        f_addr = no.addr
        self._candidate_role_function = no.successors[0].addr

        # prepare the under-contrainted-based initial state
        # we do not allow untaint as we just want to see where the key data key is leading to
        self._core_taint = CoreTaint(p, interfunction_level=2, smart_call=False,
                                     follow_unsat=True,
                                     try_thumb=True,
                                     exit_on_decode_error=True, force_paths=True, allow_untaint=False,
                                     logger_obj=log)

        # the used register is not a parameter register
        if are_parameters_in_registers(p) and reg_name not in arg_reg_names(p):
            return Role.UNKNOWN

        self._current_par_name = reg_name
        self._current_key_addr = key_addr
        self._current_f_addr = f_addr

        s = get_initial_state(p, self._core_taint, f_addr)
        s = self._apply_taint(s, key_addr, key_name)
        # enter into the call
        sim = p.factory.simgr(s)
        sim.step()
        s = sim.active[0]
        if reg_name:
            setattr(s.regs, reg_name, BVV(key_addr, p.arch.bits))

        summarized_f = prepare_function_summaries(p)
        self._f_arg_vals = []
        self._set_f_vals = True

        self._core_taint.set_alarm(TIMEOUT_TAINT, n_tries=TIMEOUT_TRIES)
        try:
            self._core_taint.run(s, (), (), summarized_f=summarized_f, force_thumb=False,
                                 check_func=self._check_key_usage, init_bss=False)
        except TimeOutException:
            log.warning("Timeout Triggered")
        except Exception as e:
            log.warning(f"Exception in Coretaint: {str(e)}")

        self._core_taint.unset_alarm()
        return self._current_role

    def _find_taint_callers(self, current_path, *_, **__):
        """
        Finds tainted callers

        :param current_path:
        :return: None
        """

        active = current_path.active[0]
        p = self._current_p
        if p.factory.block(active.addr).vex.jumpkind == 'Ijk_Call':
            next_path = current_path.copy(deep=True).step()
            nargs = get_arity(p, active.addr)
            for a in range(nargs):
                var = getattr(next_path.active[0].regs, arg_reg_name(p, a))
                if self._core_taint.is_or_points_to_tainted_data(var, next_path):
                    self._tainted_callsites.append((active.addr, arg_reg_name(p, a)))

    def _find_tainted_callers(self, key_addr, f_addr):
        """
        Retrieve the role of a binary by inferring whether it is a setter or a getter

        :param key_addr: address of the keyword used to infer the role
        :param f_addr: address of the function where we start our analysis
        :return: A list of callsites
        """

        p = self._current_p

        self._tainted_callsites = []
        # prepare the under-contrainted-based initial state
        # we do not allow untaint as we just want to see where the data key is leading to
        self._core_taint = CoreTaint(p, interfunction_level=0, smart_call=False,
                                     follow_unsat=True,
                                     try_thumb=True,
                                     exit_on_decode_error=True, force_paths=True, allow_untaint=False,
                                     logger_obj=log)

        self._current_key_addr = key_addr
        s = get_initial_state(p, self._core_taint, f_addr)
        s = self._apply_taint(s, key_addr)
        summarized_f = prepare_function_summaries(p)

        self._core_taint.set_alarm(TIMEOUT_TAINT, n_tries=TIMEOUT_TRIES)

        try:
            self._core_taint.run(s, (), (), summarized_f=summarized_f, force_thumb=False,
                                 check_func=self._find_taint_callers, init_bss=False)
        except TimeOutException:
            log.warning("Timeout Triggered")
        except Exception as e:
            log.warning(f"Exception in Coretaint: {str(e)}")

        self._core_taint.unset_alarm()
        callsites = []
        for cs in self._tainted_callsites:
            try:
                if self._current_cfg.model.get_any_node(cs[0]).function_address == f_addr and cs not in callsites:
                    callsites.append(cs)
            except:
                pass

        return callsites

    def _find_ref_http_strings(self, keyword, found: Callable, only_one=False):
        """
        Collects information about call sites referencing a given set of keys.

        :param keyword: the string to search for
        :param found: function to call when a key reference is found in a call site
        :param only_one: True if exiting after one match, False otherwise
        :return: the information collected at the call site
        """

        cfg = self._current_cfg
        p = self._current_p
        info_collected = {}

        found_references = []

        key_addrs = get_addrs_string(p, keyword)
        for func_addr, func in cfg.kb.functions.items():
            call_sites = func.get_call_sites()
            for call_site in call_sites:
                basic_block = p.factory.block(call_site)
                if basic_block:
                    for inst_addr, put_statement in get_arguments_call_with_instruction_address(p, basic_block.addr):
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
            if key_addr not in info_collected:
                info_collected[key_addr] = []

            if not BinaryDependencyGraph.is_call(p.factory.block(block_addr)):
                continue

            if are_parameters_in_registers(p):
                reg_used = get_reg_used(self._current_p, inst_addr)
                if not reg_used:
                    continue
                log.info(f"Key {keyword} is used in a function call. Checking now!")
                ret = found(cfg.model.get_any_node(block_addr), key_addr, reg_used, keyword)
                if ret:
                    info_collected[key_addr].append(ret)
            else:
                log.error("_find_ref_http_strings: arch doesn t use registers to set "
                          "function parameters. Implement me!")
                continue

            if only_one:
                return info_collected
        return info_collected

    def _find_role(self, s=None, things=None):
        """
        Find the role (SETTER vs GETTER) of the current binary

        :param s: value of the data key to find within a binary
        :param things: things to consider data keys (e.g., (global variable, address))

        :return: list or roles inferred using the input keys
        """

        self._cpf_used = None
        self._current_info = None
        self._current_key_addr = None
        self._current_role = Role.UNKNOWN
        cpfs_used = []
        roles = [Role.UNKNOWN]

        if s is None and things is None:
            raise Exception("Cannot find roles without key not addresses to taint")

        if s:
            # we got a data key to find
            self._current_data_key = s
            self._discover_data_keys = True

            #
            # Find key references
            #
            info_collected = self._find_ref_http_strings(s, found=self._get_role)
            roles = [x for x in itertools.chain.from_iterable(info_collected.values())]
            cpfs_used = [self._cpf_used]
        else:
            self._discover_data_keys = False
            # we got data keys (variable or keys) and addresses already
            for x, y in things:
                self._cpf_used = None
                self._current_info = None
                self._current_data_key = y
                self._current_key_addr = None
                self._current_role = Role.UNKNOWN

                #
                # Find references
                #

                callers = self._find_tainted_callers(x, self._source_addr)
                roles = []
                for cs in callers:
                    no = self._current_cfg.model.get_any_node(cs[0])
                    role = self._get_role(no, x, cs[1])
                    cpfs_used.append(self._cpf_used)
                    roles.append(role)

            cpfs_used = list(set([x for x in cpfs_used if x]))

            if not cpfs_used:
                roles = [Role.UNKNOWN]
                cpfs_used = [None]

            if len(cpfs_used) > 1:
                non_semantic = [x for x in cpfs_used if x.name != 'semantic']
                if len(non_semantic) != 0:
                    cpfs_used = non_semantic

        return roles, cpfs_used[-1]

    def _find_roles(self):
        """
        Implements the BDG algorithm: for each seed binary finds whether it is a setter or a getter, and if it
        communicates with any other binaries within the firmware sample. If so, the algorithm adds these new binaries
        to the set of binaries to analyze, and consider them for further inspection.

        :return: A list of BDG nodes and their roles
        """

        nodes = {}
        roles = {}

        # this speeds up the whole analysis
        window = len(self._data_keys) * ROLE_DATAKEYS_RATIO
        working_list = list(self._seed_bins)
        idx = 0

        while idx < len(working_list):
            b = working_list[idx]
            self._current_bin = b
            self._current_p = self._projects[b]
            self._current_cfg = self._cfgs[b]
            roles[b] = []
            cpfs_used = []

            # only check unique strings in a binary (this is the conversion from list -> set -> list
            strs = list(set([x[0] for x in get_bin_strings(b)]))
            count = window
            if self._keys_to_taint:
                # we got the key addresses already... use them
                things = [(x, y) for x, y in self._keys_to_taint]
                i_roles, cpf_used = self._find_role(things=things)
                # did we find any role?
                if any([r for r in i_roles if r != Role.UNKNOWN]):
                    roles[b] += i_roles
                    cpfs_used.append(cpf_used)

            elif self._arg_to_taint:
                # we got global objects
                things = [(x, "GLOBAL_VAR") for x in self._arg_to_taint]
                i_roles, cpf_used = self._find_role(things=things)
                # did we find any role?
                if any([r for r in i_roles if r != Role.UNKNOWN]):
                    roles[b] += i_roles
                    cpfs_used.append(cpf_used)
            else:
                # we got nothing: gotta find the data keys automatically.
                for h_key in self._data_keys:
                    if count <= 0:
                        count = window
                        if roles[b]:
                            break
                    for s in strs:
                        if s.startswith(h_key):
                            log.info(f"Checking data key: {s}")
                            i_roles, cpf_used = self._find_role(s=s)
                            # did we find any role?
                            if any([r for r in i_roles if r != Role.UNKNOWN]):
                                roles[b] += i_roles
                                cpfs_used.append(cpf_used)
                                break
                    count -= 1
            # add a new node
            nodes[b] = BdgNode(self._current_p, self._current_cfg, cpfs_used)
            if not self._arg_to_taint:
                nodes[b].discover_role_data_keys()

            # update data keys
            for new_s in nodes[b].role_data_keys:
                if new_s and new_s not in self._data_keys:
                    self._data_keys.append(new_s)


            candidate_new_bins = list(set(nodes[b].discover_new_binaries()))
            new_bins = self._update_projects(candidate_new_bins)
            working_list += [x for x in new_bins if x not in working_list]
            idx += 1
        return nodes, roles

    def _build_dependency_graph(self):
        """
        Build the BDG, by inferring the information flow.

        The algorithm followed is the following:
        * given a set of stating binaries, it analyzes them one by one trying to infer their role (SETTER or GETTER),
        based on how their data keys are used.
        This step is done by using a set of cpfs (see cpf module).
        During this phase, more binaries might be discovered and added to the analysis queue.

        :return: the binary dependency graph
        """

        #
        # Find the binary roles
        #
        nodes, roles = self._find_roles()

        #
        # Build the graph
        #
        working_list = list(set(nodes.keys()))

        setters = [b for b, r in roles.items() if Role.SETTER in r or Role.SETTER_GETTER in r]

        while working_list:
            b = working_list[0]
            working_list = working_list[1:]

            if nodes[b] not in self._graph:
                self._graph[nodes[b]] = []

            # it's a root node
            if Role.GETTER not in roles[b] and Role.SETTER_GETTER not in roles[b]:
                nodes[b].set_root()

            # takes params from some other binary
            else:
                is_orphan = True
                for setter in setters:
                    setter_keys_set = set(nodes[setter].role_data_keys)
                    node_keys_set = set(nodes[b].role_data_keys)
                    if setter_keys_set.intersection(node_keys_set):
                        if nodes[setter] not in self._graph:
                            self._graph[nodes[setter]] = []
                        self._graph[nodes[setter]].append(nodes[b])
                        is_orphan = False

                # mark orphans
                if is_orphan:
                    nodes[b].set_orphan()

            # Clean up
            for k, children in self._graph.items():
                self._graph[k] = list(set(children))

        # set leaves
        for k, c in self._graph.items():
            if not c:
                k.set_leaf()

        # post processing:
        # remove those nodes that are not orphans
        # and are not network parsers

        nodes = self.nodes
        children = [c for x in self._graph.values() for c in x if x]
        leafs_non_orphan = [n for n in nodes if n.leaf and not n.orphan] if nodes else []
        seed_names = [x.split('/')[-1] for x in self._seed_bins]
        spurious_nodes = [n for n in leafs_non_orphan if n not in children and n.bin.split('/')[-1] not in seed_names]
        for to_rem in spurious_nodes:
            del self._graph[to_rem]

    @property
    def nodes(self):
        """
        Returns the graph's nodes
        """
        return list(set(list(self._graph.keys()) + [x for x in itertools.chain.from_iterable(self._graph.values())]))

    @property
    def orphans(self):
        return [x for x in self.nodes if x.orphan]

    @property
    def graph(self):
        """
        Returns the binary dependency graph
        :return:
        """
        return self._graph

    def analysis_time(self):
        if not self._end_time or self._start_time:
            return 0
        return self._end_time - self._start_time

    def run(self):
        """
        Run the Binary Dependency Graph analysis
        :return: the binary dependency graph
        """

        self._start_time = time.time()
        self._build_dependency_graph()
        self._end_time = time.time()
