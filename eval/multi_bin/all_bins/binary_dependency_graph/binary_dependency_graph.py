from utils import *
import logging
import angr
import claripy
import itertools
import pyvex
import simuvex
import struct
import sys
from os.path import dirname, abspath
import json
from plugins import environment, file, socket, semantic, setter_getter
from bdp_enum import *

sys.path.append(os.path.abspath(os.path.join(dirname(abspath(__file__)), '../../../tool')))


from taint_analysis import coretaint, summary_functions
from taint_analysis.coretaint import TimeOutException
from taint_analysis.utils import ordered_agument_regs, get_ord_arguments_call
from stack_variable_recovery import stack_variable_recovery


angr.loggers.disable_root_logger()


TIMEOUT_TAINT = 60 * 5
TIMEOUT_TRIES = 3
ROLE_STRINGS_RATIO = 0.5

SEPARATOR_CHARS = ('-', '_')

log = logging.getLogger("BinaryDependencyGraph")
log.setLevel("DEBUG")

link_regs ={
    'ARMEL': archinfo.ArchARMEL.registers['lr'][0],
    'AARCH64': archinfo.ArchAArch64.registers['x30'][0],
    'MIPS32': archinfo.ArchMIPS32.registers['ra'][0]
}


class BdgNode:
    def __init__(self, project, cfg, plugin_used=[], is_root=False, is_orphan=False, is_leaf=False):
        """
        Initialize a node
        :param project: angr project
        :param cfg: angr cfg
        :param plugin_used: plugin used to infer the role of this binary
        :param is_root: flag representing whether this node is a root node or not
        """
        self._p = project
        self._bin = project.loader.main_object.binary


        """
        strings information about the node, they are:
        * role of the binary
        * string used to infer the role
        * function the string was referenced
        * the basic block calling the function defining the role
        * the role function
        * the instruction used to define the role
        * VEX idx of the instruction defining the role
        * if shared memory, the buffer used to share data
        * parameter id of function used to set or get the share data
        """
        self._role_strings_info = {}

        self._root = is_root
        self._orphan = is_orphan
        self._leaf = is_leaf
        self._cfg = cfg
        self._generator_strings = []
        self._plugins_used = [p for p in plugin_used if p]

    def __hash__(self):
        return hash(self._bin)

    def __str__(self):
        return self._bin

    def __repr__(self):
        return "<BdgNode %s>" % self._bin

    def __eq__(self, o):
        return self._bin == o.bin

    def __neq__(self, o):
        return not (self._bin == o.bin)

    def __getstate__(self):
        log.warning("You should never pickle a BDG Node, you will lose some info")
        return (self._p, self._bin, self.role_strings_info, self._root, self._generator_strings)

    def __setstate__(self, info):
        self._p = info[0]
        self._bin = info[1]
        self._role_strings_info = info[2]
        self._root = info[3]
        self._generator_strings = info[4]
        self._plugins_used = []

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
    def plugins(self):
        return self._plugins_used

    def set_root(self):
        self._root = True

    def set_orphan(self):
        self._orphan = True

    def set_leaf(self):
        self._leaf = True

    @property
    def role_strings(self):
        """
        Return the list of the strings relative to the role of the binary
        :return: list of strings
        """
        return [s[RoleInfo.STRING] for s in [v for item in self.role_strings_info.values() for v in item] if s[RoleInfo.STRING]]

    @property
    def p(self):
        return self._p

    @property
    def generator_strings(self):
        return self._generator_strings

    def _remove_duplicates(self):
        """
        Removes duplicates from role strings
        :return:
        """
        for key in self._role_strings_info:
            self._role_strings_info[key] = [dict(tupleized) for tupleized in set(tuple(item.items())
                                                                            for item in self._role_strings_info[key])]

    def _remove_unknown(self):
        for key in self._role_strings_info:
            self._role_strings_info[key] = [x for x in self._role_strings_info[key] if x[RoleInfo.ROLE] != Role.UNKNOWN]

    @property
    def role_strings_info(self):
        if not self._plugins_used:
            return self._role_strings_info

        # get them, clean them and cache them
        if not self._role_strings_info:
            self._role_strings_info = {}
            try:
                role_string_infos = [pl.role_strings_info for pl in self._plugins_used]
            except:
                import ipdb; ipdb.set_trace()
            for role_string_info in role_string_infos:
                self._role_strings_info.update(role_string_info)

            # removing duplicates
            self._remove_duplicates()

            # remove the unknown
            self._remove_unknown()

        return self._role_strings_info

    def _set_string_generators(self):
        # FIXME: do something smarter than this. For example a string generator
        # could be within a loop and pre-pended to different data and should respect the rule
        # of a setter string.

        strings = [s[0] for s in get_bin_strings(self._bin)]
        self._generator_strings = [s for s in strings if s[-1] in SEPARATOR_CHARS]
        self._generator_strings = list(set(self._generator_strings))

    def could_be_generated(self, s):
        for separator in SEPARATOR_CHARS:
            splits = s.split(separator)
            if splits[0] + separator in self._generator_strings:
                return True
        return False

    def discover_role_strings(self):
        """
        Discover the strings contained in the binary which are passed to the role function(s)
        :return:  list of strings
        """
        if not self._plugins_used:
            return {}

        # we have to refresh everything
        self._role_strings_info = {}

        for pl in self._plugins_used:
            pl.discover_strings()

        # if it could be a setter, check whether it has any
        # key string generator
        if any([j for k, v in self.role_strings_info.items() for j in v if j[RoleInfo.ROLE] == Role.SETTER]):
            self._set_string_generators()

        return self.role_strings_info

    def discover_new_binaries(self):
        """
        Using the plugin used to infer the role of this binary, search for new binaries to add to the set
        of analyzed binaries

        :return: list of binaries
        """
        # get new binaries from the discovery cpfs, if any
        if not self._plugins_used:
            return []

        plugins_bins = [pl.discover_new_binaries() for pl in self._plugins_used]
        return [item for bins in plugins_bins for item in bins]

    def add_info_string(self, key_addr, info):
        """
        Add a string among the node's info strings

        :param key_addr: string address
        :param info: info
        :return:
        """

        if key_addr not in self._role_strings_info:
            self._role_strings_info[key_addr] = []
        if info not in self._role_strings_info[key_addr]:
            self._role_strings_info[key_addr].append(info)


class BinaryDependencyGraph:
    def __init__(self, config, seed_bins, h_keywords=None, plugins=(), logger_obj=None, ignore_bins=None):
        """
        Automatically infers the flow through a set of binaries and builds a binary dependency graph

        :param bins: set of starting binary files (paths)
        :param keywords: keywords used to infer binaries hierarchy
        :param fw_path: firmware path
        :param plugins: set of cpfs used to infer the role of a binary
        :param logger_obj: logger object
        """

        global log

        if logger_obj:
            log = logger_obj

        self.config = config
        self.config['arch'] = str(self.config['arch'])
        self._strs_to_taint = [[int(x[0], 16), x[1]] for x in self.config['strings']]
        self._arg_to_taint = map(lambda x: int(x, 16), self.config['glob_var'])
        self._ignore_bins = [] if ignore_bins is None else ignore_bins
        self._seed_bins = seed_bins  # initial binaries
        self._graph = {}  # bdg (binary dependenby graph)
        self._current_p = None  # current angr's project
        self._current_cfg = None  # current cfg
        self._core_taint = None  # tainting engine
        self._current_role = Role.UNKNOWN
        self._current_bin = None
        self.taint_reg = False

        self._h_keywords = h_keywords if h_keywords is not None else []  # keywords used to infer the binary hierarchy
        self._current_info = None
        self._curret_key_string = None # current string used to infer the role of a binary
        self._current_key_addr = None
        self._current_par_name = None
        self._candidate_role_function = None
        self.callsites = []

        self._plugin_used = None
        self._fw_path = str(self.config['fw_path'])

        self._enabled_plugins = plugins

        if not plugins:
            self._enabled_plugins = [environment.Environment,  file.File, socket.Socket, setter_getter.SetterGetter, semantic.Semantic]

        self._prepare_projects()

    @staticmethod
    def is_call(x):
        if hasattr(x, 'vex'):
            return x.vex.jumpkind == 'Ijk_Call'
        if x.irsb:
            return x.irsb.jumpkind == 'Ijk_Call'
        return False

    def __getstate__(self):
        log.warning("You should never pickle a BDG graph, you will lose some info")
        return (self._seed_bins,
                self._graph,
                self._hkeywords,
                self._projects)

    def __setstate__(self, info):
        self._seed_bins = info[0]
        self._graph = info[1]
        self._hkeywords = info[2]
        self._projects = info[3]
        self._cfgs = {}
        self._current_role = Role.UNKNOWN
        self._curret_key_string = None
        self._current_key_addr = None
        self._plugin_used = None
        self._current_bin = None
        self._current_p = None

    def _update_projects(self, bins):
        added_bins = []
        for b in bins:
            if any([nb in b for nb in self._ignore_bins]):
                continue
            if b not in self._projects:
                log.info("Building %s CFG (this may take some time)" % b.split('/')[-1])
                try:
                    try:
                        self._projects[b] = angr.Project(b, auto_load_libs=False)
                    except:
                        log.info("We got a blob")
                        self._projects[b] = angr.Project(b, auto_load_libs=False, load_options={'main_opts': {'arch': self.config['arch'], 'backend': 'blob', 'custom_base_addr': int(self.config['base_addr'], 16)}})
                    self._cfgs[b] = self._projects[b].analyses.CFG(collect_data_references=True, extra_cross_references=True)
                    self._plugins[b] = []

                    # FIXME: CPY THIS ALSO FOR KARONTE BDG
                    if self._projects[b].loader.main_object.strtab.is_null():
                        memcplike = find_memcmp_like(self._projects[b], self._cfgs[b])
                    else:
                        memcplike = []

                    for plugin in self._enabled_plugins:
                        self._plugins[b].append(plugin(self._projects[b], self._cfgs[b], self._fw_path, memcmp_like_functions=memcplike, log=log))
                    added_bins.append(b)
                except:
                    log.warning("Failed to add %s" %b)
        return added_bins

    def _prepare_projects(self):
        """
        Sets up the various projects

        :param cpfs:
        :return:
        """
        self._projects = {}
        self._cfgs = {}
        self._plugins = {}

        working_bins = []
        for b in self._seed_bins:
            if any([nb in b for nb in self._ignore_bins]):
                continue

            log.info("Building %s CFG (this may take some time)" % b.split('/')[-1])
            try:
                blob = False
                try:
                    self._projects[b] = angr.Project(b, auto_load_libs=False)
                except:
                    log.info("We got a blob")
                    self._projects[b] = angr.Project(b, auto_load_libs=False, load_options={'main_opts': {'custom_arch': self.config['arch'], 'backend': 'blob', 'custom_base_addr': int(self.config['base_addr'], 16)}})
                    blob = True

                self._cfgs[b] = self._projects[b].analyses.CFG(collect_data_references=True, extra_cross_references=True)

                self._plugins[b] = []

                if blob:
                    memcplike = find_memcmp_like(self._projects[b], self._cfgs[b])
                else:
                    memcplike = []

                for plugin in self._enabled_plugins:
                    self._plugins[b].append(plugin(self._projects[b], self._cfgs[b], self._fw_path, memcmp_like_functions=memcplike,log=log))
                working_bins.append(b)
            except Exception as e:
                log.warning("Skipping binary %s" % b)
                import ipdb; ipdb.set_trace()
        self._seed_bins = list(working_bins)

    def _set_analyze_role_function_only(self, current_path):
        p = self._current_p
        ct = self._core_taint

        if current_path.active[0].addr == self._candidate_role_function:
            lr = p.arch.register_names[link_regs[p.arch.name]]
            setattr(current_path.active[0].regs, lr, ct.bogus_return)

    def _check_str_usage(self, current_path, *_, **__):
        """
        Runs every cpfs on the current path to check whether the role of the binary can be inferred with
        the current info

        :param current_path: current path given by the taint analysis
        :param _:
        :param __:
        :return:
        """

        self._set_analyze_role_function_only(current_path)
        current_bin = self._current_bin

        for pl in self._plugins[current_bin]:
            log.debug("Entering plugin %s" % pl.name)
            try:
                found, role = pl.run(self._curret_key_string, self._current_key_addr, self._current_par_name, self._core_taint, current_path)

                if found:
                    log.debug("Using plugin %s" % pl.name)
                    self._current_role = role
                    self._plugin_used = pl
                    if pl not in (semantic.Semantic, setter_getter.SetterGetter):
                        self._core_taint.stop_run()
                        break
            except Exception as e:
                pass

    def _prepare_state(self, key_addr, f_addr, reg_name=None):
        """
        Prepare the state to perform the taint analysis to infer the role of a binary

        :param key_addr: address of the string used as key to infer the role
        :param f_addr: function entry point address
        :param reg_name: register name containing the string address
        :return:
        """
        p = self._current_p
        ct = self._core_taint

        s = p.factory.blank_state(
            remove_options={
                simuvex.o.LAZY_SOLVES
            }
        )

        # taint the string
        size = len(get_string(p, key_addr))
        if size == 0:
            size = ct.taint_buf_size
        t = ct.get_sym_val(name=ct.taint_buf, bits=(size * 8))

        # we taint the ussed keyword to trace its use
        s.memory.store(key_addr, t)

        lr = p.arch.register_names[link_regs[p.arch.name]]
        setattr(s.regs, lr, ct.bogus_return)

        s.ip = f_addr
        if reg_name:
            setattr(s.regs, reg_name, claripy.BVV(key_addr, p.arch.bits))
        return s

    def _prepare_function_summaries(self):
        """
        Prepare the function summaries to be used during the taint analysis
        :return: the function summaries dictionary
        """

        p = self._current_p

        mem_cpy_summ = get_memcpy_like(p)
        size_of_summ = get_sizeof_like(p)
        heap_alloc_summ = get_heap_alloc(p)
        memcp_like = get_memcp_like(p)
        memncp_like = get_memncp_like(p)

        summaries = mem_cpy_summ
        summaries.update(size_of_summ)
        summaries.update(heap_alloc_summ)
        summaries.update(memcp_like)
        summaries.update(memncp_like)
        return summaries

    def _get_role(self, cfg, no, key_addr, reg_name):
        """
        Retrieve the role of a binary by inferring whether it is a setter or a getter

        :param cfg: CFG
        :param no: node containing the call to a set or getter function
        :param key_addr: address of the keyword used to infer the role
        :param reg: register containing the key_addr
        :return: The role and the function used to infer it whether the role could be inferred, None and None otherwise
        """

        p = self._current_p

        if not BinaryDependencyGraph.is_call(p.factory.block(no.addr)):
            return None

        # detect the role
        self._plugin_used = None
        f_addr = no.addr
        self._candidate_role_function = no.successors[0].addr

        # prepare the under-contrainted-based initial state
        # we do not allow untaint as we just want to see where the key string is leading to
        self._core_taint = coretaint.CoreTaint(p, interfunction_level=2, smart_call=False,
                                               follow_unsat=True,
                                               try_thumb=True,
                                               exit_on_decode_error=True, force_paths=True, allow_untaint=False,
                                               logger_obj=log)

        # the used register is not a parameter register
        if are_parameters_in_registers(p) and p.arch.registers[reg_name][0] not in ordered_agument_regs[p.arch.name]:
            return Role.UNKNOWN

        self._current_par_name = reg_name
        self._current_key_addr = key_addr
        s = self._prepare_state(key_addr, f_addr, reg_name)
        summarized_f = self._prepare_function_summaries()

        self._core_taint.set_alarm(TIMEOUT_TAINT, n_tries=TIMEOUT_TRIES)

        try:
            self._core_taint.run(s, (), (), summarized_f=summarized_f, force_thumb=False,
                                 check_func=self._check_str_usage, init_bss=False)
        except TimeOutException:
            log.warning("Timeout Triggered")
        except Exception as e:
            log.warning("Excption: %s" % str(e))

        self._core_taint.unset_alarm()
        return self._current_role

    def _find_taint_callers(self, current_path, *_, **__):
        active = current_path.active[0]
        p = self._current_p
        if p.factory.block(active.addr).vex.jumpkind == 'Ijk_Call':
            next_path = current_path.copy(copy_states=True).step()
            #FIXME: it was get_ord_arguments_call, but with LK we have a problem of long long paraemter
            # that gets splitted.
            n = len(get_any_arguments_call(p, active.addr))
            args = ordered_agument_regs[p.arch.name][:n]
            for a in args:
                var = getattr(next_path.active[0].regs, p.arch.register_names[a])
                if self._core_taint.is_or_points_to_tainted_data(var, next_path):
                    self.callsites.append((active.addr, p.arch.register_names[a]))

    def _find_tainted_callers(self, key_addr, f_addr):
        """
        Retrieve the role of a binary by inferring whether it is a setter or a getter

        :param cfg: CFG
        :param no: node containing the call to a set or getter function
        :param key_addr: address of the keyword used to infer the role
        :param reg: register containing the key_addr
        :return: The role and the function used to infer it whether the role could be inferred, None and None otherwise
        """

        p = self._current_p

        self.callsites = []
        # prepare the under-contrainted-based initial state
        # we do not allow untaint as we just want to see where the key string is leading to
        self._core_taint = coretaint.CoreTaint(p, interfunction_level=0, smart_call=False,
                                               follow_unsat=True,
                                               try_thumb=True,
                                               exit_on_decode_error=True, force_paths=True, allow_untaint=False,
                                               logger_obj=log)

        self._current_key_addr = key_addr
        s = self._prepare_state(key_addr, f_addr)
        summarized_f = self._prepare_function_summaries()

        self._core_taint.set_alarm(TIMEOUT_TAINT, n_tries=TIMEOUT_TRIES)

        try:
            self._core_taint.run(s, (), (), summarized_f=summarized_f, force_thumb=False,
                                 check_func=self._find_taint_callers, init_bss=False)
        except TimeOutException:
            log.warning("Timeout Triggered")
        except Exception as e:
            log.warning("Exception: %s" % str(e))

        self._core_taint.unset_alarm()
        callsites = []
        for cs in self.callsites:
            try:
                if self._current_cfg.get_any_node(cs[0]).function_address == f_addr and cs not in callsites:
                    callsites.append(cs)
            except:
                pass

        return callsites

    def _find_str_xref_in_call(self, str_addrs, found=lambda *x: True, only_one=False):
        """
        Collects information about call sites referencing a given set of strings.

        :param str_addrs: searched string addresses
        :param found: function to all when a string reference is found in a call site
        :param only_one: True if exiting after one match, False otherwise
        :return: the information collected at the call site
        """

        cfg = self._current_cfg
        p = self._current_p
        info_collected = {}

        # get all the string references we are looking for
        direct_refs = [s for s in cfg.memory_data.items() if s[0] in str_addrs]
        indirect_refs = get_indirect_str_refs(p, cfg, str_addrs)

        for a, s in direct_refs + indirect_refs:
            info_collected[s.address] = []

            if not BinaryDependencyGraph.is_call(s):
                # FIXME: we only consider those strings passed to functions, we should not doing this
                continue

            for (irsb_addr, stmt_idx, insn_addr) in list(s.refs):
                if are_parameters_in_registers(p):
                    reg_used = get_reg_used(self._current_p, self._current_cfg, irsb_addr, stmt_idx, a)
                    if not reg_used:
                        continue

                    ret = found(self._current_cfg, cfg.get_any_node(irsb_addr), s.address, reg_used)
                    if ret is None:
                        continue
                    info_collected[s.address].append(ret)
                else:
                    log.error("_find_str_xref_in_call: arch doesn t use registers to set function parameters."
                              "Implement me!")
                    import ipdb
                    ipdb.set_trace()

                if only_one:
                    break

        return info_collected

    def _find_role(self, s=None, things=None):
        """
        Find the role (SETTER vs GETTER) of the current binary

        :param key_str: string used to infer the role
        :return: list or roles inferred using the input string
        """

        self._plugin_used = None
        self._current_info = None
        self._current_key_addr = None
        self._current_role = Role.UNKNOWN
        plugins_used = []
        roles = [Role.UNKNOWN]

        if s is None and things is None:
            raise Exception("Cannot find roles without strings not addresses to taint")

        if s:
            # we got a key string to find
            self._curret_key_string = s
            str_addrs = get_addrs_string(self._current_p, s)

            #
            # Find string references
            #
            info_collected = self._find_str_xref_in_call(str_addrs, found=self._get_role)
            roles = [x for x in itertools.chain.from_iterable(info_collected.values())]
            plugins_used = [self._plugin_used]
        else:
            # we got data keys (variable or strings) and addresses already
            for x, y in things:
                self._plugin_used = None
                self._current_info = None
                self._curret_key_string = y
                self._current_key_addr = None
                self._current_role = Role.UNKNOWN

                #
                # Find references
                #

                callers = self._find_tainted_callers(x, int(self.config['eg_souce_addr'], 16))
                roles = []
                for cs in callers:
                    no = self._current_cfg.get_any_node(cs[0])
                    role = self._get_role(self._current_cfg, no, x, cs[1])
                    plugins_used.append(self._plugin_used)
                    roles.append(role)

            plugins_used = list(set([x for x in plugins_used if x]))

            if not plugins_used:
                roles = [Role.UNKNOWN]
                plugins_used = [None]
            if len(plugins_used) > 1:
                import ipdb; ipdb.set_trace()

        return roles, plugins_used[-1]

    def _find_roles(self):
        nodes = {}
        roles = {}

        working_list = list(self._seed_bins)
        idx = 0

        while idx < len(working_list):
            b = working_list[idx]
            self._current_bin = b
            self._current_p = self._projects[b]
            self._current_cfg = self._cfgs[b]
            roles[b] = []
            plugins_used = []

            strs = [x[0] for x in get_bin_strings(b)]

            # FIXME: do the following more times and perform a voting-based algorithm
            # to find the role
            window = len(self._h_keywords) * ROLE_STRINGS_RATIO
            count = window

            if self._strs_to_taint:
                # we got the string addresses already... use them
                things = [(x, y) for x, y in self._strs_to_taint]
                i_roles, plugin_used = self._find_role(things=things)
                # did we find any role?
                if any([r for r in i_roles if r != Role.UNKNOWN]):
                    roles[b] += i_roles
                    plugins_used.append(plugin_used)
            elif self._arg_to_taint:
                things = [(x, "GLOBAL_VAR") for x in self._arg_to_taint]
                i_roles, plugin_used = self._find_role(things=things)
                # did we find any role?
                if any([r for r in i_roles if r != Role.UNKNOWN]):
                    roles[b] += i_roles
                    plugins_used.append(plugin_used)
            else:
                # gotta find them
                for h_key in self._h_keywords:
                    if count <= 0:
                        count = window
                        if roles[b]:
                            break
                    for s in strs:
                        if s.startswith(h_key):
                            i_roles, plugin_used = self._find_role(s=s)
                            # did we find any role?
                            if any([r for r in i_roles if r != Role.UNKNOWN]):
                                roles[b] += i_roles
                                plugins_used.append(plugin_used)
                                break
                count -= 1

            # add a new node
            nodes[b] = BdgNode(self._current_p, self._current_cfg, plugin_used=plugins_used)

            # update data keys
            self._h_keywords = list(set(self._h_keywords + nodes[b].role_strings))

            if not self._arg_to_taint:
                nodes[b].discover_role_strings()

            new_bins = []
            candidate_new_bins = list(set(nodes[b].discover_new_binaries()))

            for nb in candidate_new_bins:
                if any([ib in nb for ib in self._ignore_bins]):
                    continue
                new_bins.append(nb)
            new_bins = self._update_projects(new_bins)
            working_list += [x for x in new_bins if x not in working_list]

            idx += 1
        return nodes, roles

    def _build_dependency_graph(self):
        """
        Sets the binaries hierarchy, by inferring the information flow.

        The algorithm followed is the following:
        * given a set of stating binaries, it analyzes them one by one trying to infer their role (SETTER or GETTER), based
        on how some key strings are used.
        This step is done by using a set of cpfs (see plugin folder). During this phase, more binaries might be
        discovered and added to the analysis queue.

        * discover all the role strings of every collected binary

        * according how these strings flown through the binaries, build the dependency graph.

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
                    setter_strings_set = set(nodes[setter].role_strings)
                    node_strings_set = set(nodes[b].role_strings)
                    if setter_strings_set.intersection(node_strings_set):
                        if nodes[setter] not in self._graph:
                            self._graph[nodes[setter]] = []
                        self._graph[nodes[setter]].append(nodes[b])
                        is_orphan = False

                # mark orphans
                if is_orphan:
                    nodes[b].set_orphan()

            # Clean up
            for k, childs in self._graph.iteritems():
                self._graph[k] = list(set(childs))

        # set leaves
        for k, c in self._graph.iteritems():
            if not c:
                k.set_leaf()

        # post processing:
        # remove those nodes that are not orphans
        # and are not network parsers

        nodes = self.nodes
        children = [c for x in self._graph.values() for c in x if x]
        leafs_non_orphan = [n for n in nodes if n.leaf and not n.orphan]
        seed_names = [x.split('/')[-1] for x in self._seed_bins]
        spurious_nodes = [n for n in leafs_non_orphan if n not in children and n.bin.split('/')[-1] not in seed_names]
        for to_rem in spurious_nodes:
            del self._graph[to_rem]

    def set_hierarchy_strings(self, keywords):
        """
        Set the set of strings that will be used to infer the hierarchy of binaries
        :param keywords:  list of strings
        :return:
        """
        self._h_keywords = keywords

    @property
    def nodes(self):
        """
        Returns the graph's nodes
        """

        return list(set(self._graph.keys() + [x for x in itertools.chain.from_iterable(self._graph.values())]))

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

    def run(self):
        """
        Run the Binary Dependency Graph analysis
        :return: the binary dependency graph
        """

        self._build_dependency_graph()


if __name__ == '__main__':
    try:
        config = json.load(open(sys.argv[1]))
    except:
        print "Usage " + sys.argv[0] + " config"
        sys.exit(0)

    plugins = [environment.Environment, file.File, socket.Socket, setter_getter.SetterGetter, semantic.Semantic]
    bdg = BinaryDependencyGraph(config, plugins=plugins)
    bdg.run()
