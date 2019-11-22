"""
*** File plugin.

The File plugin works as follow:
* given a string reference, first it looks whether this string is retrieved by a buffer read from a file, or whether
  it gets written into a file. In the former case the binary will be a getter, in the latter a setter.

  To understand whether a string is read/written from/to a file, we hook the memcmp-like functions (such as
  strcmp and memcmp) and file-write-like functions (suck as write and fprintf).
  The rationale behind this is the following: if a buffer is read from file and some keyword is seeked, a memcmp-like
  function will be used.

  Therefore, if we find that the string is used within a memcmp-like function, we perform a reach-def analysis (implemented
  using our tainting engine) and we check whether such string comes from a read from file. On the other end, if a keyword
  is used in a filewrite-like function, the binary is resolved to be a setter.

* Once the role of the binary has been defined, we scan for filenames.
  the algorithm works as follow:
  * we taint the filename of the every open in the binary. If the binary was found to be a getter, we check which taint
  reaches the read from file, if it was a setter we check which taint reaches the write to file.

  Limitations:
  * we assume that a keyword string is written directly to a file and not copied into a buffer first.
"""

from __init__ import Plugin
from binary_dependency_graph.utils import *
from binary_dependency_graph.bdp_enum import *
from taint_analysis import coretaint, summary_functions
from taint_analysis.coretaint import TimeOutException
import simuvex

TIMEOUT_TAINT = 60
TIMEOUT_TRIES = 1

M_SET_KEYWORD = ('write', 'fprintf')
M_GET_KEYWORD = 'read'
CMP_KEYWORD = ('strcmp', 'memcmp')
LIB_KEYWORD = 'lib'


class File(Plugin):

    def __init__(self, *kargs, **kwargs):
        Plugin.__init__(self, 'file', *kargs, **kwargs)
        self._strings = []
        self._roles = []
        self._opens = []
        self._role_strings_info = {}
        self._ct = None
        self._current_key_addr = None
        self._sink_addr = None
        self._read_from_file = False
        self._write_from_file = False
        self._name_files = []
        self._stop_run = False
        self._check_func = None
        self._last_file_name = None

    def _get_initial_state(self, addr):
        """
        Sets and returns the initial state of the analysis

        :param addr: entry point
        :return: the state
        """

        p = self._p
        s = p.factory.blank_state(
            remove_options={
                simuvex.o.LAZY_SOLVES
            }
        )

        lr = p.arch.register_names[link_regs[self._p.arch.name]]
        setattr(s.regs, lr, self._ct.bogus_return)
        s.ip = addr
        return s

    def _check_getter_sink(self, current_path, guards_info, *_, **__):
        # the sink here is a memcmp-like function, if both parameters are tainted,
        # the key string is compared against some content read from a file
        if current_path.active[0].addr == self._sink_addr:
            next_path = current_path.copy(copy_states=True).step()
            name_reg = self._p.arch.register_names[ordered_agument_regs[self._p.arch.name][0]]
            val_1 = getattr(next_path.active[0].regs, name_reg)
            name_reg = self._p.arch.register_names[ordered_agument_regs[self._p.arch.name][1]]
            val_2 = getattr(next_path.active[0].regs, name_reg)

            if self._ct.is_tainted(val_1) and self._ct.is_tainted(val_2):
                self._read_from_file = True
                self._ct.stop_run()
                self._stop_run = True

    def _check_setter_sink(self, current_path, guards_info, *_, **__):
        # the sink here is a write-like function, if both parameters are tainted,
        # the key string is compared against some content read from a file
        if current_path.active[0].addr == self._sink_addr:
            next_path = current_path.copy(copy_states=True).step()
            name_reg = self._p.arch.register_names[ordered_agument_regs[self._p.arch.name][0]]
            val_1 = getattr(next_path.active[0].regs, name_reg)

            if self._ct.is_tainted(val_1):
                self._write_from_file = True
                self._ct.stop_run()
                self._stop_run = True

    def _save_file_name(self, current_path, guards_info, *_, **__):
        # save and apply taint to the open function
        if not self._ct.taint_applied:
            # first get the address of the filename
            next_path = current_path.copy(copy_states=True).step()
            name_reg = self._p.arch.register_names[ordered_agument_regs[self._p.arch.name][0]]
            addr = getattr(next_path.active[0].regs, name_reg)
            if addr.concrete:
                self._last_file_name = get_string(self._p, addr.args[0], extended=True)

            self._ct.apply_taint(current_path, addr, "filename")
            self._ct.apply_taint(current_path, self._current_key_addr, "key_str")
            self._check_func(current_path, guards_info, *_, **__)

    def _find_file_name(self, check_func):
        cfg = self._cfg
        p = self._p

        self._check_func = check_func
        # first look if there is an open/fopen
        for node in cfg.nodes():
            if node.name and 'fopen' in node.name:
                pred = node.predecessors
                if len(pred) == 1 and pred[0].addr in p.loader.main_bin.reverse_plt.keys():
                    caller_blocks = pred[0].predecessors

                    for caller_block in caller_blocks:
                        self._ct = coretaint.CoreTaint(p, not_follow_any_calls=True, smart_call=False,
                                                       follow_unsat=True,
                                                       try_thumb=True,
                                                       exit_on_decode_error=True, force_paths=True,
                                                       taint_returns_unfollowed_calls=True,
                                                       taint_arguments_unfollowed_calls=True,
                                                       allow_untaint=False)

                        self._ct.set_alarm(TIMEOUT_TAINT, n_tries=TIMEOUT_TRIES)
                        s = self._get_initial_state(caller_block.addr)
                        try:
                            self._ct.run(s, (), (), force_thumb=False,
                                         check_func=self._save_file_name)
                        except TimeOutException:
                            log.warning("Hard timeout triggered")
                        except Exception as e:
                            log.error("Something went terribly wrong: %s" % str(e))

    def _open_is_close(self):
        cfg = self._cfg
        p = self._p
        try:
            open = [n for n in cfg.nodes() if n.name and n.name in 'fopen' and 'extern' in
                    p.loader.find_object_containing(n.addr).binary]

            if open:
                assert len(open) == 1
                open = open[0]

            open_plt = open.predecessors
            if open_plt:
                assert len(open_plt) == 1
                open_plt = open_plt[0]

            source_functions = [x.function_address for x in open_plt.predecessors]
            sink_function = cfg.get_any_node(self._sink_addr).function_address

            if sink_function in source_functions:
                return True

            for source in source_functions:
                one_hop_fs = cfg.functions.callgraph[source].keys()
                if sink_function in one_hop_fs:
                    return True

                for one_hop_f in one_hop_fs:
                    two_hop_fs = cfg.functions.callgraph[one_hop_f].keys()
                    if sink_function in two_hop_fs:
                        return True
        except:
            pass

        return False

    def run(self, key_string, key_addr, reg_name, core_taint, current_path):
        p = self._p
        cfg = self._cfg
        self._current_key_addr = key_addr
        path_copy = current_path
        addr = current_path.active[0]

        next_path = current_path.copy(copy_states=True).step()
        # we jump into the GoT if we have an extern call
        if next_path.active[0].addr in self._p.loader.main_bin.reverse_plt.keys():
            path_copy = next_path.copy(copy_states=True).step()
            addr = path_copy.active[0].addr

        node = cfg.get_any_node(addr)
        par_n = ordered_agument_regs[p.arch.name].index(p.arch.registers[reg_name][0])

        if not are_parameters_in_registers(p):
            print "file.run: Implement me"
            import ipdb;
            ipdb.set_trace()

        block_caller_role_function = current_path.active[0].addr

        if node and node.name and '+' not in node.name:

            # Setter
            candidate_role = Role.UNKNOWN

            if str(node.name).lower() in M_SET_KEYWORD:
                # check whether if the string is passed.
                reg_off = ordered_agument_regs[p.arch.name][1]
                reg_name = p.arch.register_names[reg_off]
                reg_cnt = getattr(path_copy.active[0].regs, reg_name)
                tainted = core_taint.is_tainted(reg_cnt)
                if not tainted:
                    tainted = core_taint.is_tainted(core_taint.safe_load(path_copy, reg_cnt), path=path_copy)

                if tainted:
                    candidate_role = Role.SETTER

                    # we got to find the filename
                    self._sink_addr = block_caller_role_function
                    self._stop_run = False
                    self._find_file_name(self._check_setter_sink)

            # getter
            # getter are more complicated. We have to understand whether the string is compared against
            # some content taken from a file
            if str(node.name).lower() in CMP_KEYWORD:

                # check whether if the string is passed. We have to check both args

                reg_off = ordered_agument_regs[p.arch.name][0]
                reg_name = p.arch.register_names[reg_off]
                reg_cnt = getattr(path_copy.active[0].regs, reg_name)
                tainted_0 = core_taint.is_tainted(reg_cnt)
                if not tainted_0:
                    tainted_0 = core_taint.is_tainted(core_taint.safe_load(path_copy, reg_cnt), path=path_copy)

                reg_off = ordered_agument_regs[p.arch.name][1]
                reg_name = p.arch.register_names[reg_off]
                reg_cnt = getattr(path_copy.active[0].regs, reg_name)
                tainted_1 = core_taint.is_tainted(reg_cnt)
                if not tainted_1:
                    tainted_1 = core_taint.is_tainted(core_taint.safe_load(path_copy, reg_cnt), path=path_copy)

                tainted = tainted_0 | tainted_1
                if tainted:
                    self._sink_addr = block_caller_role_function

                    self._stop_run = False

                    # as in this case we do not know yet whether the string comes from a file
                    # (we only found a strmp), we start looking for the open only if it is within two hops
                    # from the strcmp.
                    if self._open_is_close():
                        self._find_file_name(self._check_getter_sink)
                    if self._read_from_file:
                        candidate_role = Role.GETTER

            if candidate_role != Role.UNKNOWN:
                self._strings.append(key_string)
                self._roles.append(candidate_role)

                x_ref_fun = cfg.get_any_node(block_caller_role_function)
                # if the string contains the ":%s", ":5d" and so forth, we remove it
                key_string = key_string.split(":%")[0]

                info = {
                    RoleInfo.ROLE: candidate_role,
                    RoleInfo.STRING: key_string,
                    RoleInfo.X_REF_FUN: x_ref_fun,
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
                if self._last_file_name not in self._name_files:
                    self._name_files.append(self._last_file_name)

                return True, candidate_role

        return False, Role.UNKNOWN

    @property
    def role_strings_info(self):
        return self._role_strings_info

    def discover_new_binaries(self):
        bins = []

        self._log.debug("Discovering new binaries.. this might take a while.. take a coffee.")
        for role, string, name_file in zip(self._roles, self._strings, self._name_files):

            if role == Role.SETTER:
                cmd = "grep -r '" + name_file + "' " + self._fw_path + " | grep Binary | awk '{print $3}'"
                o, e = run_command(cmd)

                candidate_bins = list(set([x for x in o.split('\n') if x]))
                for b in candidate_bins:
                    if LIB_KEYWORD in b:
                        continue

                    name = b.split('/')[-1]
                    self._log.debug("Adding " + str(name))
                    bins.append(b)

        return list(set(bins))
