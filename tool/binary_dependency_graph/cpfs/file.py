from __init__ import CPF, LIB_KEYWORD
from taint_analysis.utils import ordered_argument_regs
from binary_dependency_graph.utils import link_regs, get_string, are_parameters_in_registers, run_command
from binary_dependency_graph.bdp_enum import Role, RoleInfo
from taint_analysis import coretaint, summary_functions
from taint_analysis.coretaint import TimeOutException
import simuvex

TIMEOUT_TAINT = 10
TIMEOUT_TRIES = 1

M_SET_KEYWORD = ('write', 'fprintf')
M_GET_KEYWORD = 'read'
CMP_KEYWORD = ('strcmp', 'memcmp')


class File(CPF):
    """
    *** File cpf.

    The File cpf works as follow:
    * given a data-key reference, first it looks whether this data-key is retrieved by a buffer read from a file, or
      whether it gets written into a file. In the former case the binary will be a getter, in the latter a setter.

      To understand whether a data-key is read/written from/to a file, we hook the memcmp-like functions (such as
      strcmp and memcmp) and file-write-like functions (suck as write and fprintf).
      The rationale behind this is the following: if a buffer is read from file and some keyword is seeked, a
      memcmp-like function will be used.

      Therefore, if we find that the data-key is used within a memcmp-like function, we perform a reach-def analysis
      (implemented using our tainting engine) and we check whether such data-key comes from a read from file.
      On the other end, if a keyword is used in a filewrite-like function, the binary is resolved to be a setter.

    * Once the role of the binary has been defined, we scan for filenames.
      the algorithm works as follow:
      * we taint the filename of the every open in the binary. If the binary was found to be a getter, we check which
      taint reaches the read from file, if it was a setter we check which taint reaches the write to file.

      Limitations:
      * we assume that a keyword data-key is written directly to a file and not copied into a buffer first.
    """

    def __init__(self, *kargs, **kwargs):
        CPF.__init__(self, 'file', *kargs, **kwargs)
        self._opens = []
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

    def _check_getter_sink(self, current_path, *_, **__):
        """
        The sink here is a memcmp-like function, if both parameters are tainted,
        he data key is compared against some content read from a file

        :param current_path: angr current pathdo you have to work?
        :return: None
        """

        if current_path.active[0].addr == self._sink_addr:
            next_path = current_path.copy(copy_states=True).step()
            name_reg = self._p.arch.register_names[ordered_argument_regs[self._p.arch.name][0]]
            val_1 = getattr(next_path.active[0].regs, name_reg)
            name_reg = self._p.arch.register_names[ordered_argument_regs[self._p.arch.name][1]]
            val_2 = getattr(next_path.active[0].regs, name_reg)

            if self._ct.is_tainted(val_1) and self._ct.is_tainted(val_2):
                self._read_from_file = True
                self._ct.stop_run()
                self._stop_run = True

    def _check_setter_sink(self, current_path, *_, **__):
        """
        The sink here is a write-like function, if both parameters are tainted,
        the data key is compared against some content read from a file.

        :param current_path: angr current path
        :return: None
        """

        if current_path.active[0].addr == self._sink_addr:
            next_path = current_path.copy(copy_states=True).step()
            name_reg = self._p.arch.register_names[ordered_argument_regs[self._p.arch.name][0]]
            val_1 = getattr(next_path.active[0].regs, name_reg)

            if self._ct.is_tainted(val_1):
                self._write_from_file = True
                self._ct.stop_run()
                self._stop_run = True

    def _save_file_name(self, current_path, guards_info, *_, **__):
        """
        Save and apply taint to the open function

        :param current_path: angr current path
        :param guards_info: guards info
        :return: None
        """

        if not self._ct.taint_applied:
            # first get the address of the filename
            next_path = current_path.copy(copy_states=True).step()
            name_reg = self._p.arch.register_names[ordered_argument_regs[self._p.arch.name][0]]
            addr = getattr(next_path.active[0].regs, name_reg)
            if addr.concrete:
                self._last_file_name = get_string(self._p, addr.args[0], extended=True)

            self._ct.apply_taint(current_path, addr, "filename")
            self._ct.apply_taint(current_path, self._current_key_addr, "key_str")
            self._check_func(current_path, guards_info, *_, **__)

    def _find_file_name(self, current_path, check_func):
        """
        Find the filename.

        :param current_path: angr current path.
        :param check_func:  checker function
        :return: None
        """

        p = self._p

        self._check_func = check_func
        caller_blocks = self._get_caller_blocks(current_path, 'fopen')
        for caller_block in caller_blocks:
            self._ct = coretaint.CoreTaint(p, not_follow_any_calls=True, smart_call=False,
                                           follow_unsat=True,
                                           try_thumb=True,
                                           exit_on_decode_error=True, force_paths=True,
                                           taint_returns_unfollowed_calls=True,
                                           taint_arguments_unfollowed_calls=True,
                                           allow_untaint=False)

            self._ct.set_alarm(TIMEOUT_TAINT, n_tries=TIMEOUT_TRIES)
            try:
                s = self._get_initial_state(caller_block)
                self._ct.run(s, (), (), force_thumb=False,
                             check_func=self._save_file_name)
            except TimeOutException:
                self._log.warning("Hard timeout triggered")
            except Exception as e:
                self._log.error("file.py: Something went terribly wrong: %s" % str(e))
            self._ct.restore_signal_handler()

    def _get_caller_blocks(self, current_path, call_name):
        """
        Get caller blocks.

        :param current_path: angr current path
        :param call_name: call function name
        :return: the caller blocks
        """

        cfg = self._cfg
        p = self._p

        no = cfg.get_any_node(current_path.active[0].addr)
        fun = cfg.functions[no.function_address]
        blocks = []
        for addr in fun.block_addrs:
            try:
                bb = p.factory.block(addr).vex
                if bb.jumpkind != 'Ijk_Call':
                    continue
                t_no = cfg.get_any_node(bb.addr)
                succ = t_no.successors[0]
                if not succ.name:
                    succ = t_no.successors[0]

                if succ.name and call_name in succ.name:
                    blocks.append(bb.addr)
            except TimeOutException:
                raise
            except Exception as e:
                self._log.error("_get_caller_blocks file.py: Something went terribly wrong: %s" % str(e))

        return blocks

    def run(self, data_key, key_addr, reg_name, core_taint, current_path, *kargs, **kwargs):
        """
        Run this CPF

        :param data_key: data key
        :param key_addr: data key address
        :param reg_name: register name where the address is stored
        :param core_taint: core taint engine
        :param current_path: angr current path
        :param kargs: kargs
        :param kwargs: kwargs
        :return: None
        """

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
        par_n = ordered_argument_regs[p.arch.name].index(p.arch.registers[reg_name][0])

        if not are_parameters_in_registers(p):
            raise Exception("file.run: Implement me")

        block_caller_role_function = current_path.active[0].addr

        if node and node.name and '+' not in node.name:

            # Setter
            candidate_role = Role.UNKNOWN

            if str(node.name).lower() in M_SET_KEYWORD:
                # check whether if the data_key is passed.
                reg_off = ordered_argument_regs[p.arch.name][1]
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
                    self._find_file_name(current_path, self._check_setter_sink)

            # getter
            # getter are more complicated. We have to understand whether the data_key is compared against
            # some content taken from a file
            if str(node.name).lower() in CMP_KEYWORD:

                # check whether if the data_key is passed. We have to check both args

                reg_off = ordered_argument_regs[p.arch.name][0]
                reg_name = p.arch.register_names[reg_off]
                reg_cnt = getattr(path_copy.active[0].regs, reg_name)
                tainted_0 = core_taint.is_tainted(reg_cnt)
                if not tainted_0:
                    tainted_0 = core_taint.is_tainted(core_taint.safe_load(path_copy, reg_cnt), path=path_copy)

                reg_off = ordered_argument_regs[p.arch.name][1]
                reg_name = p.arch.register_names[reg_off]
                reg_cnt = getattr(path_copy.active[0].regs, reg_name)
                tainted_1 = core_taint.is_tainted(reg_cnt)
                if not tainted_1:
                    tainted_1 = core_taint.is_tainted(core_taint.safe_load(path_copy, reg_cnt), path=path_copy)

                tainted = tainted_0 | tainted_1
                if tainted:
                    self._sink_addr = block_caller_role_function

                    self._stop_run = False

                    # as in this case we do not know yet whether the data_key comes from a file
                    # (we only found a strmp), we start looking for the open only if it is within two hops
                    # from the strcmp.
                    self._find_file_name(current_path, self._check_getter_sink)
                    if self._read_from_file:
                        candidate_role = Role.GETTER

            if candidate_role != Role.UNKNOWN:
                self._data_keys.append(data_key)
                self._roles.append(candidate_role)

                x_ref_fun = cfg.get_any_node(block_caller_role_function)
                # if the data_key contains the ":%s", ":5d" and so forth, we remove it
                data_key = data_key.split(":%")[0]
                if data_key:
                    info = {
                        RoleInfo.ROLE: candidate_role,
                        RoleInfo.DATAKEY: data_key,
                        RoleInfo.X_REF_FUN: x_ref_fun,
                        RoleInfo.CALLER_BB: block_caller_role_function,
                        RoleInfo.ROLE_FUN: addr,
                        RoleInfo.ROLE_INS: addr,
                        RoleInfo.ROLE_INS_IDX: None,
                        RoleInfo.COMM_BUFF: None,
                        RoleInfo.PAR_N: par_n,
                        RoleInfo.CPF: self._name
                    }
                    if key_addr not in self._role_info:
                        self._role_info[key_addr] = []
                    if info not in self._role_info[key_addr]:
                        self._role_info[key_addr].append(info)
                    if self._last_file_name not in self._name_files:
                        self._name_files.append(self._last_file_name)

                    return True, candidate_role

        return False, Role.UNKNOWN

    @property
    def role_info(self):
        return self._role_info

    def discover_new_binaries(self):
        """
        Discover other binaries within the firmware sample using the same data keys.

        :return: a list of binaries.
        """

        bins = []

        self._log.debug("Discovering new binaries.. this might take a while.. take a coffee.")
        for role, data_key, name_file in zip(self._roles, self._data_keys, self._name_files):
            if not name_file or not data_key:
                continue

            if role == Role.SETTER:
                try:
                    cmd = "grep -r '" + name_file + "' " + self._fw_path + " | grep Binary | awk '{print $3}'"
                except:
                    fp = open('/mnt/shared/eccolo_il_', 'w')
                    fp.write('namefile ' + str(name_file) + '\n')
                    fp.write('fw_path ' + str(self._fw_path) + '\n')
                    fp.close()
                    continue

                o, e = run_command(cmd)

                candidate_bins = list(set([x for x in o.split('\n') if x]))
                for b in candidate_bins:
                    if LIB_KEYWORD in b:
                        continue

                    name = b.split('/')[-1]
                    self._log.debug("Adding " + str(name))
                    bins.append(b)

        return list(set(bins))
