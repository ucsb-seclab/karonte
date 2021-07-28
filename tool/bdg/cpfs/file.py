import os

from bdg.cpfs.__init__ import CPF, LIB_KEYWORD
from taint_analysis.utils import arg_reg_name, arg_reg_id, get_initial_state
from bdg.utils import get_string, are_parameters_in_registers, run_command
from bdg.bdp_enum import Role, RoleInfo
from taint_analysis.coretaint import TimeOutException, CoreTaint

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

    def _check_getter_sink(self, current_path, *_, **__):
        """
        The sink here is a memcmp-like function, if both parameters are tainted,
        he data key is compared against some content read from a file

        :param current_path: angr current pathdo you have to work?
        :return: None
        """

        if current_path.active[0].addr == self._sink_addr:
            next_path = current_path.copy(deep=True).step()
            val_1 = getattr(next_path.active[0].regs, arg_reg_name(self._p, 0))
            val_2 = getattr(next_path.active[0].regs, arg_reg_name(self._p, 1))

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
            next_path = current_path.copy(deep=True).step()
            val_1 = getattr(next_path.active[0].regs, arg_reg_name(self._p, 0))

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
            next_path = current_path.copy(deep=True).step()
            addr = getattr(next_path.active[0].regs, arg_reg_name(self._p, 0))
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
            self._ct = CoreTaint(p, not_follow_any_calls=True, smart_call=False,
                                 follow_unsat=True,
                                 try_thumb=True,
                                 exit_on_decode_error=True, force_paths=True,
                                 taint_returns_unfollowed_calls=True,
                                 taint_arguments_unfollowed_calls=True,
                                 allow_untaint=False)

            self._ct.set_alarm(TIMEOUT_TAINT, n_tries=TIMEOUT_TRIES)
            try:
                s = get_initial_state(self._p, self._ct, caller_block)
                self._ct.run(s, (), (), force_thumb=False,
                             check_func=self._save_file_name)
            except TimeOutException:
                self._log.warning("Hard timeout triggered")
            except Exception as e:
                self._log.error(f"file.py: Something went terribly wrong: {str(e)}")
            self._ct.restore_signal_handler()

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

        next_path = current_path.copy(deep=True).step()
        # we jump into the GoT if we have an extern call
        if next_path.active and self._p.loader.find_plt_stub_name(next_path.active[0].addr):
            path_copy = next_path.copy(deep=True).step()
            addr = path_copy.active[0].addr

        node = cfg.get_any_node(addr)

        if not are_parameters_in_registers(p):
            raise Exception("file.run: Implement me")

        block_caller_role_function = current_path.active[0].addr

        if node and node.name and '+' not in node.name:

            # Setter
            candidate_role = Role.UNKNOWN

            if str(node.name).lower() in M_SET_KEYWORD:
                # check whether if the data_key is passed.
                reg_name = arg_reg_name(p, 1)
                reg_cnt = getattr(path_copy.active[0].regs, reg_name)
                reg_cnt_loaded = core_taint.safe_load(path_copy, reg_cnt)
                tainted = core_taint.is_tainted(reg_cnt) or core_taint.is_tainted(reg_cnt_loaded, path=path_copy)

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
                reg_name = arg_reg_name(p, 0)
                reg_cnt_0 = getattr(path_copy.active[0].regs, reg_name)
                reg_cnt_loaded_0 = core_taint.safe_load(path_copy, reg_cnt_0)
                tainted_0 = core_taint.is_tainted(reg_cnt_0) or core_taint.is_tainted(reg_cnt_loaded_0, path=path_copy)

                reg_name = arg_reg_name(p, 1)
                reg_cnt_1 = getattr(path_copy.active[0].regs, reg_name)
                reg_cnt_loaded_1 = core_taint.safe_load(path_copy, reg_cnt_1)
                tainted_1 = core_taint.is_tainted(reg_cnt_1) or core_taint.is_tainted(reg_cnt_loaded_1)

                tainted = tainted_0 or tainted_1
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

                x_ref_fun = cfg.model.get_any_node(block_caller_role_function)
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
                        RoleInfo.PAR_N: arg_reg_id(p, reg_name),
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
                    cmd = f"grep -r '" + name_file + "' " + self._fw_path + " | grep Binary | awk '{print $3}'"
                except:
                    fp = open('/mnt/shared/eccolo_il_', 'w')
                    fp.write(f'namefile {str(name_file)}\n')
                    fp.write(f'fw_path {str(self._fw_path)}\n')
                    fp.close()
                    continue

                o, e = run_command(cmd)
                candidate_bins = list(set([x for x in o.decode().split('\n') if x]))
                for b in candidate_bins:
                    if LIB_KEYWORD in b or b in bins:
                        continue
                    self._log.debug(f"Adding {os.path.basename(b)}")
                    bins.append(b)

        return list(set(bins))
