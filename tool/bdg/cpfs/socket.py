import math
import os
import struct

from angr.procedures.stubs.ReturnUnconstrained import ReturnUnconstrained
from claripy import BVV

from bdg.bdp_enum import Role, RoleInfo
from bdg.cpfs.__init__ import CPF
from bdg.utils import are_parameters_in_registers, run_command, get_dyn_sym_addrs, get_string
from taint_analysis.coretaint import TimeOutException, CoreTaint
from taint_analysis.utils import arg_reg_name, arg_reg_id, get_initial_state, ret_reg_name

M_SET_KEYWORD = 'send'
M_GET_KEYWORD = 'recv'

CMP_KEYWORD = ('strcmp', 'memcmp')
CPY_KEYWORD = ('memcpy', 'strcpy', 'strncpy')
LIB_KEYWORD = 'lib'

inet_pton_convesions = {0: 'IN_ADDR_ANY'}

TIMEOUT_TAINT = 10
TIMEOUT_TRIES = 1


class Socket(CPF):
    """
    *** Socket cpf.

    The socket cpf works as follow:
    * given a data key reference, first it looks whether this data key is retrieved by a buffer read from socket, or
      whether it gets sent over a socket. In the former case the binary will be a getter, in the latter a setter.

      To understand whether a date key is received/sent from/to a socket, we hook the memcmp-like functions (such as
      strcmp and memcmp) and memcpy-like functions (suck as memcpy, strcpy and strncpy).
      The rationale behind this is the following: if a buffer is received from socket and some keyword is seeked, a
      memcmp-like function will be used. On the other end, if a keyword is sent over a socket, it is either copied into
      a buffer and then sent or sent directly.

      Therefore, if we find that the date key is used within a memcmp-like function, we perform a reach-def analysis
      (implemented using our tainting engine) and we check whether such data key comes from a read from socket.
      On the other end, if a keyword is used in a memcpy-like function, we still perform a reach-def analysis to check
      whether the buffef is then written to socket.

    * Once the role of the binary has been defined, we scan for bindings: ports and ip addresses. To do this we assume
      that a sockaddr_in a binary is set in a form close to the follow:
      address.sin_family = AF_INET;
      address.sin_addr.s_addr = INADDR_ANY;
      address.sin_port = htons( PORT );

      In particular we assume that:
      * the htons function is used
      * the port is set *after* the ip
      * the port is an hardcoded value (necessary to find other binaries with the same bindings)

      the algorithm works as follow:
      * we hook htons functions and we retrieve the port. After that, assuming that the ip was already set, we retrieve
        the address the port was written to and, by knowing the sockaddr_in structure, we read past the port and we
        retrieve the ip address.
        Note that we also hook the inet_pton function in order to detect ip addresses.

    Limitations:
      * if a port is set through a variable, the cpf won't retrieve it
      * if an ip address is set after setting the port, it won't be retrieved
      * we look for a recv (or a send) only if it is within 2 hops from the current function. This helps speeding up the
        analysis

    """

    def __init__(self, *kargs, **kwargs):
        CPF.__init__(self, 'socket', *kargs, **kwargs)
        self._ips = []
        self._current_key_addr = None
        self._stop_run = False
        self._bindings = []
        self._last_port = None
        self._pton_counter = 1
        self._read_from_socket = False
        self._source_addrs = []
        self._sink_addrs = []

    def _check_ip_address(self, current_path, *_, **__):
        """
        Finds the used ip address sending/receiving tainted data

        :param current_path: angr current path
        :return: None
        """

        p = self._p

        if current_path.active[0].addr in self._sink_addrs and self._last_port:
            # we gotta find the memory address the port is assigned to
            block = p.factory.block(current_path.active[0].addr)
            next_path = current_path.copy(dee=True).step()

            # get all the memory stores
            stores = [x for x in block.vex.statements if x.tag == 'Ist_Store']
            for s in stores:
                tmp_used = s.addr.tmp
                mem_loc = next_path.active[0].scratch.temps[tmp_used]
                port_len = int(math.ceil(self._last_port.bit_length() / float(8)))
                cnt = next_path.active[0].memory.load(mem_loc, port_len)
                if 'EL' in p.arch.name:
                    # little endian, we got to reverse the value
                    cnt = cnt.reversed

                if cnt.concrete and cnt.args[0] == self._last_port:
                    # we got the right store, get the address of sockaddr_in, then the ip
                    ip_address = next_path.active[0].memory.load(mem_loc + port_len, p.arch.bytes)
                    if ip_address.concrete:
                        self._last_ip = inet_pton_convesions[ip_address.args[0]]
                        self._bindings.append((self._last_port, self._last_ip))
                        self._last_port = None
                        self._last_ip = None
                        self._ct.stop_run()

    def _find_binding(self, current_path):
        """
        Attempts to find the port and ip using to send the data to other binaries.
        The heuristic is the following:
        * first we look for the htons instruction and we retrieve the port, the we look in the nearby memory to
          retrieve the IP address. This heuristic is based on the fact that both port and ip are set in the same
          sock_addr struct
        :param current_path: angr current path
        :return: None
        """

        p = self._p
        htons_callers = self._get_caller_blocks(current_path, 'htons')
        for caller_block in htons_callers:
            self._sink_addrs = []
            self._last_port = None
            self._ct = CoreTaint(p, smart_call=False,
                                 interfunction_level=0,
                                 follow_unsat=True,
                                 try_thumb=True,
                                 exit_on_decode_error=True, force_paths=True,
                                 taint_returns_unfollowed_calls=True,
                                 taint_arguments_unfollowed_calls=True,
                                 allow_untaint=False)

            summarized_f = {}

            # summary the htons and inet_pton
            addrs = get_dyn_sym_addrs(p, ['htons'])
            for a in addrs:
                summarized_f[a] = self._htons

            addrs = get_dyn_sym_addrs(p, ['inet_pton'])
            for a in addrs:
                summarized_f[a] = self._inet_pton

            self._ct.set_alarm(TIMEOUT_TAINT, n_tries=TIMEOUT_TRIES)
            try:
                faddr = self._cfg.model.get_any_node(caller_block).function_address
                s = get_initial_state(self._p, self._ct, faddr)
                self._ct.run(s, (), (), summarized_f=summarized_f, force_thumb=False,
                             check_func=self._check_ip_address)
            except TimeOutException:
                self._log.warning("Hard timeout triggered")
            except Exception as e:
                self._log.error(f"Find binding: Something went terribly wrong: {str(e)}")
            self._ct.restore_signal_handler()

    def _check_recv(self, current_path, *_, **__):
        """
        Finds the function receving tainted data

        :param current_path: angr current path
        :return: None
        """

        if not self._ct.taint_applied:
            # first get the address of the filename
            next_path = current_path.copy(deep=True).step()
            buf_addr = getattr(next_path.active[0].regs, arg_reg_name(self._p, 1))

            self._ct.apply_taint(current_path, buf_addr, "buffer_recv")
            self._ct.apply_taint(current_path, self._current_key_addr, "key_str")

        if current_path.active[0].addr in self._sink_addrs:
            next_path = current_path.copy(deep=True).step()
            val_1 = getattr(next_path.active[0].regs, arg_reg_name(self._p, 0))
            val_2 = getattr(next_path.active[0].regs, arg_reg_name(self._p, 1))

            if (self._ct.is_tainted(val_1) and self._ct.is_tainted(val_2)) or \
                    (self._ct.is_tainted(next_path.active[0].memory.load(val_1, self._p.arch.bytes)) and
                     self._ct.is_tainted(next_path.active[0].memory.load(val_2, self._p.arch.bytes))):
                self._read_from_socket = True
                self._ct.stop_run()
                self._stop_run = True

    def _find_recv(self, current_path):
        """
        Attempts to find the port and ip using to send the data to other binaries.
        the heuristic is the following:
         * first we look for the htons instruction and we retrieve the port, the we look in the nearby memory to
         retrieve the IP address. This heuristic is based on the fact that both port and ip are set in the same
         sock_addr struct

        :param current_path: angr current path
        :return: None
        """

        p = self._p
        self._read_from_socket = False
        caller_blocks = self._get_caller_blocks(current_path, M_GET_KEYWORD)

        for caller_block in caller_blocks:
            self._ct = CoreTaint(p, smart_call=False, not_follow_any_calls=True,
                                 follow_unsat=True,
                                 try_thumb=True,
                                 exit_on_decode_error=True, force_paths=True,
                                 taint_returns_unfollowed_calls=True,
                                 taint_arguments_unfollowed_calls=True,
                                 allow_untaint=False)

            self._ct.set_alarm(TIMEOUT_TAINT, n_tries=TIMEOUT_TRIES)
            try:
                s = get_initial_state(p, self._ct, caller_block)
                self._ct.run(s, (), (), force_thumb=False,
                             check_func=self._check_recv)
            except TimeOutException:
                self._log.warning("Hard timeout triggered")
            except Exception as e:
                self._log.error(f"Find recv: Something went terribly wrong: {str(e)}")
            self._ct.restore_signal_handler()

    def _inet_pton(self, ct, caller_path, plt_path):
        """
        inet_pton summary
        :param ct: core taint engine
        :param caller_path: angr path leading to the inet_path
        :param plt_path:  angr path leading to the plt entry of inet_pton
        :return:
        """
        p = ct.p
        new_state = plt_path.active[0]

        # move data key from argument to destination addr
        addr_str = getattr(plt_path.active[0].regs, arg_reg_name(p, 1))
        cnt_str = get_string(p, addr_str.args[0], extended=True)

        # do the inet_pton conversion.
        # this is not exactly the conversion the inet_pton does, it's a trick we use to keep track of the addresses
        inet_pton_convesions[self._pton_counter] = cnt_str
        bits = p.arch.bits
        to_store = BVV(self._pton_counter, bits)
        self._pton_counter += 1

        # store it!
        dst_mem = getattr(plt_path.active[0].regs, arg_reg_name(p, 2))
        new_state.memory.store(dst_mem, to_store)

        # instead of a link register, we hook an unconstrained sim procedure
        self._p.hook(plt_path.addr, ReturnUnconstrained())
        caller_path.step().step()

    def _htons(self, ct, caller_path, plt_path):
        """
        htons summary
        :param ct: core taint engine
        :param caller_path: angr path leading to the htons
        :param plt_path:  angr path leading to the plt entry of htons
        :return:
        """

        p = ct.p
        cfg = self._cfg
        new_state = plt_path.active[0]
        old_state = caller_path.active[0]

        # move port from argument to return register
        port_n = getattr(plt_path.active[0].regs, arg_reg_name(p, 0))
        setattr(plt_path.active[0].regs, ret_reg_name(p), port_n)

        if port_n.concrete:
            self._last_port = port_n.args[0]

        # now we have to find the ip, we assume the code complies to the
        # form: address.sin_port = htons( PORT );

        # first get the node
        htons_caller_node = cfg.model.get_any_node(caller_path.active[0].addr)
        succs = htons_caller_node.successors
        next_block_addrs = []
        for succ in succs:
            region = p.loader.main_object.sections.find_region_containing(succ.addr)
            if region and region.name == '.text':
                # as the CFG has a fixed context sensitivity and there might be multiple calls to
                # htons, we might have multiple successors after the htons call. At this stage
                # we do not know which corresponds to the current running path. We save them all and we keep
                # symbolically execute the binary, when we encounter one of these blocks, we stop again
                # and collect the port
                next_block_addrs.append(succ.addr)
            else:
                succs += succ.successors

        if next_block_addrs:
            self._sink_addrs = next_block_addrs
        else:
            # we couldn't match the port with a valid ip
            self._last_port = None

        # instead of a link register, we hook an unconstrained sim procedure
        self._p.hook(plt_path.addr, ReturnUnconstrained())
        caller_path.step().step()

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
        addr = current_path.active[0].addr

        next_path = current_path.copy(deep=True).step()
        # we jump into the GoT if we have an extern call
        if next_path.active and self._p.loader.find_plt_stub_name(next_path.active[0].addr):
            path_copy = next_path.copy(deep=True).step()
            addr = path_copy.active[0].addr

        if not are_parameters_in_registers(p):
            raise Exception("socket.run: Implement me")

        node = cfg.model.get_any_node(addr)
        block_caller_role_function = current_path.active[0].addr
        candidate_role = Role.UNKNOWN
        x_ref_fun = cfg.model.get_any_node(block_caller_role_function)
        if node and node.name and '+' not in node.name:
            # setter
            if str(node.name).lower() in M_SET_KEYWORD:
                reg_cnt = getattr(path_copy.active[0].regs, arg_reg_name(p, 1))
                reg_cnt_loaded = core_taint.safe_load(path_copy, reg_cnt)
                tainted = core_taint.is_tainted(reg_cnt) or core_taint.is_tainted(reg_cnt_loaded)

                if tainted:
                    self._log.debug("tainted data is sent over socket.. looking for binding values")
                    candidate_role = Role.SETTER
                    self._find_binding(current_path)

            # getter
            # getter are more complicated. We have to understand whether the data key is compared against
            # some content retrieved from socket
            elif str(node.name).lower() in CMP_KEYWORD:
                # check whether if the data key is passed. We have to check both args
                reg_cnt_0 = getattr(path_copy.active[0].regs, arg_reg_name(p, 0))
                reg_cnt_loaded_0 = core_taint.safe_load(path_copy, reg_cnt_0)
                tainted_0 = core_taint.is_tainted(reg_cnt_0) or core_taint.is_tainted(reg_cnt_loaded_0, path=path_copy)

                reg_cnt_1 = getattr(path_copy.active[0].regs, arg_reg_name(p, 1))
                reg_cnt_loaded_1 = core_taint.safe_load(path_copy, reg_cnt_1)
                tainted_1 = core_taint.is_tainted(reg_cnt_1) or core_taint.is_tainted(reg_cnt_loaded_1, path=path_copy)

                tainted = tainted_0 or tainted_1
                if tainted:
                    self._log.debug("tainted data used in a memcmp-like function.. looking for recv")
                    self._stop_run = False
                    self._sink_addrs = [block_caller_role_function]

                    # if the data key is passed to a memcmp-like function
                    # we have to make sure that the content is compared against to is retrieved
                    # from socket. We have to find the recv.

                    self._find_recv(current_path)

                    if self._read_from_socket:
                        candidate_role = Role.GETTER
                        self._stop_run = False
                        self._find_binding(current_path)

            # Role data key is passed directly to a getter function
            elif M_GET_KEYWORD in str(node.name).lower():
                self._read_from_socket = True
                # check whether if the data key is passed. We have to check both args
                reg_cnt = getattr(path_copy.active[0].regs, arg_reg_name(p, 1))
                tainted = core_taint.is_tainted(reg_cnt)
                if not tainted:
                    tainted = core_taint.is_tainted(core_taint.safe_load(path_copy, reg_cnt), path=path_copy)

                if tainted:
                    self._log.debug("tainted data is received from socket.. looking for binding values")
                    # set_env
                    candidate_role = Role.GETTER
                    self._find_binding(current_path)

            if candidate_role != Role.UNKNOWN:
                # if the data key contains the ":%s", ":5d" and so forth, we remove it
                data_key = data_key.split(":%")[0]

                self._data_keys.append(data_key)
                self._roles.append(candidate_role)

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
        for role, data_key in zip(self._roles, self._data_keys):
            if role == Role.SETTER and data_key:
                for binding in self._bindings:
                    # write the port in the xxd tool format
                    if self._p.arch.bits == 32:
                        val = struct.pack('<I', binding[0]).hex()
                    elif self._p.arch.bits == 64:
                        val = struct.pack('<Q', binding[0]).hex()
                    else:
                        raise Exception("Unsupported number of bits")

                    counter = 0
                    to_look_val = ''
                    for v in val:
                        if counter % 4 == 0 and counter > 0:
                            to_look_val += ' '
                        to_look_val += v
                        counter += 1

                    cmd = "for file in `grep -r '" + binding[1] + "' | grep Binary | awk '{print $3}'`; do " \
                          "res=`xxd $file | grep '" + to_look_val + "'`; " \
                          'if [ -n "$res" ]; then echo $file; fi; done;'
                    o, e = run_command(cmd)
                    candidate_bins = list(set([x for x in o.decode().split('\n') if x]))
                    for b in candidate_bins:
                        if LIB_KEYWORD in b or b in bins:
                            continue
                        self._log.debug(f"Adding {os.path.basename(b)}")
                        bins.append(b)

        return list(set(bins))
