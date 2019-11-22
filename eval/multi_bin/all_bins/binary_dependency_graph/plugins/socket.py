"""
*** Socket plugin.

The socket plugin works as follow:
* given a string reference, first it looks whether this string is retrieved by a buffer read from socket, or whether
  it gets sent over a socket. In the former case the binary will be a getter, in the latter a setter.

  To understand whether a string is received/sent from/to a socket, we hook the memcmp-like functions (such as
  strcmp and memcmp) and memcpy-like functions (suck as memcpy, strcpy and strncpy).
  The rationale behind this is the following: if a buffer is received from socket and some keyword is seeked, a memcmp-like
  function will be used. On the other end, if a keyword is sent over a socket, it is either copied into a buffer and then
  sent or sent directly.

  Therefore, if we find that the string is used within a memcmp-like function, we perform a reach-def analysis (implemented
  using our tainting engine) and we check whether such string comes from a read from socket. On the other end, if a keyword
  is used in a memcpy-like function, we still perform a reach-def analysis to check whether the buffef is then written to
  socket.

* Once the role of the binary has been defined, we scan for bindings: ports and ip addresses. To do this we assume that
  a sockaddr_in a binary is set in a form close to the follow:
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
  * if a port is set through a variable, the plugin won't retrieve it
  * if an ip address is set after setting the port, it won't be retrieved
  * we look for a recv (or a send) only if it is within 2 hops from the current function. This helps speeding up the
    analysis

"""

from __init__ import Plugin
from binary_dependency_graph.utils import *
from binary_dependency_graph.bdp_enum import *
from taint_analysis import coretaint, summary_functions
from taint_analysis.coretaint import TimeOutException
import simuvex
import math
import claripy
import struct

M_SET_KEYWORD = 'send'
M_GET_KEYWORD = 'recv'
CMP_KEYWORD = ('strcmp', 'memcmp')
CPY_KEYWORD = ('memcpy', 'strcpy', 'strncpy')
LIB_KEYWORD = 'lib'

inet_pton_convesions = {0: 'IN_ADDR_ANY'}

TIMEOUT_TAINT = 5 * 60
TIMEOUT_TRIES = 1


class Socket(Plugin):

    def __init__(self, *kargs, **kwargs):
        Plugin.__init__(self, 'socket', *kargs, **kwargs)
        self._strings = []
        self._roles = []
        self._ips = []
        self._current_key_addr = None
        self._stop_run = False
        self._bindings = []
        self._last_port = None
        self._pton_counter = 1
        self._role_strings_info = {}
        self._read_from_socket = False
        self._source_addrs = []
        self._sink_addrs = []

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

    def _check_ip_address(self, current_path, guards_info, *_, **__):
        p = self._p
        cfg = self._cfg

        if current_path.active[0].addr in self._sink_addrs and self._last_port:
            # we gotta find the memory address the port is assigned to
            block = p.factory.block(current_path.active[0].addr)
            next_path = current_path.copy(copy_states=True).step()

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

    def _find_binding(self):
        # this function attempts to find the port and ip using to send the data to other binaries.
        # the heuristic is the following:
        # * first we look for the htons instruction and we retrieve the port, the we look in the nearby memory to
        # retrieve the IP address. This heuristic is based on the fact that both port and ip are set in the same
        # sock_addr struct

        cfg = self._cfg
        p = self._p

        # first look if there is an open/fopen
        for node in cfg.nodes():
            if node.name and 'htons' in node.name:
                pred = node.predecessors
                if len(pred) == 1 and pred[0].addr in p.loader.main_bin.reverse_plt.keys():
                    caller_blocks = pred[0].predecessors

                    for caller_block in caller_blocks:
                        self._sink_addrs = []
                        self._last_port = None
                        self._ct = coretaint.CoreTaint(p, smart_call=False,
                                                       interfunction_level=0,
                                                       follow_unsat=True,
                                                       try_thumb=True,
                                                       exit_on_decode_error=True, force_paths=True,
                                                       taint_returns_unfollowed_calls=True,
                                                       taint_arguments_unfollowed_calls=True,
                                                       allow_untaint=False)

                        s = self._get_initial_state(caller_block.function_address)
                        self._ct.set_alarm(TIMEOUT_TAINT, n_tries=TIMEOUT_TRIES)

                        summarized_f = {}

                        # summary the htons and inet_pton
                        addrs = get_dyn_sym_addrs(p, ['htons'])
                        for a in addrs:
                            summarized_f[a] = self._htons

                        addrs = get_dyn_sym_addrs(p, ['inet_pton'])
                        for a in addrs:
                            summarized_f[a] = self._inet_pton

                        try:
                            self._ct.run(s, (), (), summarized_f=summarized_f, force_thumb=False,
                                         check_func=self._check_ip_address)
                        except TimeOutException:
                            self._log.warning("Hard timeout triggered")
                        except Exception as e:
                            self._log.error("Something went terribly wrong: %s" % str(e))

    def _check_recv(self, current_path, guards_info, *_, **__):
        if not self._ct.taint_applied:
            # first get the address of the filename
            next_path = current_path.copy(copy_states=True).step()
            name_reg = self._p.arch.register_names[ordered_agument_regs[self._p.arch.name][1]]
            addr = getattr(next_path.active[0].regs, name_reg)

            self._ct.apply_taint(current_path, addr, "buffer_recv")
            self._ct.apply_taint(current_path, self._current_key_addr, "key_str")

        if current_path.active[0].addr in self._sink_addrs:
            next_path = current_path.copy(copy_states=True).step()
            name_reg = self._p.arch.register_names[ordered_agument_regs[self._p.arch.name][0]]
            val_1 = getattr(next_path.active[0].regs, name_reg)
            name_reg = self._p.arch.register_names[ordered_agument_regs[self._p.arch.name][1]]
            val_2 = getattr(next_path.active[0].regs, name_reg)

            if (self._ct.is_tainted(val_1) and self._ct.is_tainted(val_2)) or \
                    (self._ct.is_tainted(next_path.active[0].memory.load(val_1)) and self._ct.is_tainted(next_path.active[0].memory.load(val_2))):
                self._read_from_socket = True
                self._ct.stop_run()
                self._stop_run = True

    def _recv_is_close(self):
        cfg = self._cfg
        p = self._p

        try:
            recv = [n for n in cfg.nodes() if n.name and n.name in M_GET_KEYWORD and 'extern' in
                    p.loader.find_object_containing(n.addr).binary]

            if recv:
                assert len(recv) == 1
                recv = recv[0]

            recv_plt = recv.predecessors
            if recv_plt:
                assert len(recv_plt) == 1
                recv_plt = recv_plt[0]

            callers_recv_f = [x.function_address for x in recv_plt.predecessors]
            sink_functions = [cfg.get_any_node(x).function_address for x in self._sink_addrs]

            # 0 hops
            if any([x for x in sink_functions in callers_recv_f]):
                return True

            # 1 or 2 hops
            for caller in callers_recv_f:
                one_hop_fs = cfg.functions.callgraph[caller].keys()
                if any([x for x in sink_functions if x in one_hop_fs]):
                    return True

                for one_hop_f in one_hop_fs:
                    two_hop_fs = cfg.functions.callgraph[one_hop_f].keys()
                    if any([x for x in sink_functions if x in two_hop_fs]):
                        return True
        except:
            pass

        return False

    def _find_recv(self):
        # this function attempts to find the port and ip using to send the data to other binaries.
        # the heuristic is the following:
        # * first we look for the htons instruction and we retrieve the port, the we look in the nearby memory to
        # retrieve the IP address. This heuristic is based on the fact that both port and ip are set in the same
        # sock_addr struct

        cfg = self._cfg
        p = self._p

        # first look if there is an open/fopen
        caller_blocks = []
        for node in cfg.nodes():
            if node.name and M_GET_KEYWORD in node.name:
                region = p.loader.main_object.sections.find_region_containing(node.addr)
                if region and region.name == '.text':
                    caller_blocks = [node]
                else:
                    pred = node.predecessors
                    if len(pred) == 1 and pred[0].addr in p.loader.main_bin.reverse_plt.keys():
                        caller_blocks = pred[0].predecessors

                for caller_block in caller_blocks:
                    self._ct = coretaint.CoreTaint(p, smart_call=False, not_follow_any_calls=True,
                                                   follow_unsat=True,
                                                   try_thumb=True,
                                                   exit_on_decode_error=True, force_paths=True,
                                                   taint_returns_unfollowed_calls=True,
                                                   taint_arguments_unfollowed_calls=True,
                                                   allow_untaint=False)

                    s = self._get_initial_state(caller_block.addr)
                    self._ct.set_alarm(TIMEOUT_TAINT, n_tries=TIMEOUT_TRIES)

                    try:
                        self._ct.run(s, (), (), force_thumb=False,
                                     check_func=self._check_recv)
                    except TimeOutException:
                        self._log.warning("Hard timeout triggered")
                    except Exception as e:
                        self._log.error("Something went terribly wrong: %s" % str(e))

    def _send_is_close(self):
        cfg = self._cfg
        p = self._p
        try:
            send = [n for n in cfg.nodes() if n.name and n.name in M_SET_KEYWORD and 'extern' in
                     p.loader.find_object_containing(n.addr).binary]

            if send:
                assert len(send) == 1
                send = send[0]

            send_plt = send.predecessors
            if send_plt:
                assert len(send_plt) == 1
                send_plt = send_plt[0]

            callers_send_f = [x.function_address for x in send_plt.predecessors]
            source_functions = [cfg.get_any_node(x).function_address for x in self._source_addrs]

            # 0 hop
            if any([x for x in callers_send_f if x in self._source_addrs]):
                return True

            # 1 or two hops
            for source in source_functions:
                one_hop_fs = cfg.functions.callgraph[source].keys()
                if any([x for x in callers_send_f if x in one_hop_fs]):
                    return True

                for one_hop_f in one_hop_fs:
                    two_hop_fs = cfg.functions.callgraph[one_hop_f].keys()
                    if any([x for x in callers_send_f if x in two_hop_fs]):
                        return True
        except:
            pass

        return False

    def _inet_pton(self, ct, caller_path, plt_path):
        p = ct.p
        new_state = plt_path.active[0]
        old_state = caller_path.active[0]

        # move string from argument to destination addr
        addr_reg = ordered_agument_regs[p.arch.name][1]
        dst_reg = ordered_agument_regs[p.arch.name][2]
        addr_str = getattr(plt_path.active[0].regs, p.arch.register_names[addr_reg])
        cnt_str = get_string(p, addr_str.args[0], extended=True)

        # do the inet_pton conversion.
        # this is not exactly the conversion the inet_pton does, it's a trick we use to keep track of the addresses
        inet_pton_convesions[self._pton_counter] = cnt_str
        bits = p.arch.bits
        to_store = claripy.BVV(self._pton_counter, bits)
        self._pton_counter += 1

        # store it!
        dst_mem = getattr(plt_path.active[0].regs, p.arch.register_names[dst_reg])
        new_state.memory.store(dst_mem, to_store)

        # restore registers to return from the function call
        lr = p.arch.register_names[link_regs[p.arch.name]]
        ret_addr = getattr(new_state.regs, lr)
        ret_func = getattr(old_state.regs, lr)

        plt_path.active[0].ip = ret_addr
        setattr(plt_path.active[0].regs, lr, ret_func)
        plt_path.active[0].history.jumpkind = "Ijk_FakeRet"

    def _htons(self, ct, caller_path, plt_path):
        p = ct.p
        cfg = self._cfg
        new_state = plt_path.active[0]
        old_state = caller_path.active[0]

        # move port from argument to return register
        port_n_reg = ordered_agument_regs[p.arch.name][0]
        ret_reg = return_regs[p.arch.name]
        port_n = getattr(plt_path.active[0].regs, p.arch.register_names[port_n_reg])
        setattr(plt_path.active[0].regs, p.arch.register_names[ret_reg], port_n)

        if port_n.concrete:
            self._last_port = port_n.args[0]

        # now we have to find the ip, we assume the code complies to the
        # form: address.sin_port = htons( PORT );

        # first get the node
        htons_caller_node = cfg.get_any_node(caller_path.active[0].addr)
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

        # restore registers to return from the function call
        lr = p.arch.register_names[link_regs[p.arch.name]]
        ret_addr = getattr(new_state.regs, lr)
        ret_func = getattr(old_state.regs, lr)

        plt_path.active[0].ip = ret_addr
        setattr(plt_path.active[0].regs, lr, ret_func)
        plt_path.active[0].history.jumpkind = "Ijk_FakeRet"

    def run(self, key_string, key_addr, reg_name, core_taint, current_path):
        p = self._p
        cfg = self._cfg
        self._current_key_addr = key_addr
        path_copy = current_path
        addr = current_path.active[0].addr

        next_path = current_path.copy(copy_states=True).step()
        # we jump into the GoT if we have an extern call
        if next_path.active[0].addr in self._p.loader.main_bin.reverse_plt.keys():
            path_copy = next_path.copy(copy_states=True).step()
            addr = path_copy.active[0].addr

        if not are_parameters_in_registers(p):
            print "socket.run: Implement me"
            import ipdb;
            ipdb.set_trace()

        node = cfg.get_any_node(addr)
        block_caller_role_function = current_path.active[0].addr
        par_n = ordered_agument_regs[p.arch.name].index(p.arch.registers[reg_name][0])
        candidate_role = Role.UNKNOWN
        x_ref_fun = cfg.get_any_node(block_caller_role_function)

        if node and node.name and '+' not in node.name:

            ##### setter
            if str(node.name).lower() in M_SET_KEYWORD:
                reg_off = ordered_agument_regs[p.arch.name][1]
                reg_name = p.arch.register_names[reg_off]
                reg_cnt = getattr(path_copy.active[0].regs, reg_name)
                tainted = core_taint.is_tainted(reg_cnt)
                if not tainted:
                    tainted = core_taint.is_tainted(core_taint.safe_load(path_copy, reg_cnt), path=path_copy)

                if tainted:
                    candidate_role = Role.SETTER
                    self._find_binding()

            ##### getter
            # getter are more complicated. We have to understand whether the string is compared against
            # some content retrieved from socket
            elif str(node.name).lower() in CMP_KEYWORD:

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
                    self._stop_run = False
                    self._sink_addrs = [block_caller_role_function]

                    # if the string is passed to a memcmp-like function
                    # we have to make sure that the content is compared against to is retrieved
                    # from socket. We have to find the recv.
                    self._read_from_socket = False
                    if not self._recv_is_close():
                        self._find_recv()

                    if self._read_from_socket:
                        candidate_role = Role.GETTER
                        self._stop_run = False
                        self._find_binding()

            # Role string is passed directly to a getter function
            elif M_GET_KEYWORD in str(node.name).lower():
                self._read_from_socket = True
                # check whether if the string is passed. We have to check both args
                reg_off = ordered_agument_regs[p.arch.name][1]
                reg_name = p.arch.register_names[reg_off]
                reg_cnt = getattr(path_copy.active[0].regs, reg_name)
                tainted = core_taint.is_tainted(reg_cnt)
                if not tainted:
                    tainted = core_taint.is_tainted(core_taint.safe_load(path_copy, reg_cnt), path=path_copy)

                if tainted:
                    # set_env
                    candidate_role = Role.GETTER
                    self._find_binding()

            if candidate_role != Role.UNKNOWN:
                # if the string contains the ":%s", ":5d" and so forth, we remove it
                key_string = key_string.split(":%")[0]

                self._strings.append(key_string)
                self._roles.append(candidate_role)

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
                return True, candidate_role

        return False, Role.UNKNOWN

    @property
    def role_strings_info(self):
        return self._role_strings_info

    def discover_new_binaries(self):
        bins = []
        self._log.debug("Discovering new binaries.. this might take a while.. take a coffee.")
        for role, string in zip(self._roles, self._strings):

            if role == Role.SETTER:
                for binding in self._bindings:
                    # write the port in the xxd tool format
                    if self._p.arch.bits == 32:
                        val = struct.pack('<I', binding[0]).encode('hex')
                    elif self._p.arch.bits == 64:
                        val = struct.pack('<Q', binding[0]).encode('hex')
                    else:
                        print "Unsupported number of bits"
                        import ipdb; ipdb.set_trace()

                    counter = 0
                    to_look_val = ''
                    for v in val:
                        if counter % 4 == 0 and counter > 0:
                            to_look_val += ' '
                        to_look_val += v
                        counter += 1

                    cmd = "for file in `grep -r '" + binding[1] + "' | grep Binary | awk '{print $3}'`; do "
                    cmd += "res=`xxd $file | grep '" + to_look_val + "'`; "
                    cmd += 'if [ -n "$res" ]; then echo $file; fi; done;'
                    o, e = run_command(cmd)
                    candidate_bins = list(set([x for x in o.split('\n') if x]))
                    for b in candidate_bins:
                        if LIB_KEYWORD in b:
                            continue

                        name = b.split('/')[-1]
                        self._log.debug("Adding " + str(name))
                        bins.append(b)

        return list(set(bins))
