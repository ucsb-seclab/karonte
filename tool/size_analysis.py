from binary_dependency_graph.bdp_enum import Role, RoleInfo
from taint_analysis.utils import *
from binary_dependency_graph.utils import *
from taint_analysis.coretaint import TimeOutException

import simuvex
import logging

# FIXME: moved someplace in common with cpfs
MAX_BUF_SIZE = 2 ** 32 - 1

# heap functions and parameters to consider for the buffer size
HEAP_FUNCS = (("malloc", (0,)), ("calloc", (0, 1)), ("realloc", (1,)))
BIG_SIZE = 2 ** 16
DANGER_RANGE = (BIG_SIZE, MAX_BUF_SIZE)
DEF_ROLE_ARITY = 2

logging.basicConfig()
log = logging.getLogger("SizeAnalysis")
log.setLevel("DEBUG")


class SizeAnalysis:
    """
        Perform a size analysis to find, and then propagate the constraints of the buffer user by setter binaries
        to propagate data to getter binaries.
    """

    def __init__(self, bdg_node, logger_obj=None):
        """
        Initialization function.

        :param bdg_node: bdg node
        :param logger_obj: logger obj
        """

        global log
        if logger_obj:
            log = logger_obj

        self._p = None
        self._cpf = None
        self._current_seed_addr = None
        self._current_info = None
        self._result_size = None
        self._allocated_buffers = {}
        self._ct = None
        self._max_size = 0
        self._f_arg_vals = []
        self._set_f_vals = True
        self._current_f_addr = None
        self.run(bdg_node)

    def _call_to_ext_function(self, addr):
        """
        Checks whether the execution is about to jump in an extern function

        :param addr: current address
        :return: True if the execution is about to jump in an extern function, False otherwise
        """

        return addr in self._p.loader.main_object.reverse_plt

    def _returned_from_ext_call(self, state, addr):
        """
        Checks whether the execution returned from an extern function

        :param state: current program state
        :param addr: current address
        :return: True if the execution just returned from an extern call, False otherwise
        """

        p = self._p
        bbl_addrs = [x for x in state.history.bbl_addrs]
        if not bbl_addrs:
            return False

        return bbl_addrs[-1] in p.loader.main_object.reverse_plt and addr not in p.loader.main_object.reverse_plt

    def _function_is_heap_alloc(self, state):
        """
        Checks whether a function is a heap-allocator-type function

        :param state: current program state
        :return: the function information if the function is a heap-allocator-type function, None otherwise
        """

        def is_heap_function(name_func):
            fun = [n for n in HEAP_FUNCS if n[0] in name_func.lower()]
            if fun:
                return fun[0]
            return None

        p = self._p
        bbl_addrs = [x for x in state.history.bbl_addrs]

        for addr in reversed(bbl_addrs):
            # look for the plt call to infer the name of the function called
            if addr not in p.loader.main_object.reverse_plt:
                continue

            ext_func_name = p.loader.main_object.reverse_plt[addr]
            return is_heap_function(ext_func_name)

    def _save_call_pars(self, state, addr):
        """
        Saves the parameters of a function call

        :param state: program state
        :param addr: address of the called function
        :return:
        """

        p = self._p

        self._last_ext_pars = []
        nargs = len(get_ord_arguments_call(p, addr))
        for i in xrange(0, nargs):
            if are_parameters_in_registers(p):
                reg = p.arch.register_names[ordered_argument_regs[p.arch.name][i]]
                val = getattr(state.regs, reg)
                self._last_ext_pars.append(val)

    def _do_record_heap_alloc(self, state, addr):
        """
        Records the allocated bytes in the heap

        :param state: program state
        :param addr: address of the called function
        :return:
        """

        p = self._p
        func = self._function_is_heap_alloc(state)
        if not func:
            return

        # arch uses registers to pass arguments around
        if are_parameters_in_registers(p):
            # then we get the address pointing to the allocated memory region
            ret_reg = p.arch.register_names[return_regs[p.arch.name]]

            # get the return value
            allocated_buf_addr = getattr(state.regs, ret_reg)
            allocated_buf_addr = allocated_buf_addr.args[0]
            pars = func[1]
            size = None

            for par in pars:
                if not size:
                    size = state.se.max_int(self._last_ext_pars[par])
                else:
                    size *= state.se.max_int(self._last_ext_pars[par])

            if size > MAX_BUF_SIZE:
                size = MAX_BUF_SIZE
            self._allocated_buffers[allocated_buf_addr] = (addr, size)
        else:
            raise Exception("_do_record_alloc: Implement me..")

    def _check_and_record_heap_alloc(self, current_path):
        """
        Checks whether the program is about to enter in a heap-allocation-type function, and if so, records
        the allocated size.

        :param current_path: current path
        :return:
        """
        p = self._p
        current_state = current_path.active[0].copy()
        current_addr = current_state.addr

        next_path = current_path.copy(copy_states=True).step()
        try:
            next_state = next_path.active[0]
        except:
            assert not next_path.pruned
            return

        next_addr = next_state.addr

        # skip blocks outside the scope of the considered binary
        if p.loader.find_object_containing(current_addr) != p.loader.main_object:
            return

        # we're about to execute an extern call
        # save the parameters, they can be useful when returning
        if self._call_to_ext_function(next_addr):
            self._save_call_pars(next_state, current_addr)

        # we just got back from an extern call
        # if it was a heap allocation function, save the allocated size.
        try:
            if self._returned_from_ext_call(current_state, current_addr) and \
                    self._function_is_heap_alloc(current_state):
                self._do_record_heap_alloc(current_state, current_addr)
        except:
            return

    def _get_heap_buffer_size(self, addr):
        """
        Given the address of a heap buffer, returns its allocation size
        :param addr: buffer's address
        :return:
        """

        candidate = None
        min_diff = 0

        if hasattr(addr, 'args') and type(addr.args[0]) in (int, long):
            addr = addr.args[0]

        if hasattr(addr, 'symbolic') and addr.symbolic:
            log.error("_get_buffer_size: Buffer address is symbolic, implement me.")
            return MAX_BUF_SIZE

        for buf_addr in self._allocated_buffers.keys():
            if buf_addr > addr:
                continue

            if not candidate or (addr - buf_addr) < min_diff:
                min_diff = addr - buf_addr
                candidate = buf_addr

        assert candidate, "_get_buffer_size: Candidate for heap size was None, check me"
        return self._allocated_buffers[candidate][1]

    def _get_allocated_size_bb_heap_buffer(self, current_path):
        """
        Find the allocated size of a heap buffer accessed within a basic block

        :param current_path: angr current path
        :return: the size of the used buffer
        """

        info = self._current_info
        addr = current_path.active[0].addr
        next_path = current_path.copy(copy_states=True).step()
        try:
            state = next_path.active[0]
        except:
            print "Something went wrong, check me"
            return None

        block = self._p.factory.block(addr)
        stmt = block.vex.statements[info[RoleInfo.ROLE_INS_IDX]]

        if info[RoleInfo.ROLE] == Role.SETTER and hasattr(stmt.addr, 'tmp'):
            addr_tmp = stmt.addr.tmp
            buf_addr = state.scratch.temps[addr_tmp].args[0]
        else:
            log.error("Implement me")
            return MAX_BUF_SIZE

        return self._get_heap_buffer_size(buf_addr)

    @staticmethod
    def is_suspiciously_big(n):
        return DANGER_RANGE[0] <= n <= DANGER_RANGE[1]

    def _get_function_summaries(self):
        """
        Set and returns a dictionary of function summaries
        :return: function summaries
        """

        p = self._p

        mem_cpy_summ = get_memcpy_like(p)
        size_of_summ = get_sizeof_like(p)
        heap_alloc_summ = get_heap_alloc(p)
        env_summ = get_env(p)
        memcmp_like_unsized = get_memcmp_like_unsized(p)
        memcmp_like_sized = get_memcmp_like_sized(p)

        summaries = mem_cpy_summ
        summaries.update(size_of_summ)
        summaries.update(heap_alloc_summ)
        summaries.update(env_summ)
        summaries.update(memcmp_like_unsized)
        summaries.update(memcmp_like_sized)
        return summaries

    def _get_initial_state(self, key_addr, f_addr):
        """
        Sets and returns the initial state of the analysis

        :param key_addr: data key address
        :param f_addr: entry point
        :return: the state
        """

        p = self._p
        ct = self._ct

        s = p.factory.blank_state(
            remove_options={
                simuvex.o.LAZY_SOLVES
            }
        )

        # taint the string
        size = max(len(get_string(p, key_addr)), 1)
        t = ct.get_sym_val(name=ct.taint_buf, bits=(size * 8))

        # we taint the ussed keyword to trace its use
        s.memory.store(key_addr, t)

        lr = p.arch.register_names[link_regs[p.arch.name]]
        setattr(s.regs, lr, self._ct.bogus_return)

        s.ip = f_addr
        return s

    def _run_cpf(self, current_path, *_, **__):
        """
        Run CPFs

        :param current_path: angr current path
        :return: Role and information about the role
        """

        self._check_and_record_heap_alloc(current_path)
        key_string = self._current_info[RoleInfo.DATAKEY]
        seed_addr = self._current_seed_addr

        if not self._f_arg_vals and self._set_f_vals:
            self._set_f_vals = False
            arity = max(get_arity(self._p, self._current_f_addr), DEF_ROLE_ARITY)
            for narg in xrange(arity):
                dst_reg = ordered_argument_regs[self._p.arch.name][narg]
                dst_cnt = getattr(current_path.active[0].regs, self._p.arch.register_names[dst_reg])
                self._f_arg_vals.append(dst_cnt)

        assert are_parameters_in_registers(self._p)

        # name of the register pointing to the key string
        par_n = self._current_info[RoleInfo.PAR_N]
        par_name = self._p.arch.register_names[ordered_argument_regs[self._p.arch.name][par_n]]
        res, info = self._cpf.run(key_string, seed_addr, par_name, self._ct, current_path, self._f_arg_vals)
        if res:
            self._result_size = self._get_allocated_size_bb_heap_buffer(current_path)
            self._ct.stop_run()

        return res, info

    def _size_analysis(self, p, seed_addr, info):
            """
            Infer the size of information exchanged between the consider binary and its parents (or children)

            :param p: angr's project
            :param seed_addr: address of the string used to infer the binary's role
            :param info: node info
            :return: size of the exchanged information
            """

            self._p = p
            self._current_seed_addr = seed_addr
            self._current_f_addr = info[RoleInfo.X_REF_FUN]
            self._current_info = info
            self._result_size = None
            self._f_arg_vals = []
            self._set_f_vals = True

            # prepare the under-contrainted-based initial state
            # we do not allow untaint as we want just to see the size of the buffer
            self._ct = coretaint.CoreTaint(p, interfunction_level=1, smart_call=True,
                                           follow_unsat=True, white_calls=(info[RoleInfo.ROLE_FUN],),
                                           try_thumb=True,
                                           exit_on_decode_error=True, force_paths=True,
                                           taint_returns_unfollowed_calls=True, allow_untaint=False,
                                           logger_obj=log)

            summarized_f = self._get_function_summaries()
            s = self._get_initial_state(seed_addr, info[RoleInfo.X_REF_FUN])

            self._ct.set_alarm(TIMEOUT_TAINT, n_tries=TIMEOUT_TRIES)

            try:
                self._ct.run(s, (), (), summarized_f=summarized_f, force_thumb=False, check_func=self._run_cpf,
                             init_bss=False)
            except TimeOutException:
                log.warning("Hard timeout triggered")

            self._ct.unset_alarm()

    def run(self, bdg_node):
        max_size = 0
        self._max_size = 0
        p = bdg_node.p

        for cpf in bdg_node.cpfs:
            self._cpf = cpf
            for s_addr, s_refs_info in cpf.role_info.items():
                get_out = False
                for info in s_refs_info:
                    # we were not able to identify the type of buffer used to communicate,
                    # assuming max size
                    if not info[RoleInfo.COMM_BUFF]:
                        max_size = MAX_BUF_SIZE
                    else:
                        self._current_info = info
                        self._size_analysis(p, s_addr, info)
                        max_size = max_size if max_size > self._result_size else self._result_size

                    # trick to speed the analysis up
                    if SizeAnalysis.is_suspiciously_big(max_size):
                        get_out = True
                        break
                if get_out:
                    break

            self._max_size = max_size if max_size > self._max_size else self._max_size

    @property
    def result(self):
        return self._max_size
