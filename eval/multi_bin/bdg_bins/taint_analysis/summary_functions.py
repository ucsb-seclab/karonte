"""
Though Karonte relies on angr's simprocedures, sometimes these add in the current state some contraints to make the
used analysis faster. For example, if a malloc has an unconstraint size, angr add the constraint
size == angr-defined.MAX_SIZE. Though this makes the analysis faster, it makes impossible to reason about the maximum
buffer sizes (as needed by karonte).

In this module we wrap simprocedures to avoid them to add such constraints.

Note however, that the semantic of an expression might get lost.
Eg. strlen(taint_x) = taint_y, taint_y is an unconstrained variable
"""

from coretaint import *
import angr
import claripy

simplify_memcpy = False


def _get_function_name(addr, p):
    if addr in p.loader.main_object.reverse_plt:
        return p.loader.main_object.reverse_plt[addr]
    return None


def _restore_caller_regs(_core, old_path, new_path):
    p = _core.p
    new_state = new_path.active[0]
    old_state = old_path.active[0]

    lr = p.arch.register_names[link_regs[p.arch.name]]

    ret_addr = getattr(new_state.regs, lr)
    ret_func = getattr(old_state.regs, lr)

    new_path.active[0].ip = ret_addr
    setattr(new_path.active[0].regs, lr, ret_func)
    new_path.active[0].history.jumpkind = "Ijk_FakeRet"


def source_dummy(_core, old_path, new_path):
    pass


def memcmp_unsized(_core, call_site_path, plt_path):
    p = _core.p
    plt_path_cp = plt_path.copy(copy_states=True)

    dst_reg = arg_reg_name(p, 0)
    src_reg = arg_reg_name(p, 1)

    b1 = _core.safe_load(plt_path_cp, getattr(plt_path_cp.active[0].regs, dst_reg))
    b2 = _core.safe_load(plt_path_cp, getattr(plt_path_cp.active[0].regs, src_reg))

    if not _core.is_tainted(b1, plt_path_cp):
        b1 = None
    if not _core.is_tainted(b2, plt_path_cp):
        b2 = None

    # if either of the two is not tainted, we untaint the other
    if b1 is not None and b2 is None:
        _core.do_recursive_untaint(b1, plt_path)
    elif b2 is not None and b1 is None:
        _core.do_recursive_untaint(b2, plt_path)

    # step into it
    plt_path_cp.step()
    assert _core.p.is_hooked(plt_path_cp.active[0].addr), "memcmp_unsized: Summary function relies on angr's sim procedure, " \
                                                          "add option use_sim_procedures to the loader"
    plt_path.step().step()


def memcmp_sized(_core, call_site_path, plt_path):
    p = _core.p
    plt_path_cp = plt_path.copy(copy_states=True)

    dst_reg = arg_reg_name(p, 0)
    src_reg = arg_reg_name(p, 1)
    reg_n = arg_reg_name(p, 2)

    b1 = _core.safe_load(plt_path_cp, getattr(plt_path_cp.active[0].regs, dst_reg))
    b2 = _core.safe_load(plt_path_cp, getattr(plt_path_cp.active[0].regs, src_reg))
    n = _core.safe_load(plt_path_cp, getattr(plt_path_cp.active[0].regs, reg_n))

    # we untaint buffers only if n is not tainted
    if not _core.is_tainted(n, plt_path_cp):
        if not _core.is_tainted(b1, plt_path_cp):
            b1 = None
        if not _core.is_tainted(b2, plt_path_cp):
            b2 = None

        # if either of the two is not tainted, we untaint the other
        if b1 is not None and b2 is None:
            _core.do_recursive_untaint(b1, plt_path)
        elif b2 is not None and b1 is None:
            _core.do_recursive_untaint(b2, plt_path)

    # step into it
    plt_path_cp.step()
    assert _core.p.is_hooked(plt_path_cp.active[0].addr), "memcmp_sized: Summary function relies on angr's sim procedure, " \
                                                          "add option use_sim_procedures to the loader"
    plt_path.step().step()


def memcpy_sized(_core, call_site_path, plt_path):
    p = _core.p

    plt_path_cp = plt_path.copy(copy_states=True)

    # if the second parameter is tainted (or pointing to a tainted location)
    # or the third is tainted, we taint the first too
    plt_state_cp = plt_path_cp.active[0]

    dst_reg = arg_reg_name(p, 0)
    src_reg = arg_reg_name(p, 1)
    reg_n = arg_reg_name(p, 2)

    size = getattr(plt_state_cp.regs, reg_n)
    src = getattr(plt_state_cp.regs, src_reg)
    dst = getattr(plt_state_cp.regs, dst_reg)

    if simplify_memcpy and plt_state_cp.se.max_int(size) >= plt_state_cp.libc.max_memcpy_size:
        # we propagate th taint only if the src is tainted as well as the size, if not the dst
        # is untainted
        if (_core.is_tainted(src, path=plt_path_cp) or _core.is_tainted(_core.safe_load(plt_path_cp, src), path=plt_path_cp)) and \
                        _core.is_tainted(size, path=plt_path_cp):
            t = _core.get_sym_val(name=_core.taint_buf, bits=_core.taint_buf_size).reversed
        else:
            t = _core.get_sym_val(name="memcpy_unc_buff", bits=plt_state_cp.libc.max_memcpy_size).reversed

        plt_path.active[0].memory.store(getattr(plt_path.active[0].regs, dst_reg), t)

        # restore the register values to return the call
        _restore_caller_regs(_core, call_site_path, plt_path)

    else:
        plt_path_cp.step()
        assert _core.p.is_hooked(plt_path_cp.active[0].addr), "memcpy_sized: Summary function relies on angr's sim procedure, " \
                                                              "add option use_sim_procedures to the loader"
        plt_path.step().step()
        if not plt_path.active:
            raise Exception("size of function has no active successors, not walking this path...")

        # untaint if the size is constrained
        if (_core.is_tainted(dst, path=plt_path_cp) or _core.is_tainted(_core.safe_load(plt_path_cp, dst), path=plt_path_cp)) and \
                        not _core.is_tainted(size, path=plt_path_cp):
            # do untaint
            _core.do_recursive_untaint(dst, plt_path)


def memcpy_unsized(_core, call_site_path, plt_path):
    p = _core.p

    # FIXME do taint untaint!
    plt_path_cp = plt_path.copy(copy_states=True)
    plt_state_cp = plt_path_cp.active[0]

    src = getattr(plt_state_cp.regs, arg_reg_name(p, 1))
    dst = getattr(plt_state_cp.regs, arg_reg_name(p, 0))

    if _core.is_tainted(src, path=plt_path_cp) or _core.is_tainted(_core.safe_load(plt_path_cp, src), path=plt_path_cp):
        # FIXME: make the actual copy so that taint dependency will be respected
        t = _core.get_sym_val(name=_core.taint_buf, bits=_core.taint_buf_size).reversed
    else:
        plt_path_cp.step()
        assert _core.p.is_hooked(plt_path_cp.active[0].addr), "memcpy_unsized: Summary function relies on angr's sim procedure, " \
                                                              "add option use_sim_procedures to the loader"
        plt_path.step().step()
        if not plt_path.active:
            raise Exception("size of function has no active successors, not walking this path...")
        return

    dst = getattr(plt_path.active[0].regs, arg_reg_name(p, 0))
    plt_path.active[0].memory.store(dst, t)

    # restore the register values to return the call
    _restore_caller_regs(_core, call_site_path, plt_path)


def sizeof(_core, call_site_path, plt_path):
    p = _core.p
    plt_path_cp = plt_path.copy(copy_states=True)
    plt_state_cp = plt_path_cp.active[0]

    n = getattr(plt_state_cp.regs, arg_reg_name(p, 0))

    cnt = _core.safe_load(plt_path_cp, n, _core.taint_buf_size/8)
    # if parameter is tainted (or pointing to a tainted location)
    if _core.is_tainted(n, path=plt_path_cp) or _core.is_tainted(cnt, path=plt_path_cp):
        t = _core.get_sym_val(name=_core.taint_buf, bits=_core.p.arch.bits).reversed
        _core.add_taint_glob_dep(t, cnt, plt_path)
        setattr(plt_path.active[0].regs, arg_reg_name(p, 0), t)

    # not tainted, but symbolic and huge
    elif cnt.symbolic:
        # check whether it has a limited size
        for i in xrange(0, plt_state_cp.libc.max_str_len):
            cnt_i = _core.safe_load(plt_path_cp, n + i, 1)
            vals = plt_state_cp.se.eval_upto(cnt_i, 2)
            if len(vals) == 1 and vals[0] == 0:
                t = claripy.BVV(i, _core.p.arch.bits)
                break
        else:
            # ok, uncontrain it
            t = _core.get_sym_val(name="ret_sizeof_kind", bits=_core.p.arch.bits)
        setattr(plt_path.active[0].regs, arg_reg_name(p, 0), t)

    # we use simprocedure for all the other cases
    else:
        plt_path_cp.step()
        assert _core.p.is_hooked(plt_path_cp.active[0].addr), "sizeof: Summary function relies on angr's sim procedure, " \
                                                              "add option use_sim_procedures to the loader"
        plt_path.step().step()
        if not plt_path.active:
            raise Exception("size of function has no active successors, not walking this path...")
        return

    # restore the register values to return the call
    _restore_caller_regs(_core, call_site_path, plt_path)

#
# Heap functions
#


def _malloc(_core, call_site_path, plt_path):
    p = _core.p

    state = plt_path.active[0]
    sim_size = getattr(state.regs, arg_reg_name(p, 0))

    if state.se.symbolic(sim_size):
        size = state.se.max_int(sim_size)
        if size > state.libc.max_variable_size:
            size = state.libc.max_variable_size
    else:
        size = state.se.eval(sim_size)

    addr = state.libc.heap_location
    state.libc.heap_location += size
    setattr(state.regs, arg_reg_name(p, 0), addr)


def _realloc(_core, call_site_path, plt_path):
    p = _core.p

    state = plt_path.active[0]
    sim_size = getattr(state.regs, arg_reg_name(p, 1))
    ptr = getattr(state.regs, arg_reg_name(p, 0))

    if state.se.symbolic(sim_size):
        size = state.se.max_int(sim_size)
        if size > state.libc.max_variable_size:
            size = state.libc.max_variable_size
    else:
        size = state.se.eval(sim_size)

    addr = state.libc.heap_location
    v = state.memory.load(ptr, size)
    state.memory.store(addr, v)
    state.libc.heap_location += size
    setattr(state.regs, arg_reg_name(p, 0), addr)


def heap_alloc(_core, call_site_path, plt_path):
    fname = _get_function_name(plt_path.active[0].addr, _core._p)

    # step over the plt
    plt_path.step()

    if fname == 'malloc':
        _malloc(_core, call_site_path, plt_path)
    elif fname == 'realloc':
        _realloc(_core, call_site_path, plt_path)
    else:
        print "Implement this heap alloc: " + fname

    _restore_caller_regs(_core, call_site_path, plt_path)


#
# Env function
#
env_var = {}


def _setenv(_core, call_site_path, plt_path):
    global env_var
    p = _core.p

    plt_path_cp = plt_path.copy(copy_states=True)
    plt_state_cp = plt_path_cp.active[0]

    key = getattr(plt_state_cp.regs, arg_reg_name(p, 0))
    env_var[str(key)] = getattr(plt_state_cp.regs, arg_reg_name(p, 1))


def _getenv(_core, call_site_addr, plt_path):
    global env_var
    p = _core.p

    env_var_size = _core.taint_buf_size
    plt_path_cp = plt_path.copy(copy_states=True)
    plt_state_cp = plt_path_cp.active[0]

    reg = getattr(plt_state_cp.regs, arg_reg_name(p, 0))
    cnt_mem = _core.safe_load(plt_path_cp, reg)
    key = str(reg)

    # this info is passed by some user controllable source
    if _core.is_tainted(reg, path=plt_path_cp) or _core.is_tainted(cnt_mem, path=plt_path_cp):
        to_store = _core.get_sym_val(name=_core.taint_buf, bits=env_var_size)
    # it was set before
    elif key in env_var:
        to_store = env_var[key]
    # fresh symbolic var
    else:
        to_store = _core.get_sym_val(name="env_var", bits=env_var_size)

    setattr(plt_path.active[0].regs, arg_reg_name(p, 0), claripy.BVV(env_var_size, _core.p.arch.bits))
    _malloc(_core, call_site_addr, plt_path)
    addr = getattr(plt_path.active[0].regs, arg_reg_name(p, 0))
    plt_path.active[0].memory.store(addr, to_store)


def env(_core, call_site_path, plt_path):

    fname = _get_function_name(plt_path.active[0].addr, _core._p)
    if fname == 'setenv':
        _setenv(_core, call_site_path, plt_path)
    elif fname == 'getenv':
        _getenv(_core, call_site_path, plt_path)
    else:
        print "Implement this Env function: " + fname

    _restore_caller_regs(_core, call_site_path, plt_path)
