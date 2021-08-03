"""
Though karonte relies on angr's sim procedures, sometimes these add in the current state some constraints to make the
used analysis faster. For example, if a malloc has an unconstrained size, angr add the constraint
size == angr-defined.MAX_SIZE. Though this makes the analysis faster, it makes impossible to reason about the maximum
buffer sizes (as needed by karonte).

In this module we wrap sim procedures to avoid them to add such constraints.

Note however, that the semantic of an expression might get lost.
Eg. strlen(taint_x) = taint_y, taint_y is an unconstrained variable
"""

from taint_analysis.coretaint import *


def _get_function_name(addr, p):
    """
    Return a function name

    :param addr: function address
    :param p: angr project
    :return: function name
    """
    return p.loader.find_plt_stub_name(addr)


def source_dummy(*_, **__):
    pass


def memcmp_unsized(_core, _, plt_path):
    """
    memcmp-like unsized (e.g., strlen) function summary

    :param _core: core taint engine
    :param _: not used
    :param plt_path:  path to the plt (i.e., call_site.step())
    :return: None
    """

    p = _core.p

    dst_reg = arg_reg_name(p, 0)
    src_reg = arg_reg_name(p, 1)

    b1 = _core.safe_load(plt_path, getattr(plt_path.active[0].regs, dst_reg))
    b2 = _core.safe_load(plt_path, getattr(plt_path.active[0].regs, src_reg))

    if not _core.is_tainted(b1, plt_path):
        b1 = None
    if not _core.is_tainted(b2, plt_path):
        b2 = None

    # if either of the two is not tainted, we untaint the other
    if b1 is not None and b2 is None:
        _core.do_recursive_untaint(b1, plt_path)
    elif b2 is not None and b1 is None:
        _core.do_recursive_untaint(b2, plt_path)

    # step into it
    plt_path.step()
    assert _core.p.is_hooked(plt_path.active[0].addr), "memcmp_unsized: Summary function relies on angr's " \
                                                       "sim procedure, add option use_sim_procedures to the loader"
    plt_path.step()


def memcmp_sized(_core, _, plt_path):
    """
    memcmp-like sized (e.g., memcmp) function summary

    :param _core: core taint engine
    :param _: not used
    :param plt_path:  path to the plt (i.e., call_site.step())
    :return: None
    """

    p = _core.p

    dst_reg = arg_reg_name(p, 0)
    src_reg = arg_reg_name(p, 1)
    reg_n = arg_reg_name(p, 2)

    b1 = _core.safe_load(plt_path, getattr(plt_path.active[0].regs, dst_reg))
    b2 = _core.safe_load(plt_path, getattr(plt_path.active[0].regs, src_reg))
    n = _core.safe_load(plt_path, getattr(plt_path.active[0].regs, reg_n))

    # we untaint buffers only if n is not tainted
    if not _core.is_tainted(n, plt_path):
        if not _core.is_tainted(b1, plt_path):
            b1 = None
        if not _core.is_tainted(b2, plt_path):
            b2 = None

        # if either of the two is not tainted, we untaint the other
        if b1 is not None and b2 is None:
            _core.do_recursive_untaint(b1, plt_path)
        elif b2 is not None and b1 is None:
            _core.do_recursive_untaint(b2, plt_path)

    # step into it
    plt_path.step()
    assert _core.p.is_hooked(plt_path.active[0].addr), "memcmp_sized: Summary function relies on angr's " \
                                                       "sim procedure, add option use_sim_procedures to the loader"
    plt_path.step()


def memcpy_sized(_core, call_site_path, plt_path):
    """
    memcpy-like sized (e.g., memcpy) function summary

    :param _core: core taint engine
    :param call_site_path: call site angr path
    :param plt_path:  path to the plt (i.e., call_site.step())
    :return: None
    """

    p = _core.p

    # if the second parameter is tainted (or pointing to a tainted location)
    # or the third is tainted, we taint the first too
    dst_reg = arg_reg_name(p, 0)
    dst = getattr(plt_path.active[0].regs, dst_reg)
    dst_loaded = _core.safe_load(plt_path, dst)

    src_reg = arg_reg_name(p, 1)
    src = getattr(plt_path.active[0].regs, src_reg)
    src_loaded = _core.safe_load(plt_path, src)

    reg_n = arg_reg_name(p, 2)
    n = getattr(plt_path.active[0].regs, reg_n)
    # n_loaded = _core.safe_load(plt_path_cp, size)

    plt_path.step()
    assert _core.p.is_hooked(plt_path.active[0].addr), "memcpy_sized: Summary function relies on angr's " \
                                                       "sim procedure, add option use_sim_procedures to the loader"
    plt_path.step()

    if not plt_path.active:
        raise Exception("size of function has no active successors, not walking this path...")

    # apply taint to dst if source is tainted and constrain this buffer
    # TODO take N into account
    if _core.is_tainted(src_loaded, path=plt_path):
        src_loaded_full = _core.safe_load(plt_path, src, estimate_size=True)
        new_dst_t = _core.get_sym_val(name=_core.taint_buf, bits=src_loaded_full.length).reversed
        _core.add_taint_glob_dep(new_dst_t, src_loaded_full, plt_path)
        plt_path.active[0].add_constraints(src_loaded_full == new_dst_t)
        plt_path.active[0].memory.store(dst, new_dst_t)

    # untaint if the size is constrained
    if (_core.is_tainted(dst, path=plt_path) or
            _core.is_tainted(dst_loaded, path=plt_path)) and \
            not _core.is_tainted(n, path=plt_path):
        # do untaint
        _core.do_recursive_untaint(dst_loaded, plt_path)


def memcpy_unsized(_core, call_site_path, plt_path):
    """
    memcpy-like unsize (e.g., strcpy) function summary

    :param _core: core taint engine
    :param call_site_path: call site angr path
    :param plt_path:  path to the plt (i.e., call_site.step())
    :return: None
    """
    p = _core.p

    dst_reg = arg_reg_name(p, 0)
    dst = getattr(plt_path.active[0].regs, dst_reg)
    # dst_loaded = _core.safe_load(plt_path_cp, dst, estimate_size=True)

    src_reg = arg_reg_name(p, 1)
    src = getattr(plt_path.active[0].regs, src_reg)
    src_loaded = _core.safe_load(plt_path, src)

    # run the sim procedure
    plt_path.step()
    assert _core.p.is_hooked(plt_path.active[0].addr), "memcpy_unsized: Summary function relies on angr's " \
                                                       "sim procedure, add option use_sim_procedures to the loader"
    plt_path.step()

    if not plt_path.active:
        raise Exception("size of function has no active successors, not walking this path...")

    # apply taint to dst if source is tainted and constrain this buffer
    if _core.is_tainted(src_loaded, path=plt_path):
        src_loaded_full = _core.safe_load(plt_path, src, estimate_size=True)
        new_dst_t = _core.get_sym_val(name=_core.taint_buf, bits=src_loaded_full.length).reversed
        _core.add_taint_glob_dep(new_dst_t, src_loaded_full, plt_path)
        plt_path.active[0].add_constraints(src_loaded_full == new_dst_t)
        plt_path.active[0].memory.store(dst, new_dst_t)


def is_size_taint(v):
    return '__size__' in str(v)


def sizeof(_core, call_site_path, plt_path):
    """
    sizeof-like (e.g., strlen) function summary

    :param _core: core taint engine
    :param call_site_path: call site angr path
    :param plt_path:  path to the plt (i.e., call_site.step())
    :return: None
    """
    p = _core.p

    n = getattr(plt_path.active[0].regs, arg_reg_name(p, 0))

    cnt = _core.safe_load(plt_path, n, _core.taint_buf_size/8)

    # use the sim procedure to continue to the next state and add constraints
    plt_path.step()
    assert _core.p.is_hooked(plt_path.active[0].addr), "sizeof: Summary function relies on angr's " \
                                                       "sim procedure, add option use_sim_procedures to the loader"
    plt_path.step()
    if not plt_path.active:
        raise Exception("size of function has no active successors, not walking this path...")

    return_value = getattr(plt_path.active[0].regs, ret_reg_name(p))

    # TODO: check if the constraints set by angr sim procedure are correct
    # if there is a tainted buffer in one of the registers then also taint this variable
    if _core.is_tainted(cnt, path=plt_path) or _core.is_tainted(n, path=plt_path):
        t = _core.get_sym_val(name=(_core.taint_buf + '__size__'), bits=p.arch.bits).reversed
        _core.add_taint_glob_dep(t, cnt, plt_path)
        # constrain output of this variable equal to the output of sizeof and add it to the return register
        plt_path.active[0].add_constraints(return_value == t)
        setattr(plt_path.active[0].regs, ret_reg_name(p), t)


#
# Heap functions
#
def _malloc(_core, _, plt_path):
    """
    maclloc function summary

    :param _core: core taint engine
    :param plt_path: path to the plt (i.e., call_site.step())
    :return: None
    """
    p = _core.p

    state = plt_path.active[0]
    sim_size = getattr(state.regs, arg_reg_name(p, 0))

    # when the size is symbolic, choose the maximum size possible
    if state.solver.symbolic(sim_size):
        size = state.solver.max(sim_size)
        if size > state.libc.max_variable_size:
            size = state.libc.max_variable_size
        setattr(state.regs, arg_reg_name(p, 0), size)

    # use the sim procedure
    plt_path.step()
    assert _core.p.is_hooked(plt_path.active[0].addr), "malloc: Summary function relies on angr's " \
                                                       "sim procedure, add option use_sim_procedures to the loader"
    plt_path.step()

    return sim_size


def _realloc(_core, _, plt_path):
    """
    realloc function summary

    :param _core: core taint engine
    :param plt_path: path to the plt (i.e., call_site.step())
    :return: None
    """

    p = _core.p

    state = plt_path.active[0]
    sim_size = getattr(state.regs, arg_reg_name(p, 1))
    # ptr = getattr(state.regs, arg_reg_name(p, 0))

    # when the size is symbolic, choose the maximum size possible
    if state.solver.symbolic(sim_size):
        size = state.solver.max(sim_size)
        if size > state.libc.max_variable_size:
            size = state.libc.max_variable_size
        setattr(state.regs, arg_reg_name(p, 0), size)

    # if the size is not tainted, use the sim procedure
    plt_path.step()
    assert _core.p.is_hooked(plt_path.active[0].addr), "realloc: Summary function relies on angr's " \
                                                       "sim procedure, add option use_sim_procedures to the loader"
    plt_path.step()

    return sim_size


def heap_alloc(_core, call_site_path, plt_path):
    """
    Heap allocation function stub

    :param _core: core taint engine
    :param call_site_path: call site angr path
    :param plt_path: path to the plt (i.e., call_site.step())
    :return: None
    """
    fname = _get_function_name(plt_path.active[0].addr, _core.p)

    sim_size = None
    if fname == 'malloc':
        sim_size = _malloc(_core, call_site_path, plt_path)
    elif fname == 'realloc':
        sim_size = _realloc(_core, call_site_path, plt_path)
    else:
        print(f"Implement this heap alloc: {fname}")

    if sim_size is not None:
        taint_args = [l for l in sim_size.recursive_leaf_asts if _core.is_tainted(l, call_site_path)]
        if taint_args and len(set(taint_args)) == 1:
            arg = taint_args[0]
            if is_size_taint(arg):
                _core.do_recursive_untaint(arg, plt_path)


#
# Env function
#
env_var = {}


def _setenv(_core, _, plt_path):
    """
    setenv function summary

    :param _core: core taint engine
    :param plt_path: path to the plt (i.e., call_site.step())
    :return: None
    """
    global env_var
    p = _core.p

    plt_path_cp = plt_path.copy(deep=True)
    plt_state_cp = plt_path_cp.active[0]

    # add the environment variable to the list of env_variables with this key
    key = getattr(plt_path.active[0].regs, arg_reg_name(p, 0))
    env_var[str(key)] = getattr(plt_path.active[0].regs, arg_reg_name(p, 1))

    # this call can continue with an empty sim procedure since it does nothing
    next_state = plt_state_cp.step()
    _core.p.hook(next_state.addr, ReturnUnconstrained())
    plt_path.step().step()


def _getenv(_core, call_site_addr, plt_path):
    """
    getenv function summary
    :param _core: core taint engine
    :param call_site_addr: call site angr path
    :param plt_path: path to the plt (i.e., call_site.step())
    :return: None
    """

    global env_var
    p = _core.p

    env_var_size = _core.taint_buf_size

    reg = getattr(plt_path.active[0].regs, arg_reg_name(p, 0))
    cnt_mem = _core.safe_load(plt_path, reg)
    key = str(reg)

    # this info is passed by some user controllable source
    if _core.is_tainted(reg, path=plt_path) or _core.is_tainted(cnt_mem, path=plt_path):
        to_store = _core.get_sym_val(name=_core.taint_buf, bits=env_var_size)
    # it was set before
    elif key in env_var:
        to_store = env_var[key]
    # fresh symbolic var
    else:
        to_store = _core.get_sym_val(name="env_var", bits=env_var_size)

    # store the symbolic buffer at the memory address
    addr = plt_path.active[0].heap.allocate(env_var_size)
    plt_path.active[0].memory.store(addr, to_store)

    # use an empty hook as sim procedure to continue with the program
    plt_path_cp = plt_path.copy(deep=True)
    plt_state_cp = plt_path_cp.active[0]
    next_state = plt_state_cp.step()
    _core.p.hook(next_state.addr, ReturnUnconstrained())
    plt_path.step().step()

    # set the return address to the pointer
    setattr(plt_path.active[0].regs, ret_reg_name(p), addr)


def env(_core, call_site_path, plt_path):
    """
    Summarize environment functions (getenv, and setenv)
    :param _core: core taint engin
    :param call_site_path: call site angr path
    :param plt_path: path to the plt (i.e., call_site.step())
    :return:
    """
    fname = _get_function_name(plt_path.active[0].addr, _core.p)
    if fname == 'setenv':
        _setenv(_core, call_site_path, plt_path)
    elif fname == 'getenv':
        _getenv(_core, call_site_path, plt_path)
    else:
        print(f"Implement this Env function: {fname}")
    # return the env_var if tainted to store for bug_finders


#
# Numerical
#
def atoi(_core, _, plt_path):
    p = _core.p

    state = plt_path.active[0]
    val = getattr(state.regs, arg_reg_name(p, 0))
    if _core.is_or_points_to_tainted_data(val, plt_path):
        addr = plt_path.active[0].memory.load(val, p.arch.bytes)
        _core.do_recursive_untaint(addr, plt_path)
    plt_path.step().step()
