from binary_dependency_graph.utils import are_parameters_in_registers, get_string
from taint_analysis.utils import ordered_argument_regs, arg_reg_name


def strcpy(p, core_taint, plt_path, size_con=None):
    """
    strcpy function summary

    :param p: angr project
    :param core_taint: core taint engine
    :param plt_path: path to the plt entry
    :return:  None
    """

    plt_state = plt_path.active[0]
    if are_parameters_in_registers(p):
        name_reg_src = p.arch.register_names[ordered_argument_regs[p.arch.name][1]]
        reg_src = getattr(plt_state.regs, name_reg_src)
        if core_taint.is_tainted(reg_src, path=plt_path):
            return True

        # check the size of the two buffers
        name_reg_dst = p.arch.register_names[ordered_argument_regs[p.arch.name][0]]
        reg_dst = getattr(plt_state.regs, name_reg_dst)

        src = core_taint.safe_load(plt_path, reg_src)
        dst = core_taint.safe_load(plt_path, reg_dst)
        tainted = core_taint.is_tainted(src, path=plt_path)

        # we raise alerts also for equal size of src and dst, as the analysis might be under-constrained.
        return tainted and size_con >= (src.cardinality - 1) >= (dst.cardinality - 1)
    else:
        raise Exception("implement me")


def memcpy(p, core_taint, plt_path, *_, **__):
    """
    memcpy function summary

    :param p: angr project
    :param core_taint: core taint engine
    :param plt_path: path to the plt entry
    :return: None
    """

    plt_state = plt_path.active[0]
    if are_parameters_in_registers(p):
        name = p.arch.register_names[ordered_argument_regs[p.arch.name][2]]
        reg = getattr(plt_state.regs, name)
        return (core_taint.is_tainted(reg, path=plt_path) or
                core_taint.is_tainted(core_taint.safe_load(plt_path, reg), path=plt_path))
    else:
        raise Exception("implement me")


def fwrite(p, core_taint, plt_path,  *_, **__):
    """
    fwrite function summary

    :param p: angr project
    :param core_taint: core taint engine
    :param plt_path: path to the plt entry
    :return: None
    """

    plt_state = plt_path.active[0]
    if are_parameters_in_registers(p):
            name = p.arch.register_names[ordered_argument_regs[p.arch.name][0]]
            reg = getattr(plt_state.regs, name)
            return (core_taint.is_tainted(reg, path=plt_path) or
                    core_taint.is_tainted(core_taint.safe_load(plt_path, reg), path=plt_path))
    else:
        raise Exception("implement me")


def sprintf(p, core_taint, plt_path,  *_, **__):
    """
    sprintf function summary

    :param p: angr project
    :param core_taint: core taint engine
    :param plt_path: path to the plt entry
    :return: None
    """

    plt_state = plt_path.active[0]
    if are_parameters_in_registers(p):
            frmt_str = getattr(plt_state.regs, arg_reg_name(p, 1))
            str_val = get_string(p, frmt_str.args[0], extended=True)
            n_vargs = str_val.count('%s')
            for i in range(2, 2 + n_vargs):
                name = p.arch.register_names[ordered_argument_regs[p.arch.name][i]]
                reg = getattr(plt_state.regs, name)
                if (core_taint.is_tainted(reg, path=plt_path) or
                    core_taint.is_tainted(core_taint.safe_load(plt_path, reg), path=plt_path)):
                    return True
            return False
    else:
        raise Exception("implement me")
