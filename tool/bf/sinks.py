from bdg.utils import are_parameters_in_registers, get_string
from taint_analysis.utils import arg_reg_name


def strcpy(p, core_taint, plt_path, *_, **__):
    """
    strcpy function summary

    :param p: angr project
    :param core_taint: core taint engine
    :param plt_path: path to the plt entry
    :return:  None
    """
    plt_state = plt_path.active[0]
    if are_parameters_in_registers(p):
        reg_src = getattr(plt_state.regs, arg_reg_name(p, 1))
        reg_dst = getattr(plt_state.regs, arg_reg_name(p, 0))

        # estimate the size of the two buffers (this may be a bit off due to the arch size
        src = core_taint.safe_load(plt_path, reg_src, estimate_size=True)
        dst = core_taint.safe_load(plt_path, reg_dst, estimate_size=True)
        # we only care if the loaded register is tainted
        tainted = core_taint.is_tainted(src, path=plt_path)

        # we raise alerts also for equal size of src and dst, as the analysis might be under-constrained.
        # at an alert, we will return some of the parameters, so we can check later if it is actually interesting
        if tainted and (src.cardinality - 1) >= (dst.cardinality - 1):
            return True
        return False
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
    # raise an alert when the size is tainted
    plt_state = plt_path.active[0]
    if are_parameters_in_registers(p):
        reg_n = getattr(plt_state.regs, arg_reg_name(p, 2))
        reg_src = getattr(plt_state.regs, arg_reg_name(p, 1))
        reg_dst = getattr(plt_state.regs, arg_reg_name(p, 0))

        src = core_taint.safe_load(plt_path, reg_src, estimate_size=True)
        dst = core_taint.safe_load(plt_path, reg_dst, estimate_size=True)
        n = core_taint.safe_load(plt_path, reg_n, estimate_size=True)

        if core_taint.is_tainted(n, path=plt_path):
            return True
        return False
    else:
        raise Exception("implement me")


# TODO fix the detection of vulnerability for fwrite
def fwrite(p, core_taint, plt_path, *_, **__):
    """
    fwrite function summary

    :param p: angr project
    :param core_taint: core taint engine
    :param plt_path: path to the plt entry
    :return: None
    """

    plt_state = plt_path.active[0]
    if are_parameters_in_registers(p):
        reg = getattr(plt_state.regs, arg_reg_name(p, 0))

        if (core_taint.is_tainted(reg, path=plt_path) or
                core_taint.is_tainted(core_taint.safe_load(plt_path, reg), path=plt_path)):
            # TODO think about  when to raise an alert
            return True
        return False
    else:
        raise Exception("implement me")


def sprintf(p, core_taint, plt_path, *_, **__):
    """
    sprintf function summary

    :param p: angr project
    :param core_taint: core taint engine
    :param plt_path: path to the plt entry
    :return: None
    """

    plt_state = plt_path.active[0]
    if are_parameters_in_registers(p):
        dst = getattr(plt_state.regs, arg_reg_name(p, 0))
        dst_loaded = core_taint.safe_load(plt_path, dst, estimate_size=True)
        frmt_str = getattr(plt_state.regs, arg_reg_name(p, 1))
        str_val = get_string(p, frmt_str.args[0], extended=True)
        n_vargs = str_val.count('%s')
        taint = False
        total_size = len(str_val) - (n_vargs*2)
        for i in range(2, 2 + n_vargs):
            reg = getattr(plt_state.regs, arg_reg_name(p, i))
            reg_loaded = core_taint.safe_load(plt_path, reg, estimate_size=True)
            if core_taint.is_tainted(reg, path=plt_path) or core_taint.is_tainted(reg_loaded, path=plt_path):
                taint = True
            total_size += reg_loaded.length
        return taint and dst_loaded.length <= total_size
    else:
        raise Exception("implement me")
