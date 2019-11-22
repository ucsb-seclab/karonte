import archinfo

ordered_argument_regs = {
    'ARMEL': [
        archinfo.ArchARMEL.registers['r0'][0],
        archinfo.ArchARMEL.registers['r1'][0],
        archinfo.ArchARMEL.registers['r2'][0],
        archinfo.ArchARMEL.registers['r3'][0],
        archinfo.ArchARMEL.registers['r4'][0],
        archinfo.ArchARMEL.registers['r5'][0],
        archinfo.ArchARMEL.registers['r6'][0],
        archinfo.ArchARMEL.registers['r7'][0],
        archinfo.ArchARMEL.registers['r8'][0],
        archinfo.ArchARMEL.registers['r9'][0],
        archinfo.ArchARMEL.registers['r10'][0],
        archinfo.ArchARMEL.registers['r11'][0],
        archinfo.ArchARMEL.registers['r12'][0]
    ],
    'AARCH64': [
        archinfo.ArchAArch64.registers['x0'][0],
        archinfo.ArchAArch64.registers['x1'][0],
        archinfo.ArchAArch64.registers['x2'][0],
        archinfo.ArchAArch64.registers['x3'][0],
        archinfo.ArchAArch64.registers['x4'][0],
        archinfo.ArchAArch64.registers['x5'][0],
        archinfo.ArchAArch64.registers['x6'][0],
        archinfo.ArchAArch64.registers['x7'][0],
    ],
    'MIPS32': [
        archinfo.ArchMIPS32.registers['a0'][0],
        archinfo.ArchMIPS32.registers['a1'][0],
        archinfo.ArchMIPS32.registers['a2'][0],
        archinfo.ArchMIPS32.registers['a3'][0],
    ],
}


return_regs = {
    'ARMEL': archinfo.ArchARMEL.registers['r0'][0],
    'AARCH64': archinfo.ArchAArch64.registers['x0'][0],
    'MIPS32': archinfo.ArchMIPS32.registers['v0'][0]
}

link_regs = {
    'ARMEL': archinfo.ArchARMEL.registers['lr'][0],
    'AARCH64': archinfo.ArchAArch64.registers['x30'][0],
    'MIPS32': archinfo.ArchMIPS32.registers['ra'][0]
}


def arg_reg_name(p, n):
    """
    Return the name of a register

    :param p: angr project
    :param n: register offset
    :return: register name
    """

    return p.arch.register_names[ordered_argument_regs[p.arch.name][n]]


# FIXME: so far we only consider arguments passed through registers
def get_ord_arguments_call(p, b_addr):
    """
    Retrieves the list of instructions setting arguments for a function call. It checks the arguments in order
    so to infer the arity of the function:
    Example: if the first argument (e.g., r0 in ARM) is not set, it assumes the arity's function is 0.

    :param p: angr project
    :param b_addr: basic block address
    :return: the arguments of a function call
    """

    set_params = []
    b = p.factory.block(b_addr)
    for reg_off in ordered_argument_regs[p.arch.name]:
        put_stmts = [s for s in b.vex.statements if s.tag == 'Ist_Put' and s.offset == reg_off]
        if not put_stmts:
            break

        # if more than a write, only consider the last one
        # eg r0 = 5
        # ....
        # r0 = 10
        # BL foo
        put_stmt = put_stmts[-1]
        set_params.append(put_stmt)

    return set_params


def get_any_arguments_call(p, b_addr):
    """
    Retrieves the list of instructions setting arguments for a function call.

    :param p: angr project
    :param b_addr: basic block address
    :return: instructions setting arguments
    """

    set_params = []
    b = p.factory.block(b_addr)
    put_stmts = [s for s in b.vex.statements if s.tag == 'Ist_Put']
    for stmt in put_stmts:
        if stmt.offset in ordered_argument_regs[p.arch.name]:
            set_params.append(stmt)

    return set_params


def get_arity(p, b_addr):
    """
    Retrieves the arity by inspecting a funciton call

    :param p: angr project
    :param b_addr: basic block address
    :return: arity of the function
    """

    return len(get_ord_arguments_call(p, b_addr))
