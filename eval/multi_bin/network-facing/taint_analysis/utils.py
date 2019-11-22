import archinfo

ordered_agument_regs = {
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


return_regs ={
    'ARMEL': archinfo.ArchARMEL.registers['r0'][0],
    'AARCH64': archinfo.ArchAArch64.registers['x0'][0],
    'MIPS32': archinfo.ArchMIPS32.registers['v0'][0]
}

link_regs ={
    'ARMEL': archinfo.ArchARMEL.registers['lr'][0],
    'AARCH64': archinfo.ArchAArch64.registers['x30'][0],
    'MIPS32': archinfo.ArchMIPS32.registers['ra'][0]
}


def arg_reg_name(p, n):
    return p.arch.register_names[ordered_agument_regs[p.arch.name][n]]


def get_ord_arguments_call(p, b_addr):
    """
        Retrieves the list of instructions setting arguments for a function call. It checks the arguments in order
        so to infer the artity of the function:
        Example: if the first argument (e.g., r0 in ARM) is not set, it assumes the arity's function is 0.

        :param b: basic block address
        :return:
        """

    return get_ord_arguments_call_caller(p, b_addr)


# FIXME: so far we only consider arguments passed through registers
def get_ord_arguments_call_caller(p, b_addr):
    """
        Retrieves the list of instructions setting arguments for a function call. It checks the arguments in order
        so to infer the artity of the function:
        Example: if the first argument (e.g., r0 in ARM) is not set, it assumes the arity's function is 0.

        :param b: basic block address
        :return:
        """

    set_params = []
    b = p.factory.block(b_addr)
    for reg_off in ordered_agument_regs[p.arch.name]:
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

# FIXME: so far we only consider arguments passed through registers
def get_ord_arguments_call_callee(p, b_addr):
    """
        Retrieves the list of instructions setting arguments for a function call. It checks the arguments in order
        so to infer the artity of the function:
        Example: if the first argument (e.g., r0 in ARM) is not set, it assumes the arity's function is 0.

        :param b: basic block address
        :return:
        """

    get_params = []
    b = p.factory.block(b_addr)
    for reg_off in ordered_agument_regs[p.arch.name]:
        get_stmts = [s for s in b.vex.expressions if s.tag == 'Iex_Get' and s.offset == reg_off]
        if not get_stmts:
            break

        # if more than a write, only consider the last one
        # eg r0 = 5
        # ....
        # r0 = 10
        # BL foo
        get_stmt = get_stmts[-1]
        get_params.append(get_stmt)

    puts = [x for x in b.vex.statements if x.tag == 'Ist_Put']
    unwritten_gets = []
    for g in get_params:
        off = g.offset
        if not any([x for x in puts if x.offset == off]):
            unwritten_gets.append(g)
    return unwritten_gets


def get_any_arguments_call(p, b_addr):
    """
        Retrieves the list of instructions setting arguments for a function call.
        :param b: basic block address
        :return:
        """

    set_params = []
    b = p.factory.block(b_addr)
    put_stmts = [s for s in b.vex.statements if s.tag == 'Ist_Put']
    for stmt in put_stmts:
        if stmt.offset in ordered_agument_regs[p.arch.name]:
            set_params.append(stmt)

    return set_params


def get_arity(p, b_addr, role='caller'):
    """
    Retrieves the arity by inspecting a funciton call

    :param b: basic block address
    :return:
    """

    if role == 'caller':
        nargs = len(get_ord_arguments_call_caller(p, b_addr))
    else:
        nargs = len(get_ord_arguments_call_callee(p, b_addr))
    return nargs

