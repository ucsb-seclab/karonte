class StackVariableRecovery:

    def __init__(self, fun):
        assert fun
        self._vars = {0: fun.binary.arch.bytes}
        self._fun = fun
        self._bp = None
        self._tmp_bps = []
        self._tmp_sp = None

    def _detect_bp(self, stmt):
        arch = self._fun.binary.arch
        if self._tmp_bps and stmt.tag == 'Ist_Put':
            if hasattr(stmt.data, 'tmp') and stmt.data.tmp in self._tmp_bps:
                if 'sp' not in arch.register_names[stmt.offset]:
                    self._bp = stmt.offset

                    # accessing the tmp_sp and adding an offset -> tmp_bp
        if self._tmp_sp is not None and hasattr(stmt, 'data'):
            rd_tmps = [x for x in stmt.data.child_expressions if x.tag == 'Iex_RdTmp']
            for rd_tmp in rd_tmps:
                if rd_tmp.tmp == self._tmp_sp or rd_tmp.tmp in self._tmp_bps:
                    self._tmp_bps.append(stmt.tmp)
                    break
                    # accessing_sp and putting the result in tmp
        if hasattr(stmt, 'data') and stmt.data.tag == 'Iex_Get' \
                and 'sp' in arch.register_names[stmt.data.offset]:
            self._tmp_sp = stmt.tmp

    def _detect_var(self, stmt):
        # new bp tmp
        if hasattr(stmt, 'data') and stmt.data.tag == 'Iex_Get' \
                and self._bp == stmt.data.offset:
            self._tmp_bps.append(stmt.tmp)

        # accessing a var
        if hasattr(stmt, 'data') and hasattr(stmt.data, 'op'):
            if 'Iop_Sub' in stmt.data.op or 'Iop_Add' in stmt.data.op:
                rd_tmps = [x for x in stmt.data.child_expressions if x.tag == 'Iex_RdTmp']
                if any([x for x in rd_tmps if x.tmp in self._tmp_bps]):
                    const = [x for x in stmt.data.child_expressions if x.tag == 'Iex_Const']
                    assert len(const) == 1, 'stack_variable_recovery: too many constants'
                    const = const[0].con.value
                    if const not in self._vars:
                        if 'Sub' in stmt.data.op:
                            const = -const
                        self._vars[const] = None

    def _estimate_sizes(self):
        for off in self._vars.keys():
            if off == 0:
                continue

            if off > 0:
                val = min([off - x for x in self._vars.keys() if x != off and off > x >= 0])
            else:
                val = -max([off - x for x in self._vars.keys() if x != off and off < x <= 0])
            self._vars[off] = val

    def _analyze(self):
        topological_blocks = [x for x in self._fun.blocks]
        topological_blocks.sort(key=lambda x: x.addr)

        for block in topological_blocks:
            for stmt in block.vex.statements:

                # the base pointer is not set yet
                if not self._bp:
                    self._detect_bp(stmt)
                # it is
                else:
                    self._detect_var(stmt)

        self._estimate_sizes()

    def run(self):
        self._analyze()
        return self._vars
