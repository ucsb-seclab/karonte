# IMPORTANT
# this part only work with linux binaries so far!

from utils import *
import angr
import sys
import os
from os.path import dirname, abspath
import simuvex
import archinfo
import logging
from random import shuffle


sys.path.append(os.path.abspath(os.path.join(dirname(abspath(__file__)), '../../tool')))

from taint_analysis import coretaint, summary_functions
from taint_analysis.coretaint import TimeOutException
from taint_analysis.utils import ordered_agument_regs, get_ord_arguments_call, get_any_arguments_call, return_regs
from stack_variable_recovery import stack_variable_recovery
from binary_dependency_graph.utils import * # FIXME: move utils someplace else


MAX_DEPTH_BACKWARD = 3

log = logging.getLogger("BackWardTainter")
log.setLevel("DEBUG")


link_regs ={
    'ARMEL': archinfo.ArchARMEL.registers['lr'][0],
    'AARCH64': archinfo.ArchAArch64.registers['x30'][0],
    'MIPS32': archinfo.ArchMIPS32.registers['ra'][0]
}


TIMEOUT_TAINT = 60 * 5
TIMEOUT_TRIES = 3

class ForwardBackWardTaintTracker:
    def __init__(self, p, sources=None, sinks=None):
        self._ct = None
        self._p = p
        self._cfg = p.analyses.CFG()
        self._taint_locs = []
        self._sinks_info = sinks if sinks else {}
        self._sources_info = sources if sources else {}
        self._bb_sinks = []
        self._bb_sources = []
        self._found_recv = False
        self.populate_symbol_table()
        self._taint_applied_sources = []
        self._sink_bound_to_recv = False
        self._sink_dep_args = False
        self._interesting_returns = []
        self._current_function_address = None
        self.backward_analysis_completed = False

    # FIXME
    # move samplace else
    def _prepare_state(self, start_addr, addr_return=None):
        """
        Prepare the state to perform the taint analysis to infer the role of a binary

        :param start_addr: address of the string used as key to infer the role
        :return:
        """
        p = self._p
        ct = self._ct

        s = p.factory.blank_state(remove_options={simuvex.o.LAZY_SOLVES})

        lr = p.arch.register_names[link_regs[p.arch.name]]
        addr_return = addr_return if addr_return else ct.bogus_return
        setattr(s.regs, lr, addr_return)

        s.ip = start_addr
        return s

    def populate_symbol_table(self):
        p = self._p
        buckets = p.loader.main_object.hashtable.buckets + p.loader.main_object.hashtable.chains
        symtab = p.loader.main_object.hashtable.symtab
        names = [symtab.get_symbol(n).name for n in buckets]
        names = list(set([str(n) for n in names if n]))
        for name in names:
            # this will provoke symbol table to be populated
            [x for x in p.loader.find_all_symbols(name)]

    def _prepare_function_summaries(self):
        """
        Prepare the function summaries to be used during the taint analysis
        :return: the function summaries dictionary
        """

        p = self._p

        mem_cpy_summ = get_memcpy_like(p)
        size_of_summ = get_sizeof_like(p)
        heap_alloc_summ = get_heap_alloc(p)
        memcp_like = get_memcp_like(p)
        memncp_like = get_memncp_like(p)

        summaries = mem_cpy_summ
        summaries.update(size_of_summ)
        summaries.update(heap_alloc_summ)
        summaries.update(memcp_like)
        summaries.update(memncp_like)
        return summaries

    def _exploration_strategy(self, current_path, next_states):
        try:
            p = self._p
            cfg = self._cfg
            history = [x for x in current_path.active[0].state.history.bbl_addrs]

            current_addr = current_path.active[0].addr
            new_states = list(next_states)

            no = cfg.get_any_node(current_addr)

            if not no:
                shuffle(next_states)
                return next_states
            if self._current_function_address is None or no.function_address != self._current_function_address:
                self._interesting_returns = self._get_interesting_returns(no.function_address)
                self._current_function_address = no.function_address

            bl = p.factory.block(current_addr)
            if self._interesting_returns and bl.vex.jumpkind == 'Ijk_Ret':
                new_states = []
                for st in next_states:
                    try:
                        returns = [x for x in self._interesting_returns if x[0] == bl.addr]
                        if not returns:
                            st.ip = self._ct.bogus_return
                        else:
                            last_bb = history[-1]

                            for r in returns:
                                if len(r) == 1 or (len(r) == 2 and r[1] == last_bb):
                                    new_states.append(st)
                                    break
                    except:
                        new_states.append(st)

            shuffle(new_states)
            return new_states
        except:
            shuffle(next_states)
            return next_states

    def _backward_taint(self, current_path, *_, **__):
        try:
            p = self._p
            addr  = current_path.active[0].addr
            bl = p.factory.block(addr)
            cfg = self._cfg

            if not self._ct.taint_applied:
                if self._taint_locs:
                    for mem_addr in self._taint_locs:
                        self._ct.apply_taint(current_path, mem_addr, 'intial_taint', bit_size=self._ct.taint_buf_size)
                else:
                    no = cfg.get_any_node(current_path.active[0].addr)
                    if not no:
                        return

                    preds = no.predecessors
                    if not preds:
                        return

                    pred = preds[0]
                    nargs = len(get_any_arguments_call(p, pred.addr))
                    for i in xrange(nargs):
                        off = ordered_agument_regs[p.arch.name][i]
                        reg = p.arch.register_names[off]
                        t_addr = getattr(current_path.active[0].regs, reg)
                        self._ct.apply_taint(current_path, t_addr, 'intial_taint', bit_size=self._ct.taint_buf_size)

            # check sink
            if bl.vex.jumpkind == 'Ijk_Call':
                try:
                    no = self._cfg.get_any_node(addr)
                    succ = no.successors
                    succ = succ[0]

                    if (succ.name and ('recv' in succ.name or 'read' in succ.name)) or \
                            'recv' in p.loader.find_symbol(succ.addr).name:
                        #FIXME: should I check if tainted args
                        self._found_recv = True
                except:
                    pass

            next_path = current_path.copy(copy_states=True).step()
            sink = [x for x in self._bb_sinks if x[0] == addr]

            if sink:
                for curr_sink in sink:
                    for reg_name in curr_sink[1]:
                        m_addr = getattr(next_path.active[0].regs, reg_name)
                        if self._ct.is_or_points_to_tainted_data(m_addr, next_path):
                            self._sink_dep_args = True
                            if self._found_recv:
                                self._sink_bound_to_recv = True
                                self._ct.stop_run()
                                break
        except Exception as e:
            pass

    def _frontward_taint(self, current_path, *_, **__):
        try:
            p = self._p
            addr  = current_path.active[0].addr
            bl = p.factory.block(addr)
            cfg = self._cfg

            source = [x for x in self._bb_sources if x[0] == addr]

            if source and addr not in self._taint_applied_sources:
                self._taint_applied_sources.append(addr)
                self.apply_ret_taint = True
                source = source[0]
                regs = source[1]
                for reg in regs:
                    t_addr = getattr(current_path.active[0].regs, reg)
                    self._ct.apply_taint(current_path, t_addr, 'intial_taint', bit_size=self._ct.taint_buf_size)

            # check sink
            if bl.vex.jumpkind == 'Ijk_Call' and self._ct.taint_applied:
                try:
                    next_path = current_path.copy(copy_states=True).step()
                    no = cfg.get_any_node(addr)
                    succ = no.successors
                    succ = succ[0]

                    if (succ.name and any([x in succ.name for x in CMP_SUCCS])) or \
                            any([x in p.loader.find_symbol(succ.addr).name for x in CMP_SUCCS]):
                        nargs = len(get_any_arguments_call(p, no.addr))
                        for i in xrange(nargs):
                            off = ordered_agument_regs[p.arch.name][i]
                            reg = p.arch.register_names[off]
                            if self._ct.is_or_points_to_tainted_data(getattr(next_path.active[0].regs, reg), next_path):
                                self._sink_bound_to_recv = True
                                self._ct.stop_run()
                except:
                    pass
        except Exception as e:
            pass

    def _get_interesting_returns(self, faddr):
        interesting_returns = []
        p = self._p
        cfg = self._cfg

        try:
            off = return_regs[p.arch.name]
            ret_reg = p.arch.register_names[off]
            fun = cfg.functions[faddr]
            returns = list(fun.endpoints_with_type['return'])

            for r in returns:

                addrs = [r.addr]
                steps = 1
                # if possible go a further step back to
                # get also return stubs
                no = cfg.get_any_node(r.addr)
                if no:
                    preds = no.predecessors
                    addrs = [pred.addr for pred in preds]
                    steps = 2

                for a in addrs:
                    s = self._prepare_state(a)

                    simgr = p.factory.simgr(s, save_unconstrained=True, save_unsat=True)
                    simgr.step()
                    if steps == 2:
                        simgr.step()

                    stashes = [x for y in simgr.stashes.values() for x in y]
                    for stash in stashes:
                        val = getattr(stash.regs, ret_reg)
                        if val.concrete:
                            continue
                        to_add = [r.addr] if steps == 1 else [r.addr, a]
                        interesting_returns.append(to_add)
        except:
            pass
        return interesting_returns

    def _has_interesting_calls_backward(self, addr):
        p = self._p
        cfg = self._cfg
        interesting = []
        fun = cfg.functions[addr]
        bls = []

        for bl in fun.blocks:
            try:
                if bl.vex.jumpkind == 'Ijk_Call':
                    bls.append(bl)
            except:
                pass

        for bl in bls:
            try:
                no = cfg.get_any_node(bl.addr)
                succ = no.successors
                succ = succ[0]

                called_fun = cfg.functions[succ.addr]
                for bl2 in [y for y in called_fun.blocks if y.vex.jumpkind == 'Ijk_Call']:
                    try:
                        no2 = cfg.get_any_node(bl2.addr)
                        succ2 = no2.successors
                        succ2 = succ2[0]

                        if (succ2.name and ('recv' in succ2.name or 'read' in succ2.name)) or \
                                        'recv' in p.loader.find_symbol(succ2.addr).name:
                            interesting.append(succ.addr)
                    except:
                        pass
            except:
                pass
        return list(set(interesting))

    def _has_interesting_calls_frontward(self, addr):
        p = self._p
        cfg = self._cfg
        interesting = []
        fun = cfg.functions[addr]
        bls = []

        for bl in fun.blocks:
            try:
                if bl.vex.jumpkind == 'Ijk_Call':
                    bls.append(bl)
            except:
                pass

        for bl in bls:
            try:
                no = cfg.get_any_node(bl.addr)
                succ = no.successors
                succ = succ[0]

                called_fun = cfg.functions[succ.addr]
                for bl2 in [y for y in called_fun.blocks if y.vex.jumpkind == 'Ijk_Call']:
                    try:
                        no2 = cfg.get_any_node(bl2.addr)
                        succ2 = no2.successors
                        succ2 = succ2[0]

                        if (succ2.name and any([x in succ2.name for x in CMP_SUCCS])) or \
                                    any([x in p.loader.find_symbol(succ2.addr).name for x in CMP_SUCCS]):
                            interesting.append(succ.addr)
                    except:
                        pass
            except:
                pass
        return list(set(interesting))

    def backward_tainter(self, function_addr):
        min_lvl = MAX_DEPTH_BACKWARD

        to_analyze = [(function_addr, self._bb_sinks, 0)]
        p = self._p
        cfg = self._cfg
        self.backward_analysis_completed = False

        # ITERATE HERE!
        while to_analyze:
            self._sink_bound_to_recv = False
            self._sink_dep_args = False

            faddr, self._bb_sinks, curr_lvl = to_analyze[0]
            if min_lvl >= curr_lvl:
                min_lvl = curr_lvl
            if curr_lvl >= MAX_DEPTH_BACKWARD:
                continue

            to_analyze = to_analyze[1:]

            white_calls = self._has_interesting_calls_backward(faddr)
            self._ct = coretaint.CoreTaint(p, interfunction_level=0, smart_call=True, only_tracker=True,
                                           follow_unsat=True, shuffle_sat=True, white_calls=white_calls,
                                           exploration_strategy=self._exploration_strategy,
                                           try_thumb=True, taint_returns_unfollowed_calls=True,
                                           taint_arguments_unfollowed_calls=True,
                                           exit_on_decode_error=True, force_paths=True, allow_untaint=False)

            s = self._prepare_state(faddr)
            summarized_f = self._prepare_function_summaries()
            self._ct.set_alarm(TIMEOUT_TAINT, n_tries=TIMEOUT_TRIES)

            try:
                # to trigger it refer to httpd 0x16410. Switch case is mostly UNSAT!
                self._ct.run(s, (), (), summarized_f=summarized_f, force_thumb=False, use_smart_concretization=False,
                             check_func=self._backward_taint, init_bss=False)
            except TimeOutException:
                log.warning("Timeout Triggered")
            except Exception as e:
                log.warning("Exception: %s" % str(e))

            self._ct.unset_alarm()

            if self._sink_bound_to_recv:
                return True

            elif not self._taint_locs and self._sink_dep_args:
                # consider the callers
                no = cfg.get_any_node(faddr)
                if not no:
                    continue

                functions = {}
                for pred in no.predecessors:
                    if pred.function_address not in functions:
                        functions[pred.function_address] = []
                    callee_args = len(get_any_arguments_call(p, pred.addr))
                    curr_sink = (pred.addr, tuple(
                        [p.arch.register_names[ordered_agument_regs[p.arch.name][i]] for i in xrange(callee_args)]))
                    functions[pred.function_address].append(curr_sink)

                for faddr, finfo in functions.items():
                    to_analyze.append((faddr, finfo, curr_lvl + 1))

        if min_lvl < MAX_DEPTH_BACKWARD:
            self.backward_analysis_completed = False

        return False

    def frontward_tainter(self, function_addr):
        to_analyze = [(function_addr, self._bb_sinks)]
        p = self._p
        cfg = self._cfg

        # ITERATE HERE!
        while to_analyze:
            self._taint_applied_sources = []
            self._sink_bound_to_recv = False
            self._sink_dep_args = False

            faddr, self._bb_sinks = to_analyze[0]
            to_analyze = to_analyze[1:]

            white_calls = list(self._has_interesting_calls_frontward(faddr))

            self._ct = coretaint.CoreTaint(p, interfunction_level=0, smart_call=True, only_tracker=True,
                                           follow_unsat=True, shuffle_sat=True, white_calls=white_calls,
                                           exploration_strategy=self._exploration_strategy,
                                           try_thumb=True, taint_returns_unfollowed_calls=True,
                                           taint_arguments_unfollowed_calls=True,
                                           exit_on_decode_error=True, force_paths=True, allow_untaint=False)

            s = self._prepare_state(faddr)
            summarized_f = self._prepare_function_summaries()
            self._ct.set_alarm(TIMEOUT_TAINT, n_tries=TIMEOUT_TRIES)

            try:
                # to trigger it refer to httpd 0x16410. Switch case is mostly UNSAT!
                self._ct.run(s, (), (), summarized_f=summarized_f, force_thumb=False, use_smart_concretization=False,
                             check_func=self._frontward_taint, init_bss=False)
            except TimeOutException:
                log.warning("Timeout Triggered")
            except Exception as e:
                log.warning("Exception: %s" % str(e))

            self._ct.unset_alarm()

            if self._sink_bound_to_recv:
                return True

        return False

    def run(self):
        completed_analysis = 0
        tot = 0

        for function_addr, bbl_sinks in self._sinks_info.items():
            tot += 1

            if bbl_sinks:
                self._bb_sinks = [(x[0], (x[1],)) for x in bbl_sinks if x[2] is None]
                self._taint_locs = []
                result = self.backward_tainter(function_addr)
                if result:
                    return True, 100.0

                if self.backward_analysis_completed:
                    completed_analysis += 1

                self._taint_locs = [x[2] for x in bbl_sinks if x[2] is not None]
                self._bb_sinks = []
                if self._taint_locs:
                    result = self.backward_tainter(function_addr)
                    if result:
                        return True, 100.0

        for function_addr, bbl_sources in self._sources_info.items():
            if bbl_sources:
                self._bb_sources = bbl_sources
                self._taint_locs = []
                result = self.frontward_tainter(function_addr)
                if result:
                    return True, self.backward_analysis_completed

        return False, (completed_analysis / float(tot)) * 100


if __name__ == '__main__':
    p = angr.Project('/tmp/httpd')
    sink = {0x1128c: [(0x11324, ('r0',))]}
    bt = ForwardBackWardTaintTracker(p, sinks=sink)
    bt.run()
