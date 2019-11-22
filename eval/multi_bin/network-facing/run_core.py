# HELP
# Analyze each network-facing binary in a firmware assuming that attacker-controlled data comes from any IPC channel.
import angr
import subprocess as sp
from taint_analysis import coretaint, utils
from run_utils import *
import os
from os.path import dirname, abspath
import sys
from optparse import OptionParser
from optparse import Option, OptionValueError
import time
import archinfo
import parser_finder.find_parser
import threading
import time

MAX_HOURS_FUNCTION = 5
RESULT_DRECTORY = 'results'
SINKS = (('memcpy', (0, 1, 2)), ('strcpy', (0, 1)), ('sprintf', (0,)))

class MultipleOption(Option):
    ACTIONS = Option.ACTIONS + ("extend",)
    STORE_ACTIONS = Option.STORE_ACTIONS + ("extend",)
    TYPED_ACTIONS = Option.TYPED_ACTIONS + ("extend",)
    ALWAYS_TYPED_ACTIONS = Option.ALWAYS_TYPED_ACTIONS + ("extend",)

    def take_action(self, action, dest, opt, value, values, parser):
        if action == "extend":
            values.ensure_value(dest, []).append(value)
        else:
            Option.take_action(self, action, dest, opt, value, values, parser)


class AlertTest:
    def __init__(self):
        self.current_starting_addr = None
        self.current_source_addr = None
        self.args_to_taint = []
        self.result_dir = RESULT_DRECTORY
        self.p = None
        self.cfg = None
        self.ct = None
        self._skipped = 0
        self._bin_with_IPC = 0
        self._total = 0
        self._errored = 0
        self.safe = True
        self.buff_can_reach_sink = False
        self.total_safe_calls = 0
        self.total_unsafe_calls = 0
        self.current_bin_safe_calls = 0
        self.current_bin_unsafe_calls = 0
        self.addr_alert_recorded = []
        self.addr_safe_recorded = []
        self._IPC_reach_sink = 0
        self.taint_names_applied = []
        self.adaptive_to = 10 * 60
        self.fw_pickle = None
        self.fp = None
        self.n_param = 0
        self.taint_counter = 0
        self.filter = []
        self.ignore = []
        self.fw_directory = None

    def parse_options(self):
        parser = OptionParser(option_class=MultipleOption, description="Analyze each binary in a firmware assuming that "
                                                                       "attacker-controlled data comes from any IPC"
                                                                       "channel",
                              usage="usage: %prog [options] [binaries] -d firmware_directory",
                              version="%prog 1.0")
        parser.add_option("-i", "--ignore",
                          action="extend",   metavar='CATEGORIES',
                          help="list of binaries to ignore")
        parser.add_option("-p", "--pickle",
                          action="extend", metavar='CATEGORIES',
                          help="firwmare pickle")
        parser.add_option("-f", "--force",
                          action="extend",  metavar='CATEGORIES',
                          help="List of binaries to consider", )
        parser.add_option("-d", "--dir",
                          action="extend",  metavar='CATEGORIES',
                          help="Firmware directory path", )
        parser.add_option("-l", "--log_dir",
                          action="extend",  metavar='CATEGORIES',
                          help="log directory path", )

        (options, args) = parser.parse_args()

        if options.dir:
            self.fw_directory = options.dir[0]
        if options.force:
            self.filter = options.force
        if options.ignore:
            self.ignore = options.ignore
        if options.pickle:
            self.fw_pickle = options.pickle[0]
        if options.log_dir:
            self.result_dir = options.log_dir[0]
            

    def get_bins(self):
        pf = parser_finder.find_parser.ParserFinder(self.fw_directory)
        bins = pf.run(pickle_file=self.fw_pickle)
        filtered_bins = []
        for b in bins:
            new_b = b
            if b.startswith('./'):
                new_b = '../../../' + b[2:]
            filtered_bins.append(new_b)
        bins = filtered_bins
        return bins

    def get_additional_taint(self, p, f_addr, sink_addr):
        if 'ARM' not in self.p.arch.name:
            raise ("Sorry this test is only thought for ARM binaries :(")

        f_obj = self.cfg.functions.function(f_addr)

        # first let's see if the strcpy src is set within the function
        t = (self.p.factory.block(sink_addr).instruction_addrs[-1], angr.analyses.reaching_definitions.OP_AFTER)
        try:
            rd = p.analyses.ReachingDefinitions(func=f_obj, observation_points=[t, ], init_func=True)
        except:
            return []
        buff_addrs = []

        if t in rd.observed_results:
            results = rd.observed_results[t]
            reg_off = archinfo.ArchARMEL.registers['r1'][0]

            for r_def in results.register_definitions.get_objects_by_offset(reg_off):
                for val in r_def.data.data:
                    if type(val) == angr.analyses.reaching_definitions.undefined.Undefined:
                        continue

                    is_string = get_string(self.p, val)
                    if is_string:
                        print "Skipping string: " + is_string
                        continue

                    buff_addrs.append(val)

        # if we have no use we'll taint the function parameters
        return buff_addrs

    def bv_to_hash(self, v):
        args_str = map(str, v.recursive_leaf_asts)
        new_v_str = ''
        for a_str in args_str:
            if '_' in a_str:
                splits = a_str.split('_')
                a_str = '_'.join(splits[:-2] + splits[-1:])
                new_v_str += a_str
        return new_v_str

    def is_tainted_by_us(self, tainted_val):
        hash = self.bv_to_hash(tainted_val)
        if hash in self.taint_names_applied:
            return True
        return False

    def is_address(self, val):
        p = self.p
        if val.concrete and val.args[0] < p.loader.main_object.min_addr:
            return False
        return True

    def taint_parameters(self, addr, current_path, next_state):
        """
        Applies the taint to the role function call

        :param addr: address of the role function
        :param current_path: current angr's path
        :param next_state: state at the entry of the function
        :return:
        """

        def is_arg_key(arg):
            return hasattr(arg, 'args') and type(arg.args[0]) in (int, long) and arg.args[0] == self._current_seed_addr

        p = self.p

        # FIXME: refactor me using get_arg_call
        ins_args = get_ord_arguments_call(p, addr)
        if not ins_args:
            ins_args = get_any_arguments_call(p, addr)

        for stmt in ins_args:
            reg_off = stmt.offset
            reg_name = p.arch.register_names[reg_off]
            val_arg = getattr(next_state.regs, reg_name)
            size = None
            if val_arg.concrete and val_arg.args[0] < p.loader.main_object.min_addr:
                continue
            self.ct.apply_taint(current_path, val_arg, reg_name, size)

    def check_func(self, current_path, guards_info, *_, **__):
        next_path = current_path.copy(copy_states=True).step()
        ord_args = ordered_agument_regs[self.p.arch.name]
        current_addr = current_path.active[0].addr

        # taint arguments
        history_bbl = [x for x in current_path.active[0].history.bbl_addrs]

        if history_bbl and history_bbl[-1] == self.current_source_addr and 'RET' in self.args_to_taint:
            offset = return_regs[self.p.arch.name]
            reg_name = self.p.arch.register_names[offset]
            t = self.ct._get_sym_val(name=self.ct._taint_buf + '_' + str(self.taint_counter) + '_', bits=self.p.arch.bits)
            setattr(current_path.active[0].regs, reg_name, t)

        if current_path.active[0].addr == self.current_source_addr:
            for a in self.args_to_taint:
                if a == 'RET':
                    continue
                offset = ord_args[a]
                reg_name = self.p.arch.register_names[offset]
                addr = getattr(current_path.active[0].regs, reg_name)
                self.ct.apply_taint(current_path, addr, str(self.taint_counter))
                self.ct._taint_applied = True
                self.taint_counter += 1

        try:
            node = self.cfg.get_any_node(current_path.active[0].addr)
            succ = node.successors
            if len(succ) == 1:
                succ = succ[0]
                if hasattr(succ, 'name') and succ.name is not None and succ.name:
                    sink = [x for x in SINKS if succ.name in x[0]]
                    if sink:
                        sink = sink[0]
                        if 'sprintf' in sink[0]:
                            # sprinf is a bit more complex
                            # we gotta consider the format string to get the argument count

                            offset = ord_args[1]
                            reg_name = self.p.arch.register_names[offset]

                            state = next_path.active[0]
                            frmt_str = getattr(state.regs, reg_name)

                            if self.ct.is_or_points_to_tainted_data(frmt_str, next_path):
                                self.addr_alert_recorded.append((current_addr, 1))
                                self.buff_can_reach_sink = True

                            if not frmt_str.symbolic:
                                str_val = get_string(self.p, frmt_str.args[0], extended=True)
                                n_vargs = len([x for x in str_val if x == '%'])
                                if n_vargs < 1:
                                    # there must be at least one!
                                    n_vargs = 1

                                for i in range(2, 2 + n_vargs):
                                    name = self.p.arch.register_names[ordered_agument_regs[self.p.arch.name][i]]
                                    buff_addr = getattr(state.regs, name)
                                    expr = next_path.active[0].memory.load(buff_addr)
                                    if 'taint' in str(expr) or 'taint' in str(buff_addr):
                                        if self.ct.is_or_points_to_tainted_data(buff_addr, next_path):
                                            self.addr_alert_recorded.append((current_addr, i))
                                        else:
                                            self.addr_safe_recorded.append((current_addr, i))

                                        self.buff_can_reach_sink = True
                        else:
                            args_to_check = sink[1]
                            for a_ord in args_to_check:
                                offset = ord_args[a_ord]
                                reg_name = self.p.arch.register_names[offset]

                                buff_addr = getattr(next_path.active[0].regs, reg_name)
                                expr = next_path.active[0].memory.load(buff_addr)
                                if 'taint' in str(expr) or 'taint' in str(buff_addr):
                                    if self.ct.is_or_points_to_tainted_data(buff_addr, next_path):
                                        self.addr_alert_recorded.append((current_addr, a_ord))
                                    else:
                                        self.addr_safe_recorded.append((current_addr, a_ord))

                                    self.buff_can_reach_sink = True

            # tainted call address and tainted parameters
            bl = self.p.factory.block(current_addr)
            if not len(next_path.active) and len(next_path.unconstrained) and bl.vex.jumpkind == 'Ijk_Call':
                cap = bl.capstone.insns[-1]
                vb = bl.vex
                reg_jump = cap.insn.op_str
                val_jump_reg = getattr(next_path.unconstrained[0].regs, reg_jump)
                if not hasattr(vb.next, 'tmp'):
                    return

                val_jump_tmp = next_path.unconstrained[0].scratch.temps[vb.next.tmp]

                if not self.is_tainted_by_us(val_jump_reg) and not self.is_tainted_by_us(val_jump_tmp):
                    if self.ct.is_or_points_to_tainted_data(val_jump_reg, next_path, unconstrained=True):
                        nargs = get_arity(self.p, current_path.active[0].addr)
                        for ord_reg in ordered_agument_regs[self.p.arch.name][:nargs]:
                            reg_name = self.p.arch.register_names[ord_reg]
                            if reg_name == reg_jump:
                                continue

                            reg_val = getattr(next_path.unconstrained[0].regs, reg_name)
                            if self.ct.is_or_points_to_tainted_data(reg_val, next_path, unconstrained=True) and self.is_address(
                                    reg_val):
                                self.buff_can_reach_sink = True
                                self.addr_alert_recorded.append((current_addr, ord_reg))

                        next_state = next_path.unconstrained[0]
                        hash_val = self.bv_to_hash(val_jump_tmp)
                        self.taint_names_applied.append(hash_val)
                        hash_val = self.bv_to_hash(val_jump_reg)
                        self.taint_names_applied.append(hash_val)
                        self.taint_parameters(current_addr, current_path, next_state)

            # eventually if we are in a loop guarded by a tainted variable
            next_active = next_path.active
            current_state = current_path.active[0]
            cfg = self.cfg

            if len(next_active) > 1:
                history_addrs = [t for t in current_state.history.bbl_addrs]
                seen_addr = [a.addr for a in next_active if a.addr in history_addrs]

                if len(seen_addr) == 0:
                    return

                back_jumps = [a for a in seen_addr if a < current_addr]
                if len(back_jumps) == 0:
                    return

                bj = back_jumps[0]
                node_s = cfg.get_any_node(bj)
                node_f = cfg.get_any_node(current_addr)

                if not node_s or not node_f:
                    return

                fun_s = node_s.function_address
                fun_f = node_f.function_address

                if fun_s != fun_f:
                    return

                idx_s = history_addrs.index(bj)
                for a in history_addrs[idx_s:]:
                    n = cfg.get_any_node(a)
                    if not n:
                        continue

                    if n.function_address != fun_s:
                        return

                # if we have a back-jump satisfiying all the conditions
                cond_guard = [g for g in next_active[0].guards][-1]

                for node in cond_guard.recursive_leaf_asts:
                    if self.ct._taint_buf in str(node):
                        self.buff_can_reach_sink = True
                        self.addr_alert_recorded.append((current_addr, 'loop'))

        except Exception as e:
            print "Exception " + str(e)

    def estimate_n_param(self, f_addr, filter_strings=False):
        no = self.cfg.get_any_node(f_addr).predecessors
        if no:
            no = no[0]
            nargs = get_arity(self.p, no.addr)
            if nargs:
                return nargs

        # check in the first block of the callee what registers are read without a previous write
        return get_arity(self.p, f_addr, role='callee')

    def run_taint_analysis(self, f_addr, source_addr, name_source, args_to_taint):
        p = self.p
        self.buff_can_reach_sink = False
        self.addr_alert_recorded = []
        self.addr_safe_recorded = []
        self.taint_names_applied = []

        self.ct = coretaint.CoreTaint(p, interfunction_level=1, smart_call=True,
                                follow_unsat=True, only_follow_near_calls=True,
                                try_thumb=True, black_calls=[source_addr],
                                exit_on_decode_error=True, force_paths=True,
                                taint_arguments_unfollowed_calls=True,
                                taint_returns_unfollowed_calls=True, allow_untaint=True)

        summarized_f = get_function_summaries(p)
        # initial_taint = self.get_additional_taint(self.p, f_addr, sink_addr)
        s = get_initial_state(p, f_addr, self.ct)#, initial_taint=initial_taint)

        self.current_source_addr = source_addr
        self.current_starting_addr = f_addr
        self.ct.set_alarm(self.adaptive_to, n_tries=3)
        self.args_to_taint = args_to_taint
        # self.n_param = self.estimate_n_param(f_addr)

        try:
            self.ct.run(s, (), (), summarized_f=summarized_f, force_thumb=False, check_func=self.check_func, init_bss=False)
        except Exception as e:
            print "Exception: %s" % str(e)

        self.ct.unset_alarm()

        self.total_safe_calls += len(list(set(self.addr_safe_recorded)))
        self.current_bin_safe_calls += len(list(set(self.addr_safe_recorded)))
        self.total_unsafe_calls += len(list(set(self.addr_alert_recorded)))
        self.current_bin_unsafe_calls += len(list(set(self.addr_alert_recorded)))

        return self.buff_can_reach_sink

    def get_sources(self):
        sources = [(x, ('RET',)) for x in self.get_callers('socket')]
        sources += [(x, ('RET', 0)) for x in self.get_callers('open')]
        #sources += [(x, (0, 1)) for x in self.get_callers('read')]
        #sources += [(x, (0, 3)) for x in self.get_callers('fread')]
        sources += [(x, ('RET', 0)) for x in self.get_callers('fopen')]
        sources += [(x, ('RET', 0)) for x in self.get_callers('open64')]
        sources += [(x, ('RET', 0)) for x in self.get_callers('fopen64')]
        sources += [(x, ('RET', 0)) for x in self.get_callers('getenv')]
        sources += [(x, ('RET', 0, 1)) for x in self.get_callers('setenv')]
        sources += [(x, ('RET', 0)) for x in self.get_callers('pipe')]
        sources += [(x, ('RET', 0)) for x in self.get_callers('ftok')]
        sources += [(x, ('RET', 0)) for x in self.get_callers('shm_open')]
        return sources

    def get_sinks(self):
        to_analyze = self.get_callers('strcpy')
        to_analyze += self.get_callers('strcat')
        to_analyze += self.get_callers('sprintf')
        return to_analyze

    def get_callers(self, name_f):
        to_analyze = []
        if name_f in self.p.loader.main_object.plt:
            plt_addr = self.p.loader.main_object.plt[name_f]
            node = [x for x in self.cfg.nodes() if x.addr == plt_addr]
            if node:
                node = node[0]
                preds = self.cfg.get_predecessors(node)
                to_analyze += [(p.function_address, p, name_f) for p in preds]

        return to_analyze

    def calculate_to(self, tot_run):
        tentative_to = 10
        hours = tot_run * 10 / 60
        if hours > MAX_HOURS_FUNCTION:
            tentative_to = (60 * MAX_HOURS_FUNCTION) / float(tot_run)
            if tentative_to < 2:
                tentative_to = 2
        return tentative_to * 60

    def run(self):
        print "Analyzing firmware sample: " + self.fw_directory

        parent_dir = self.fw_directory.replace('.', '').replace('/', '_')
        dirs = self.result_dir + '/' + parent_dir

        if not os.path.exists(dirs):
            os.makedirs(dirs)
            
        sum_res = open(dirs + '/summary_result.log', 'w')
        self.ignore += os.listdir(self.result_dir + '/' + parent_dir + '/')

        bins = self.get_bins()
        tot_time = time.time()

        for b in list(set(bins)):
            try:

                bin_name = b.split('/')[-1]
                bin_time = time.time()

                if self.ignore:
                    if any([x for x in self.ignore if bin_name.lower().startswith(x.lower())]):
                        print 'Analyzing binary: ' + b
                        print "Ignoring it as specified"
                        continue

                if self.filter:
                    if not any([x for x in self.filter if bin_name.lower().startswith(x.lower())]):
                        continue

                self.p = angr.Project(b)
                self.cfg = self.p.analyses.CFG()

                print 'Analyzing binary: ' + b

                sources = self.get_sources()
                if sources:
                    self._bin_with_IPC += 1

                self._total += 1

                self.fp = open(self.result_dir + '/' + parent_dir + '/' + bin_name, 'w')

                self.current_bin_safe_calls = 0
                self.current_bin_unsafe_calls = 0
                sink_reached = False

                self.adaptive_to = int(self.calculate_to(len(sources)))

                print "Expected completition time: {} h".format(str(self.adaptive_to  / float(3600) * len(sources)))
                for (f, bb_source, name_source), args_to_taint in sources:
                    print "Entering function " + hex(f) + '\n'
                    buff_reach_sink = self.run_taint_analysis(f, bb_source.addr, name_source, args_to_taint)
                    if buff_reach_sink and not sink_reached:
                        self._IPC_reach_sink += 1
                        sink_reached = True

                print "Total Time: " + str(time.time() - tot_time)
                print "Current safe paths: " + str(self.current_bin_safe_calls)
                print "Current unsafe paths: " + str(self.current_bin_unsafe_calls)
                print "Total safe paths: " + str(self.total_safe_calls)
                print "Total unsafe paths: " + str(self.total_unsafe_calls)
                print "Binary with IPC: " + str(self._bin_with_IPC)
                print "Binary with IPC reaching sinks: " + str(self._IPC_reach_sink)
                print "Binary Analyzed: " + str(self._total) + '\n'

                self.fp.write("Time: " + str(time.time() - bin_time)  + '\n')
                self.fp.write("Current safe paths: " + str(self.current_bin_safe_calls)  + '\n')
                self.fp.write("Current unsafe paths: " + str(self.current_bin_unsafe_calls)  + '\n')

                sum_res.write("Total safe paths: " + str(self.total_safe_calls) + '\n')
                sum_res.write("Total unsafe paths: " + str(self.total_unsafe_calls) + '\n')
                sum_res.write("Binaries with IPC: " + str(self._bin_with_IPC) + '\n')
                sum_res.write("Binaries with with IPC reaching sinks: " + str(self._IPC_reach_sink) + '\n')
                sum_res.write('Time: ' + str(time.time() - tot_time) + '\n')
                sum_res.write('Tot binaries analyzed: ' + str(self._total) + '\n')

                self.fp.close()
                print 'DONE binary: ' + b

            except Exception as e:
                print "Exception: " + str(e)
                pass

        sum_res.close()
        print 'Done.'

if __name__ == '__main__':
    obj = AlertTest()
    obj.parse_options()
    obj.run()

