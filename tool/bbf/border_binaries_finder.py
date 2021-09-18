"""
    This module finds the network parsers within a firmware sample.
"""
import logging
import os
import pickle
import struct
import time
from functools import partial
from multiprocessing import Pool

import angr
import numpy as np
from archinfo import Endness
from sklearn.cluster import DBSCAN

from loggers import bar_logger
from bbf.binary_finder import *
from bbf.forward_backward_taint_tracker import ForwardBackWardTaintTracker
from bbf.utils import *
from config import *
from taint_analysis.utils import arg_reg_off, arg_reg_names, get_arity
from bdg.utils import get_mem_string
from bdg.cpfs import LIB_KEYWORD

# logging.basicConfig()
from utils import MAX_THREADS, DEFAULT_PICKLE_DIR

log = logging.getLogger("BorderBinariesFinder")
log.setLevel("DEBUG")

angr.loggers.disable_root_logger()
angr.logging.disable(logging.ERROR)


def get_string(p, mem_addr, extended=True):
    """
    Get string from a memory address
    :param p: angr project
    :param mem_addr: memory address
    :param extended: consider extended characters
    :return: the candidate string
    """

    bin_bounds = (p.loader.main_object.min_addr, p.loader.main_object.max_addr)

    # get string representation at mem_addr
    try:
        cnt = p.loader.memory.load(mem_addr, STR_LEN)
    except KeyError:
        # this memory address is not readable
        cnt = ''
    string_1 = get_mem_string(cnt, extended=extended)
    string_2 = ''
    string_3 = ''
    string_4 = ''

    # check whether the mem_addr might contain an address
    # or the string is referenced by offset to the .got (yep, this happens)
    try:
        endianness = 'little' if p.arch.memory_endness == Endness.LE else 'big'
        ind_addr = int.from_bytes(p.loader.memory.load(mem_addr, p.arch.bytes), endianness)
        if bin_bounds[0] <= ind_addr <= bin_bounds[1]:
            cnt = p.loader.memory.load(ind_addr, STR_LEN)
            string_2 = get_mem_string(cnt)

        tmp_addr = (ind_addr + p.loader.main_object.sections_map['.got'].min_addr) & (2 ** p.arch.bits - 1)
        cnt = p.loader.memory.load(tmp_addr, STR_LEN)
        string_3 = get_mem_string(cnt)

        tmp_addr = (mem_addr + p.loader.main_object.sections_map['.got'].min_addr) & (2 ** p.arch.bits - 1)
        cnt = p.loader.memory.load(tmp_addr, STR_LEN)
        string_4 = get_mem_string(cnt)

    except KeyError as e:
        pass

    # return the most probable string
    candidate = string_1 if len(string_1) > len(string_2) else string_2
    candidate2 = string_3 if len(string_3) > len(string_4) else string_4
    candidate = candidate if len(candidate) > len(candidate2) else candidate2

    return candidate if len(candidate) >= MIN_STR_LEN else ''


class BorderBinariesFinder:
    """
    Find parser binaries within a firmware sample
    """

    def __init__(self, fw_path, bb_m=0.5, bbr_m=0.4, cmp_m=0.7, use_connection_mark=True, use_network_mark=True,
                 logger_obj=None):
        """
        Initialization function

        :param fw_path:  firmware sample path
        :param bb_m: multiplier for number of basic block (leave to default value to optimal results)
        :param bbr_m: multiplier for number of branches (leave to default value to optimal results)
        :param cmp_m: multiplier for number of comparisons (leave to default value to optimal results)
        :param use_connection_mark: apply network metric (True gives more accurate results, but it might be slower)
        :param use_network_mark: apply network metric
        :param logger_obj: logger object to... log
        """

        global log

        if logger_obj:
            log = logger_obj

        self._bb = bb_m
        self._bbr = bbr_m
        self._cmp = cmp_m
        self._use_connection_mark = use_connection_mark
        self._tot_fw_bb = {}

        self._fw_path = fw_path
        self._bins = find_binaries(fw_path)
        self._stats = {}

        self._use_network_mark = use_network_mark
        self._multiplier = {}
        self._network_data_is_checked = []
        self._candidates = {}
        self._border_binaries = []
        self._clusters = []

        # stats vars
        self._start_time = None
        self._end_time = None

    @staticmethod
    def get_network_keywords(start=None, end=None, ):
        """
        Return the list of network strings used by this module
        :param start: start
        :param end: end
        :return:list of strings
        """
        return NETWORK_KEYWORDS[start:end]

    @staticmethod
    def get_matrix(data):
        matrix = []
        for i, i_val in enumerate(data):
            entry = []
            for j, j_val in enumerate(data):
                entry.append(abs(i_val - j_val))
            matrix.append(entry)
        return matrix

    @staticmethod
    def _get_first_cluster(binaries):
        """
        Performs DBSCAN using the parsing score on the candidate parsers, and retrieve the cluster with the highest
        parsing score.

        :return: the parser with the highest parsing score
        """
        # TODO, this is not correctly implemented. I updated this to get it to return at least something.
        if not binaries.items():
            return []

        scores = sorted([(b, max(i['stats'])) for b, i in binaries.items()], key=lambda x: x[1], reverse=True)
        data = [s[1] for s in scores]
        # use a logarithmic scale, to make some of them fit with a bit larger epsilon than usual
        data_log = np.log(data)
        reshaped_data = np.array(data_log).reshape(-1, 1)
        labels = list(DBSCAN(eps=1).fit(reshaped_data).labels_)

        # DBSCAN labels "noisy" data as -1
        # if the first binary is invalid, we take the top 5 binaries
        # print(scores)
        # print(labels)
        num_bins_to_take = 5
        if labels[0] == -1:
            return [score[0] for score in scores[:num_bins_to_take]]

        # otherwise we take all binaries with the same label as the highest scoring binary
        label_highest = labels[0]
        return [scores[i][0] for i, label in enumerate(labels) if label == label_highest]

    @property
    def border_binaries(self):
        return self._border_binaries

    def get_total_bins_fw(self):
        """
        Get the binaries within a firmware sample.

        :return: Binaries within a firmware sample
        """
        return self._bins

    @staticmethod
    def _get_function_stats(function, p, cfg, multiplier):
        """
        Retrieves the number of basic blocks, number of memory comparisons, and number of branches
        :param function: angr function
        :param p: the project
        :param cfg: the control flow graph
        :param multiplier: multiplier for calculating the parsing score
        :return: number of basic blocks, number of memory comparisons, and number of branches in the function
        """
        n_blocks = 0
        n_branch = 0
        n_memcmp = 0

        strs = []

        for block_addr in function.block_addrs:
            n_blocks += 1

            # initialize the multiplier for this function
            if function.addr not in multiplier:
                multiplier[function.addr] = 0

            try:
                bb_block = p.factory.block(block_addr)
                cfg_node = cfg.model.get_any_node(block_addr)
                succs = cfg_node.successors
            except:
                continue

            if not succs:
                # we look either for calls or
                # branching blocks. A block with not successor
                # is not interesting
                continue

            if bb_block.vex.jumpkind == 'Ijk_Call':
                # call
                succ = succs[0]
                name = p.loader.find_plt_stub_name(succ.addr)
                if any([n in name for n in CMP_SUCCS if name]):
                    for con_addr in bb_block.vex.all_constants:
                        if con_addr is not None:
                            st = get_string(p, con_addr.value)
                            if st:
                                n_memcmp += 1
                            if st and not st.startswith('-'):
                                strs.append(st)
                                if any([s.lower() in st.lower() for s in NETWORK_KEYWORDS]) or \
                                        any([s in st for s in CASE_SENS_NETWORK_KEYWORDS]):
                                    # add the address to the multiplier if it does not exist
                                    multiplier[function.addr] += 1
            elif len(succs) > 1:
                # branch
                n_branch += 1

        return n_blocks, n_branch, n_memcmp

    def _collect_stats(self, bins=None):
        """
        Collect statistic (number of basic block, branches, memory comparisons, and connection and network marks) of
        a list of binaries

        :param bins: binaries (leave to None to consider all the binaries within a firmware sample)
        :return: None
        """
        process_pool = Pool(MAX_THREADS)  # number of processes
        func = partial(self._collect_stats_bin_thread, use_connection_mark=self._use_connection_mark, bins=bins)
        output = process_pool.map(func, self._bins)
        process_pool.close()  # do not feed more work to the workers than
        process_pool.join()  # wait for all processes to finish

        # alternative without pools for easier debugging
        # func = partial(self._collect_stats_bin_thread, use_connection_mark=self._use_connection_mark, bins=bins)
        # output = map(func, self._bins)

        # add the calculated outputs to the class entries
        for entry in [x for x in output if x]:
            b, bin_sources, bin_sinks, stats, multiplier, tot_bb, network_data_is_checked = entry
            self._stats.update(stats)
            self._multiplier[b] = multiplier
            self._tot_fw_bb[b] = tot_bb
            # only add the binary if the data from a source reached a sink
            if network_data_is_checked:
                self._network_data_is_checked.append(b)

    @staticmethod
    def _collect_stats_bin_thread(b, use_connection_mark, bins=None):
        """
        This method can be started as a thread to speed up the analysis
        :param b: the binary
        :param bins: binaries (leave to None to consider all the binaries within a firmware sample)
        :return: None
        """
        log.info(f"Binary: {os.path.basename(b)}")
        if bins and b not in bins:
            return
        network_data_reach_memcmp = False

        try:
            p = angr.Project(b, auto_load_libs=False)
        except:
            return

        # As a speed optimization, we will first check if there are actually sinks. Those cannot be a border binary
        # otherwise we will skip the generation of the cfg and stats. This is a significant speedup
        # we will also skip libraries, since those are never the border binaries
        items = [(x, y) for x, y in p.loader.main_object.plt.items() if any(s_m in x for s_m in CMP_SUCCS)]
        if LIB_KEYWORD in b or not items:
            log.debug(f"Skipped generation of CFG: {os.path.basename(b)}")
            return

        try:
            cfg = p.analyses.CFG()
            tot_bb = len(cfg.model.nodes())
        except:
            return

        bin_sources = BorderBinariesFinder._find_sources_of_taint(p, cfg)
        bin_sinks = BorderBinariesFinder._find_sinks_of_taint(p, cfg)

        reached_memcmp = False
        stats = {}
        multiplier = {}

        for f_addr, f in cfg.functions.items():
            key = (b, f_addr)

            if use_connection_mark:
                # log.info(f"{os.path.basename(str(b))}: Using network metric")
                f_sources = {f_addr: []}
                f_sinks = {f_addr: []}

                if f_addr in bin_sources:
                    # TODO check if this comparison in the if needs to exist
                    f_sources[f_addr] = [x for x in bin_sources[f_addr] if len(x[1]) == 2]
                if f_addr in bin_sinks:
                    f_sinks[f_addr] = bin_sinks[f_addr]

                # skip if there are no interesting memcmps
                if not f_sinks[f_addr]:
                    stats[key] = (0, 0, 0)
                    continue

                # taint analysis is only useful when there are sources and sinks, so skip if either one is empty
                if not network_data_reach_memcmp and f_sources[f_addr] and f_sinks[f_addr]:
                    btt = ForwardBackWardTaintTracker(p, cfg.copy(), sources=f_sources, sinks=f_sinks)
                    network_data_reach_memcmp, _ = btt.run()

                # store if this binary reached a memcmp operation
                reached_memcmp = reached_memcmp or network_data_reach_memcmp

            stats[key] = BorderBinariesFinder._get_function_stats(f, p, cfg, multiplier)

        # the thread needs to return all changed information so that we can store it in the class
        return b, bin_sources, bin_sinks, stats, multiplier, tot_bb, reached_memcmp

    def _apply_parsing_score(self):
        """
        Apply parsing scores to each function of each binary, and retrieve superset of parsing candidates
        """
        candidates = {}

        for (bin_name, f_addr), s in self._stats.items():
            if 0 in s:
                continue

            # 0: blocks
            # 1: branches
            # 2: memcmp
            # 3: socket data reach strcmp

            multiplier = 1
            if bin_name in self._network_data_is_checked:
                multiplier = 2

            t_val = (s[0] * self._bb + s[1] * self._bbr + s[2] * self._cmp) * multiplier
            if bin_name in self._multiplier and f_addr in self._multiplier[bin_name]:
                mul = 5 * self._multiplier[bin_name][f_addr]
                if self._use_network_mark:
                    t_val *= mul

            if t_val > 0:
                if bin_name not in candidates:
                    candidates[bin_name] = {'stats': list(), 'addr': list()}

                candidates[bin_name]['stats'].append(t_val)
                candidates[bin_name]['addr'].append(f_addr)

        self._candidates = candidates

    @staticmethod
    def _find_interesting_memcmp(function, p, cfg):
        """
        Find memory comparison in a function that use network-related strings
        :param function: angr function
        :return: memory comparisons info
        """

        interesting_memcmp = {function.addr: []}

        for block_addr in function.block_addrs:
            candidate_str = None
            candidate_glob_addr = None
            candidate_local_var_reg = None

            try:
                bb_block = p.factory.block(block_addr)
                cfg_node = cfg.model.get_any_node(block_addr)
                succs = cfg_node.successors
            except:
                continue

            if not succs:
                # we look either for calls or
                # branching blocks. A block with not successor
                # is not interesting
                continue

            if bb_block.vex.jumpkind == 'Ijk_Call':
                # call
                succ = succs[0]

                name = p.loader.find_plt_stub_name(succ.addr)
                if any([n in name for n in CMP_SUCCS if name]):

                    # Get parameters values and check whether there is any string
                    arg1, arg2 = (arg_reg_off(p, 0), arg_reg_off(p, 1))
                    args_cnt_list = [x for x in bb_block.vex.statements if x.tag == 'Ist_Put'
                                     and x.offset in (arg1, arg2)]
                    for arg_cnt in args_cnt_list:
                        con_addr = None
                        if hasattr(arg_cnt.data, 'tmp'):
                            tmp_index = arg_cnt.data.tmp
                            tmp = [x for x in bb_block.vex.statements if x.tag == 'Ist_WrTmp' and x.tmp == tmp_index]
                            if not tmp:
                                continue
                            tmp = tmp[0]
                            if tmp.data.constants:
                                con_addr = tmp.data.constants[0]

                        elif hasattr(arg_cnt.data, 'constants'):
                            con_addr = arg_cnt.data.constants[0]

                        if con_addr is not None:
                            # then if it's a string

                            st = get_string(p, con_addr.value, extended=False)
                            if st:
                                if not st.startswith('-'):
                                    if any([s.lower() in st.lower() for s in NETWORK_KEYWORDS]) or \
                                            any([s in st for s in CASE_SENS_NETWORK_KEYWORDS]):
                                        candidate_str = st
                            else:
                                # first check if it's an address pointing to glob memory
                                # (i.e., not the stack nor heap)
                                # let's assume it's a data pointer then
                                candidate_glob_addr = con_addr.value
                        else:
                            candidate_local_var_reg = p.arch.register_names[arg_cnt.offset]

            if candidate_str and (candidate_glob_addr or candidate_local_var_reg):
                interesting_memcmp[function.addr].append((block_addr, candidate_local_var_reg, candidate_glob_addr))

            elif len(succs) > 1:
                pass

        return interesting_memcmp

    @staticmethod
    def _find_sources_of_taint(p, cfg):
        """
        Find sources of taint
        :return: addresses of taintable basic blocks and the registers that are used
        as inputs
        """
        # methods to discover that are sources of taint
        source_methods = ['read, recv']
        # source_methods = ['scanf']

        # LIMITATION: this part only works for linux binaries so far
        sources = {}
        bb_call = []

        # find all basic blocks containing the methods we are looking for
        plt_addrs = [(x, y) for x, y in p.loader.main_object.plt.items() if any(s_m in x for s_m in source_methods)]
        # retrieve the basic block of the call
        for f_name, plt_addr in plt_addrs:
            no = cfg.model.get_any_node(plt_addr)
            if no:
                bb_call += [pred.addr for pred in no.predecessors]

        # for each basic block and predecessor discover the registers
        # providing input to the methods
        for b_block in bb_call:
            try:
                no = cfg.model.get_any_node(b_block)
                faddr = no.function_address
                if faddr not in sources:
                    sources[faddr] = []
                regs = arg_reg_names(p, get_arity(p, no.addr))

                sources[faddr].append((no.addr, tuple(regs)))

                # we go one level back
                n_f = cfg.model.get_any_node(faddr)
                preds = n_f.predecessors
                for pred in preds:
                    regs = arg_reg_names(p, get_arity(p, pred.addr))

                    if pred.function_address not in sources:
                        sources[pred.function_address] = []
                    sources[pred.function_address].append((pred.addr, tuple(regs)))
            except Exception as e:
                log.error(f"BBF: Error encountered when discovering input registers: {e}")

        for k in sources:
            sources[k] = list(set(sources[k]))

        return sources

    @staticmethod
    def _find_sinks_of_taint(p, cfg):
        """
        Find sinks of taint (i.e., memcmp-like functions)
        :return: list of sinks
        """

        sinks = {}
        for f in cfg.functions.values():
            res = BorderBinariesFinder._find_interesting_memcmp(f, p, cfg)
            if res[f.addr]:
                sinks.update(res)
        return sinks

    def get_border_binaries(self):
        """
        Return a list of parser binaries
        :return: list of parser binaries
        """

        return self._candidates

    def get_bb_fw(self):
        """
        Get the number of basic blocs in a firmware sample
        :return: Number of basic blocs in a firmware sample
        """

        return self._tot_fw_bb

    def _pickle_it(self, pickle_file):
        """
        Pickle this module results
        :param pickle_file: path to pickle file
        """
        log.info(f"Candidates pickled in {pickle_file}")

        pickle_dir = '/'.join(pickle_file.split('/')[:-1])
        if not os.path.exists(pickle_dir):
            os.makedirs(pickle_dir)

        fp = open(pickle_file, 'wb')
        pickle.dump((self._candidates, self._stats, self._multiplier), fp)
        fp.close()

    def analysis_time(self):
        """
        Gets the analysis time
        :return: return the analysis time
        """
        if not self._end_time or self._start_time:
            return 0
        return self._end_time - self._start_time

    def run(self, pickle_file=None, bins=None):
        """
        Run the this module algorithm
        :param pickle_file: path to pickle file
        :param bins: binaries to consider
        :return: the list of border binaries
        """

        self._start_time = time.time()
        if pickle_file and os.path.isfile(pickle_file):
            with open(pickle_file, 'rb') as fp:
                self._candidates, self._stats, self._multiplier = pickle.load(fp)
        else:
            if not pickle_file:
                pickle_dir = DEFAULT_PICKLE_DIR
                rel_pickle_name = self._fw_path.replace('/', '_').replace('.', '')
                pickle_file = pickle_dir + '/' + rel_pickle_name + '.pk'

            self._collect_stats(bins)
            self._apply_parsing_score()
            self._border_binaries = BorderBinariesFinder._get_first_cluster(self._candidates)
            self._pickle_it(pickle_file)

        self._end_time = time.time()
        log.info(f"The discovered border binaries are: {self._border_binaries}")
        return self._border_binaries
