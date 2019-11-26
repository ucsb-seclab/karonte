"""
    This module finds the network parsers within a firmware sample.
"""

import angr
import time
import struct
import sys
import pickle
import os
import logging
import numpy as np
from sklearn.cluster import DBSCAN

from utils import *
from binary_finder import *
from os.path import dirname, abspath

sys.path.append(os.path.abspath(os.path.join(dirname(abspath(__file__)), '../../tool')))
from taint_analysis.utils import ordered_argument_regs, get_any_arguments_call
from forward_backward_taint_tracker import ForwardBackWardTaintTracker

# logging.basicConfig()
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
    cnt = p.loader.memory.read_bytes(mem_addr, STR_LEN)
    string_1 = get_mem_string(cnt, extended=extended)
    string_2 = ''
    string_3 = ''
    string_4 = ''

    # check whether the mem_addr might contain an address
    # or the string is referenced by offset to the .got (yep, this happens)
    try:
        endianess = '<I' if 'LE' in p.arch.memory_endness else '>I'
        ind_addr = struct.unpack(
            endianess, ''.join(p.loader.memory.read_bytes(mem_addr, p.arch.bytes))
        )[0]
        if bin_bounds[0] <= ind_addr <= bin_bounds[1]:
            cnt = p.loader.memory.read_bytes(ind_addr, STR_LEN)
            string_2 = get_mem_string(cnt)

        tmp_addr = (ind_addr + p.loader.main_object.sections_map['.got'].min_addr) & (2 ** p.arch.bits - 1)
        cnt = p.loader.memory.read_bytes(tmp_addr, STR_LEN)
        string_3 = get_mem_string(cnt)

        tmp_addr = (mem_addr + p.loader.main_object.sections_map['.got'].min_addr) & (2 ** p.arch.bits - 1)
        cnt = p.loader.memory.read_bytes(tmp_addr, STR_LEN)
        string_4 = get_mem_string(cnt)

    except:
        pass

    # return the most probable string
    candidate = string_1 if len(string_1) > len(string_2) else string_2
    candidate2 = string_3 if len(string_3) > len(string_4) else string_4
    candidate = candidate if len(candidate) > len(candidate2) else candidate2

    return candidate if len(candidate) >= MIN_STR_LEN else ''


def get_mem_string(mem_bytes, extended=False):
    """
    Get string from a list of bytes
    
    :param mem_bytes: list of bytes
    :param extended: consider extended characters
    :return:  the string
    """
    
    tmp = ''
    chars = EXTENDED_ALLOWED_CHARS if extended else ALLOWED_CHARS

    for c in mem_bytes:

        if c not in chars:
            break
        tmp += c

    return tmp


class BorderBinariesFinder:
    """
    Find parser binaries within a firmware sample    
    """
    def __init__(self, fw_path, bb=0.5, bbr=0.4, cmp=0.7, use_connection_mark=True, use_network_mark=True,
                 logger_obj=None):
        """
        Initialization function
        
        :param fw_path:  firmware sample path
        :param bb: multiplier for number of basic block (leave to default value to optimal results)
        :param bbr: multiplier for number of branches (leave to default value to optimal results) 
        :param cmp: multiplier for number of comparisons (leave to default value to optimal results)
        :param use_connection_mark: apply network metric (True gives more accurate results, but it might be slower)
        :param apply_multiplier: apply network metric
        :param logger_obj: logger object to... log
        """

        global log

        if logger_obj:
            log = logger_obj

        self._bb = bb
        self._bbr = bbr
        self._cmp = cmp
        self._use_connection_mark = use_connection_mark
        self._tot_fw_bb = {}

        self._current_p = None
        self._current_cfg = None
        self._fw_path = fw_path
        self._bins = find_binaries(fw_path)
        self._stats = {}
        self._current_bin = None

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
                entry.append(i_val - j_val)
            matrix.append(entry)
        return matrix

    @staticmethod
    def _get_first_cluster(binaries):
        """
        Performs DBSCAN using the parsing score on the candidate parsers, and retrieve the cluster with the highest 
        parsing score.
        
        :return: the parser with the highest parsing score 
        """

        if not binaries.items():
            return []

        scores = sorted([(b, max(i['stats'])) for b, i in binaries.items()], key=lambda x: x[1], reverse=True)
        data = [s[1] for s in scores]
        X = np.matrix(BorderBinariesFinder.get_matrix(data))
        labels = list(DBSCAN(metric='precomputed').fit(X).labels_)
        clusters = []
        new_c = []
        old_l = 0
        index = 0

        for l in labels:
            b = scores[index][0]
            if old_l != l:
                clusters.append(new_c)
                new_c = []

            new_c.append(b)
            old_l = l
            index += 1

        # all in one cluster?
        if not clusters and new_c:
            clusters.append(new_c)

        # DBSCAN labels "noisy" data as -1
        # if we do not have any valid cluster, we take the
        # highest-score binary
        if not any([a for a in clusters if a]) and not any(l != -1 for l in labels):
            clusters = [[scores[0][0]]]

        return list(set(list(clusters)[0]))

    @property
    def border_binaries(self):
        return self._border_binaries

    def get_total_bins_fw(self):
        """
        Get the binaries within a firmware sample.
        
        :return: Binaries within a firmware sample
        """
        
        return self._bins

    def _get_function_stats(self, function):
        """
        Retrieves the number of basic blocks, number of memory comparisons, and number of branches
        :param function: angr function

        :return: number of basic blocks, number of memory comparisons, and number of branches in the function
        """

        n_blocks = 0
        n_branch = 0
        n_memcmp = 0

        p = self._current_p
        cfg = self._current_cfg
        strs = []

        for block_addr in function.block_addrs:
            n_blocks += 1

            try:
                bb_block = p.factory.block(block_addr)
                cfg_node = cfg.get_any_node(block_addr)
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

                if succ.addr in p.loader.main_bin.reverse_plt.keys() and \
                        hasattr(succ, 'name') and any([n in succ.name for n in CMP_SUCCS if succ.name]):

                    for con_addr in bb_block.vex.all_constants:
                        if con_addr is not None:
                            st = get_string(self._current_p, con_addr.value)
                            if st:
                                n_memcmp += 1
                            if st and not st.startswith('-'):
                                strs.append(st)
                                if any([s.lower() in st.lower() for s in NETWORK_KEYWORDS]) or \
                                        any([s in st for s in CASE_SENS_NETWORK_KEYWORDS]):
                                    if self._current_bin not in self._multiplier:
                                        self._multiplier[self._current_bin] = {}
                                    if function.addr not in self._multiplier[self._current_bin]:
                                        self._multiplier[self._current_bin][function.addr] = 0

                                    self._multiplier[self._current_bin][function.addr] += 1
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
        
        for b in self._bins:
            log.info("Binary: " + str(b).split('/')[-1])
            if bins and b not in bins:
                continue
            network_data_reach_memcmp = False

            try:
                self._current_bin = b
                self._current_p = angr.Project(b, auto_load_libs=False)
                self._current_cfg = self._current_p.analyses.CFG()
                self._tot_fw_bb[b] = len(self._current_cfg.nodes())
            except:
                continue

            bin_sources = self._find_sources_of_taint()
            bin_sinks = self._find_sinks_of_taint()

            for f_addr, f in self._current_cfg.functions.items():
                if self._use_connection_mark:
                    log.info("Using network metric")
                    f_sources = {f_addr:  []}
                    f_sinks = {f_addr: []}

                    if f_addr in bin_sources:
                        f_sources[f_addr] = [x for x in bin_sources[f_addr] if len(x[1]) == 2]
                    if f_addr in bin_sinks:
                        f_sinks[f_addr] = bin_sinks[f_addr]

                    if not network_data_reach_memcmp:
                        btt = ForwardBackWardTaintTracker(self._current_p, sources=f_sources, sinks=f_sinks)
                        network_data_reach_memcmp, perc_completed = btt.run()

                    if network_data_reach_memcmp and b not in self._network_data_is_checked:
                        self._network_data_is_checked.append(b)

                key = (b, f_addr)
                self._stats[key] = self._get_function_stats(f)

    # TODO: remove n and m, they are a useless optimization
    def _apply_parsing_score(self, n, m):
        """
        Apply parsing scores to each function of each binary, and retrieve superset of parsing candidates
        
        :param n:
        :param m: 
        :return: 
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

            if bin_name in candidates:
                i_min = candidates[bin_name]['stats'].index(min(candidates[bin_name]['stats']))
                if t_val > candidates[bin_name]['stats'][i_min]:
                    candidates[bin_name]['stats'][i_min] = t_val
                    candidates[bin_name]['addr'][i_min] = f_addr

            elif len(candidates.keys()) < n:
                candidates[bin_name] = {'stats': [0] * m, 'addr': [0] * m}
                candidates[bin_name]['stats'][0] = t_val
                candidates[bin_name]['addr'][0] = f_addr

            else:
                ord_cand = sorted([(b, max(info['stats'])) for b, info in candidates.items()], key=lambda x: x[1])
                if t_val > ord_cand[0][1]:
                    del candidates[ord_cand[0][0]]
                    candidates[bin_name] = {'stats': [0] * m, 'addr': [0] * m}
                    candidates[bin_name]['stats'][0] = t_val
                    candidates[bin_name]['addr'][0] = f_addr
        self._candidates = candidates

    def _find_interesting_memcmp(self, function):
        """
        Find memory comparison in a function that use network-related strings

        :param function: angr function
        :return: memory comparisons info
        """

        p = self._current_p
        cfg = self._current_cfg
        interesting_memcmp = {function.addr: []}

        for block_addr in function.block_addrs:
            candidate_str = None
            candidate_glob_addr = None
            candidate_local_var_reg = None

            try:
                bb_block = p.factory.block(block_addr)
                cfg_node = cfg.get_any_node(block_addr)
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

                if succ.addr in p.loader.main_bin.reverse_plt.keys() and \
                        hasattr(succ, 'name') and any([n in succ.name for n in CMP_SUCCS if succ.name]):

                    # Get parameters values and check whether there is any string
                    arg1, arg2 = ordered_argument_regs[self._current_p.arch.name][:2]
                    args_cnt = [x for x in bb_block.vex.statements if x.tag == 'Ist_Put' and x.offset in (arg1, arg2)]
                    for n_ord, arg_cnt in enumerate(args_cnt):
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
                            st = get_string(p, con_addr.value)
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
                            candidate_local_var_reg = p.arch.register_names[ordered_argument_regs[p.arch.name][n_ord]]

            if candidate_str and (candidate_glob_addr or candidate_local_var_reg):
                interesting_memcmp[function.addr].append((block_addr, candidate_local_var_reg, candidate_glob_addr))

            elif len(succs) > 1:
                pass

        return interesting_memcmp

    def _find_sources_of_taint(self):
        """
        Find source of taint in a Linux binary (recv, and reads)

        :return: a list of sources
        """

        # LIMITATION: this part only works for linux binaries so far
        p = self._current_p
        cfg = self._current_cfg
        sources = {}
        bb_call = []

        plt_addrs = [(x, y) for x, y in p.loader.main_object.plt.items() if 'recv' in x or 'read' in x]
        for f_name, plt_addr in plt_addrs:
            no = cfg.get_any_node(plt_addr)
            if no:
                bb_call += [pred.addr for pred in no.predecessors]

        for bb in bb_call:
            try:
                no = cfg.get_any_node(bb)
                faddr = no.function_address
                if faddr not in sources:
                    sources[faddr] = []
                nargs = len(get_any_arguments_call(p, no.addr))
                regs = []
                for i in xrange(nargs):
                    off = ordered_argument_regs[p.arch.name][i]
                    regs.append(p.arch.register_names[off])

                sources[faddr].append((no.addr, tuple(regs)))

                # we go one level back
                n_f = cfg.get_any_node(faddr)
                preds = n_f.predecessors
                for pred in preds:
                    nargs = len(get_any_arguments_call(p, pred.addr))
                    regs = []
                    for i in xrange(nargs):
                        off = ordered_argument_regs[p.arch.name][i]
                        regs.append(p.arch.register_names[off])

                    if pred.function_address not in sources:
                        sources[pred.function_address] = []
                    sources[pred.function_address].append((pred.addr, tuple(regs)))
            except Exception as e:
                log.debug(str(e))

        for k in sources:
            sources[k] = list(set(sources[k]))

        return sources

    def _find_sinks_of_taint(self):
        """
        Find sinks of taint (i.e., memcmp-like functions)

        :return: list of sinks
        """

        cfg = self._current_cfg
        sinks = {}
        for f in cfg.functions.values():
            res = self._find_interesting_memcmp(f)
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
        Pickle this module resutls

        :param pickle_file: path to pickle file
        """

        # TODO: create directories that do not already exist in pickle_file
        log.info("Candidates pickled in " + pickle_file)

        fp = open(pickle_file, 'w')
        pickle.dump((self._candidates, self._stats, self._multiplier), fp)
        fp.close()

    def analysis_time(self):
        """
        Gets the analysis time

        :return: return the analysis time
        """

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
            with open(pickle_file) as fp:
                self._candidates, self._stats, self._multiplier = pickle.load(fp)
        else:
            if not pickle_file:
                abs_path = os.path.abspath(__file__)
                pickle_dir = '/'.join(abs_path.split('/')[:-3]) + '/pickles/parser/'
                rel_pickle_name = self._fw_path.replace('./firmware/', '').replace('/', '_').replace('.', '')
                vendor = self._fw_path.split('/')[2]

                if not os.path.exists(pickle_dir + vendor):
                    os.makedirs(pickle_dir + vendor)
                pickle_file = pickle_dir + vendor + '/' + rel_pickle_name + '.pk'

            self._collect_stats(bins)
            self._apply_parsing_score(50000, 50000)
            self._pickle_it(pickle_file)

        self._border_binaries = BorderBinariesFinder._get_first_cluster(self._candidates)
        self._end_time = time.time()

        return self._border_binaries


#
# this is use for testing purpose
#

if __name__ == "__main__":

    path = sys.argv[1]
    if path == 'create_pickle':
        path = sys.argv[2]
        pname = sys.argv[3]
        pf = BorderBinariesFinder(path)
        pf.run(pickle_file=pname)
    else:
        node_pickle = None
        if len(sys.argv) == 3:
            node_pickle = sys.argv[2]
        pf = BorderBinariesFinder(path)
        bb = pf.run(pickle_file=node_pickle)
        print str(bb)
