from utils import *
import angr
import archinfo
import struct
import subprocess as sp
from binary_finder import *
import pickle
import sys
import numpy as np
import pickle
from sklearn.cluster import DBSCAN
import os
from os.path import dirname, abspath

sys.path.append(os.path.abspath(os.path.join(dirname(abspath(__file__)), '../../tool')))

from taint_analysis.utils import ordered_agument_regs, get_any_arguments_call
from forward_backward_taint_tracker import ForwardBackWardTaintTracker


angr.loggers.disable_root_logger()


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

MIN_STR_LEN = 3
STR_LEN = 255
ALLOWED_CHARS = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-/_'
EXTENDED_ALLOWED_CHARS = ALLOWED_CHARS + "%,.;+=_)(*&^%$#@!~`|<>{}[]"
WANTED_STR = ["REMOTE_ADDR", "username", "HTTP_", "boundary=", "Content-Type", "http_", "http", "query", "remote", "user-agent", "soap", "POST", "GET"]


def get_string(p, mem_addr, extended=True):
    bin_bounds = (p.loader.main_object.min_addr, p.loader.main_object.max_addr)

    # get string representation at mem_addr
    cnt = p.loader.memory.read_bytes(mem_addr, STR_LEN)
    string_1 = get_mem_string(cnt, extended=extended)
    string_2 = ''

    # check whether the mem_addr might contain an address
    try:
        endianess = '<I' if 'LE' in p.arch.memory_endness else '>I'
        tmp_addr = struct.unpack(
            endianess, ''.join(p.loader.memory.read_bytes(mem_addr, p.arch.bytes))
        )[0]
        if bin_bounds[0] <= tmp_addr <= bin_bounds[1]:
            cnt = p.loader.memory.read_bytes(tmp_addr, STR_LEN)
            string_2 = get_mem_string(cnt)
    except:
        pass

    # return the most probable string
    candidate = string_1 if len(string_1) > len(string_2) else string_2
    return candidate if len(candidate) >= MIN_STR_LEN else ''


def get_mem_string(mem_bytes, extended=False):
    tmp = ''
    chars = EXTENDED_ALLOWED_CHARS if extended else ALLOWED_CHARS

    for c in mem_bytes:

        if c not in chars:
            break
        tmp += c

    return tmp


class ParserFinder:
    def __init__(self, os_path, bb=0.5, bbr=0.4, cmp=0.7, use_network_metric=False, apply_multiplier=True):
        self.bb = bb
        self.bbr = bbr
        self.cmp = cmp
        self.use_network_metric = use_network_metric

        self.current_p = None
        self.current_cfg = None
        self.path = os_path
        self.bins = find_binaries(os_path)
        self.stats = {}
        self.str_shared = {}
        self.failed_bins = []
        self.current_bin = None
        # filter them: no libraries
        # this makes analysis faster
        self.bins = [b for f in FILTER for b in self.bins if b and f not in b]
        self.do_apply_multiplier = apply_multiplier
        self.apply_multiplier = {}
        self.apply_division = {}
        self.strs = {}
        self.network_data_is_checked = []
        self.candidates = {}
        self.all_candidates = {}
        self.clusters = []

    @staticmethod
    def get_matrix(data):
        matrix = []
        for i, i_val in enumerate(data):
            entry = []
            tot_len = 0
            for j, j_val in enumerate(data):
                entry.append(i_val - j_val)
            matrix.append(entry)
        return matrix

    def get_cluster(self):
        scores = sorted([(b, max(i['stats'])) for b, i in self.all_candidates.items()], key=lambda x: x[1], reverse=True)
        data = [s[1] for s in scores]
        X = np.matrix(ParserFinder.get_matrix(data))
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
        self.clusters = list(clusters)

    def shared_with_other_bins(self, st):
        cmd = 'grep {} {} {}'.format(st, self.path, ' '.join(self.bins))
        p = sp.Popen(cmd, stdout=sp.PIPE, stderr=sp.PIPE, stdin=sp.PIPE, shell=True)
        o, e = p.communicate()
        return len(o.split('\n')) - 1

    def get_function_stats(self, function):
        # FIXME: find a way to only consider if and not while-s
        # FIXME: consider semantically-equivalent strmcmp-s
        n_blocks = 0
        n_branch = 0
        n_memcmp = 0

        p = self.current_p
        cfg = self.current_cfg
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

                    # Get parameters values an check that one is astring and doesn't start with -
                    # note: to make the anlaysis faster, we only look for strings passed directly as arguments. Do a reach-def instead
                    arg1, arg2 = ordered_argument_regs[self.current_p.arch.name][:2]
                    args_cnt = [x for x in bb_block.vex.statements if x.tag == 'Ist_Put' and x.offset in (arg1, arg2)]
                    for arg_cnt in args_cnt:
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

                            st = get_string(self.current_p, con_addr.value)
                            if st:
                                n_memcmp += 1
                            if st and not st.startswith('-'):  # and self.shared_with_other_bins(st):
                                strs.append(st)
                                if any([s.lower() in st.lower() for s in WANTED_STR]):
                                    if self.current_bin not in self.apply_multiplier:
                                        self.apply_multiplier[self.current_bin] = {}
                                    if function.addr not in self.apply_multiplier[self.current_bin]:
                                        self.apply_multiplier[self.current_bin][function.addr] = 0

                                    self.apply_multiplier[self.current_bin][function.addr] += 1
            elif len(succs) > 1:
                # branch
                n_branch += 1

        return (n_blocks, n_branch, n_memcmp), strs

    def collect_stats(self, bins=None):
        for b in self.bins:
            print "Binary: " + str(b).split('/')[-1]
            if bins and b not in bins:
                continue
            network_data_reach_memcmp = False

            try:
                self.current_bin = b
                self.current_p = angr.Project(b, auto_load_libs=False)
                self.current_cfg = self.current_p.analyses.CFG()
            except Exception as e:
                self.failed_bins.append(b)
                continue

            bin_sources = self.find_sources_of_taint()
            bin_sinks = self.find_sinks_of_taint()

            for f_addr, f in self.current_cfg.functions.items():
                if self.use_network_metric:
                    f_sources = {f_addr:  []}
                    f_sinks = {f_addr: []}

                    if f_addr in bin_sources:
                        f_sources[f_addr] = [x for x in bin_sources[f_addr] if len(x[1]) == 2]
                    if f_addr in bin_sinks:
                        f_sinks[f_addr] = bin_sinks[f_addr]

                    if not network_data_reach_memcmp:
                        btt = ForwardBackWardTaintTracker(self.current_p, sources=f_sources, sinks=f_sinks)
                        network_data_reach_memcmp, perc_completed = btt.run()

                    if network_data_reach_memcmp and b not in self.network_data_is_checked:
                        self.network_data_is_checked.append(b)

                key = (b, f_addr)
                stats, strs = self.get_function_stats(f)
                self.stats[key] = stats

                if b not in self.strs:
                    self.strs[b] = []
                self.strs[b] += strs

    def print_stats(self, n, m):
        candidates = {}

        for (bin_name, f_addr), s in self.stats.items():
            if 0 in s:
                continue

            # 0: blocks
            # 1: branches
            # 2: memcmp
            # 3: socket data reach strcmp

            multiplier = 1
            if bin_name in self.network_data_is_checked:
                multiplier = 2

            t_val = (s[0] * self.bb + s[1] * self.bbr + s[2] * self.cmp) * multiplier
            if bin_name in self.apply_multiplier and f_addr in self.apply_multiplier[bin_name]:
                mul = 5 * self.apply_multiplier[bin_name][f_addr]
                if self.do_apply_multiplier:
                    t_val *= mul
            if bin_name in self.apply_division and f_addr in self.apply_division[bin_name]:
                div = 5 * self.apply_division[bin_name][f_addr]
                t_val /= div

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
        self.candidates = candidates

    def find_interesting_memcmp(self, function):
        p = self.current_p
        cfg = self.current_cfg
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

                    # Get parameters values an check that one is astring and doesn't start with -
                    # note: to make the anlaysis faster, we only look for strings passed directly as arguments. Do a reach-def instead
                    arg1, arg2 = ordered_argument_regs[self.current_p.arch.name][:2]
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
                                if not st.startswith('-'):  # and self.shared_with_other_bins(st):
                                    if any([s.lower() in st.lower() for s in WANTED_STR]):
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

    def find_sources_of_taint(self):
        # LIMITATION: this part only works for linux binaries so far
        p = self.current_p
        cfg = self.current_cfg
        sources = {}
        bb_call = []

        plt_addrs = [(x, y) for x, y in p.loader.main_object.plt.items() if 'recv' in x or 'read' in x]
        for f_name, plt_addr in plt_addrs:
            no = cfg.get_any_node(plt_addr)
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
                    off = ordered_agument_regs[p.arch.name][i]
                    regs.append(p.arch.register_names[off])

                sources[faddr].append((no.addr, tuple(regs)))

                # we go one level back
                n_f = cfg.get_any_node(faddr)
                preds  = n_f.predecessors
                for pred in preds:
                    nargs = len(get_any_arguments_call(p, pred.addr))
                    regs = []
                    for i in xrange(nargs):
                        off = ordered_agument_regs[p.arch.name][i]
                        regs.append(p.arch.register_names[off])

                    if pred.function_address not in sources:
                        sources[pred.function_address] = []
                    sources[pred.function_address].append((pred.addr, tuple(regs)))
            except Exception as e:
                print str(e)

        for k in sources:
            sources[k] = list(set(sources[k]))

        return sources

    def find_sinks_of_taint(self):
        cfg = self.current_cfg
        sinks = {}
        for function in cfg.functions.values():
            res = self.find_interesting_memcmp(function)
            if res[function.addr]:
                sinks.update(res)
        return sinks

    def get_bins(self):
        return self.candidates#.keys()

    def get_strs(self, start=None, end=None, ):
        if end and start:
            return WANTED_STR[start:end]
        if start:
            return WANTED_STR[start:]
        if end:
            return WANTED_STR[:end]
        return WANTED_STR

    def run(self, pickle_file=None, pname=None, bins=None):
        if pickle_file and os.path.isfile(pickle_file):
            with open(pickle_file) as fp:
                self.candidates, self.stats, self.strs, self.apply_multiplier = pickle.load(fp)
        else:
            if pname is None:
                abs_path = os.path.abspath(__file__)
                pickle_dir = '/'.join(abs_path.split('/')[:-5]) + '/pickles/parser/'
                rel_pname = self.path.replace('./firmware/', '').replace('/', '_').replace('.', '')[2:]
                vendor = self.path.split('/')[4]
                if not os.path.exists(pickle_dir + vendor):
                    os.makedirs(pickle_dir + vendor)
                pname = pickle_dir + vendor + '/' + rel_pname + '.pk'

            self.collect_stats(bins)
            self.print_stats(50000, 50000)
            fp = open(pname, 'w')
            pickle.dump((self.candidates, self.stats, self.strs, self.apply_multiplier), fp)
            print "Candidates pickled in " + pname
            fp.close()

        self.all_candidates = dict(self.candidates)

        if not self.all_candidates:
            return []

        self.get_cluster()
        self.candidates = self.clusters[0]

        return self.candidates


if __name__ == "__main__":
    path = sys.argv[1]
    if path == 'create_pickle':
        path = sys.argv[2]
        pname = sys.argv[3]
        pf = ParserFinder(path)
        pf.run(pname=pname)
    else:
        node_pickle = None
        if len(sys.argv) == 3:
            node_pickle = sys.argv[2]
        pf = ParserFinder(path)
        pf.run(pickle_file=node_pickle)
        print str(pf.candidates)

        import ipdb; ipdb.set_trace()
