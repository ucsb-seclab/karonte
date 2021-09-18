import signal
import time
from bdg.bdp_enum import RoleInfo, Role
from loggers.utils import *
import json
import copy
import os


class FileLogger:
    def __init__(self, fw, filename):
        self._fw = fw
        self._filename = filename
        self._logged_paths = set()
        self._start_time = None
        self._end_time = None
        self._complexity = {}
        self._fp = open(filename, "w")

    def handler(self, signum, frame):
        raise Exception("Get out")

    # FIXME add paper reference
    def _get_binary_complexity(self, node):
        """
        Retrieve the path complexity of a binary
        :param node: BDG node
        :return: the binary complexity
        """

        if node.bin in self._complexity:
            return self._complexity[node.bin]

        self._complexity[node.bin] = lambda x: -1
        cfg = node.cfg
        fun_sizes = [len(f.block_addrs_set) for f in cfg.functions.values()]
        avg_size = sum(fun_sizes) / len(fun_sizes)
        i = 0

        while True:
            new_size = avg_size - i
            if new_size < 0:
                break

            fs = [f for f in cfg.functions.values() if len(f.graph.edges()) >= new_size]
            f = min(fs, key=lambda x: len(x.graph.edges()))
            signal.signal(signal.SIGALRM, self.handler)
            signal.alarm(60)

            try:
                _, u = get_path_n(f)
                signal.alarm(0)
                self._complexity[node.bin] = u
                break
            except:
                print("Timeout triggered")
                self._complexity[node.bin] = lambda x: -1
                i += 1
        return self._complexity[node.bin]

    def _get_n_paths(self, node, n_path):
        """
        Get the total number of paths of a binary

        :param node: BDG node
        :param n_path: number of basic blocks in the longest path
        :return: the number of paths in a binary
        """

        try:
            complexity = self._get_binary_complexity(node)
            return complexity(n_path)
        except:
            return 0

    @property
    def name(self):
        return self._filename

    def start_logging(self):
        """
        Starts logging

        :return: None
        """
        self._start_time = time.time()

        self.log_line("General info\n")
        self.log_line("======================\n\n")
        self.log_line(f"Firmware path: {self._fw}\n")
        self.log_line(f"Firmware name: {os.path.basename(self._fw)}\n")
        self.log_line(f"Logging started at: {self._start_time}\n\n\n")

    def log_line(self, txt):
        """
        Log line
        :param txt: content in a text form
        :return: None
        """
        self._fp.write(txt)
        self._fp.flush()

    def close_log(self):
        """
        Closes the log
        :return:  None
        """
        self._fp.close()

    def save_loop_info(self, name, path, addr, cond, pl_name="Unknown", report_time=None):
        """
        Dump the info about a tainted variable guarding a loop
        :param name: binary name
        :param path: path found to be tainted
        :param addr: sink address
        :param cond: tainted condition
        :param pl_name: CPF name
        :param report_time: logging time

        :return: None
        """
        self.log_line("===================== Start Info path =====================\n")
        self.log_line(f"Binary: {os.path.basename(name)}: ")
        if report_time is None:
            self.log_line(f"Dangerous loop condition at address {hex(addr)}\n")
        else:
            self.log_line(f"Dangerous loop condition at address {hex(addr)}, time: {str(report_time)} sec\n")
        self.log_line("\nReason: a tainted variable is used in the guard of a loop condition\n")
        self.log_line(f"\nCondition: {cond}\n")
        self.log_line(f"\nPlugin responsible to propagate the data: {pl_name}\n")
        self.log_line("\n\nTainted Path \n----------------\n")
        path = ' -> '.join([hex(a) for a in path.active[0].history.bbl_addrs])
        self.log_line(path + '\n\n')
        self.log_line("===================== End Info path =====================\n\n\n")

    def save_sink_info(self, name, path, sink_address, key, pl_name="Unknown", report_time=None):
        """
        Dump the info about a tainted sink into the log file
        :param name: binary name
        :param path: path found to be tainted
        :param sink_address: address of the sink
        :param key: data key
        :param pl_name: CPF name
        :param report_time: logging time

        :return: None
        """
        self.log_line("===================== Start Info path =====================\n")
        self.log_line(f"Binary: {os.path.basename(name)}: ")
        self.log_line(f"\nPlugin responsible to propagate the data: {pl_name}\n")
        if report_time is None:
            self.log_line(f"Key: {key}, Sink address: {hex(sink_address)}\n")
        else:
            self.log_line(f"Key: {key}, Sink address: {hex(sink_address)}, time: {report_time} sec\n")

        self.log_line("\n\nPath \n----------------\n")
        path = ' -> '.join([hex(a) for a in path.active[0].history.bbl_addrs])
        self.log_line(path + '\n\n')

        self.log_line("Fully tainted conditions \n----------------\n")

        self.log_line("===================== End Info path =====================\n\n\n")

    def save_alert(self, type_alert, *args, **kwargs):
        """
        Saves an alert
        :param type_alert: type of alert (sink/loop)
        :return: None
        """

        if type_alert == 'loop':
            self.save_loop_info(*args, **kwargs)
        elif type_alert == 'sink':
            self.save_sink_info(*args, **kwargs)
        else:
            self.log_line("Got unrecognized alert:")
            for arg in args:
                self.log_line(str(arg))
            for key, value in kwargs.items():
                self.log_line(f"{key} == {str(value)}")

    def save_stats(self, node, stats):
        """
        Saves the analysis statistics
        :param node: BDG node
        :param stats: Vulnerability analysis statistics
        :return:
        """

        if node.bin not in stats:
            return

        bin_name = node.bin
        n_runs = stats[bin_name]['n_runs']
        to = stats[bin_name]['to']
        visited_bb = stats[bin_name]['visited_bb']
        n_paths = stats[bin_name]['n_paths']
        avg_bb = visited_bb / float(n_runs) if n_runs > 0 else -1
        analysis_time = stats[bin_name]['ana_time']

        self.log_line(f"\n\nVuln analysis stats: {bin_name}\n")
        self.log_line("======================\n\n")
        self.log_line(f"Tot num runs: {str(n_runs)}\n")
        self.log_line(f"Num runs timedout: {str(to)}\n")
        self.log_line(f"Tot num visited bb: {str(visited_bb)}\n")
        self.log_line(f"Explored paths: {str(n_paths)}\n")

        try:
            n_tot_paths = self._get_n_paths(node, avg_bb)
            self.log_line(f"Estimated binary paths: {str(n_tot_paths)}\n")
        except OverflowError:
            self.log_line("Estimated binary paths: INF")
        except Exception:
            self.log_line("Estimated binary paths: -1\n")

        self.log_line(f"Analysis time: {str(analysis_time)}\n")

    def save_global_stats(self, bbf=None, bdg=None, bf=None):
        """
        Saves the global statistics

        :param bbf: border binary finder
        :param bdg: BDG
        :param bf: Bug finder
        :return: None
        """
        self._end_time = time.time()

        self.log_line("\n\nGlobal stats\n")
        self.log_line("======================\n")

        self.log_line(f"\nTotal Running time {str(self._end_time - self._start_time)} seconds\n")

        if bbf:
            self.log_line(f"\nParser time {str(bbf.analysis_time())} seconds\n")
            self.log_line(f"Parser bins: {str(bbf.border_binaries)}\n")
            self.log_line(f"Parser #bins: {str(len(bbf.border_binaries))}\n")

        if bdg:
            self.log_line(f"\nBdg time {str(bdg.analysis_time())} seconds\n")

        if bf:
            analysis_time = bf.analysis_time()
            stats = bf.stats
            n_runs = sum([x['n_runs'] for x in stats.values()])
            to = sum([x['to'] for x in stats.values()])
            bb_visited = sum([x['visited_bb'] for x in stats.values()])
            n_paths = sum([x['n_paths'] for x in stats.values()])

            tot_paths = 0
            for node in bdg.nodes:
                if node.bin in stats:
                    bin_bb_visited = stats[node.bin]['visited_bb']
                    bin_runs = stats[node.bin]['n_runs']
                    avg_visited = bin_bb_visited / float(bin_runs) if n_runs > 0 else -1
                    paths = self._get_n_paths(node, avg_visited)
                    if paths > 0:
                        tot_paths += paths

            self.log_line(f"\nBug finding time {str(analysis_time)} seconds\n")
            self.log_line(f"Tot num runs: {str(n_runs)}\n")
            self.log_line(f"Num runs timed out: {str(to)}\n")
            self.log_line(f"Tot num visited bb: {str(bb_visited)}\n")
            self.log_line(f"Explored paths: {str(n_paths)}\n")
            self.log_line(f"Estimated number of paths: {str(tot_paths)}\n")
