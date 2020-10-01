import signal
import time
from binary_dependency_graph.bdp_enum import RoleInfo, Role
from utils import *
import json
import copy
import os

class FileLogger:
    def __init__(self, fw, filename):
        self._fw = fw
        self._filename = filename + '.json'
        self._logged_paths = set()
        self._start_time = None
        self._end_time = None
        self._complexity = {}

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
                print "Timeout triggered"
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
        data = {"firmware_path": self._fw, "firmware_name": self._fw.split('/')[-1], "logging_started": self._start_time}
        self.log_line(data)

    def log_line(self, cnt):
        """
        Log line
        :param cnt: content in a dictionary form
        :return: None
        """

        if not os.path.isfile(self._filename):
            with open(self._filename, "w") as file:
                json.dump({}, file)

        with open(self._filename, "r+") as file:
            data = json.load(file)
            data.update(cnt)
            file.seek(0)
            json.dump(data, file)

    def close_log(self):
        """
        Closes the log
        :return:  None
        """
        pass

    def save_bdg_stats(self, bbf, bdg):
        """
        Save statistics about the BDG module

        :param bbf: border binary finder object
        :param bdg: bdg object
        :return: None
        """

        bdg_bins = [b.bin for b in bdg.nodes]
        bb_fw = bbf.get_bb_fw()
        orphans = [n for n in bdg.nodes if n.orphan]

        data = {"bdg": {
                    "basic_blocks": str(sum([v for k, v in bb_fw.items() if k in bdg_bins])),
                    "analysis_time": str(bdg.analysis_time()),
                    "orphans": [x.bin for  x in orphans]
                     }
                }

        for node in bdg.nodes:
            data['bdg'][node.bin] = []
            info_bin = data['bdg'][node.bin]

            for succ in bdg.graph[node]:
                for info in succ.role_info.values():
                    for elem in info:
                        if elem[RoleInfo.ROLE] != Role.GETTER:
                            continue

                        dk = elem[RoleInfo.DATAKEY]
                        setters = [x for y in node.role_info.values() for x in y if x[RoleInfo.DATAKEY] == dk and \
                                  x[RoleInfo.ROLE] in (Role.SETTER, Role.SETTER_GETTER)]

                        if not setters:
                            continue

                        for setter in setters:
                            metadata = {
                                'cpf_in': setter[RoleInfo.CPF],
                                'cpf_out': elem[RoleInfo.CPF],
                                'data_key': dk,
                            }
                            info_bin.append(copy.deepcopy(metadata))
        self.log_line(data)

    def save_parser_stats(self, bbf):
        """
        Save statistics about the border binaries finder module
        
        :param bbf: border binaries finder
        :return: None
        """

        ana_time = bbf.analysis_time()
        bb = bbf.border_binaries
        bb_fw = bbf.get_bb_fw()
        tot_bins = bbf.get_total_bins_fw()

        data = {
            "num_binaries": str(len(tot_bins)),
            "basic_blocks": str(sum(bb_fw.values())),
            "border_binaries": {
                "analysis_time": str(ana_time),
                "binaries": bb,
                "basic_blocks": str(sum([v for k, v in bb_fw.items() if k in bb]))
            }
        }

        self.log_line(data)

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

        f = self._fp

        f.write("===================== Start Info path =====================\n")
        f.write("Binary: %s: " % name)
        if report_time is None:
            f.write("Dangerous loop condition at address %s\n" % hex(addr))
        else:
            f.write("Dangerous loop condition at address %s, time: %s sec\n" % (hex(addr), str(report_time)))
        f.write("\nReason: a tainted variable is used in the guard of a loop condition\n")
        f.write("\nCondition: %s\n" % cond)
        f.write("\nPlugin responsible to propagate the data: %s\n" % pl_name)
        f.write("\n\nTainted Path \n----------------\n")
        addr_path = ' -> '.join([hex(a) for a in path.active[0].addr_trace])
        f.write(addr_path + '\n\n')
        f.write("===================== End Info path =====================\n\n\n")

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

        f = self._fp

        f.write("===================== Start Info path =====================\n")
        f.write("Binary: %s: " % name)
        f.write("\nPlugin responsible to propagate the data: %s\n" % pl_name)
        if report_time is None:
            f.write("Key: %s, Sink address: %s\n" % (key, hex(sink_address)))
        else:
            f.write("Key: %s, Sink address: %s, time: %s sec\n" % (key, hex(sink_address), report_time))

        f.write("\n\nPath \n----------------\n")
        path = ' -> '.join([hex(a) for a in path.active[0].history.bbl_addrs])
        f.write(path + '\n\n')

        f.write("Fully tainted conditions \n----------------\n")

        f.write("===================== End Info path =====================\n\n\n")

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
                self.log_line("%s == %s" % (key, str(value)))

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

        self.log_line("\n\nVuln analysis stats: %s\n" % bin_name)
        self.log_line("======================\n\n")
        self.log_line("Tot num runs: %s\n" % str(n_runs))
        self.log_line("Num runs timedout: %s\n" % str(to))
        self.log_line("Tot num visited bb: %s\n" % str(visited_bb))
        self.log_line("Explored paths: %s\n" % str(n_paths))

        try:
            n_tot_paths = self._get_n_paths(node, avg_bb)
            self.log_line("Estimated binary paths: %s\n" % str(n_tot_paths))
        except OverflowError:
            self.log_line("Estimated binary paths: INF")
        except Exception:
            self.log_line("Estimated binary paths: -1\n")

        self.log_line("Analysis time: %s\n" % str(analysis_time))

    def save_global_stats(self, bbf=None, bdg=None, bf=None):
        """
        Saves the global statistics

        :param bbf: border binary finder
        :param bdg: BDG
        :param bf: Bug finder
        :return: None
        """

        self._end_time = time.time()

        self.log_line("\nTotal Running time %s seconds\n" % str(self._end_time - self._start_time))

        if bbf:
            self.log_line("\nParser time %s seconds\n" % str(bbf.analysis_time()))
            self.log_line("\nParser bins: %s\n" % str(bbf.border_binaries))
            self.log_line("\nParser #bins: %s\n" % str(len(bbf.border_binaries)))

        if bdg:
            self.log_line("\nBdg time %s seconds\n" % str(bdg.analysis_time()))

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

            self.log_line("\n\nGlobal stats\n")
            self.log_line("======================\n\n")
            self.log_line("\nBug finding time %s seconds\n" % str(analysis_time))
            self.log_line("Tot num runs: %s\n" % str(n_runs))
            self.log_line("Num runs timed out: %s\n" % str(to))
            self.log_line("Tot num visited bb: %s\n" % str(bb_visited))
            self.log_line("Explored paths: %s\n" % str(n_paths))
            self.log_line("Estimated number of paths: %s\n" % str(tot_paths))
