import logging
import sys
from os.path import dirname, abspath

sys.path.append(dirname(dirname(abspath(__file__))))

from binary_dependency_graph.utils import run_command
from binary_dependency_graph.bdp_enum import RoleInfo

log = logging.getLogger("BinaryDependencyGraph")
log.setLevel("DEBUG")

LIB_KEYWORD = 'lib'


class CPF:
    """
    CPF base class
    """

    def __init__(self, name, p, cfg, fw_path, memcmp_like_functions=None, *kargs, **kwargs):
        """
        Initialization routine

        :param name: CPF name
        :param p:  angr project
        :param cfg: angr CFG
        :param fw_path:  firmware path
        :param memcmp_like_functions: memcmp-like functions within the binary
        :param kargs: kargs
        :param kwargs: kwargs
        """

        global log
        self._role_info = {}
        self._roles = []
        self._data_keys = []
        self._fw_path = fw_path
        self._cfg = cfg
        self._p = p
        self._log = kwargs['log'] if 'log' in kwargs else log
        self._name = name
        self._memcmp_like = memcmp_like_functions if memcmp_like_functions is not None else []
        self._blob = True if not hasattr(self._p.loader.main_bin, 'reverse_plt') else False

    @property
    def name(self):
        return self._name

    def run(self, *kargs, **kwargs):
        raise Exception("You have to implement at least the cpf's run")

    def discover_data_keys(self, *kargs, **kwargs):
        return {}

    @property
    def role_info(self):
        return {}

    def discover_new_binaries(self):
        """
        Find other binaries within the firmware sample that have data dependencies with those associated
        with a CPF object
        :return: a list of binaries
        """

        bins = []
        seen_strs = []

        for _, r_info in self._role_info.items():
            for info in r_info:
                data_key = info[RoleInfo.DATAKEY]
                if data_key in seen_strs or not data_key:
                    continue

                self._log.debug("New data key: " + str(data_key))
                seen_strs.append(data_key)
                cmd = "grep -r '" + data_key + "' " + self._fw_path + " | grep Binary | awk '{print $3}'"
                o, e = run_command(cmd)

                candidate_bins = list(set([x for x in o.split('\n') if x]))
                for b in candidate_bins:
                    # optimization: this is handle by angr anyway
                    if LIB_KEYWORD in b:
                        continue

                    name = b.split('/')[-1]
                    self._log.debug("Adding " + str(name))
                    bins.append(b)

        return list(set(bins))
