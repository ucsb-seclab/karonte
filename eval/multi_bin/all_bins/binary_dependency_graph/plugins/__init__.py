import logging

log = logging.getLogger("BinaryDependencyGraph")
log.setLevel("DEBUG")


class Plugin:
    def __init__(self, name, p, cfg, fw_path, memcmp_like_functions=None, *kargs, **kwargs):
        global log
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
        raise Exception("You have to implement at least a plugin's run")

    def discover_new_binaries(self, *kargs, **kwargs):
        return []

    def discover_strings(self, *kargs, **kwargs):
        return {}

    @property
    def role_strings_info(self):
        return {}
