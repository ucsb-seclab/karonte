# 1) fw dir
# 2) result file
# 3) log file

import os
import sys
import json

class Runner:
    def __init__(self, cmd):
        self.cmd = cmd

    def run_it(self):
        os.system(self.cmd)


def run(config, log_dir):
    jconfig = json.load(open(config, 'r'))
    core_script = '/'.join(__file__.split('/')[:-1]) + '/run_core.py'
    cmd = 'python ./' + core_script + '   -d ' + jconfig['fw_path'] + ' -l ' + log_dir
    obj = Runner(cmd)
    obj.run_it()


if __name__ == '__main__':
    run(sys.argv[1], sys.argv[2])

