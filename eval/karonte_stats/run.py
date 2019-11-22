# HELP:
# Run karonte on a set of firmware sample and store the results in ./eval/karonte_stats/results/<vendor>

import os
import sys
import subprocess as sp
from optparse import OptionParser
from optparse import Option, OptionValueError
import threading
import time


RESULTS = './eval/karonte_stats/results/'

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


class KaronteStats:
    def __init__(self):
        self.N = 1
        self.vendors = ['tenda', 'netgear', 'tp_link', 'd-link', 'lk', 'huawei', 'mediatek']

    def parse_options(self):
        parser = OptionParser(option_class=MultipleOption, description="Run karonte on a set of firmware sample and store the"
                                                                 " results in ./eval/karonte_stats/results/<vendor>",
                              usage="%prog -n parallel_runs -v vendor",
                              version="%prog 1.0")
        parser.add_option("-v", "--vendors",
                          action="extend",   metavar='CATEGORIES',
                          help="tenda, netgear, tp-link, d-link, lk, huawei, mediatek")
        parser.add_option("-n", "--n",
                          action="extend",  metavar='CATEGORIES',
                          help="Number of parallel runs", )

        (options, args) = parser.parse_args()

        if options.n:
            self.N = int(options.n[0])
        self.vendors = options.vendors
        if not self.N or self.N == 0:
            self.N = 1
        if not self.vendors:
            self.vendors = ['tenda', 'netgear', 'tp_link', 'd-link', 'lk', 'huawei', 'mediatek']

        self.vendors = [x.lower() for x in self.vendors]

    def run_fw(self, config_file, log_path):
        os.system('python tool/karonte.py ' + config_file + ' ' + log_path)

    def run(self):
        self.parse_options()
        os.chdir('../../')
        pool = [None] * self.N

        i = self.N
        free_pos = [x for x in xrange(self.N)]

        if not os.path.exists(RESULTS):
            os.makedirs(RESULTS)

        for d in os.listdir('config'):
            if d.lower() not in self.vendors:
                continue

            if not os.path.exists(RESULTS + '/' + d):
                os.makedirs(RESULTS + '/' + d)

            for f in os.listdir('config/' + d + '/'):
                config_file = 'config/' + d + '/' + f
                log_file = RESULTS + '/' + d + '/' + f

                pos = free_pos[0]
                free_pos = free_pos[1:]

                pool[pos] = threading.Thread(target=self.run_fw, args=(config_file, log_file))
                pool[pos].start()
                i -= 1

                while i == 0:
                    alive = [x.is_alive() for x in pool]
                    free_pos += [x for x, y in enumerate(alive) if not y]
                    i += len([x for x in alive if not x])
                    time.sleep(1)

        # wait for them to finish
        print "Waiting... "
        [x.join() for x in pool if x]


if __name__ == '__main__':
    KaronteStats().run()
