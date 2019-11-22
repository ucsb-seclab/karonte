import os
import threading
import subprocess as sp

RESULT_DRECTORY = 'results'

class Runner:
    def __init__(self, cmd):
        self.cmd = cmd

    def run_it(self):
        os.system(self.cmd)


def run_vendor(vendor_dir, vendor):
    print "Running vendor: " +  vendor
    p = sp.Popen("find {} -name 'squashfs-root'".format(vendor_dir), stdout=sp.PIPE, stderr=sp.PIPE, stdin=sp.PIPE, shell=True)
    o, e = p.communicate()
    abs_path = os.path.abspath(__file__)
    pickle_dir = '/'.join(abs_path.split('/')[:-4]) + '/pickles/parser/'

    for fw in o.split('\n'):
        cmd = 'python run_core.py   -d ' + fw
        rel_pname = fw.replace('../../../firmware/', '').replace('/', '_').replace('.', '')
        #cmd += ' -p ' + pickle_dir + vendor + '/' + rel_pname + '.pk'
        cmd += ' -l ' + RESULT_DRECTORY + '/' + vendor + '/'
        obj = Runner(cmd)
        obj.run_it()
        
def run_eval():
    # paper eval
    vendors = ['../../../firmware/NETGEAR/analyzed/',
               '../../../firmware/d-link/analyzed/',
               '../../../firmware/TP_Link/analyzed/',
               '../../../firmware/Tenda/analyzed/']

    pool = []

    for vendor_dir in vendors:
        vendor = vendor_dir.split('/')[-3]
        pool.append(threading.Thread(target=run_vendor, args=(vendor_dir, vendor)))
        pool[-1].start()

    # wait for them to finish
    [x.join() for x in pool if x]

if __name__ == '__main__':
    run_eval()
    
