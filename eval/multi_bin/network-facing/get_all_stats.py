import sys
import os


def run(directory):
    n_unsafe = 0
    tot_bin = 0
    ana = 0
    time = 0
    for f in os.listdir(directory):
        with open(directory + '/' + f, 'r') as fp:
            try:
                tot_bin += 1

                cnt = fp.read()
                if not cnt:
                    continue
                ana += 1
                last_line = cnt.split('\n')[-2]
                unsafe_tmp = last_line.split(' ')[-1]
                time += float(cnt.split('\n')[0].split('Time: ')[1])

                n_unsafe += int(unsafe_tmp)
            except:
                pass
    return tot_bin, ana, n_unsafe, time


for d in os.listdir('results/'):
    if 'NET' in d:
        print "NETGEAR R7800"
    elif 'DIR' in d:
        print "D-Link 880"
    elif 'Tenda' in d:
        print "Tenda AC15"
    else:
        print "TP-Link Archer C3200"
    print '======'
    directory = 'results/' + d
    tot_bin, ana, n_unsafe, time = run(directory)
    print "#Total Time (h): " + str(time/float(3600))
    print "#Binaries: " + str(tot_bin)
    print "#Analyzed: " + str(ana)
    print "#Unsafe: " + str(n_unsafe)
    print '======\n\n'


