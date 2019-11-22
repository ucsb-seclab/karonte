import sys
import os


try:
    directory = sys.argv[1]
except:
    print "Usage: " + sys.argv[0] + ' <result directory of static experiment (run.py)>'
    sys.exit(0)

for vendor in os.listdir(directory):
    vendor_unsafe = 0
    vendor_bin = 0
    vendor_time = 0
    tot_vendor = 0

    for fw in os.listdir(directory + '/' + vendor):
        for f in os.listdir(directory + '/' + vendor + '/' + fw):
            with open(directory + '/' + vendor + '/' + fw + '/' + f, 'r') as fp:
                if 'summary' in f:
                    continue
                cnt = fp.read()
                if not cnt:
                    continue
                info = cnt.split('\n')
                if 'unsafe' not in info[2] or 'Time' not in info[0]:
                    import ipdb; ipdb.set_trace()
                assert 'unsafe' in info[2]
                assert 'Time' in info[0]
                vendor_unsafe += int(info[2].split(' ')[-1])
                vendor_time += float(info[0].split(' ')[-1])
                vendor_bin += 1

        tot_vendor += 1

    print vendor
    print "#tot time Time (h): " + str((vendor_time) / float(3600))
    print "tot #Binaries: " + str(vendor_bin)
    print "to #Unsafe: " + str(vendor_unsafe)
    print "#Avg time Time (h): " + str((vendor_time/float(tot_vendor)) / float(3600))
    print "AVG #Binaries: " + str(vendor_bin / float(tot_vendor))
    print "Avg #Unsafe: " + str(vendor_unsafe /float(tot_vendor))


