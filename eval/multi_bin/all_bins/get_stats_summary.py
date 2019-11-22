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
        if 'summary_result.log' not in os.listdir(directory + '/' + vendor + '/' + fw):
            import ipdb; ipdb.set_trace()
            continue

        with open(directory + '/' + vendor + '/' + fw + '/summary_result.log', 'r') as fp:
            cnt = fp.read()
            if not cnt:
                continue
            info = cnt.split('\n')[-5:]
            if 'Total unsafe' not in info[0]:
                info = cnt.split('\n')[-6:]
            assert 'Total unsafe' in info[0]
            assert 'Time' in info[3]
            assert 'Tot bin' in info[4]
            tot_vendor += 1
            vendor_unsafe += int(info[0].split(' ')[-1])
            vendor_time += float(info[3].split(' ')[-1])
            vendor_bin += int(info[4].split(' ')[-1])

    print vendor
    print "#Avg time Time (h): " + str((vendor_time/float(tot_vendor)) / float(3600))
    print "AVG #Binaries: " + str(vendor_bin / float(tot_vendor))
    print "Avg #Unsafe: " + str(vendor_unsafe /float(tot_vendor))


