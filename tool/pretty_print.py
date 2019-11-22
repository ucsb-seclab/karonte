import subprocess as sp
import sys

def exec_cmd(cmd):
    p = sp.Popen(cmd, stdout=sp.PIPE,
                 stderr=sp.PIPE,
                 stdin=sp.PIPE, shell=True)
    return p.communicate()


try:
    res_path = sys.argv[1]
except:
    print "Usage: {}  karonte_result_file".format(sys.argv[0])
    sys.exit(1)

o, e = exec_cmd("grep -r 'Sink' {} | sort | cut -d\" \" -f1-5 |sort|uniq ".format(res_path))

counter = 1
alerts = [x for x in o.split('\n') if x]
for alert in alerts:
    cmd = "grep -B8 -A10 -r \'{}\' {}".format(alert, res_path)
    o, e = exec_cmd(cmd)
    print "Alert " + str(counter)
    print "=="
    counter += 1
    print o.split('===================== Start Info path =====================')[1].split(
        '===================== End Info path =====================')[0]
    print '==\n\n'