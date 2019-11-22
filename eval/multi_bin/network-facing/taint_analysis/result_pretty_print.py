import sys
import subprocess

if len(sys.argv) < 2:
    print "Usage: " + sys.argv[0] + " results file"
    sys.exit(0)

result_file = sys.argv[1]

# sinks
cmd = 'grep \'sink\' ' + result_file + ' | sort | uniq'
p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
o, _ = p.communicate()

interesting_str = o.split('\n')
counter = 1
counter_sinks = 0

for e in interesting_str:
    if not e:
        continue

    cmd = 'grep -A12 -B3 -m 1 \'' + e + '\' ' + result_file
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    o, _ = p.communicate()
    print str(counter) + ")"
    counter += 1
    counter_sinks += 1
    print o
    print "\n\n"


# Loops
cmd = 'grep \'Dangerous loop\' ' + result_file + ' | sort | uniq'
p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
o, _ = p.communicate()

interesting_str = o.split('\n')
counter_loop = 0
for e in interesting_str:
    if not e:
        continue

    cmd = 'grep -A12 -B1 -m 1 \'' + e + '\' ' + result_file
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    o, _ = p.communicate()
    print str(counter) + ")"
    counter += 1
    counter_loop += 1
    print o
    print "\n\n"


# Dereferences
cmd = 'grep \'Dereference address\' ' + result_file + ' | sort | uniq'
p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
o, _ = p.communicate()

interesting_str = o.split('\n')
counter_deref = 0

for e in interesting_str:
    if not e:
        continue

    cmd = 'grep -A12 -B1 -m 1 \'' + e + '\' ' + result_file
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    o, _ = p.communicate()
    print str(counter) + ")"
    counter += 1
    counter_deref += 1
    print o
    print "\n\n"

print "Total sinks related alerts: " + str(counter_sinks)
print "Total loop related alerts: " + str(counter_loop)
print "Total dereference related alerts: " + str(counter_deref)
