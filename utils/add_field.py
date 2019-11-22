import sys
import json
import subprocess as sp

try:
    field_name = sys.argv[1]
    field_value = sys.argv[2]
except:
    print "Usage: {} [field_name] [field_value]".format(sys.argv[0])
    print "Changes/Adds a field within any config files in ../config/"
    sys.exit(1)

p = sp.Popen("find ../config -type f", stdin=sp.PIPE, stdout=sp.PIPE, stderr=sp.PIPE, shell=True)
o, e = p.communicate()

for f in o.split('\n'):
    try:
        config = json.load(open(f))
    except:
        continue
    config[field_name] = field_value
    json.dump(config, open(f, 'w'))

