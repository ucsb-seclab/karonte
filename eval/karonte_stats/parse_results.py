# HELP
# parse and beautify the results created by karonte

import sys
import subprocess as sp
import ast

if len(sys.argv) < 2:
    print "Usage {} karonte_stats_file".format(sys.argv[0])
    sys.exit(0)

res_file = sys.argv[1]


try:
    # Running Time
    cmd1 = "grep 'Total Running' " + res_file
    p = sp.Popen(cmd1, stdout=sp.PIPE, stderr=sp.PIPE, stdin=sp.PIPE, shell=True)
    tot_time, e = p.communicate()
    tot_time = tot_time.strip().split(' ')[3]

    #BDG time
    cmd1 = "grep 'Bdg time' " + res_file
    p = sp.Popen(cmd1, stdout=sp.PIPE, stderr=sp.PIPE, stdin=sp.PIPE, shell=True)
    bdg_time, e = p.communicate()
    bdg_time = bdg_time.strip().split(' ')[2]

    # Parser Times
    cmd1 = "grep 'Parser time ' " + res_file
    p = sp.Popen(cmd1, stdout=sp.PIPE, stderr=sp.PIPE, stdin=sp.PIPE, shell=True)
    parser_time, e = p.communicate()
    parser_time = parser_time.strip().split(' ')[2]

    # Bug finding Times
    cmd1 = "grep 'Bug finding' " + res_file
    p = sp.Popen(cmd1, stdout=sp.PIPE, stderr=sp.PIPE, stdin=sp.PIPE, shell=True)
    bug_finding, e = p.communicate()
    bug_finding = bug_finding.strip().split(' ')[3]


    # binaries
    cmd1 = "grep 'Binaries' " + res_file
    p = sp.Popen(cmd1, stdout=sp.PIPE, stderr=sp.PIPE, stdin=sp.PIPE, shell=True)
    str_binaries, e = p.communicate()
    binaries = str_binaries.strip().split(' ')[1:]

    # Bdg
    cmd1 = "grep 'BdgNode' " + res_file
    p = sp.Popen(cmd1, stdout=sp.PIPE, stderr=sp.PIPE, stdin=sp.PIPE, shell=True)
    str_bdg, e = p.communicate()
    str_bdg = str_bdg.strip()


    # CPS
    cmd1 = "grep -A3 'Plugins' " + res_file
    p = sp.Popen(cmd1, stdout=sp.PIPE, stderr=sp.PIPE, stdin=sp.PIPE, shell=True)
    cps, e = p.communicate()
    str_cps = cps.split('\n\n')[1]

    bdg = ast.literal_eval(str_bdg.replace("<", "'<").replace(">", ">'").strip())

    # remove duplicates entries
    seen_names = []
    to_del = []

    for n in bdg.keys():
        name = n.split('/')[-1]
        if name in seen_names:
            to_del.append(n)
            continue

        seen_names.append(name)


    for d in to_del:
        del bdg[d]

    tot_bdg_multi = 0
    sum_node_bdg_multi = 0
    seen_names = []
    for k,vs in bdg.items():
        new_entry = []
        for v in vs:
            name = v.split('/')[-1]
            if name in seen_names:
                continue
            seen_names.append(name)
            new_entry.append(v)
        if len(new_entry) > 1:
            sum_node_bdg_multi += (len(new_entry) + 1)
            tot_bdg_multi += 1
        bdg[k] = new_entry

    str_bdg = str(bdg)

    # Sinks
    cmd1 = "cat " + res_file + " | grep Sink | sort | cut -d\" \" -f1-7 | uniq"
    p = sp.Popen(cmd1, stdout=sp.PIPE, stderr=sp.PIPE, stdin=sp.PIPE, shell=True)
    sinks, e = p.communicate()
    sinks = [x for x in sinks.split('\n') if x]

    # Loops
    cmd1 = "cat " + res_file + " | grep \"Dangerous loop\" | sort | cut -d\" \" -f1-6 | uniq"
    p = sp.Popen(cmd1, stdout=sp.PIPE, stderr=sp.PIPE, stdin=sp.PIPE, shell=True)
    loops, e = p.communicate()
    loops = [x for x in loops.split('\n') if x]

    print "Network-facing binaries: "
    print "========================="
    print "Time (s): " + str(parser_time) + '\n'
    for b in binaries:
        print b
    print "=========================\n\n"

    print "BDG "
    print "========================="
    print "Time (s): " + str(bdg_time) + '\n'
    print str_bdg
    print "=========================\n\n"

    print "Matching CPS "
    print "========================="
    print str_cps
    print "=========================\n\n"

    print "Possible BoF"
    print "========================="
    for s in sinks:
        print s.strip()
    print "=========================\n\n"

    print "Dangeours loops"
    print "========================="
    for l in loops:
        print l.strip('\n')
    print "=========================\n\n"

    print "Overall Stats:"
    print "# network-facing binaries: " + str(len(binaries))
    print "AVG Cardinality BDG: " + str(sum_node_bdg_multi / float(tot_bdg_multi if tot_bdg_multi != 0 else 1))
    print "# alerts: " + str(len(loops) + len(sinks))
    print "Analysis time (s): " + str(tot_time)
except:
    print "No info to show :(.\nDid you set 'stats: 'True' in the configuration file?"
