# HELP
# parse and beautify the results created by karonte

import sys
import subprocess as sp
import ast
import os
import json

for vendor in os.listdir('./results'):
    parsers = []
    fw_samples = 0
    single_bins = 0
    multi_bins = 0
    tot_alerts = []
    min_time = None
    max_time = None
    avg_time = []
    cpss = []
    multi_bdg = []

    for rel_res_file in os.listdir('./results/' + vendor):
        fw_samples += 1
        res_file = './results/' + vendor + '/' + rel_res_file


        try:
            # Running Time
            cmd1 = "grep 'Total Running' " + res_file
            p = sp.Popen(cmd1, stdout=sp.PIPE, stderr=sp.PIPE, stdin=sp.PIPE, shell=True)
            tot_time, e = p.communicate()
            tot_time = float(tot_time.strip().split(' ')[3])

            if min_time is None or min_time > tot_time:
                min_time = tot_time
            if max_time is None or max_time < tot_time:
                max_time = tot_time
            avg_time.append(tot_time)

            # binaries
            cmd1 = "grep 'Binaries' " + res_file
            p = sp.Popen(cmd1, stdout=sp.PIPE, stderr=sp.PIPE, stdin=sp.PIPE, shell=True)
            str_binaries, e = p.communicate()
            binaries = str_binaries.strip().split(' ')[1:]
            parsers.append(len(binaries))

            # Bdg
            cmd1 = "grep 'BdgNode' " + res_file
            p = sp.Popen(cmd1, stdout=sp.PIPE, stderr=sp.PIPE, stdin=sp.PIPE, shell=True)
            str_bdg, e = p.communicate()
            str_bdg = str_bdg.strip()

            # CPS
            try:
                cmd1 = "grep -A3 'Plugins' " + res_file
                p = sp.Popen(cmd1, stdout=sp.PIPE, stderr=sp.PIPE, stdin=sp.PIPE, shell=True)
                cps, e = p.communicate()
                str_cps = cps.split('\n\n')[1]
                cpss += ast.literal_eval(str_cps.strip())
            except:
                pass

            sum_node_bdg_multi = 0
            tot_bdg_multi = 0

            try:
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

                seen_names = []
                for k, vs in bdg.items():
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

            except:
                pass
            if sum_node_bdg_multi == 0:
                single_bins += 1
            else:
                multi_bins += 1
                multi_bdg.append(sum_node_bdg_multi)

            # we added this manually, as explained in the paper
            if 'ac_9' in rel_res_file or 'ac_15' in rel_res_file or 'ac_18' in rel_res_file:
                multi_bins += 1
                single_bins -= 1
                multi_bdg.append(2)

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

            tot_alerts.append(len(loops) + len(sinks))
        except Exception as e:
            print "No info to show :(.\nDid you set 'stats: 'True' in the configuration file?"

    print "Vendor: " + vendor

    try:
        fw_path = '../../firmware/' + vendor
        if 'lk' not in vendor and 'NVIDIA' not in vendor and 'huawei' not in vendor:
            fw_path += '/analyzed/'
        cmd = 'grep -r \'read\' ' + fw_path + ' | grep Binary | wc -l'
        p = sp.Popen(cmd, stdout=sp.PIPE, stderr=sp.PIPE, shell=True)
        o, e = p.communicate()
        n_bins = int(o.strip())
    except:
        pass

    print "# binaries: " + str(n_bins)
    print "Avg network-facing binaries: " + str(sum([x for x in parsers]) / len([x for x in parsers if x]))
    print "Firmware samples: " + str(fw_samples)
    print "Single binaries: " + str(single_bins)
    print "Multi binaries: " + str(multi_bins)
    print "# Alerts: " + str(sum([x for x in tot_alerts]))
    print "Min analysis time: " + str(min_time)
    print "Avg analysis time: " + str(sum([x for x in avg_time]) / len(avg_time))
    print "Max analysis time: " + str(max_time)
    print "#Environment CPS: " + str(len([x for x in cpss if 'nvi' in x ]))
    print "#Semantic CPS: " + str(len([x for x in cpss if 'ema' in x or 'er_ge' in x]))
    if sum([x for x in multi_bdg]) != 0:
        print "AVG Bdg cardinality: " + str(sum([x for x in multi_bdg]) / (len(multi_bdg) if multi_bdg != 0 else 1))
    else:
        print "AVG Bdg cardinality: 1"
    print "Multi binary firmware samples: " + str(multi_bins)
    print "=========================\n\n"
