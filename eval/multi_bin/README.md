**multi_bin**
=

It contains three directories: (i) **all_bins**, (ii) **bdg_bins** , and (iii) **network-facing**.

## *all_bins*
It contains the necessary scripts to analyze each binary of a given firmware sample, and scan it for bugs. The analysis assumes that every IPC mark (e.g., *getenv*) represents a possible input source for attacker-controlled data.

## *bdg_bins*
It contains the necessary scripts to analyze each binary of a given BDG of a firmware sample, and scan it for bugs. The analysis assumes that every IPC mark represents a possible input source for attacker-controlled data.

## *network-facing*
It contains the necessary scripts to analyze each network-facing binary of a firmware sample (as retrieved by the network service discovery) and scan it for bugs. The analysis assumes that every IPC mark represents a possible input source for attacker-controlled data.


