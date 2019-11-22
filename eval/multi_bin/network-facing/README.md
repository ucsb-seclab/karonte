This folder contains mainly three script: `run.py`, `get_all_stats.py` and `get_stats.py`.

### `run.py`
It runs the analysis on every network-facing binary of a given firmware sample:
> **SYNOPSIS**  
> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;python **run.py** [-i BINARIES] [-f BINARIES] [-d FIRMWARE_PATH]
>
> **DESCRIPTION**  
> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;**-i**, **--ignore** BINARIES  binaries to ignore  
> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;**-f**, **--force**&nbsp;&nbsp; BINARIES binaries to consider  
> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;**-d**, **--dir** &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;FIRMWARE_PATH Firmware sample path  
>
> **EXAMPLE**  
>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;python run.py -d ../../../firmware/d-link/analyzed/DIR-880   -i httpd  
>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;It analyzes every netowkr-facing binary of the DIR-880 firmware sample, but httpd.

If no argument is specified, `run.py` runs this evaluation of four firmware samples (NETGEAR R7800, D-Link 880, Tenda AC15 and TP-Link archer c3200),  simultaneously.

The results of the analysis are stored in **./results/<firmware sample>**.

**NOTE**: This script is CPU and memory intensive, and it is suggested to not run more than four instances at the same time.

### `get_stats.py`
It parses the results produced by `run.py` and shows them to the user:

> **SYNOPSIS**   
> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;python **get_stats.py** RESULT_DIR
>
> **DESCRIPTION**  
> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;It parses the analysis results stored in RESULT_DIR, and shows them to the user.
>
> **EXAMPLE**  
> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;python get_stats.py ./results/DIR-880  
> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;It shows the results of the analysis over the DIR-880 D-Link firmware  

For each firmware sample analyzed, this script reports:
* Number of binaries encountered during the analysis 
* Number of binaries successfully analyzed
* Number of raised alerts
* Total time spent to analyze the firmware sample.

### `get_all_stats.py`
It parses **all** the results stored in **./results/**, and shows them to the user, divided per firmware sample.

> **SYNOPSIS**  
> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;python **get_all_stats.py**
>
> **DESCRIPTION**  
> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;It parses all the analysis results stored in RESULT_DIR, and shows them to the user.  