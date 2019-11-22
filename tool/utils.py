import os
import subprocess
from random import *

FW_TMP_DIR = '/tmp/fw/'
N_TYPE_DATA_KEYS = 4

DEFAULT_LOG_PATH = "/tmp/Karonte.txt_" + str(randint(1, 100))

extract_script = """
#!/bin/sh

# first, remove all previous binwalked data
# find $1 -type d -name "_*.extracted" -prune -exec rm -r "{}" \;

DIRNAME=$2

mkdir -p $DIRNAME"/" &
tar -xvzf $1 -C $DIRNAME

COMPRESSED=`find $DIRNAME -type f -exec file {} \;  | grep compress | awk -F ":" '{print $1}' | grep -v '.html' | grep -v '.js' | grep -v '.swf'`
MAX_DEPTH=5
THRESHOLD=50

for file in $COMPRESSED; do
    echo $file
    tot_files=`find $DIRNAME -type f  | wc -l`
    pt=`dirname $file`

    for depth in $(seq 0 $MAX_DEPTH); do
        # remove already binwalked directory, if any
        f=`basename $file`            
        rm -r $pt"/_"$f".extracted" > /dev/null 2>&1 

        # try again with updated depth
        binwalk  -eMq -d=$depth $file --directory $pt"/"

        # check if enough
        curr_files=`find $DIRNAME -type f  | wc -l`
        if (( $curr_files > ($tot_files + $THRESHOLD) ));           
        then
            break
        fi;
    done
done;
"""


def run_command(cmd):
    """
    Run shell commands

    :param cmd: command
    :return: stdout and stderr
    """

    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    o, e = p.communicate()
    return o, e


def unpack_firmware(fw):
    """
    Unpacks the firmware

    :param fw:  firmware path
    :return: the path of the unpacked firmware
    """

    fw_out = FW_TMP_DIR + fw.split('/')[-1] + '._unpacked'
    if not os.path.exists(FW_TMP_DIR):
        os.makedirs(FW_TMP_DIR)
    extract_script_path = FW_TMP_DIR + '/extract_here.sh'
    open(extract_script_path, 'w').write(extract_script)
    run_command('bash ' + extract_script_path + ' ' + fw + ' ' + fw_out)
    return fw_out

