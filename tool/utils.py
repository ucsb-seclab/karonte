import os
from random import randint

from libraries.extractor.extractor import Extractor


MAX_THREADS = 3
N_TYPE_DATA_KEYS = 4
DEFAULT_LOG_PATH = "/tmp/Karonte.txt_" + str(randint(1, 100))
DEFAULT_PICKLE_DIR = "/tmp/pickles"
FW_TMP_DIR = '/tmp/fw/'


def unpack_firmware(fw_path, out_dir):
    """
    Unpacks the firmware
    :param fw_path:  firmware path
    :param out_dir: the directory to extract to
    :return: the path of the unpacked firmware, which is stored in the brand folder
    """
    input_file = fw_path

    # arguments for the extraction
    rootfs = True
    kernel = False
    enable_parallel = False
    enable_debug = False

    # extract the file to the provided output directory using the FirmAE extractor
    extract = Extractor(input_file, out_dir, rootfs,
                        kernel, enable_parallel, enable_debug)
    extract.extract()

    return out_dir
