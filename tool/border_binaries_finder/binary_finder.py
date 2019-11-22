import subprocess as sp


def find_binaries(fw_path):
    """
    Gets a list of possible binaries within a firmare sample.
    The list might contain false positives, angr will ignore them.      
    
    :param fw_path:  firmware path
    :return: a list of binaries
    """

    cmd = "find \""+ fw_path + "\""
    cmd += " -executable -type f -exec file {} \; | grep -iv image | grep -iv text | awk -F':' '{print $1}'"
    p = sp.Popen(cmd, stdout=sp.PIPE, stderr=sp.PIPE, shell=True)
    o, e = p.communicate()
    if o:
        return o.split('\n')

    return []
