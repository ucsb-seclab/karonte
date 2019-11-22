import subprocess as sp


def find_binaries(os_path):
    cmd = "find \""+ os_path + "\""
    cmd += " -executable -type f -exec file {} \; | grep -iv image | grep -iv text | awk -F':' '{print $1}'"
    p = sp.Popen(cmd, stdout=sp.PIPE, stderr=sp.PIPE, shell=True)
    o, e = p.communicate()
    if o:
        return o.split('\n')
    return []


if __name__ == "__main__":
    os_path = 'firmware/NETGEAR/R7800/_R7800-V1.0.2.52.img.extracted/'
    print find_binaries(os_path)