import os.path


def decompile_function(binary_path, alert):
    try:
        block_addr = list(alert['intra-bin_data-flow'][0].values())[0][-1]

        import angr
        p = angr.Project(binary_path, auto_load_libs=False)
        cfg = p.analyses.CFGFast(normalize=True)
        func = cfg.functions.floor_func(block_addr)
        func.normalize()
        d = p.analyses.Decompiler(func)

        return d.codegen.text

    except:
        return 'Decompilation error'

def get_edge_index(edge, bins_path):
    for i in range(len(bins_path) - 1):
        if bins_path[i] == edge[0] and bins_path[i+1] == edge[1]:
            return i

    return -1


def get_alert_str(alert):
    return str([os.path.basename(b) for b in alert['bins_path']])
