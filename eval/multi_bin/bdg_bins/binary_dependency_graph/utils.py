import sys
import os
from os.path import dirname, abspath
sys.path.append(os.path.abspath(os.path.join(dirname(abspath(__file__)), '../../../tool')))
import subprocess
import string
import archinfo
import binascii
import pyvex
from taint_analysis import coretaint, summary_functions
from taint_analysis.utils import *
import networkx

import struct

MIN_STR_LEN = 3
STR_LEN = 255
ALLOWED_CHARS = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-/_'
EXTENDED_ALLOWED_CHARS = ALLOWED_CHARS + "%,.;+=_)(*&^%$#@!~`|<>{}[]"


def get_string(p, mem_addr, extended=False):
    bin_bounds = (p.loader.main_object.min_addr, p.loader.main_object.max_addr)

    # get string representation at mem_addr
    cnt = p.loader.memory.read_bytes(mem_addr, STR_LEN)
    string_1 = get_mem_string(cnt, extended=extended)
    string_2 = ''

    # check whether the mem_addr might contain an address
    try:
        endianess = '<I' if 'LE' in p.arch.memory_endness else '>I'
        tmp_addr = struct.unpack(
            endianess, ''.join(p.loader.memory.read_bytes(mem_addr, p.arch.bytes))
        )[0]
        if bin_bounds[0] <= tmp_addr <= bin_bounds[1]:
            cnt = p.loader.memory.read_bytes(tmp_addr, STR_LEN)
            string_2 = get_mem_string(cnt)
    except:
        pass

    # return the most probable string
    candidate = string_1 if len(string_1) > len(string_2) else string_2
    return candidate if len(candidate) >= MIN_STR_LEN else ''


def get_mem_string(mem_bytes, extended=False):
    tmp = ''
    chars = EXTENDED_ALLOWED_CHARS if extended else ALLOWED_CHARS

    for c in mem_bytes:

        if c not in chars:
            break
        tmp += c

    return tmp


def run_command(cmd):
    """
    Run shell commands
    :param cmd: command
    :return: stdout and stderr
    """

    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    o, e = p.communicate()
    return o, e


def contains(keyws, str):
    for k in keyws:
        if k in str:
            return True
    return False


def get_addrs_string(p, s):
    b = p.loader.main_object.binary
    str_info = get_bin_strings(b)
    offs = [x[1] for x in str_info if s == x[0]]
    return [p.loader.main_object.min_addr + off for off in offs]


def get_addrs_similar_string(p, s):
    b = p.loader.main_object.binary
    str_info = get_bin_strings(b)
    tmp = [x for x in str_info if s in x[0]]

    # filter the strings to allow only the most similar ones
    info = []
    for t in tmp:
        sub_str = t[0].replace(s, '')
        non_aplha_num = list(set([x for x in sub_str if not x.isalnum()]))
        if len(non_aplha_num) == 0 or (len(non_aplha_num) == 1 and non_aplha_num[0] in ('_', '-')):
            info.append(t)

    return [(s, p.loader.main_object.min_addr + off) for s, off in info]


def get_bin_strings(filename):
    with open(filename, "rb") as f:
        results = []
        last_off = None
        off = 0
        str = ""

        for c in f.read():
            if c in string.printable and c != '\n':
                last_off = off if not last_off else last_off
                str += c
            else:
                if str and len(str) > 1:
                    results.append((str, last_off))
                last_off = None
                str = ""
            off += 1

    return results


def get_dyn_sym_addrs(p, syms):
    found = []

    for f in syms:
        try:
            found.append(get_dyn_sym_addr(p, f))
        except:
            pass

    return found


def get_dyn_sym_addr(p, sym):
    if type(sym) == list:
        return get_dyn_sym_addrs(p, sym)

    try:
        return p.loader.main_object.plt[sym]
    except:
        return None


def get_memcpy_like(p):
    # TODO: add sprintf
    addrs = get_dyn_sym_addrs(p, ['strcpy'])
    summarized_f = {}
    for f in addrs:
        summarized_f[f] = summary_functions.memcpy_unsized

    addrs = get_dyn_sym_addrs(p, ['strncpy', 'memcpy'])
    for f in addrs:
        summarized_f[f] = summary_functions.memcpy_sized

    return summarized_f


def get_memcp_like(p):
    addrs = get_dyn_sym_addrs(p, ['strcmp', 'strcasecmp'])
    summarized_f = {}
    for f in addrs:
        summarized_f[f] = summary_functions.memcmp_unsized

    return summarized_f


def get_memncp_like(p):
    addrs = get_dyn_sym_addrs(p, ['strncasecmp', 'strncmp'])
    summarized_f = {}
    for f in addrs:
        summarized_f[f] = summary_functions.memcmp_sized

    return summarized_f


# we have to redefine this summary as angr by default adds some
# constraints to make the analysis faster, but sometimes inaccurate.
# We do not want such constraints!
def get_heap_alloc(p):
    addrs = get_dyn_sym_addrs(p, ['malloc', 'realloc', 'calloc'])
    summarized_f = {}
    for f in addrs:
        summarized_f[f] = summary_functions.heap_alloc

    return summarized_f


def get_sizeof_like(p):
    addrs = get_dyn_sym_addrs(p, ['strlen', 'sizeof'])
    summarized_f = {}
    for f in addrs:
        summarized_f[f] = summary_functions.sizeof
    return summarized_f


def get_env(p):
    addrs = get_dyn_sym_addrs(p, ['getenv', 'setenv'])
    summarized_f = {}
    for f in addrs:
        summarized_f[f] = summary_functions.env
    return summarized_f


def get_indirect_str_refs(p, cfg, str_addrs):
    ret = []

    # FIXME: (DEPRECATED?)
    # code reference
    code_refs = [s for s in cfg.memory_data.items() if 'code reference' in str(s)]
    for a, ref in code_refs:
        addr = ref.address
        cnt = p.loader.memory.read_bytes(addr, p.arch.bytes)

        if 'LE' in p.arch.memory_endness:
            cnt = reversed(cnt)

        cnt = binascii.hexlify(bytearray(cnt))
        if int(cnt, 16) in str_addrs:
            ret += [s for s in cfg.memory_data.items() if s[0] == addr]

    # pointers
    refs = [s for s in cfg.memory_data.items() if s[0] in str_addrs]
    for ref in refs:
        cnt = ref[1]
        if hasattr(cnt, 'pointer_addr'):
            pt = cnt.pointer_addr
            ret += [s for s in cfg.memory_data.items() if s[0] == pt]

    refs = [s for s in cfg.memory_data.items() if s[0] in str_addrs]
    for ref in refs:
        cnt = ref[1]
        if hasattr(cnt, 'pointer_addr'):
            pt = cnt.pointer_addr
            # we collect both references
            ret += [(s.address, s) for k, s in cfg.insn_addr_to_memory_data.items() if s.address == pt]
            ret += [(ind_addr, s) for k, s in cfg.insn_addr_to_memory_data.items() if s.address == pt for ind_addr in str_addrs]

    return ret


def are_parameters_in_registers(p):
    return hasattr(p.arch, 'argument_registers')


def get_args_call(p, no):
    """
    Gets the arguments of function call

    :param no: CFG Accurate node of the call site
    :return:
    """

    ins_args = get_ord_arguments_call(p, no.addr)
    if not ins_args:
        ins_args = get_any_arguments_call(p, no.addr)

    vals = {}

    for state in no.final_states:
        vals[state] = []
        for ins_arg in ins_args:
            # get the values of the arguments
            if hasattr(ins_arg.data, 'tmp'):
                val = state.scratch.temps[ins_arg.data.tmp]
                val = val.args[0] if type(val.args[0]) in (int, long) else None
                if val:
                    vals[state].append((ins_arg.offset, val))
            elif type(ins_arg.data) == pyvex.expr.Const:
                assert len(ins_arg.data.constants) == 1, "Too many constants assigned. Fix me"
                vals[state].append((ins_arg.offset, ins_arg.data.constants[0].value))
            else:
                print("Cant' get the value for function call")
                return []
    return vals


def get_reg_used(p, cfg, addr, idx, s_addr):
    """
    Finds whether and which register is used to store a string address.

    :param addr: basic block address
    :param idx: statement idx of the statement referencing a string
    :param s: string referenced in the statement pointed by idx
    :return: the register name the string is assigned to
    """

    if not are_parameters_in_registers(p):
        raise Exception("Parameters are not in registers")

    block = p.factory.block(addr)
    stmt = block.vex.statements[idx]
    no = cfg.get_any_node(addr)

    # sometimes strings are reference indirectly through an address contained in the
    # text section
    endianess = '<I' if 'LE' in p.arch.memory_endness else '>I'
    s_addr_2 = None
    try:
        s_addr_2 = struct.unpack(endianess, ''.join(p.loader.memory.read_bytes(s_addr, p.arch.bytes)))[0]
    except:
        pass

    if hasattr(stmt, 'offset'):
        return p.arch.register_names[stmt.offset]

    # damn! The string is not assigned directly to a register, but to a tmp.
    # It means we have to find out what register is used to pass the string
    # to the function call
    # save the function manager, CFGAccurate will change it
    fm = p.kb.functions

    cfga = p.analyses.CFGAccurate(starts=(no.function_address,), keep_state=True, call_depth=0)
    no = cfga.get_any_node(addr)
    if not no:
        cfga = p.analyses.CFGAccurate(starts=(addr,), keep_state=True, call_depth=0)
        no = cfga.get_any_node(addr)
        if not no:
            return None

    args = get_args_call(p, no)

    # restore the old function manager
    p.kb.functions = fm

    for _, vals in args.iteritems():
        for o, v in vals:
            if v in (s_addr, s_addr_2):
                return p.arch.register_names[o]
    return None


def find_memcmp_like(p, cfg):
    memcpy_like = [f.addr for f in cfg.functions.values() if 'memcmp' in f.name]
    tots = []
    for fun in cfg.functions.values():
        css = []

        try:
            no = cfg.get_any_node(fun.addr)
            css = [pred for pred in no.predecessors]
        except:
            pass

        if css == []:
            continue

        cs = css[0]
        args = get_ord_arguments_call(p, cs.addr)
        if len(args) > 3 or len(args) < 2:
            continue

        for loop in [x for x in networkx.simple_cycles(fun.graph)]:
            # CMPNE or CMPEQ
            if any([op for l in loop for op in p.factory.block(l.addr).vex.operations if 'cmpeq' in op.lower() or 'cmpne' in op.lower()]):
                tots.append(hex(fun.addr))
                # INCREMENT
                wr_tmp = [st for l in loop for st in p.factory.block(l.addr).vex.statements if st.tag == 'Ist_WrTmp']
                cons = [w.constants for w in wr_tmp if hasattr(w, 'data') and hasattr(w.data, 'op') and w.data.op == 'Iop_Add64']
                if cons:
                    cons = [c.value for cs in cons for c in cs]
                # using BootStomp thresholds
                if 1 in cons and len([x for x in fun.blocks]) <= 8:
                    memcpy_like.append(fun.addr)
    return list(set(memcpy_like))


# FIXME: to finish
def find_memcpy_like(p, cfg=None):
    memcpy_like = [f.addr for f in p.kb.functions.values() if 'memcpy' in f.name]
    if cfg is None:
        return memcpy_like

    tots = []
    for fun in cfg.functions.values():
        css = []

        try:
            no = cfg.get_any_node(fun.addr)
            css = [pred for pred in no.predecessors]
        except:
            pass

        if css == []:
            continue

        cs = css[0]
        args = get_ord_arguments_call(p, cs.addr)
        if len(args) > 3 or len(args) < 2:
            continue

        for loop in [x for x in networkx.simple_cycles(fun.graph)]:
            # CMPNE or CMPEQ
            if any([op for l in loop for op in p.factory.block(l.addr).vex.operations if 'cmpeq' in op.lower() or 'cmpne' in op.lower()]):
                tots.append(hex(fun.addr))
                # INCREMENT
                wr_tmp = [st for l in loop for st in p.factory.block(l.addr).vex.statements if st.tag == 'Ist_WrTmp']
                cons = [w.constants for w in wr_tmp if hasattr(w, 'data') and hasattr(w.data, 'op') and w.data.op == 'Iop_Add64']
                if cons:
                    cons = [c.value for cs in cons for c in cs]
                # using BootStomp thresholds
                if 1 in cons and len([x for x in fun.blocks]) <= 8:
                    memcpy_like.append(fun.addr)

    return list(set(memcpy_like))


