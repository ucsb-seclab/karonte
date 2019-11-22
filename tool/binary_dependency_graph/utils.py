import sys
import os
import subprocess
import string
import archinfo
import binascii
import pyvex
import subprocess as sp
import networkx
import struct

from os.path import dirname, abspath
sys.path.append(os.path.abspath(os.path.join(dirname(abspath(__file__)), '../../../tool')))
from taint_analysis import coretaint, summary_functions
from taint_analysis.utils import get_ord_arguments_call, get_any_arguments_call, ordered_argument_regs

# Strings stuff
MIN_STR_LEN = 3
STR_LEN = 255
ALLOWED_CHARS = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-/_'
EXTENDED_ALLOWED_CHARS = ALLOWED_CHARS + "%,.;+=_)(*&^%$#@!~`|<>{}[]"
SEPARATOR_CHARS = ('-', '_')

# taint stuff
TIMEOUT_TAINT = 60 * 5
TIMEOUT_TRIES = 2
ROLE_DATAKEYS_RATIO = 0.5
DEF_ROLE_ARITY = 2

link_regs = {
    'ARMEL': archinfo.ArchARMEL.registers['lr'][0],
    'AARCH64': archinfo.ArchAArch64.registers['x30'][0],
    'MIPS32': archinfo.ArchMIPS32.registers['ra'][0]
}


def is_pem_key(file_path):
    """
    Checks whether a file is a PEM key

    :param file_path: file path
    :return: True if file is a PEM key, false otherwise
    """

    p = sp.Popen('file ' + file_path, stdout=sp.PIPE, stderr=sp.PIPE, stdin=sp.PIPE, shell=True)
    o, e = p.communicate()
    if o and 'private key' in o:
        return True
    return False


def get_string(p, mem_addr, extended=False):
    """
    Get a string from a memory address

    :param p: angr project
    :param mem_addr: memory address
    :param extended: use extended set of characters
    :return: the string
    """

    bin_bounds = (p.loader.main_object.min_addr, p.loader.main_object.max_addr)
    try:
        text_bounds = (p.loader.main_object.sections_map['.text'].min_addr,
                       p.loader.main_object.sections_map['.text'].max_addr)
    except:
        text_bounds = None

    # check if the address contain another address
    try:
        endianess = '<I' if 'LE' in p.arch.memory_endness else '>I'
        tmp_addr = struct.unpack(
            endianess, ''.join(p.loader.memory.read_bytes(mem_addr, p.arch.bytes))
        )[0]
    except:
        tmp_addr = None

    # if the .text exists, we make sure that the actual string
    # is someplace else.
    if text_bounds is not None and text_bounds[0] <= mem_addr <= text_bounds[1]:
        # if the indirect address is not an address, or it points to the text segment,
        # or outside the scope of the binary
        if not tmp_addr or text_bounds[0] <= tmp_addr <= text_bounds[1] or \
               tmp_addr < bin_bounds[0] or tmp_addr > bin_bounds[1]:
            return ''

    # get string representation at mem_addr
    cnt = p.loader.memory.read_bytes(mem_addr, STR_LEN)
    string_1 = get_mem_string(cnt, extended=extended)
    string_2 = ''

    try:
        if tmp_addr and bin_bounds[0] <= tmp_addr <= bin_bounds[1]:
            cnt = p.loader.memory.read_bytes(tmp_addr, STR_LEN)
            string_2 = get_mem_string(cnt)
    except:
        string_2 = ''

    # return the most probable string
    candidate = string_1 if len(string_1) > len(string_2) else string_2
    return candidate if len(candidate) >= MIN_STR_LEN else ''


def get_mem_string(mem_bytes, extended=False):
    """
    Return the set of consecutive ASCII characters within a list of bytes

    :param mem_bytes: list of bytes
    :param extended: use extended list of characters
    :return: the longest string found
    """

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


def contains(list_subs, another_str):
    """
    Checks whether a set contains a substring of another string

    :param list_subs: list of strings
    :param another_str: another string
    :return:  True if list_subs contains a substring of another_str, False otherwise
    """

    for k in list_subs:
        if k in another_str:
            return True
    return False


def get_addrs_string(p, s):
    """
    Finds the memory address of a string
    :param p: angr project
    :param s: string
    :return: the memory address of the string
    """

    b = p.loader.main_object.binary
    str_info = get_bin_strings(b)
    offs = [x[1] for x in str_info if s == x[0]]
    refs = [p.loader.main_object.min_addr + off for off in offs]
    return refs


def get_addrs_similar_string(p, s):
    """
    Gets the memory addresses of strings similar to a string
    :param p: angr project
    :param s: the string
    :return: memory addresses of strings similar to the string s
    """
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
    """
    Retrieve the strings within a binary

    :param filename: binary path
    :return: the strings within the binary
    """

    with open(filename, "rb") as f:
        results = []
        last_off = None
        off = 0
        t_str = ""

        for c in f.read():
            if c in string.printable and c != '\n':
                last_off = off if not last_off else last_off
                t_str += c
            else:
                if t_str and len(t_str) > 1:
                    results.append((t_str, last_off))
                last_off = None
                t_str = ""
            off += 1

    return results


def get_dyn_sym_addrs(p, syms):
    """
    Get the addresses of a list of symbols

    :param p: angr project
    :param syms: list of symbols
    :return: addresses of a list of symbols
    """

    found = []

    for f in syms:
        try:
            found.append(get_dyn_sym_addr(p, f))
        except:
            pass

    return found


def get_dyn_sym_addr(p, sym):
    """
    Get the address of a symbol

    :param p: angr project
    :param sym: symbol
    :return: addresses of the symbol
    """

    if type(sym) == list:
        return get_dyn_sym_addrs(p, sym)

    try:
        return p.loader.main_object.plt[sym]
    except:
        return None


def get_memcpy_like(p):
    """
    Gets and summarizes memcpy like functions within a Linux binary

    :param p: angr project
    :return: function summaries
    """

    # TODO: add sprintf
    addrs = get_dyn_sym_addrs(p, ['strcpy'])
    summarized_f = {}
    for f in addrs:
        summarized_f[f] = summary_functions.memcpy_unsized

    addrs = get_dyn_sym_addrs(p, ['strncpy', 'memcpy'])
    for f in addrs:
        summarized_f[f] = summary_functions.memcpy_sized

    return summarized_f


def get_memcmp_like_unsized(p):
    """
    Gets and summarizes memcmp-like unsized functions within a Linux binary

    :param p: angr project
    :return: function summaries
    """

    addrs = get_dyn_sym_addrs(p, ['strcmp', 'strcasecmp'])
    summarized_f = {}
    for f in addrs:
        summarized_f[f] = summary_functions.memcmp_unsized

    return summarized_f


def get_memcmp_like_sized(p):
    """
    Gets and summarizes memcmp-like sized functions within a Linux binary

    :param p: angr project
    :return: function summaries
    """

    addrs = get_dyn_sym_addrs(p, ['strncasecmp', 'strncmp'])
    summarized_f = {}
    for f in addrs:
        summarized_f[f] = summary_functions.memcmp_sized

    return summarized_f


# we have to redefine this summary as angr by default adds some
# constraints to make the analysis faster, but sometimes inaccurate.
# We do not want such constraints!
def get_heap_alloc(p):
    """
    Gets and summarizes heap allocation functions within a Linux binary

    :param p: angr project
    :return: function summaries
    """

    addrs = get_dyn_sym_addrs(p, ['malloc', 'realloc', 'calloc'])
    summarized_f = {}
    for f in addrs:
        summarized_f[f] = summary_functions.heap_alloc

    return summarized_f


def get_sizeof_like(p):
    """
    Gets and summarizes heap sizeof-like functions within a Linux binary

    :param p: angr project
    :return: function summaries
    """

    addrs = get_dyn_sym_addrs(p, ['strlen', 'sizeof'])
    summarized_f = {}
    for f in addrs:
        summarized_f[f] = summary_functions.sizeof
    return summarized_f


def get_env(p):
    """
    Gets and summarizes heap environment functions within a Linux binary

    :param p: angr project
    :return: function summaries
    """

    addrs = get_dyn_sym_addrs(p, ['getenv', 'setenv'])
    summarized_f = {}
    for f in addrs:
        summarized_f[f] = summary_functions.env
    return summarized_f


def get_indirect_str_refs(p, cfg, str_addrs):
    """
    Gets indirect string references

    :param p: angr project
    :param cfg: angr cfg
    :param str_addrs: string addresses
    :return: reference objects
    """

    # some binary use the GOT to ref strings
    try:
        new_str_addrs = str_addrs + [(r - p.loader.main_object.sections_map['.got'].min_addr) & (2 ** p.arch.bits - 1)
                                     for r in str_addrs]
    except:
        new_str_addrs = str_addrs

    ret = []
    code_refs = [s for s in cfg.memory_data.items()]
    for a, ref in code_refs:
        addr = ref.address
        cnt = p.loader.memory.read_bytes(addr, p.arch.bytes)
        if 'LE' in p.arch.memory_endness:
            cnt = reversed(cnt)

        try:
            cnt = binascii.hexlify(bytearray(cnt))
            if int(cnt, 16) in new_str_addrs:
                ret += [s for s in cfg.memory_data.items() if s[0] == addr]
        except:
            pass

    # pointers
    refs = [s for s in cfg.memory_data.items() if s[0] in new_str_addrs]
    for ref in refs:
        cnt = ref[1]
        if hasattr(cnt, 'pointer_addr'):
            pt = cnt.pointer_addr
            ret += [s for s in cfg.memory_data.items() if s[0] == pt]

    refs = [s for s in cfg.memory_data.items() if s[0] in new_str_addrs]
    for ref in refs:
        cnt = ref[1]
        if hasattr(cnt, 'pointer_addr'):
            pt = cnt.pointer_addr
            # we collect both references
            ret += [(s.address, s) for k, s in cfg.insn_addr_to_memory_data.items() if s.address == pt]
            ret += [(ind_addr, s) for k, s in cfg.insn_addr_to_memory_data.items() if s.address == pt for ind_addr
                    in new_str_addrs]

    return ret


def are_parameters_in_registers(p):
    """
    Checks whether function arguments are passed through registers

    :param p: angr project
    :return:  True if function arguments are passed through registers
    """

    return hasattr(p.arch, 'argument_registers')


def get_args_call(p, no):
    """
    Gets the arguments of function call

    :param p: angr project
    :param no: CFG Accurate node of the call site
    :return: the values of function called in node no
    """

    ins_args = get_ord_arguments_call(p, no.addr)
    if not ins_args:
        ins_args = get_any_arguments_call(p, no.addr)

    vals = {}

    for state in no.final_states:
        vals[state] = []
        for ins_arg in ins_args:
            # get the values of the arguments
            if hasattr(ins_arg.data, 'tmp') and ins_arg.data.tmp in state.scratch.temps:
                val = state.scratch.temps[ins_arg.data.tmp]
                val = val.args[0] if type(val.args[0]) in (int, long) else None
                if val:
                    vals[state].append((ins_arg.offset, val))
            elif type(ins_arg.data) == pyvex.expr.Const and len(ins_arg.data.constants) == 1:
                    vals[state].append((ins_arg.offset, ins_arg.data.constants[0].value))
            else:
                print("Cant' get the value for function call")
    return vals


def get_reg_used(p, cfg, addr, idx, s_addr, all_str_addrs):
    """
    Finds whether and which register is used to store a string address.

    :param p: angr project
    :param cfg: angr cfg
    :param addr: basic block address
    :param idx: statement idx of the statement referencing a string
    :param s_addr: address of string referenced in the statement pointed by idx
    :param all_str_addrs: all string addresses
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
            if v in ((s_addr, s_addr_2) + tuple(all_str_addrs)):
                return p.arch.register_names[o]
    return None


def find_memcmp_like(p, cfg):
    """
    Finds all the memcmp-like functions in a given binary (Linux and binary blob)

    :param p: angr project
    :param cfg: angr cfg
    :return: memcmp-like functions
    """

    memcmp_like = [f.addr for f in cfg.functions.values() if 'memcmp' in f.name]
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
            if any([op for l in loop for op in p.factory.block(l.addr).vex.operations if 'cmpeq' in op.lower() or
                                                                                         'cmpne' in op.lower()]):
                # INCREMENT
                wr_tmp = [st for l in loop for st in p.factory.block(l.addr).vex.statements if st.tag == 'Ist_WrTmp']
                cons = [w.constants for w in wr_tmp if hasattr(w, 'data') and hasattr(w.data, 'op') and
                        w.data.op == 'Iop_Add64']
                if cons:
                    cons = [c.value for cs in cons for c in cs]
                # using BootStomp thresholds
                if 1 in cons and len([x for x in fun.blocks]) <= 8:
                    memcmp_like.append(fun.addr)
    return list(set(memcmp_like))


# FIXME: to check and finish last part
def find_memcpy_like(p, cfg=None):
    """
    Finds all the memcpy-like functions in a given binary (Linux and binary blob)

    :param p: angr project
    :param cfg: angr cfg
    :return: memcpy-like functions
    """

    memcpy_like = [f.addr for f in p.kb.functions.values() if 'memcpy' in f.name]
    if cfg is None:
        return memcpy_like

    for fun in cfg.functions.values():
        css = []

        try:
            no = cfg.get_any_node(fun.addr)
            css = [pred for pred in no.predecessors]
        except:
            pass

        if not css:
            continue

        cs = css[0]
        args = get_ord_arguments_call(p, cs.addr)
        if len(args) > 3 or len(args) < 2:
            continue

        for loop in [x for x in networkx.simple_cycles(fun.graph)]:
            # CMPNE or CMPEQ
            if any([op for l in loop for op in p.factory.block(l.addr).vex.operations if 'cmpeq' in op.lower() or
                                                                                         'cmpne' in op.lower()]):
                # INCREMENT
                wr_tmp = [st for l in loop for st in p.factory.block(l.addr).vex.statements if st.tag == 'Ist_WrTmp']
                cons = [w.constants for w in wr_tmp if hasattr(w, 'data') and hasattr(w.data, 'op') and
                        w.data.op == 'Iop_Add64']
                if cons:
                    cons = [c.value for cs in cons for c in cs]
                # using BootStomp thresholds
                if 1 in cons and len([x for x in fun.blocks]) <= 8:
                    memcpy_like.append(fun.addr)

    return list(set(memcpy_like))


def get_atoi(p):
    """
    Atoi function summary
    :param p: angr project
    :return:  the atoi function summary
    """

    summarized_f = {}
    addrs = get_dyn_sym_addrs(p, ['atoi', 'atol', 'atoll'])
    for f in addrs:
        summarized_f[f] = summary_functions.atoi
    return summarized_f
