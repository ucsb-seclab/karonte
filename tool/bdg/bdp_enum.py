from enum import Enum


class Role(Enum):
    SETTER = 0
    GETTER = 1
    UNKNOWN = 2
    SETTER_GETTER = 3


class BuffType(Enum):
    HEAP = 0
    STACK = 1
    GLOBAL = 2


"""
strings information about the node, they are:
* role of the binary
* string used to infer the role
* function the string was referenced
* the basic block calling the function defining the role
* the role function
* the instruction used to define the role
* VEX idx of the instruction defining the role
* if shared memory, the buffer used to share data
* parameter id of function used to set or get the share data
"""


class RoleInfo(Enum):
    ROLE = 'role'
    DATAKEY = 'datakey'
    X_REF_FUN = 'x_ref_function'
    CALLER_BB = 'block_caller_role_function'
    ROLE_FUN = 'role_function'
    ROLE_INS = 'role_ins'
    ROLE_INS_IDX = 'role_ins_idx'
    COMM_BUFF = 'comm_buf'
    PAR_N = 'par_n'
    CPF = 'cpf'
