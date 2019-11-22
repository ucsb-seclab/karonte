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


class RoleInfo(Enum):
    ROLE = 'role'
    STRING = 'string'
    X_REF_FUN = 'x_ref_function'
    CALLER_BB = 'block_caller_role_function'
    ROLE_FUN = 'role_function'
    ROLE_INS = 'role_ins'
    ROLE_INS_IDX = 'role_ins_idx'
    COMM_BUFF = 'comm_buf'
    PAR_N = 'par_n'
