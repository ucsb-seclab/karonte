import mpmath
import sympy

mpmath.mp.pretty = True
ROUND = 5


def get_generating_function(f, T=None):
    """
    Get the generating function

    :param f: function addr
    :param T: edges matrix of the function f
    :return: the generating function
    """

    if not T:
        edges = [(a[0].addr, a[1].addr) for a in f.graph.edges()]
        N = sorted([x for x in f.block_addrs])
        T = []
        for b1 in N:
            T.append([])
            for b2 in N:
                if b1 == b2 or (b1, b2) in edges:
                    T[-1].append(1)
                else:
                    T[-1].append(0)
    else:
        N = T[0]

    T = sympy.Matrix(T)
    z = sympy.var('z')
    I = sympy.eye(len(N))

    tmp = I - z * T
    tmp.row_del(len(N) - 1)
    tmp.col_del(0)
    det_num = tmp.det()
    det_den = (I - z * T).det()
    quot = det_num / det_den
    g_z = ((-1) ** (len(N) + 1)) * quot
    return g_z


def get_path_n(f, T=None):
    # TODO cire paper here
    """
    Get the formula to estimate the number of path of a function, given its longest path.

    :param f: function addr
    :param T: edges matrix of the function f
    :return: formula to estimate the number of paths
    """

    g_z = get_generating_function(f, T)
    expr = g_z.as_numer_denom()[1]
    rs = sympy.roots(expr)
    D = len(set(rs.keys()))  # number of distinct roots
    d = sum(rs.values())  # number of roots

    # get taylor coefficients
    f = sympy.utilities.lambdify(list(g_z.free_symbols), g_z)
    taylor_coeffs = mpmath.taylor(f, 0, d - 1)  # get the first d terms of taylor expansion

    #
    # calculate path_n
    #

    n = sympy.var('n')
    e_path_n = 0
    e_upper_n = 0
    coeff = []

    for i in range(1, D + 1):
        # TODO fix. This does not work
        ri, mi = rs.items()[i - 1]
        for j in range(mi):
            c_ij = sympy.var('c_' + str(i) + str(j))
            coeff.append(c_ij)
            e_path_n += c_ij * (n ** j) * ((1 / ri) ** n)
            if ri.is_complex:
                ri = sympy.functions.Abs(ri)
            e_upper_n += c_ij * (n ** j) * ((1 / ri) ** n)
    equations = []

    for i, c in enumerate(taylor_coeffs):
        equations.append(sympy.Eq(e_path_n.subs(n, i), c))
    coeff_sol = sympy.linsolve(equations, coeff)

    # assert unique solution
    assert type(coeff_sol) == sympy.sets.FiniteSet, "Zero or more solutions returned for path_n coefficients"
    coeff_sol = list(coeff_sol)[0]
    coeff_sol = [sympy.N(c, ROUND) for c in coeff_sol]

    for val, var in zip(coeff_sol, coeff):
        name = var.name
        e_path_n = e_path_n.subs(name, val)
        e_upper_n = e_upper_n.subs(name, val)

    return sympy.utilities.lambdify(list(e_path_n.free_symbols), e_path_n), sympy.utilities.lambdify(
        list(e_upper_n.free_symbols), e_upper_n)
