from math import prod
import ALGEBRA as Modular_Math
from ALGEBRA import Montgomery_Point, MontgomeryEllipticCurve 

class CSIDH_Tools:
    @staticmethod
    def isogeny_from_montgomery_model(E, P, R):
        p = E.p
        A = E.A
        B = E.B
        G = E.generate_subgroup(R)
        G = [point for point in G if not point.is_infinity]
        
        pi = prod([T.x for T in G])
        sigma = sum([(T.x - Modular_Math.inverse_of(T.x, p)) for T in G])
        new_A = pi * (A - 3*sigma) % p
        new_E = MontgomeryEllipticCurve(p, new_A, B)
        
        x = P.x
        product = [(x*T.x - 1)*(Modular_Math.inverse_of(x - T.x, p)) for T in G]
        f_x = x * prod(product) 
        new_x = f_x
        new_y = new_E.lift_x(new_x).y

        if new_x == 0 and new_y == 0:
            new_P = Montgomery_Point(p, new_E)
        else:
            new_P = Montgomery_Point(p, new_E, new_x, new_y)

        return new_E, new_P

    @staticmethod
    def CSIDH(E, priv, p, ell):
        L_side = (p+1)*E.random_point()
        R_side = Montgomery_Point(p, E)
        assert L_side == R_side
        for cl in ([max(0, e) for e in priv], [max(0, -e) for e in priv]):
            while any(cl) != 0:
                j = [n for n in zip(ell, cl)]
                P = E.random_point()
                S = [j.index(ei) for ei in j if ei[1]!=0]
                if S:
                    k = prod(ell[i] for i in S)
                    Q = ((p+1)//k)*P
                    for i in S:
                        l = ell[i]
                        R = (k//l)*Q
                        if not (R.x is None and R.y is None):
                            E, Q = CSIDH_Tools.isogeny_from_montgomery_model(E, Q, R)
                            k = k//l
                            cl[i] -= 1
            E = E.quadratic_twist()                
        return E
