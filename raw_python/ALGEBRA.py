import random
from sympy import isprime


xP = 82395230866857848939

PARAMETERS = {
        "SKIP": 1000,
        "FP": xP,
        "ELL": [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 67],
        "A": 0,
        "BOUND": 1,
        "OPKS_num": 4
    }

class Modular_Math:
    @staticmethod
    def extended_euclidean_algorithm(a, b):
        if a == 0:
            return 0, 1
        x, y = Modular_Math.extended_euclidean_algorithm(b % a, a)
        return y - (b // a) * x, x

    @staticmethod
    def inverse_of(n, p):
        x, y = Modular_Math.extended_euclidean_algorithm(n, p)
        return x % p


class Montgomery_Point:
    def __init__(self, p, E, x=None, y=None):
        self.x = x % p if x is not None else None
        self.y = y % p if y is not None else None
        self.p = p
        self.curve = E
        self.is_infinity = (x is None and y is None)

    
    def __str__(self):
        if self.is_infinity:
            return "Point at Infinity"
        return f"Point({self.x}, {self.y} with p={self.p})"


    def __eq__(self, other):
        if self.is_infinity and other.is_infinity:
            return True
        if self.is_infinity or other.is_infinity:
            return False
        return self.curve == other.curve and self.x == other.x and self.y == other.y


    def __add__(self, other):
        if self.is_infinity:
            return other
        if other.is_infinity:
            return self
        if self == other.opposite():
            return Montgomery_Point(self.p, self.curve)
        if self == other:
            return self.double()

        x1, y1 = self.x, self.y
        x2, y2 = other.x, other.y
        p = self.p
        A = self.curve.A
        B = self.curve.B

        dx = (x2 - x1) % p
        dy = (y2 - y1) % p
        if dx == 0:
            return Montgomery_Point(self.p, self.curve)
        dx_inv = Modular_Math.inverse_of(dx, p)
        slope = (dy * dx_inv) % p
        x3 = (B * slope**2 - A - x1 - x2) % p
        y3 = (slope * (x1 - x3) - y1) % p

        return Montgomery_Point(p, self.curve, x3, y3)


    def double(self):
        if self.is_infinity:
            return self
        x1, y1 = self.x, self.y
        p = self.p
        A = self.curve.A
        B = self.curve.B

        numerator = (3 * x1**2 + 2 * A * x1 + 1) % p
        denominator = (2 * B * y1) % p

        if denominator == 0:
            return Montgomery_Point(self.p, self.curve)

        denominator_inv = Modular_Math.inverse_of(denominator, p)
        slope = (numerator * denominator_inv) % p

        x3 = (B * slope**2 - A - 2 * x1) % p
        y3 = (slope * (3 * x1 + A) - B * slope**3 - y1) % p

        return Montgomery_Point(p, self.curve, x3, y3)


    def __mul__(self, scalar):
        result = Montgomery_Point(self.p, self.curve)
        addend = self
        while scalar > 0:
            if scalar & 1:
                result += addend
            addend = addend.double()
            scalar >>= 1
        return result


    def __rmul__(self, scalar):
        return self.__mul__(scalar)


    def opposite(self):
        if self.is_infinity:
            return self
        return Montgomery_Point(self.p, self.curve, self.x, (-self.y) % self.p)


class MontgomeryEllipticCurve:
    def __init__(self, p, A, B):
        self.p = p
        self.A = A
        self.B = B 


    def __eq__(self, E):
        return self.A == E.A


    def random_point(self):
        while True:
            x = random.randint(0, self.p - 1)
            try:
                random_point_P = self.lift_x(x)
                return random_point_P
            except ValueError:
                continue


    def legendre_symbol(self, a, p):
            ls = pow(a, (p - 1) // 2, p)
            return -1 if ls == p - 1 else ls


    def Elliptic_Point_Order(self, point):
            i = 1
            identity_point = Montgomery_Point(point.p, point.curve)
            current_point = point
            while current_point != identity_point:
                current_point += point
                i += 1
            return i


    def modular_sqrt(self, a, p):
        if self.legendre_symbol(a, p) != 1:
            return 0
        elif a == 0:
            return 0
        elif p == 2:
            return p
        elif p % 4 == 3:
            return pow(a, (p + 1) // 4, p)

        p - 1
        e = 0
        while s % 2 == 0:
            s //= 2
            e += 1

        n = 2
        while self.legendre_symbol(n, p) != -1:
            n += 1

        x = pow(a, (s + 1) // 2, p)
        b = pow(a, s, p)
        g = pow(n, s, p)
        r = e

        while True:
            t = b
            m = 0
            for m in range(r):
                if t == 1:
                    break
                t = pow(t, 2, p)

            if m == 0:
                return x

            gs = pow(g, 2 ** (r - m - 1), p)
            g = (gs * gs) % p
            x = (x * gs) % p
            b = (b * g) % p
            r = m


    def lift_x(self, x):
        y_squared = x**3 + self.A * x**2 + x
        y = self.modular_sqrt(y_squared, self.p)
        if y is None:
            raise ValueError("The x-cordinate does not have y-cordinate")
        return Montgomery_Point(self.p, self, x, y)
    

    def to_Montgomery_model(self, a, b, p):
        candidate = None
        p1 = (-1 * (b * Modular_Math.inverse_of(2, p))) % p
        p2 = pow(b, 2, p) * Modular_Math.inverse_of(4, p)
        p3 = pow(a, 3, p) * Modular_Math.inverse_of(27, p)
        p4 = pow(p2 + p3, (p + 1) // 4, p)
        u1 = p1 + p4
        u2 = p1 - p4
        candidate = pow(u1, (2*p-1)//3, p) + pow(u2, (2*p-1)//3, p)
        QR = (3 * candidate**2 + a) % p          
        r,s = candidate, QR
        root_s = pow(s, (p + 1) // 4, p)
        new_A = ((3 * r) * Modular_Math.inverse_of(root_s, p)) % p
        new_B = 1
        return new_A, new_B


    def to_Weierstrass_model(self):
        A = self.A
        B = self.B
        p = self.p
        new_a = (3 - A**2) * Modular_Math.inverse_of(3 * B**2, p) % p
        new_b = (2 * A**3 - 9 * A) * Modular_Math.inverse_of(27 * B**3, p) % p
        return new_a, new_b


    def quadratic_twist(self):
        p = self.p
        if not isprime(p):
            raise ValueError("The field characteristic p must be prime.")
        D = random.randint(2, p-1)
        while self.legendre_symbol(D, p) != -1:
            D = random.randint(2, p-1) 

        t, s = self.to_Weierstrass_model()
        a4 = (D ** 2 * t) % p
        a6 = (D ** 3 * s) % p
        A, B = self.to_Montgomery_model(a4, a6, p)

        return MontgomeryEllipticCurve(p, A % p, B % p)

    def generate_subgroup(self, generator_point):
        G = []
        point = generator_point
        order = self.Elliptic_Point_Order(generator_point)

        for _ in range(order):
            G.append(point)
            point = point + generator_point
        return G


    def __str__(self):
        return f"Montgomery elliptic curve as {self.B} * y^2 = x^3 + {self.A} * x^2 +x"


    def __repr__(self):
        return f"EllipticCurve(a={self.A}, p={self.p})"
    