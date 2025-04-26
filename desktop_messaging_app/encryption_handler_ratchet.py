import os
import random
import json
import ast
import hashlib
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from math import prod
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

SIGNATURE_PARAMETERS = {
    "ELL": [3, 5, 7, 11, 13, 17],
    "P": 1021019
}

class EncryptionHandler:
    def __init__(self, key_storage_path='keys/'):
        if not os.path.exists(key_storage_path):
            os.makedirs(key_storage_path)
        self.key_storage_path = key_storage_path
        self.identity_private_key = None
        self.sign_private_key = None
        self.spk_private_key = None
        self.opk_private_key = None
        self.sign_p = SIGNATURE_PARAMETERS["P"]
        self.sign_ell = SIGNATURE_PARAMETERS['ELL']
        self.ell = PARAMETERS["ELL"]
        self.p = PARAMETERS["FP"]
        self.bound = PARAMETERS["BOUND"]
        self.parameters = PARAMETERS
        self.start_curve = MontgomeryEllipticCurve(self.parameters["FP"], self.parameters["A"], 1)
        self.sign_start_curve = MontgomeryEllipticCurve(self.sign_p, self.parameters["A"], 1)


    def generate_csidh_key_pair(self, user_email):
        bound = self.parameters["BOUND"]
        p = self.parameters["FP"]
        ell = self.parameters["ELL"]
        priv_len = len(ell)

        key_type = "IDENTITY"
        identity_private_key = [random.randint(-bound, bound) for _ in range(priv_len)]
        identity_public_key_curve = CSIDH_Tools.CSIDH(self.start_curve, identity_private_key, p, ell)
        identity_public_key = str(identity_public_key_curve.A)
        with open(f"{self.key_storage_path}{user_email}{key_type}_private.pem", 'w') as file:
            json.dump(identity_private_key, file)

        key_type = "SPK"
        spk_private_key = [random.randint(-bound, bound) for _ in range(priv_len)]
        spk_public_key_curve = CSIDH_Tools.CSIDH(self.start_curve, spk_private_key, p, ell)
        spk_public_key = str(spk_public_key_curve.A)
        with open(f"{self.key_storage_path}{user_email}{key_type}_private.pem", 'w') as file:
            json.dump(spk_private_key, file)

        key_type = "SIGN"
        sign_priv_len = len(self.sign_ell)
        sign_private_key = [random.randint(-bound, bound) for _ in range(sign_priv_len)]
        sign_public_key_curve = CSIDH_Tools.CSIDH(self.sign_start_curve, sign_private_key, self.sign_p, self.sign_ell)
        sign_public_key = str(sign_public_key_curve.A) 
        with open(f"{self.key_storage_path}{user_email}{key_type}_private.pem", 'w') as file:
            json.dump(sign_private_key, file)

        signature, bs = SEASIGN_Tools.sign(self.sign_start_curve, sign_private_key, spk_public_key, bound, sign_priv_len, self.sign_p, self.sign_ell)
        while signature == False:
            signature, bs = SEASIGN_Tools.sign(self.sign_start_curve, sign_private_key, spk_public_key, bound, sign_priv_len, self.sign_p, self.sign_ell)

        OPKs = []
        key_type = "ONETIME"
        for i in range(self.parameters["OPKS_num"]):
            onetime_private_key = [random.randint(-bound, bound) for _ in range(priv_len)]
            onetime_public_key_curve = CSIDH_Tools.CSIDH(self.start_curve, onetime_private_key, p, ell)
            onetime_public_key = str(onetime_public_key_curve.A)
            OPKs.append(onetime_public_key)
            ctr = str(i)
            with open(f"{self.key_storage_path}{user_email}{key_type}{ctr}_private.pem", 'w') as file:
                json.dump(onetime_private_key, file)

        key_bundle = {
            "IK" : identity_public_key,
            "SIGN": sign_public_key,
            "SPK": spk_public_key,
            "SIGNATURE": signature, 
            "BS": bs,
            "OPKS": OPKs
        }

        return key_bundle

    
    def verify_signature(self, user_email, signature, bs, msg, SIGN):
        self.load_private_key(user_email, "SIGN")
        SIGN = ast.literal_eval(SIGN)
        signature = list(ast.literal_eval(signature))
        bs = list(ast.literal_eval(bs))
        pub_key = MontgomeryEllipticCurve(self.sign_p, int(SIGN), 1)
        result = SEASIGN_Tools.verify(signature, bs, msg, self.sign_start_curve, pub_key, self.sign_p, self.sign_ell, len(self.sign_ell))
        return result
        

    def load_private_key(self, user_email, key_type, ctr=None):
        if key_type == "ONETIME":
            with open(f"{self.key_storage_path}{user_email}{key_type}{ctr}_private.pem", 'r') as f:
                private_key_data = json.load(f)
            self.opk_private_key = private_key_data
            return
        with open(f"{self.key_storage_path}{user_email}{key_type}_private.pem", 'r') as f:
            private_key_data = json.load(f)
        if key_type == "IDENTITY":
            self.identity_private_key = private_key_data
        if key_type == "SIGN":
            self.sign_private_key = private_key_data
        else:
            self.spk_private_key = private_key_data


    def generate_ephemeral_key(self):
        self.EK_A_key_pair = GENERATE_DH(self.start_curve, self.parameters["BOUND"], len(self.ell), self.p, self.ell)
        return str(self.EK_A_key_pair['public_key'].A)

    
    def return_state(self, state):
        return {
            "DHs": {
                "private_key": state.DHs["private_key"],
                "public_key": str(state.DHs["public_key"].A)
            },
            "DHr": str(state.DHr.A) if state.DHr is not None else state.DHr,
            "RK": str(state.RK),
            "CKs": str(state.CKs),
            "CKr": str(state.CKr),
            "Ns": str(state.Ns),
            "Nr": str(state.Nr),
            "PN": str(state.PN),
            "MKSKIPPED": state.MKSKIPPED,
            "name": state.name,
            "AD": str(state.AD)
        }
    

    def X3DH_Alice(self, email, IKB, SPKB, OPKB):
        bound = self.parameters["BOUND"]
        p = self.parameters["FP"]
        ell = self.parameters["ELL"]
        priv_len = len(ell)
        self.load_private_key(email, "IDENTITY")
        SPKB = MontgomeryEllipticCurve(self.p, int(SPKB), 1)
        IKB = MontgomeryEllipticCurve(self.p, int(IKB), 1)
        OPKB = MontgomeryEllipticCurve(self.p, int(OPKB), 1)

        DH1 = CSIDH_Tools.CSIDH(SPKB, self.identity_private_key, self.p, self.ell).A
        DH2 = CSIDH_Tools.CSIDH(IKB, self.EK_A_key_pair['private_key'], self.p, self.ell).A
        DH3 = CSIDH_Tools.CSIDH(SPKB, self.EK_A_key_pair['private_key'], self.p, self.ell).A
        DH4 = CSIDH_Tools.CSIDH(OPKB, self.EK_A_key_pair['private_key'], self.p, self.ell).A
        kdf_material_A = IntToBytes(DH1) + IntToBytes(DH2) + IntToBytes(DH3) + IntToBytes(DH4)
        SK_A = KDF(kdf_material_A)
        del DH1, DH2, DH3, DH4, self.EK_A_key_pair['private_key']

        IKA = CSIDH_Tools.CSIDH(self.start_curve, self.identity_private_key, p, ell).A
        AD = IntToBytes(IKA) + IntToBytes(IKB.A)
        state_alice = State()
        RatchetInitAlice(state_alice, SK_A, SPKB, AD, self.start_curve, bound, priv_len, p, ell)
        return self.return_state(state_alice)
    

    def X3DH_Bob(self, email, EK, IKA, OPK_id):
        p = self.parameters["FP"]
        ell = self.parameters["ELL"]
        self.load_private_key(email, "IDENTITY")
        self.load_private_key(email, "SPK")
        self.load_private_key(email, "ONETIME", ctr=int(OPK_id))
        EK = MontgomeryEllipticCurve(self.p, int(EK), 1)
        IKA = MontgomeryEllipticCurve(self.p, int(IKA), 1)

        DH1 = CSIDH_Tools.CSIDH(IKA, self.spk_private_key, self.p, self.ell).A
        DH2 = CSIDH_Tools.CSIDH(EK, self.identity_private_key, self.p, self.ell).A
        DH3 = CSIDH_Tools.CSIDH(EK, self.spk_private_key, self.p, self.ell).A
        DH4 = CSIDH_Tools.CSIDH(EK, self.opk_private_key, self.p, self.ell).A
        kdf_material_B = IntToBytes(DH1) + IntToBytes(DH2) + IntToBytes(DH3) + IntToBytes(DH4)
        SK_B = KDF(kdf_material_B)
        del DH1, DH2, DH3, DH4

        IKB = CSIDH_Tools.CSIDH(self.start_curve, self.identity_private_key, p, ell).A
        spk_public_key = CSIDH_Tools.CSIDH(self.start_curve, self.spk_private_key, p, ell)
        AD = IntToBytes(IKA.A) + IntToBytes(IKB)
        state_bob = State()
        SPKB = {
            "private_key": self.spk_private_key,
            "public_key": spk_public_key
        }
        RatchetInitBob(state_bob, SK_B, SPKB, AD)
        return self.return_state(state_bob)


    def create_state(self, state):
        created = State()
        created.DHs = {
            "private_key": state["DHs"]["private_key"],
            "public_key": MontgomeryEllipticCurve(self.p, int(state["DHs"]["public_key"]), 1)
        }
        created.DHr = MontgomeryEllipticCurve(self.p, int(state["DHr"]), 1) if state["DHr"] != None else None
        created.RK = ast.literal_eval(state["RK"]) if state["RK"] != 'None' else None
        created.CKs = ast.literal_eval(state["CKs"]) if state["CKs"] != 'None' else None
        created.CKr = ast.literal_eval(state["CKr"]) if state["CKr"] != 'None' else None
        created.Ns = int(state["Ns"])
        created.Nr = int(state["Nr"])
        created.PN = int(state["PN"])
        created.MKSKIPPED = state["MKSKIPPED"]
        created.name = state["name"]
        created.AD = ast.literal_eval(state["AD"])
        return created


    def ratchet_encrypt(self, state, plaintext, AD):
        AD = string_to_bytes(AD)
        received_state = self.create_state(state)
        received_state.CKs, mk = KDF_CK(received_state.CKs)
        header = HEADER(received_state.DHs['public_key'], received_state.PN, received_state.Ns)
        received_state.Ns += 1
        ciphertext = ENCRYPT(mk, plaintext.encode('utf-8'), CONCAT(AD, header))
        base64_encoded = base64.b64encode(ciphertext)
        base64_ciphertext = base64_encoded.decode('utf-8')
        header["dh_public_key"] = str(header["dh_public_key"].A) 
        return header, base64_ciphertext, self.return_state(received_state)

    
    def ratchet_decrypt(self, state, header, ciphertext, AD):
        AD = string_to_bytes(AD)
        received_state = self.create_state(state)
        header["dh_public_key"] = MontgomeryEllipticCurve(self.p, int(header["dh_public_key"]), 1)
        ciphertext = base64.b64decode(ciphertext)
        plaintext = TrySkippedMessageKeys(received_state, header, ciphertext, AD)
        if plaintext is not None:
            return plaintext
        
        if received_state.DHr is None:
            SkipMessageKeys(received_state, header['pn'])
            DHRatchet(received_state, header, self.start_curve, self.bound, len(self.ell), self.p, self.ell)
        elif header['dh_public_key'] != received_state.DHr:
            SkipMessageKeys(received_state, header['pn'])
            DHRatchet(received_state, header, self.start_curve, self.bound, len(self.ell), self.p, self.ell)
            
        SkipMessageKeys(received_state, header['ns'])
        received_state.CKr, mk = KDF_CK(received_state.CKr)
        received_state.Nr += 1
        decrypted_message = DECRYPT(mk, ciphertext, CONCAT(AD, header))
        modified_state = self.return_state(received_state)
        return decrypted_message.decode('utf-8'), modified_state


    def derive_shared_key(self, peer_public_key):
        p = self.parameters["FP"]
        ell = self.parameters["ELL"]
        peer_public_key = int(peer_public_key)
        peer_curve = MontgomeryEllipticCurve(p, peer_public_key, 1)
        shared_key_curve = CSIDH_Tools.CSIDH(peer_curve, self.spk_private_key, p, ell)
        shared_key = shared_key_curve.A
        shared_key_bytes = str(shared_key).encode()

        derived_key = HKDF(
            algorithm=SHA256(),
            length=32,
            salt=None,
            info=b'shared-secret',
        ).derive(shared_key_bytes)

        return derived_key


    def encrypt_attachment(self, message, recipient_public_key, user_email):
        self.load_private_key(user_email, "SPK")
        shared_key = self.derive_shared_key(recipient_public_key)
        encrypted_message = self.aes_encrypt(shared_key, message.encode('utf-8'))
        return base64.b64encode(encrypted_message).decode('utf-8')


    def decrypt_attachment(self, encrypted_message_base64, recipient_public_key, user_email):
        self.load_private_key(user_email, "SPK")
        encrypted_message = base64.b64decode(encrypted_message_base64)
        shared_key = self.derive_shared_key(recipient_public_key)
        decrypted_message = self.aes_decrypt(shared_key, encrypted_message)
        return decrypted_message.decode('utf-8')


    def aes_encrypt(self, key, plaintext):
        nonce = get_random_bytes(12)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        return nonce + tag + ciphertext


    def aes_decrypt(self, key, ciphertext):
        nonce = ciphertext[:12]
        tag = ciphertext[12:28]
        ciphertext = ciphertext[28:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)


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


def string_to_bytes(s):
    x = s[2:-1]
    x_in_bytes = x.encode('utf-8')
    return x_in_bytes 


def calculate_key(object):
    return str((int(object[0]) << 32) | int(object[1]))


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


def GENERATE_DH(E, bound, priv_len, p, ell) -> dict:
    private_key = [random.randint(-bound,bound) for _ in range(priv_len)]
    public_key = CSIDH_Tools.CSIDH(E, private_key, p, ell)
    return {'private_key': private_key, 'public_key': public_key}


def DH(private_key, public_key, p, ell):
    shared_key = CSIDH_Tools.CSIDH(public_key, private_key, p, ell)
    return shared_key


def IntToBytes(given_int) -> bytes:
    return given_int.to_bytes((given_int.bit_length() + 7) // 8, byteorder='big')


def KDF_RK(root_key, dh_output):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=root_key,
        info=b'root-key',
    )
    dh_output_int = int(dh_output.A)
    dh_output_bytes = IntToBytes(dh_output_int)
    output = hkdf.derive(dh_output_bytes)
    
    new_root_key = output[:32]
    chain_key_send = output[32:]
    return new_root_key, chain_key_send


class State:
    def __init__(self):
        self.DHs = None
        self.DHr = None
        self.RK = None
        self.CKs = None
        self.CKr = None
        self.Ns = 0
        self.Nr = 0
        self.PN = 0
        self.MKSKIPPED = {}
        self.name = ""
        self.AD = None


def RatchetInitAlice(state, SK, bob_public_key, AD, E, bound, priv_len, p, ell):
    state.DHs = GENERATE_DH(E, bound, priv_len, p, ell)
    state.DHr = bob_public_key
    state.RK, state.CKs = KDF_RK(SK, DH(state.DHs['private_key'], state.DHr, p, ell))
    state.CKr = None
    state.Ns = 0
    state.Nr = 0
    state.PN = 0
    state.MKSKIPPED = {}
    state.name = "Alice"
    state.AD = AD


def RatchetInitBob(state, SK, bob_dh_key_pair, AD):
    state.DHs = bob_dh_key_pair
    state.DHr = None
    state.RK = SK
    state.CKs = None
    state.CKr = None
    state.Ns = 0
    state.Nr = 0
    state.PN = 0
    state.MKSKIPPED = {}
    state.name = "Bob"
    state.AD = AD


def KDF_CK(ck):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=None,
        info=b'ratchet-message-key'
    )
    output = hkdf.derive(ck)
    new_ck = output[:32]
    mk = output[32:]
    return new_ck, mk


def HEADER(dh_public_key, pn, ns) -> dict:
    return {
        'dh_public_key': dh_public_key,
        'pn': pn,
        'ns': ns
    }


def ENCRYPT(mk, plaintext, ad) -> bytes:
    aesgcm = AESGCM(mk)
    nonce = os.urandom(12)  
    ciphertext = aesgcm.encrypt(nonce, plaintext, ad)
    return nonce + ciphertext  


def CONCAT(ad, header) -> bytes:
    header_bytes = b"%b|%d|%d" % (IntToBytes(int(header['dh_public_key'].A)), header['pn'], header['ns'])
    return ad + header_bytes  


def RatchetEncrypt(state, plaintext, AD, first_message):
    state.CKs, mk = KDF_CK(state.CKs)
    header = HEADER(state.DHs['public_key'], state.PN, state.Ns)
    state.Ns += 1
    ciphertext = ENCRYPT(mk, plaintext, CONCAT(AD, header))
    return header, ciphertext


def DECRYPT(mk, ciphertext, ad) -> bytes:
    aesgcm = AESGCM(mk)
    nonce = ciphertext[:12]
    encrypted_message = ciphertext[12:]
    plaintext = aesgcm.decrypt(nonce, encrypted_message, ad)
    return plaintext


def RatchetDecrypt(state, header, ciphertext, AD):
    plaintext = TrySkippedMessageKeys(state, header, ciphertext, AD)
    if plaintext is not None:
        return plaintext
    
    if header['dh_public_key'] != state.DHr:
        SkipMessageKeys(state, header['pn'])
        DHRatchet(state, header)

    SkipMessageKeys(state, header['ns'])
    state.CKr, mk = KDF_CK(state.CKr)
    state.Nr += 1

    return DECRYPT(mk, ciphertext, CONCAT(AD, header))


def TrySkippedMessageKeys(state, header, ciphertext, AD):
    key_id = calculate_key((header['dh_public_key'].A, header['ns']))
    if key_id in state.MKSKIPPED:
        mk = state.MKSKIPPED[key_id]
        del state.MKSKIPPED[key_id]
        return DECRYPT(mk, ciphertext, CONCAT(AD, header))
    else:
        return None

def SkipMessageKeys(state, until):
    MAX_SKIP = 1000
    if state.Nr + MAX_SKIP < until:
        raise Exception("Too many skipped messages")
    if state.CKr is not None:
        while state.Nr < until and state.CKr is not None:
            state.CKr, mk = KDF_CK(state.CKr)
            key_id = calculate_key((state.DHr.A, state.Nr))
            state.MKSKIPPED[key_id] = str(mk)
            state.Nr += 1


def DHRatchet(state, header, E, bound, priv_len, p, ell):
    state.PN = state.Ns
    state.Ns = 0  
    state.Nr = 0  
    state.DHr = header['dh_public_key']
    state.RK, state.CKr = KDF_RK(state.RK, DH(state.DHs['private_key'], state.DHr, p, ell))
    state.DHs = GENERATE_DH(E, bound, priv_len, p, ell)
    state.RK, state.CKs = KDF_RK(state.RK, DH(state.DHs['private_key'], state.DHr, p, ell))


def KDF(input_str):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  
        salt=None,  
        info=b'diffie-hellman-concatenation'
    )
    output_sk = hkdf.derive(input_str)
    return output_sk


def Initial_message_constructor(IK_public_key, EK_public_key, OPK_public_key, ciphertext):
    dict_return = {
        "IK_public_key": IK_public_key.A,
        "EK_public_key": EK_public_key.A,
        "OPK_public_key": OPK_public_key.A,
        "ciphertext": ciphertext
        }
    return str(dict_return)

class SEASIGN_Tools:
    @staticmethod
    def subtract_vectors(vector1, vector2):
        return [v1 - v2 for v1, v2 in zip(vector1, vector2)]

    @staticmethod
    def check_bounds(vector, bound):
        return all(-bound <= element <= bound for element in vector)

    @staticmethod
    def HASH(t, lst):
        concatenated = ''.join(map(str, lst))
        hash_object = hashlib.sha256(concatenated.encode('utf-8'))
        full_hash = hash_object.hexdigest() 
        full_hash_binary = bin(int(full_hash, 16))[2:]
        truncated_binary = full_hash_binary[:t]
        return truncated_binary

    @staticmethod
    def sign(E, priv_key, msg, bound, len_priv, p, ell, t=4):
        data = []
        signature = []
        privs = []
        bs = []
        for _ in range(t):
            temp_priv = [random.randint(-bound * len_priv * t, bound * len_priv * t) for x in range(len_priv)]
            privs.append(temp_priv)
            temp_pub = CSIDH_Tools.CSIDH(E, temp_priv, p, ell)
            data.append(temp_pub.A)
        data.append(msg)
        bx = SEASIGN_Tools.HASH(t, data)
        n = 0
        for b in bx:
            if b == "0":
                signature = signature + privs[n]
                bs.append(0)
            else:
                sub = SEASIGN_Tools.subtract_vectors(privs[n], priv_key)
                if SEASIGN_Tools.check_bounds(sub, bound * len_priv * t):
                    signature = signature + sub
                else: 
                    return False, None

                bs.append(1)
            n = n + 1
        return signature, bs

    @staticmethod
    def verify(sig, bs, msg, E, pub_key, p, ell, len_priv, t=4):
        data = []
        n = 0
        i = 0
        signature = []
        for _ in range(t):
            signature.append(sig[i*len_priv:i*len_priv+len_priv])
            i = i + 1
        for b in bs:
            if b == 0:
                temp_key = CSIDH_Tools.CSIDH(E, signature[n], p, ell)
                data.append(temp_key.A)
            else:
                temp_key = CSIDH_Tools.CSIDH(pub_key, signature[n], p, ell)
                data.append(temp_key.A)
            n = n + 1
        data.append(msg)
        H = SEASIGN_Tools.HASH(t, data)
        bs_prim = ''.join(str(bit) for bit in bs)
        if H == bs_prim:
            return True
        else:
            return False