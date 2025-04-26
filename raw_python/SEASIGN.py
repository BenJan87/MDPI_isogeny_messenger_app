import random
import hashlib
from CSIDH import CSIDH_Tools


SIGNATURE_PARAMETERS = {
        "ELL": [3, 5, 7, 11, 13, 17],
        "P": 1021019
    }


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
        full_hash_binary = bin(int(full_hash, 16))[2:].zfill(256) 
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
