import random
import os
from ALGEBRA import MontgomeryEllipticCurve
from CSIDH import CSIDH_Tools
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


xP = 82395230866857848939

PARAMETERS = {
    "SKIP": 1000,
    "FP": xP,
    "ELL": [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 67],
    "A": 0,
    "BOUND": 1,
    "OPKS_num": 4
}

def GENERATE_DH():
    private_key = [random.randint(-PARAMETERS["bound"], PARAMETERS["bound"]) for _ in range(len(PARAMETERS['ELL']))]
    public_key = CSIDH_Tools.CSIDH(MontgomeryEllipticCurve(PARAMETERS["FP"]), private_key)
    return {'private_key': private_key, 'public_key': public_key}

def DH(private_key, public_key):
    shared_key = CSIDH_Tools.CSIDH(public_key, private_key)
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
    if dh_output:
        dh_output_int = int(dh_output.A)
        dh_output_bytes = IntToBytes(dh_output_int)
        output = hkdf.derive(dh_output_bytes)
    else:
        output = hkdf.derive(dh_output)
    
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

def RatchetInitAlice(state, SK, bob_public_key, AD):
    state.DHs = GENERATE_DH()
    state.DHr = bob_public_key
    state.RK, state.CKs = KDF_RK(SK, DH(state.DHs['private_key'], state.DHr))
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
        print("ZMIANA")
        DHRatchet(state, header)

    SkipMessageKeys(state, header['ns'])
    state.CKr, mk = KDF_CK(state.CKr)
    state.Nr += 1

    return DECRYPT(mk, ciphertext, CONCAT(AD, header))


def TrySkippedMessageKeys(state, header, ciphertext, AD):
    key_id = (header['dh_public_key'], header['ns'])
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
    if state.CKr != None:
        while state.Nr < until and state.CKr is not None:
            state.CKr, mk = KDF_CK(state.CKr)
            state.MKSKIPPED[(state.DHr, state.Nr)] = mk
            state.Nr += 1


def DHRatchet(state, header):
    state.PN = state.Ns
    state.Ns = 0  
    state.Nr = 0  
    state.DHr = header['dh_public_key']
    state.RK, state.CKr = KDF_RK(state.RK, DH(state.DHs['private_key'], state.DHr))
    state.DHs = GENERATE_DH()
    state.RK, state.CKs = KDF_RK(state.RK, DH(state.DHs['private_key'], state.DHr))


def DECRYPT(mk, ciphertext, ad):
    aesgcm = AESGCM(mk)
    nonce = ciphertext[:12]
    encrypted_message = ciphertext[12:]
    plaintext = aesgcm.decrypt(nonce, encrypted_message, ad)
    return plaintext.decode('utf-8')


def KDF(input_str):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  
        salt=None,  
        info=b'diffie-hellman-concatenation'
    )
    output_sk = hkdf.derive(input_str)
    return output_sk
