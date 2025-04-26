import random
import ast
from ALGEBRA import MontgomeryEllipticCurve 
from CSIDH import CSIDH_Tools
from DOUBLE_RATCHET import State, GENERATE_DH, IntToBytes, KDF, ENCRYPT, RatchetInitAlice, RatchetInitBob, PARAMETERS


def Initial_message_constructor(IK_public_key, EK_public_key, OPK_public_key, ciphertext):
    dict_return = {
        "IK_public_key": IK_public_key.A,
        "EK_public_key": EK_public_key.A,
        "OPK_public_key": OPK_public_key.A,
        "ciphertext": ciphertext
        }
    return str(dict_return)


def InicializateConversation():
    state_alice = State()
    state_bob = State()

    IK_A_key_pair = GENERATE_DH()
    IK_B_key_pair = GENERATE_DH()

    OPK_A_key_pair_list = [GENERATE_DH() for _ in range(6)]
    OPK_B_key_pair_list = [GENERATE_DH() for _ in range(6)]

    SPK_A_key_pair = GENERATE_DH() 
    SPK_B_key_pair = GENERATE_DH()

    EK_A_key_pair = GENERATE_DH()

    DH1 = CSIDH_Tools.CSIDH(SPK_B_key_pair['public_key'], IK_A_key_pair['private_key'])
    DH2 = CSIDH_Tools.CSIDH(IK_B_key_pair['public_key'], EK_A_key_pair['private_key'])
    DH3 = CSIDH_Tools.CSIDH(SPK_B_key_pair['public_key'], EK_A_key_pair['private_key'])

    
    i = random.randint(0, len(OPK_B_key_pair_list) - 1)
    OPK_B_key_pair = OPK_B_key_pair_list[i]
    DH4 = CSIDH_Tools.CSIDH(OPK_B_key_pair['public_key'], EK_A_key_pair['private_key'])
    kdf_material_A = IntToBytes(DH1.A) + IntToBytes(DH2.A) + IntToBytes(DH3.A) + IntToBytes(DH4.A)
    print("DH1-4 for Alice:", DH1.A, DH2.A, DH3.A, DH4.A)
    SK_A = KDF(kdf_material_A)
    del DH1, DH2, DH3, DH4, EK_A_key_pair['private_key']

    AD_A = IntToBytes(IK_A_key_pair['public_key'].A) + IntToBytes(IK_B_key_pair['public_key'].A)

    initial_message = Initial_message_constructor(
        IK_A_key_pair['public_key'],
        EK_A_key_pair['public_key'],
        OPK_B_key_pair['public_key'],
        ENCRYPT(SK_A, b"INITIAL_ENCRYPT", AD_A)
    )

    retrieved_data = ast.literal_eval(initial_message)
    IK_A_key_pair['public_key'] = MontgomeryEllipticCurve(PARAMETERS["FP"], retrieved_data['IK_public_key'], 1)
    EK_A_key_pair['public_key'] = MontgomeryEllipticCurve(PARAMETERS["FP"], retrieved_data['EK_public_key'], 1)
    OPK_B_key_pair['public_key'] = MontgomeryEllipticCurve(PARAMETERS["FP"], retrieved_data['OPK_public_key'], 1)

    DH1 = CSIDH_Tools.CSIDH(IK_A_key_pair['public_key'], SPK_B_key_pair['private_key'])
    DH2 = CSIDH_Tools.CSIDH(EK_A_key_pair['public_key'], IK_B_key_pair['private_key'])
    DH3 = CSIDH_Tools.CSIDH(EK_A_key_pair['public_key'], SPK_B_key_pair['private_key'])

    correct_one_time = OPK_B_key_pair['public_key']
    for key_pair in OPK_B_key_pair_list:
        if key_pair['public_key'] == correct_one_time:
            OPK_B_private = key_pair['private_key']

    DH4 = CSIDH_Tools.CSIDH(EK_A_key_pair['public_key'],OPK_B_private)

    kdf_material_B = IntToBytes(DH1.A) + IntToBytes(DH2.A) + IntToBytes(DH3.A) + IntToBytes(DH4.A)
    print("DH1-4 for Bob:", DH1.A, DH2.A, DH3.A, DH4.A)
    SK_B = KDF(kdf_material_B)
    del DH1, DH2, DH3, DH4

    AD_B = IntToBytes(IK_A_key_pair['public_key'].A) + IntToBytes(IK_B_key_pair['public_key'].A)

    assert AD_A == AD_B
    assert SK_A == SK_B

    RatchetInitAlice(state_alice, SK_A, SPK_B_key_pair['public_key'], AD_A)
    RatchetInitBob(state_bob, SK_B, SPK_B_key_pair, AD_B)

    return state_alice, state_bob
