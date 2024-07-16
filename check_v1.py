"""
This work, "MIC - Monero Inflation Checker", is a derivative of:
    "Mininero" by ShenNoether (https://github.com/monero-project/mininero).
    "dumb25519" by SarangNoether (https://github.com/SarangNoether/skunkworks/tree/curves/dumb25519)
"MIC - Monero Inflation Checker" is licensed under GPL 3.0 by DangerousFreedom.
"""

import sys
import com_db
import misc_func
from df25519 import Scalar, Point, PointVector
import df25519
import struct
import numpy as np
import multiprocessing
from concurrent.futures import as_completed, ProcessPoolExecutor


def get_tx_prefix_hash(resp_json, resp_hex):
    signatures = resp_json["signatures"]
    sig = signatures[0]
    tx_prefix_raw = resp_hex.split(sig)[0]
    tx_prefix_hash = df25519.cn_fast_hash(tx_prefix_raw)
    return tx_prefix_hash.encode()
#--------------------------------------------------------------------------------------------
def get_signatures(resp_json, resp_hex, index):
    signatures = resp_json["signatures"]
    sig = signatures[index]

    n_ring_members = len(sig) // (64 * 2)
    sc, sr = [], []

    for i in range(0, int(2 * n_ring_members), 2):
        sc.append(df25519.Scalar(sig[int(i * 64) : int((i + 1) * 64)]))
        sr.append(df25519.Scalar(sig[int((i + 1) * 64) : int((i + 2) * 64)]))

    sigc = df25519.ScalarVector(sc)
    sigr = df25519.ScalarVector(sr)

    return n_ring_members, sigr, sigc
#--------------------------------------------------------------------------------------------
def get_key_image(resp_json, index):
    image = resp_json["vin"][index]["key"]["k_image"]
    return image
#--------------------------------------------------------------------------------------------
def check_v1(resp_json, resp_hex, sig_ind, pubs, tx_prefix):
    pubs_count, sigr, sigc = get_signatures(resp_json, resp_hex, sig_ind)
    key_image = get_key_image(resp_json, sig_ind)

    return check_ring_signature(
        tx_prefix, key_image, df25519.PointVector(pubs[sig_ind]), pubs_count, sigr, sigc
    )
#--------------------------------------------------------------------------------------------
def ring_sig_correct(h, resp_json, resp_hex, txs, i_tx, inputs, outputs, details):
    tx_prefix = get_tx_prefix_hash(resp_json, resp_hex)

    str_commits = check_balance(inputs, outputs, resp_json)

    str_ki = []
    for sig_ind in range(inputs):
        Iv = Point(resp_json["vin"][sig_ind]["key"]["k_image"])
        str_ki.append(misc_func.verify_ki(Iv))

    pubs, _ = misc_func.get_members_and_masks_in_rings(resp_json)

    y = []
    for sig_ind in range(inputs):
        try:
            with ProcessPoolExecutor() as exe:
                y.append(
                    exe.submit(
                        check_v1, resp_json, resp_hex, sig_ind, pubs, tx_prefix, details
                    )
                )

        except:
            print(
                "Verify block_height: "
                + str(h)
                + " tx : "
                + str(txs[i_tx])
                + " ring signature failed"
            )

    str_inp = []
    for res in as_completed(y):
        str_inp.append(res.result())

    return str_ki, str_inp, "", str_commits
#--------------------------------------------------------------------------------------------
def check_balance(inputs, outputs, resp_json):
    Cin = 0.0
    Cout = 0.0

    for sig_ind in range(inputs):
        Cin += resp_json["vin"][sig_ind]["key"]["amount"]

    for sig_ind in range(outputs):
        Cout += resp_json["vout"][sig_ind]["amount"]

    Fees = Cin - Cout

    if Cin >= Cout:
        return True
    
    return False
#--------------------------------------------------------------------------------------------
def generate_ring_signature(prefix, image, pubs, pubs_count, sec, sec_index):
    summ = Scalar(0)
    aba = [Scalar(0) for xx in range(pubs_count)]
    abb = [Scalar(0) for xx in range(pubs_count)]
    # these are the c[i]'s from the whitepaper
    sigc = [Scalar(0) for xx in range(pubs_count)]
    # these are the r[i]'s from the whitepaper
    sigr = [Scalar(0) for xx in range(pubs_count)]
    for ii in range(0, pubs_count):
        if ii == sec_index:
            kk = df25519.random_scalar()
            print("prefix: ")
            print(prefix)

            tmp3 = df25519.scalarmultBase(kk)  # L[i] for i = s
            # Random Public key
            aba[ii] = tmp3
            print("aba: ")
            print(tmp3)
            # tmp4 = df25519.hash_to_point2(pubs) #R[i] for i = s
            tmp4 = df25519.hash_to_point(str(pubs[ii]))
            print("after hashtopoint: ")
            print(tmp4)
            abb[ii] = kk * tmp4
            print("abb: ")
            print(abb[ii])
        else:
            k1 = df25519.random_scalar()
            k2 = df25519.random_scalar()

            tmp2 = df25519.ge_double_scalarmult_base_vartime(
                k1, pubs[ii], k2
            )  # this is L[i] for i != s
            print("aba: ")
            print(tmp2)
            aba[ii] = tmp2
            tmp3 = df25519.hash_to_point(str(pubs[ii]))
            print("tmp3: ")
            print(tmp3)
            abb[ii] = df25519.ge_double_scalarmult_vartime(
                k2, tmp3, k1, Point(image)
            )  # R[i] for i != s
            print("abb: ")
            print(abb[ii])
            sigc[ii] = k1  # the random c[i] for i != s
            sigr[ii] = k2  # the random r[i] for i != s
            # summing the c[i] to get the c[s] via page 9 whitepaper
            summ = df25519.sc_add(summ, sigc[ii])

    buf = struct.pack("64s", prefix)
    for ii in range(0, pubs_count):
        buf += struct.pack("64s", str(aba[ii]).encode())
        buf += struct.pack("64s", str(abb[ii]).encode())

    # hh is Scalar
    print("buf: ")
    print(buf)
    c = df25519.hash_to_scalar(buf.decode())

    sigc[sec_index] = df25519.sc_sub(c, summ)  # c[s] = hash - sum c[i] mod l
    # r[s] = q[s] - sec * c[index]
    sigr[sec_index] = df25519.sc_mulsub(sigc[sec_index], sec, kk)

    print("sigc: ")
    print(sigc)

    print("sigr: ")
    print(sigr)
    return image, sigc, sigr
#--------------------------------------------------------------------------------------------
def check_ring_signature(prefix, key_image, pubs, pubs_count, sigr, sigc):
    Li = [Scalar(0) for xx in range(pubs_count)]
    Ri = [Scalar(0) for xx in range(pubs_count)]

    summ = Scalar(0)
    for ii in range(0, pubs_count):
        Li[ii] = sigr[ii] * df25519.G + sigc[ii] * pubs[ii]
        tmp1 = df25519.hash_to_point(str(pubs[ii]))
        Ri[ii] = sigr[ii] * df25519.hash_to_point(str(pubs[ii])) + sigc[ii] * Point(
            key_image
        )

        summ += sigc[ii]

    buf = prefix.decode()
    for ii in range(0, pubs_count):
        buf += str(Li[ii])
        buf += str(Ri[ii])

    h = df25519.hash_to_scalar(buf)
    res = summ - h

    return res == Scalar(0) 
#--------------------------------------------------------------------------------------------


if __name__ == "__main__":
    if sys.argv[1] == "gen_ring_sig":
        prefix = b"8ae47e12cca160c1a52e5517f6f1822d2bb6f1a24e8094b78891458f2b3e4d5d"
        image = "f1206393161213a5e4093f9c65e6ef92ca7f21b3513c90e50422e1280ca8165b"
        pubs_array = [
            Point("649f27680aa9cbfb1166d5ad0dd80d20508646442e3e850c0a772a13a4c6b14a")
        ]
        pubs = PointVector(pubs_array)
        pubs_count = 1
        sec = Scalar("568325b113beabab5b8a1643b065f4bae5181c7b2026ea8dfefeff118ba6de0d")
        sec_index = 0

        ima, sic, sir = generate_ring_signature(
            prefix, image, pubs, pubs_count, sec, sec_index
        )

        print("ima", ima)
        print("sic", sir)
        print("sir", sic)
        # print(check_ring_signature("dest", ima, [Pa, Pb], 2, sir, sic))

    if sys.argv[1] == "gen_ring_sig_mult":
        prefix = b"7f658119722803b0fdab41843d4c3c2510e1cbbe64746255dfbd93b48a380856"
        image = "e525d54d017780fd439141cf9ec25ffeecdc6a2cb7b60c332c93740b3834bd8e"
        pubs_array = [
            Point("a9e8410fbdee927953160354801f281845e00f8cdd476b5012195854f6d1dfeb"),
            Point("b4493a0bbb5b9968685202619eff663dbc7f95d6baec74b229fbb935d9e88610"),
        ]
        pubs = PointVector(pubs_array)
        pubs_count = len(pubs_array)
        sec = Scalar("ef0338f3ab4d27b137aa5d82b481e7e1b942f513b1faa8cbbdca8bacadb6bb09")
        sec_index = 0

        ima, sic, sir = generate_ring_signature(
            prefix, image, pubs, pubs_count, sec, sec_index
        )

        print("ima", ima)
        print("sic", sir)
        print("sir", sic)

    if sys.argv[1] == "check_ring_sig":
        prefix = b"ad19333d6a1e36907f47d2f37904f9fa17557661ff3ff6f3c3207785050e9b59"
        image = "52e8e81fe928a338b92dadfff62baa93055ec82d3891108c8e0a21d2db4316c4"
        # image = 'a855ad897cb46e3e772143e33f1c8cf548ef4139cabab101db673cebe9e27ddc'
        pubs_array = [
            Point("d0a86250c342d8cbcf528fcff880defe0a8116ba5e2db4cfe1aea4dd7102e934"),
            Point("1623db2b826c4b3753d91a91af9542e6b7f3d8d674eefa0c6e9261b9e5867dbe"),
        ]
        pubs = PointVector(pubs_array)
        pubs_count = len(pubs_array)

        sc = [
            Scalar("2d87a80cf708e6d23b7038b3854d98f4a95ec50647b9e05ef7ad2665c0910d0a"),
            Scalar("0a8b8b3849e3e5d6bf712f263d94f00bbf6abe5ef5f00192e91c83f3461d660f"),
        ]
        sr = [
            Scalar("d9697f46b2430cbcbe5a2fc18e0e4c7364c92d90e43e7903bf32eb58c4d4010c"),
            Scalar("bd20e7ec116ec1ab3c3edd0dd003fbfe3e51f1edc66b6061ab6bd0489d86aa09"),
        ]

        sigc = df25519.ScalarVector(sc)
        sigr = df25519.ScalarVector(sr)

        result = check_ring_signature(prefix, image, pubs, pubs_count, sigr, sigc)

        print("sic", sigr)
        print("sir", sigc)
        print("Verified: ")
        print(result)
