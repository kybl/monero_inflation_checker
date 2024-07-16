"""
This work, "MIC - Monero Inflation Checker", is a derivative of:
    "Mininero" by ShenNoether (https://github.com/monero-project/mininero).
    "dumb25519" by SarangNoether (https://github.com/SarangNoether/skunkworks/tree/curves/dumb25519)
"MIC - Monero Inflation Checker" is licensed under GPL 3.0 by DangerousFreedom.
"""
import com_db
import misc_func
import check_v1
import check_mlsag
import check_clsag
import check_rangeproofs
from df25519 import Point
import settings_df25519
import logging


import json
import csv
import time
import multiprocessing


def verify_tx_with_string(h, tx_to_check, i_tx=0, details=0):
    if len(tx_to_check) >= 1:
        txs = tx_to_check
        resp_json, resp_hex = com_db.get_tx(tx_to_check, i_tx)
    else:
        return 0

    inputs = len(resp_json["vin"])
    outputs = len(resp_json["vout"])

    if resp_json["version"] == 1:
        if "gen" in resp_json["vin"][0]:
            amount = 0
            for i in range(outputs):
                amount += resp_json["vout"][i]["amount"]
            print(
                "Miner transaction. Total amount mined and transaction fees: "
                + str(amount / 1e12)
                + " XMR."
            )
        else:
            str_ki, str_inp, str_out, str_commit = check_v1.ring_sig_correct(
                h, resp_json, resp_hex, txs, i_tx, inputs, outputs, details
            )

    else:
        # Check type
        type_tx = resp_json["rct_signatures"]["type"]
        if type_tx == 1 or type_tx == 2:  # RCTTypeSimple and RCTTypeFull
            str_ki, str_inp, str_out, str_commit = check_mlsag.ring_sig_correct(
                h, resp_json, resp_hex, txs, i_tx, inputs, outputs, details
            )
        elif type_tx == 3 or type_tx == 4:  # RCTTypeBulletproof and RCTTypeBulletproof2
            str_ki, str_inp, str_out, str_commit = check_mlsag.ring_sig_correct_bp1(
                h, resp_json, resp_hex, txs, i_tx, inputs, outputs, details
            )
        elif type_tx == 5:  # RCTTypeCLSAG
            str_ki, str_inp, str_out, str_commit = check_clsag.ring_sig_correct_bp1(
                h, resp_json, resp_hex, txs, i_tx, inputs, outputs, details
            )
        elif type_tx == 6:  # RCTTypeBulletproofPlus
            str_ki, str_inp, str_out, str_commit = check_clsag.ring_sig_correct_bp_plus(
                h, resp_json, resp_hex, txs, i_tx, inputs, outputs, details
            )

        elif type_tx == 0:
            amount = 0
            for i in range(outputs):
                amount += resp_json["vout"][i]["amount"]
            print(
                "Miner transaction. Total amount mined and transaction fees: "
                + str(amount / 1e12)
                + " XMR."
            )
        else:
            raise Exception

    return str_ki, str_inp, str_out, str_commit
#--------------------------------------------------------------------------------------------
def verify_tx(tx_to_check, i_tx=0):
    if len(tx_to_check) >= 1:
        txs = tx_to_check
        resp_json, resp_hex = com_db.get_tx(tx_to_check, i_tx)
    else:
        return 0

    inputs = len(resp_json["vin"])
    outputs = len(resp_json["vout"])

    if resp_json["version"] == 1:
        if "gen" in resp_json["vin"][0]:
            amount = 0
            for i in range(outputs):
                amount += resp_json["vout"][i]["amount"]
            print(
                "Miner transaction. Total amount mined and transaction fees: "
                + str(amount / 1e12)
                + " XMR."
            )
        else:
            if not verify_v1(resp_json, resp_hex, txs, i_tx, inputs, outputs):
                return False

    else:
        # Check type
        type_tx = resp_json["rct_signatures"]["type"]
        if type_tx == 1 or type_tx == 2:  # RCTTypeSimple and RCTTypeFull
            if not verify_v2_t1_t2(resp_json, resp_hex, txs, i_tx, inputs, outputs):
                return False
        elif type_tx == 3 or type_tx == 4:  # RCTTypeBulletproof and RCTTypeBulletproof2
            if not verify_v2_t3_t4(resp_json, resp_hex, txs, i_tx, inputs, outputs):
                return False
        elif type_tx == 5:  # RCTTypeCLSAG
            if not verify_v2_t5(resp_json, resp_hex, txs, i_tx, inputs, outputs):
                return False
        elif type_tx == 6:  # RCTTypeBulletproofPlus
            if not verify_v2_t6(resp_json, resp_hex, txs, i_tx, inputs, outputs):
                return False

        elif type_tx == 0:
            amount = 0
            for i in range(outputs):
                amount += resp_json["vout"][i]["amount"]
            print(
                "Miner transaction. Total amount mined and transaction fees: "
                + str(amount / 1e12)
                + " XMR."
            )
        else:
            raise Exception

    return True
#--------------------------------------------------------------------------------------------
def verify_v1(resp_json, resp_hex, txs, i_tx, inputs, outputs):
    tx_prefix = check_v1.get_tx_prefix_hash(resp_json, resp_hex)

    if not check_v1.check_balance(inputs, outputs, resp_json):
        str_res = "Verification of balance v1 failed. See tx: " + str(txs[i_tx])
        settings_df25519.logger_inflation.critical(str_res)
        return False

    for sig_ind in range(inputs):
        Iv = Point(resp_json["vin"][sig_ind]["key"]["k_image"])
        if not (misc_func.verify_ki(Iv)):
            str_res = "Verification of key_image: " + str(Iv) + " failed."
            settings_df25519.logger_inflation.critical(str_res)
            return False

    pubs, _ = misc_func.get_members_and_masks_in_rings(resp_json)

    for sig_ind in range(inputs):
        if not check_v1.check_v1(resp_json, resp_hex, sig_ind, pubs, tx_prefix):
            str_res = (
                "Verify block_height: "
                + str(h)
                + " tx : "
                + str(txs[i_tx])
                + " ring signature failed"
            )
            settings_df25519.logger_inflation.critical(str_res)
            return False

    return True
#--------------------------------------------------------------------------------------------
def verify_v2_t1_t2(resp_json, resp_hex, txs, i_tx, inputs, outputs):
    rows = len(resp_json["vin"][0]["key"]["key_offsets"])
    message = check_mlsag.get_tx_hash_mlsag(resp_json, resp_hex)
    pubs, masks = misc_func.get_members_and_masks_in_rings(resp_json)

    # Check key images 
    for sig_ind in range(inputs):
        Iv = Point(resp_json["vin"][sig_ind]["key"]["k_image"])
        if not (misc_func.verify_ki(Iv)):
            str_res = "Verification of key_image: " + str(Iv) + " failed."
            settings_df25519.logger_inflation.critical(str_res)
            return False

    # Check ring-signatures 
    for sig_ind in range(inputs):
        if not (check_mlsag.check_sig_mlsag(
                    resp_json,
                    sig_ind,
                    inputs,
                    rows,
                    pubs,
                    masks,
                    message
                )):

            str_res = ("Verify "
            + " tx : "
            + str(txs[i_tx])
            + " ring signature failed")
            settings_df25519.logger_inflation.critical(str_res)
            # raise Exception("ring_signature_failure")
            return False

    # Check rangeproofs
    for sig_out in range(outputs):
        if not check_rangeproofs.check_sig_Borromean(resp_json,sig_out):
            str_res = ("Verify "
                + " tx : "
                + str(txs[i_tx])
                + " Borromean failed"
            )
            settings_df25519.logger_inflation.critical(str_res)
            return False

    # Check commitments 
    if not check_rangeproofs.check_commitments(resp_json):
        str_res = ("Verify "
        + " tx : "
        + str(txs[i_tx])
        + " commitments check failed")
        settings_df25519.logger_inflation.critical(str_res)
        return False

    return True
#--------------------------------------------------------------------------------------------
def verify_v2_t3_t4(resp_json, resp_hex, txs, i_tx, inputs, outputs):
    rows = len(resp_json["vin"][0]["key"]["key_offsets"])
    message = check_mlsag.get_tx_hash_bp1(resp_json, resp_hex)
    pubs, masks = misc_func.get_members_and_masks_in_rings(resp_json)

    # Check key images 
    for sig_ind in range(inputs):
        Iv = Point(resp_json["vin"][sig_ind]["key"]["k_image"])
        if not (misc_func.verify_ki(Iv)):
            str_res = "Verification of key_image: " + str(Iv) + " failed."
            settings_df25519.logger_inflation.critical(str_res)
            return False

    # Check ring-signatures 
    for sig_ind in range(inputs):
        if not (check_mlsag.check_sig_mlsag_bp1(
                    resp_json,
                    sig_ind,
                    inputs,
                    rows,
                    pubs,
                    masks,
                    message
                )):

            str_res = ("Verify "
            + " tx : "
            + str(txs[i_tx])
            + " ring signature failed")
            settings_df25519.logger_inflation.critical(str_res)
            # raise Exception("ring_signature_failure")
            return False

    # Check rangeproofs
    if not check_rangeproofs.check_sig_bp1(resp_json):
        str_res = (
            "Verify "
            + " tx : "
            + str(txs[i_tx])
            + " Borromean failed"
        )
        settings_df25519.logger_inflation.critical(str_res)
        return False

    # Check commitments 
    if not check_rangeproofs.check_commitments_bp1(resp_json):
        str_res = (
            "Verify "
            + " tx : "
            + str(txs[i_tx])
            + " commitments check failed"
        )
        settings_df25519.logger_inflation.critical(str_res)
        return False

    return True
#--------------------------------------------------------------------------------------------
def verify_v2_t5(resp_json, resp_hex, txs, i_tx, inputs, outputs):
    rows = len(resp_json["vin"][0]["key"]["key_offsets"])
    message = check_clsag.get_tx_hash_clsag(resp_json, resp_hex)
    pubs, masks = misc_func.get_members_and_masks_in_rings(resp_json)

    # Check key images 
    for sig_ind in range(inputs):
        Iv = Point(resp_json["vin"][sig_ind]["key"]["k_image"])
        if not (misc_func.verify_ki(Iv)):
            str_res = "Verification of key_image: " + str(Iv) + " failed."
            settings_df25519.logger_inflation.critical(str_res)
            return False

    # Check ring-signatures 
    for sig_ind in range(inputs):
        if not (check_clsag.check_sig_clsag_bp1(
                    resp_json,
                    sig_ind,
                    inputs,
                    rows,
                    pubs,
                    masks,
                    message
                )):

            str_res = ("Verify "
            + " tx : "
            + str(txs[i_tx])
            + " ring signature failed")
            settings_df25519.logger_inflation.critical(str_res)
            # raise Exception("ring_signature_failure")
            return False

    # Check rangeproofs
    if not check_rangeproofs.check_sig_bp1(resp_json):
        str_res = (
            "Verify "
            + " tx : "
            + str(txs[i_tx])
            + " Bulletproofs failed"
        )
        settings_df25519.logger_inflation.critical(str_res)
        return False

    # Check commitments 
    if not check_rangeproofs.check_commitments_bp1(resp_json):
        str_res = (
            "Verify "
            + " tx : "
            + str(txs[i_tx])
            + " commitments check failed"
        )
        settings_df25519.logger_inflation.critical(str_res)
        return False

    return True
#--------------------------------------------------------------------------------------------
def verify_v2_t6(resp_json, resp_hex, txs, i_tx, inputs, outputs):

    rows = len(resp_json["vin"][0]["key"]["key_offsets"])
    message = check_clsag.get_tx_hash_clsag_bp_plus(resp_json, resp_hex)
    pubs, masks = misc_func.get_members_and_masks_in_rings(resp_json)

    # Check key images 
    for sig_ind in range(inputs):
        Iv = Point(resp_json["vin"][sig_ind]["key"]["k_image"])
        if not (misc_func.verify_ki(Iv)):
            str_res = "Verification of key_image: " + str(Iv) + " failed."
            settings_df25519.logger_inflation.critical(str_res)
            return False

    # Check ring-signatures 
    for sig_ind in range(inputs):
        if not (check_clsag.check_sig_clsag_bp1(
                    resp_json,
                    sig_ind,
                    inputs,
                    rows,
                    pubs,
                    masks,
                    message
                )):

            str_res = ("Verify "
            + " tx : "
            + str(txs[i_tx])
            + " ring signature failed")
            settings_df25519.logger_inflation.critical(str_res)
            # raise Exception("ring_signature_failure")
            return False

    # Check rangeproofs
    if not check_rangeproofs.check_sig_bp_plus(resp_json):
        str_res = (
            "Verify "
            + " tx : "
            + str(txs[i_tx])
            + " Bulletproofs failed"
        )
        settings_df25519.logger_inflation.critical(str_res)
        return False

    # Check commitments 
    if not check_rangeproofs.check_commitments_bp1(resp_json):
        str_res = (
            "Verify block_height: "
            + str(h)
            + " tx : "
            + str(txs[i_tx])
            + " commitments check failed"
        )
        settings_df25519.logger_inflation.critical(str_res)
        return False

    return True
#--------------------------------------------------------------------------------------------