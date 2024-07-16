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
import check_rangeproofs

import json

import csv
import time
import verify_tx


def read_height(filename):
    with open(filename, "r") as file:
        # Reading from a file
        height = int(file.read())
    return height

def write_height(filename,height):
    with open(filename, "w") as file:
        # Writing data to a file
        file.write(height)

def start_scanning(filename, h, scan):

    filename_save_stats = 'block_stats.csv'

    while True:
        initial_time = time.time()
        params_block = {"height": h}
        block_json = com_db.get_block(params_block)
        txs = block_json["tx_hashes"]
        nbr_txs = len(txs)

        for i_tx in range(nbr_txs):
            if not verify_tx.verify_tx(txs, i_tx):
                raise Exception("Tx: " + str(txs[i_tx]) + " failed verification")

        # if everything went fine so far, write scanned height to file
        time_verify = time.time() - initial_time
        print("Block: " + str(h) + " Txs: " + str(nbr_txs) + " Duration(s): " + str(time_verify))
        write_height(filename, str(h))
        h += 1

        with open(filename_save_stats, 'a') as csvfile:
            csvwriter = csv.writer(csvfile)
            gt = time.gmtime()
            # Block_height | Quantity of txs | Duration to verify | Date of verification
            row = [str(h),  str(nbr_txs), str(time_verify),str(gt.tm_year)+'-'+str(gt.tm_mon)+'-'+str(gt.tm_mday)+'--'+str(gt.tm_hour)+':'+str(gt.tm_min)+':'+str(gt.tm_sec)]
            csvwriter.writerow(row)

        if scan == False:
            break

def txs_to_benchmark():

    import time
    t1 = time.time()

    txs = []
    # V1 2/8
    txs.append("3b26d90c460ccab37925300ca830b569636ba8053f859a95312c227312d1a72d")
    
    # V1 4/5
    txs.append("8d7aea7480fcf53e6b9bef5d398c4031d923b0a0a47d6e088f69b49a8674a542")

    # V2T1 1/2
    txs.append("a61c75c5c5f8e449f93dd395e44f090ca66176dad62c5a4c89f26a921630d4e0")

    # V2T2 2/2
    txs.append("257b917219699be7ea8ace43c80773674c2d0cda12702ad6a82de61a861a08c7")

    # V2T3 1/2
    txs.append("b374a5abf666a189d6fa8bb4fe3724278b7c553dba4837f2d52e644401b78222")

    # V2T4 1/2
    txs.append("0fcb5cb5ed4b84008d8f01c8c10ad255417deff5862513c99d8b9203c68a4acc")

    # V2T5 1/2
    txs.append("d6093af328ea42984a715eaddfdfec6a67d4572f4f5cc5344a5d0d5f67b5a9f2")

    # V2T6 1/2
    txs.append("d6eb7f7f27f643c4b8ea6ef2683bd0601ee540cb37f4e27eb18ad85d1f46a85a")

    nbr_txs = len(txs)

    for i_tx in range(nbr_txs):
        if not verify_tx.verify_tx(txs, i_tx):
            raise Exception("Tx: " + str(txs[i_tx]) + " failed verification")

    print("Total execution time: " + str(time.time()-t1))
