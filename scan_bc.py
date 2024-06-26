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

# from varint import encode as to_varint
import csv
import time
import multiprocessing
import verify_tx


def read_height():
    with open("height.txt", "r") as file1:
        # Reading form a file
        height = int(file1.read())
    return height


def write_height(height):
    with open("height.txt", "w") as file1:
        # Writing data to a file
        file1.write(height)


def start_scanning(h):
    initial_time = time.time()

    while h < 4000000:
        write_height(str(h))
        params_block = {"height": h}
        # block = com_db.rpc_connection.get_block(params_block)
        block_json = com_db.get_block(params_block)
        txs = block_json["tx_hashes"]
        nbr_tx = len(txs)
        print(h)
        # print(nbr_tx)

        for i_tx in range(nbr_tx):
            verify_tx.verify_tx(h, txs, i_tx, 0)

        h += 1

    print("Total time", time.time() - initial_time)

def scan_block(h):
    initial_time = time.time()

    params_block = {"height": h}
    block_json = com_db.get_block(params_block)
    txs = block_json["tx_hashes"]
    nbr_tx = len(txs)
    print("Block contains " + str(nbr_tx) + " transactions.")
    # print(nbr_tx)

    for i_tx in range(nbr_tx):
        verify_tx.verify_tx(h, txs, i_tx, 0)

    print("Total time", time.time() - initial_time)
