"""
This work, "MIC - Monero Inflation Checker", is a derivative of:
    "Mininero" by ShenNoether (https://github.com/monero-project/mininero).
    "dumb25519" by SarangNoether (https://github.com/SarangNoether/skunkworks/tree/curves/dumb25519)
"MIC - Monero Inflation Checker" is licensed under GPL 3.0 by DangerousFreedom.
"""
import copy
from df25519 import (
    Scalar,
    Point,
    ScalarVector,
    PointVector,
    random_scalar,
    random_point,
    hash_to_scalar,
    hash_to_point,
    cn_fast_hash,
)
import df25519
import varint_mic as varint
import numpy as np

#--------------------------------------------------------------------------------------------
### Load generators and node string (url_str) 
#--------------------------------------------------------------------------------------------
global url_str
global Hi_df, Gi_df, Hi_plus_df, Gi_plus_df

#url_str = "http://node.sethforprivacy.com:18089/"
url_str = "http://xmr-node.cakewallet.com:18081/"

Hi_df = PointVector(np.load("Hi_df.npy", allow_pickle=True))
Gi_df = PointVector(np.load("Gi_df.npy", allow_pickle=True))
Hi_plus_df = PointVector(np.load("Hi_plus_df.npy", allow_pickle=True))
Gi_plus_df = PointVector(np.load("Gi_plus_df.npy", allow_pickle=True))


def node_choice(choice):
    global node_conn, url_str

    node_conn = copy.copy(choice)

    if node_conn == 0:
        url_str = "http://xmr-node.cakewallet.com:18081/"
    else:
        url_str = "http://localhost:18081/"

#--------------------------------------------------------------------------------------------
### Load loggers 
#--------------------------------------------------------------------------------------------
import logging
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')

def setup_logger(name, log_file, level=logging.INFO):

    handler = logging.FileHandler(log_file)        
    handler.setFormatter(formatter)

    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.addHandler(handler)

    return logger

global logger_basic, logger_inflation

# Basic logger
logger_basic = setup_logger('logger_basic', 'logger_basic.log')

# Inflation logger (This file should be empty or inexistent)
logger_inflation = setup_logger('logger_inflation', 'logger_inflation.log', logging.CRITICAL)

#--------------------------------------------------------------------------------------------
### Code used to create generators 
#--------------------------------------------------------------------------------------------
# M,N = 16,64

# domain = str("bulletproof")
# Hi_df = PointVector([hash_to_point(cn_fast_hash(str(df25519.H) + domain.encode("utf-8").hex() + varint.encode_as_varint(i))) for i in range(0,2*M*N,2)])
# Gi_df = PointVector([hash_to_point(cn_fast_hash(str(df25519.H) + domain.encode("utf-8").hex() + varint.encode_as_varint(i))) for i in range(1,2*M*N+1,2)])

# domain_plus = str("bulletproof_plus")
# Hi_plus_df = PointVector([hash_to_point(cn_fast_hash(str(df25519.H) + domain_plus.encode("utf-8").hex() + varint.encode_as_varint(i))) for i in range(0,2*M*N,2)])
# Gi_plus_df = PointVector([hash_to_point(cn_fast_hash(str(df25519.H) + domain_plus.encode("utf-8").hex() + varint.encode_as_varint(i))) for i in range(1,2*M*N+1,2)])

# np.save("Hi_df.npy", Hi_df)
# np.save("Gi_df.npy", Gi_df)

# np.save("Hi_plus_df.npy", Hi_plus_df)
# np.save("Gi_plus_df.npy", Gi_plus_df)
