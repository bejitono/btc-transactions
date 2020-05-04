import ecdsa
import ecdsa.der
import ecdsa.util
import hashlib
import unittest
import random
import re
import struct
import utils


def private_key_to_wif(key_hex):
    return utils.base58_check_encode(0x80, key_hex.decode('hex'))

def private_key_to_public_key(s):
    sk = ecdsa.SigningKey.from_string(s.decode('hex'), curve=ecdsa.SECP256k1)
    return ('\04' + sk.verifying_key.to_string()).encode('hex')

def public_key_to_address(s):
    sha256_hash = hashlib.sha256(s.decode('hex')).digest()
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256_hash)
    return utils.base58_check_encode(0, ripemd160.digest())

