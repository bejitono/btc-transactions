import ecdsa
import hashlib
import struct
import unittest

import utils
import key_utils

def make_raw_transaction(output_tx_hash, source_index, script_sig, outputs):
    def make_output(data):
        redemption_sat, output_script = data
        return (struct.pack("<Q", redemption_sat).encode('hex') +
        '%02x' % len(output_script.decode('hex')) + output_script)

    formatted_output = ''.join(map(make_output, outputs))
    return (
        "01000000" + # 4 bytes version
        "01" + # varint for number of inputs
        output_tx_hash.decode('hex')[::-1].encode('hex') + # reverse outputTransactionHash
        struct.pack('<L', source_index).encode('hex') +
        '%02x' % len(script_sig.decode('hex')) + script_sig +
        "ffffffff" + # sequence
        "%02x" % len(outputs) + # number of outputs
        formatted_output +
        "00000000" # lockTime
    )