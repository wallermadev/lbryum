import binascii
from lbrycrd import Hash
from transaction import opcodes


class InvalidProofError(Exception):
    pass


def height_to_vch(n):
    r = [0 for i in range(8)]
    r[4] = n >> 24
    r[5] = n >> 16
    r[6] = n >> 8
    r[7] = n % 256
    # need to reset each value mod 256 because for values like 67784
    # 67784 >> 8 = 264, which is obviously larger then the maximum
    # value input into chr()
    return ''.join([chr(x % 256) for x in r])


def get_hash_for_outpoint(txhash, nOut, nHeightOfLastTakeover):
    txhash_hash = Hash(txhash)
    nOut_hash = Hash(str(nOut))
    height_of_last_takeover_hash = Hash(height_to_vch(nHeightOfLastTakeover))
    outPointHash = Hash(txhash_hash + nOut_hash + height_of_last_takeover_hash)
    return outPointHash


# noinspection PyPep8
def verify_proof(proof, rootHash, name):
    previous_computed_hash = None
    reverse_computed_name = ''
    verified_value = False
    for i, node in enumerate(proof['nodes'][::-1]):
        found_child_in_chain = False
        to_hash = ''
        previous_child_character = None
        for child in node['children']:
            assert not child['character'] < 0 or child['character'] > 255, \
                InvalidProofError("child character not int between 0 and 255")
            if previous_child_character:
                assert previous_child_character < child['character'], \
                    InvalidProofError("children not in increasing order")
            previous_child_character = child['character']
            to_hash += chr(child['character'])
            if 'nodeHash' in child:
                assert len(child['nodeHash']) == 64, InvalidProofError("invalid child nodeHash")
                to_hash += binascii.unhexlify(child['nodeHash'])[::-1]
            else:
                assert previous_computed_hash is not None, \
                    InvalidProofError("previous computed hash is None")
                assert found_child_in_chain is not True, \
                    InvalidProofError("already found the next child in the chain")
                found_child_in_chain = True
                reverse_computed_name += chr(child['character'])
                to_hash += previous_computed_hash

        if not found_child_in_chain:
            assert i == 0, InvalidProofError("did not find the alleged child")
        if i == 0 and 'txhash' in proof and 'nOut' in proof and 'last takeover height' in proof:
            assert len(proof['txhash']) == 64, \
                InvalidProofError("txhash was invalid: {}".format(proof['txhash']))
            assert isinstance(proof['nOut'], (long, int)), \
                InvalidProofError("nOut was invalid: {}".format(proof['nOut']))
            assert isinstance(proof['last takeover height'], (long, int)), \
                InvalidProofError(
                    'last takeover height was invalid: {}'.format(proof['last takeover height']))
            to_hash += get_hash_for_outpoint(
                binascii.unhexlify(proof['txhash'])[::-1],
                proof['nOut'],
                proof['last takeover height']
            )
            verified_value = True
        elif 'valueHash' in node:
            assert len(node['valueHash']) == 64, InvalidProofError("valueHash was invalid")
            to_hash += binascii.unhexlify(node['valueHash'])[::-1]

        previous_computed_hash = Hash(to_hash)

    assert previous_computed_hash == binascii.unhexlify(rootHash)[::-1], InvalidProofError("computed hash does not match roothash")
    if 'txhash' in proof and 'nOut' in proof:
        assert verified_value, InvalidProofError("mismatch between proof claim and outcome")
    if 'txhash' in proof and 'nOut' in proof:
        assert name == reverse_computed_name[::-1], InvalidProofError("name did not match proof")
    assert name.startswith(reverse_computed_name[::-1]), InvalidProofError("name fragment does not match proof")
    return True

