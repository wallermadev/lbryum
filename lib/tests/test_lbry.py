import unittest

from lib import lbrycrd

def get_powhash(input_str):
    out=lbrycrd.PoWHash(input_str)
    hex_out = out.encode('hex_codec')
    out_str=''
    for i in range(64,0,-2):
        out_str+=hex_out[i-2:i]
    return out_str


class Test_Lbry(unittest.TestCase):

    def test_hash(self):

        test = get_powhash("test string")
        value="485f3920d48a0448034b0852d1489cfa475341176838c7d36896765221be35ce"
        self.assertEqual(test,value)

        test = get_powhash("a"*70)
        value="eb44af2f41e7c6522fb8be4773661be5baa430b8b2c3a670247e9ab060608b75"
        self.assertEqual(test,value)

        test = get_powhash("d"*140)
        value="74044747b7c1ff867eb09a84d026b02d8dc539fb6adcec3536f3dfa9266495d9"
        self.assertEqual(test,value)


