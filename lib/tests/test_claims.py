import unittest
import binascii
from lib import claims


class TestClaims(unittest.TestCase):
    def test_height_to_vch(self):
        expected = '\x00\x00\x00\x00\x00\x01\x08\xc8'
        result = claims.height_to_vch(67784)
        self.assertEqual(expected, result)
