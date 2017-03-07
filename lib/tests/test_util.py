import unittest
from lib.util import format_satoshis, parse_URI, format_lbrycrd_keys


class TestUtil(unittest.TestCase):
    def test_format_lbrycrd_keys(self):
        a = {'test': 1,
         'nOut': 1}
        out = format_lbrycrd_keys(a)
        self.assertTrue('nout' in out)
        self.assertFalse('nOut' in out)
        self.assertEqual(1, out['nout'])
        self.assertEqual(1, out['test'])
        a = [{'test': 1,
          'nOut': 1}, {'test': 1,
          'nOut': [{'nOut': 1}]}]
        out = format_lbrycrd_keys(a)
        self.assertTrue('nout' in out[0])
        self.assertFalse('nOut' in out[0])
        self.assertEqual(1, out[0]['nout'])
        self.assertTrue('nout' in out[1])
        self.assertFalse('nOut' in out[1])
        self.assertTrue('nout' in out[1]['nout'][0])
        self.assertFalse('nOut' in out[1]['nout'][0])
        self.assertEqual(1, out[1]['nout'][0]['nout'])

    def test_format_satoshis(self):
        result = format_satoshis(1234)
        expected = "0.00001234"
        self.assertEqual(expected, result)

    def test_format_satoshis_diff_positive(self):
        result = format_satoshis(1234, is_diff=True)
        expected = "+0.00001234"
        self.assertEqual(expected, result)

    def test_format_satoshis_diff_negative(self):
        result = format_satoshis(-1234, is_diff=True)
        expected = "-0.00001234"
        self.assertEqual(expected, result)

    def _do_test_parse_URI(self, uri, expected):
        result = parse_URI(uri)
        self.assertEqual(expected, result)

    def test_parse_URI_address(self):
        self._do_test_parse_URI('bitcoin:bFnNVhPUNRWiA6Y2hbd1KBAMgQBrFsc5u3',
                                {'address': 'bFnNVhPUNRWiA6Y2hbd1KBAMgQBrFsc5u3'})

    def test_parse_URI_only_address(self):
        self._do_test_parse_URI('bFnNVhPUNRWiA6Y2hbd1KBAMgQBrFsc5u3',
                                {'address': 'bFnNVhPUNRWiA6Y2hbd1KBAMgQBrFsc5u3'})

    def test_parse_URI_address_label(self):
        self._do_test_parse_URI('bitcoin:bFnNVhPUNRWiA6Y2hbd1KBAMgQBrFsc5u3?label=electrum%20test',
                                {'address': 'bFnNVhPUNRWiA6Y2hbd1KBAMgQBrFsc5u3', 'label': 'electrum test'})

    def test_parse_URI_address_message(self):
        self._do_test_parse_URI('bitcoin:bFnNVhPUNRWiA6Y2hbd1KBAMgQBrFsc5u3?message=electrum%20test',
                                {'address': 'bFnNVhPUNRWiA6Y2hbd1KBAMgQBrFsc5u3', 'message': 'electrum test',
                                 'memo': 'electrum test'})

    def test_parse_URI_address_amount(self):
        self._do_test_parse_URI('bitcoin:bFnNVhPUNRWiA6Y2hbd1KBAMgQBrFsc5u3?amount=0.0003',
                                {'address': 'bFnNVhPUNRWiA6Y2hbd1KBAMgQBrFsc5u3', 'amount': 30000})

    def test_parse_URI_address_request_url(self):
        self._do_test_parse_URI('bitcoin:bFnNVhPUNRWiA6Y2hbd1KBAMgQBrFsc5u3?r=http://domain.tld/page?h%3D2a8628fc2fbe',
                                {'address': 'bFnNVhPUNRWiA6Y2hbd1KBAMgQBrFsc5u3',
                                 'r': 'http://domain.tld/page?h=2a8628fc2fbe'})

    def test_parse_URI_ignore_args(self):
        self._do_test_parse_URI('bitcoin:bFnNVhPUNRWiA6Y2hbd1KBAMgQBrFsc5u3?test=test',
                                {'address': 'bFnNVhPUNRWiA6Y2hbd1KBAMgQBrFsc5u3', 'test': 'test'})

    def test_parse_URI_multiple_args(self):
        self._do_test_parse_URI(
            'bitcoin:bFnNVhPUNRWiA6Y2hbd1KBAMgQBrFsc5u3?amount=0.00004&label=electrum-test&message=electrum%20test&test=none&r=http://domain.tld/page',
            {'address': 'bFnNVhPUNRWiA6Y2hbd1KBAMgQBrFsc5u3', 'amount': 4000, 'label': 'electrum-test',
             'message': u'electrum test', 'memo': u'electrum test', 'r': 'http://domain.tld/page', 'test': 'none'})

    def test_parse_URI_no_address_request_url(self):
        self._do_test_parse_URI('bitcoin:?r=http://domain.tld/page?h%3D2a8628fc2fbe',
                                {'r': 'http://domain.tld/page?h=2a8628fc2fbe'})

    def test_parse_URI_invalid_address(self):
        self.assertRaises(AssertionError, parse_URI, 'bitcoin:invalidaddress')

    def test_parse_URI_invalid(self):
        self.assertRaises(AssertionError, parse_URI, 'notbitcoin:bFnNVhPUNRWiA6Y2hbd1KBAMgQBrFsc5u3')

    def test_parse_URI_parameter_polution(self):
        self.assertRaises(Exception, parse_URI,
                          'bitcoin:bFnNVhPUNRWiA6Y2hbd1KBAMgQBrFsc5u3?amount=0.0003&label=test&amount=30.0')
