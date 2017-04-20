import unittest
from lib import commands
from lib import util


class MocWallet(object):
    def get_spendable_coins(self):
        out = [{'is_support': False, 'prevout_hash': u'a3900bede6252a9c844987bc9c4c1d901611fc831d03c8239ca9c31961cd5105', 'is_update': False, 'address': 'bNy6H2ZioUPxhpcbUAjcJ24XCqBBQicizD', 'coinbase': False, 'height': 77872, 'is_claim': False, 'value': 600, 'prevout_n': 1}]
        return out

    def get_spendable_claimtrietx_coin(self, txid, nout):
        out = {'x_pubkeys': ['ff0488b21e000000000000000000b0d157dd75c32e0ffeb037e52a27177b597d4cc547b4643e7fb377b2d79b078f0238609014cf243c8cdf7c1b24d0d9f7db295fed6e16e5088cc76069e1852ff20300003104'], 'signatures': [None], 'prevout_hash': '13a78af0e3f29e04e416ac47bd4196a2a476bdc1cf05b4be476ace2ab5de942b', 'is_update': 0, 'claim_value': 'test', 'claim_name': 'testpub12-14-2016-1320', 'redeemPubkey': u'037ab1ba72039546e640317961ed7bdaa062502d4ba3fb036ba0c2e0b24d1b1669', 'value': 1000, 'is_support': 0, 'address': 'bHU9jNvYABJhY93xDXDqT2bFzAs31QMWiL', 'num_sig': 1, 'pubkeys': [u'037ab1ba72039546e640317961ed7bdaa062502d4ba3fb036ba0c2e0b24d1b1669'], 'is_claim': 8, 'prevout_n': 0}
        return out

    def make_unsigned_transaction(self, coins, outputs, config, tx_fee, change_addr):
        raise util.NotEnoughFunds()

    def get_name_claims(self, domain=None, include_abandoned=True, include_supports=True):
        return []

    def create_new_address(self, **kwargs):
        return "bScaWvgzAzFXzAcVgDDARfo9RFhdrm4pVc"


class MocNetwork(object):
    pass


class MocCommands(commands.Commands):
    def __init__(self,wallet,network):
        self.wallet = wallet
        self.network = network
        self.config = {}


class Test_Commands(unittest.TestCase):

    # test that NotEnoughFunds exceptions are caught in claim commands
    def test_claim_not_enough_funds(self):
        network = MocNetwork()
        wallet = MocWallet()
        cmds = MocCommands(wallet, network)

        out = cmds.claim('test', 'value', 1, skip_validate_schema=True, raw=True)
        self.assertEqual(False, out['success'])
        self.assertEqual('Not enough funds', out['reason'])

        out = cmds.update('test', 'test', amount=1, tx_fee=1, skip_validate_schema=True, raw=True)
        self.assertEqual(False, out['success'])
        self.assertEqual('No claim to update', out['reason'])


        out = cmds.support('test','d13d485b18f0b7a8ed2482e8f44b533e47948ded',1, claim_addr='',change_addr='',tx_fee=1)
        self.assertEqual(False, out['success'])
        self.assertEqual('Not enough funds', out['reason'])

    def test_format_lbrycrd_keys(self):
        a = {'test': 1,
         'nOut': 1}
        out = commands.format_lbrycrd_keys(a)
        self.assertTrue('nout' in out)
        self.assertFalse('nOut' in out)
        self.assertEqual(1, out['nout'])
        self.assertEqual(1, out['test'])

        a = [{'test': 1,
          'nOut': 1}, {'test': 1,
          'nOut': [{'nOut': 1}]}]
        out = commands.format_lbrycrd_keys(a)
        self.assertTrue('nout' in out[0])
        self.assertFalse('nOut' in out[0])
        self.assertEqual(1, out[0]['nout'])
        self.assertTrue('nout' in out[1])
        self.assertFalse('nOut' in out[1])
        self.assertTrue('nout' in out[1]['nout'][0])
        self.assertFalse('nOut' in out[1]['nout'][0])
        self.assertEqual(1, out[1]['nout'][0]['nout'])

        a = {'amount': 100000000}
        out = commands.format_amount_value(a)
        self.assertEqual(1.0, out['amount'])





