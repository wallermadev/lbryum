#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2011 thomasv@gitorious
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.


# Note: The deserialization code originally comes from ABE.


import lbrycrd
from lbrycrd import *
from util import print_error, profiler
import time
import sys
import struct

#
# Workalike python implementation of Bitcoin's CDataStream class.
#
import struct
import StringIO
import random

NO_SIGNATURE = 'ff'


class SerializationError(Exception):
    """ Thrown when there's a problem deserializing or serializing """

class BCDataStream(object):
    def __init__(self):
        self.input = None
        self.read_cursor = 0

    def clear(self):
        self.input = None
        self.read_cursor = 0

    def write(self, bytes):  # Initialize with string of bytes
        if self.input is None:
            self.input = bytes
        else:
            self.input += bytes

    def read_string(self):
        # Strings are encoded depending on length:
        # 0 to 252 :  1-byte-length followed by bytes (if any)
        # 253 to 65,535 : byte'253' 2-byte-length followed by bytes
        # 65,536 to 4,294,967,295 : byte '254' 4-byte-length followed by bytes
        # ... and the Bitcoin client is coded to understand:
        # greater than 4,294,967,295 : byte '255' 8-byte-length followed by bytes of string
        # ... but I don't think it actually handles any strings that big.
        if self.input is None:
            raise SerializationError("call write(bytes) before trying to deserialize")

        try:
            length = self.read_compact_size()
        except IndexError:
            raise SerializationError("attempt to read past end of buffer")

        return self.read_bytes(length)

    def write_string(self, string):
        # Length-encoded as with read-string
        self.write_compact_size(len(string))
        self.write(string)

    def read_bytes(self, length):
        try:
            result = self.input[self.read_cursor:self.read_cursor+length]
            self.read_cursor += length
            return result
        except IndexError:
            raise SerializationError("attempt to read past end of buffer")

        return ''

    def read_boolean(self): return self.read_bytes(1)[0] != chr(0)
    def read_int16(self): return self._read_num('<h')
    def read_uint16(self): return self._read_num('<H')
    def read_int32(self): return self._read_num('<i')
    def read_uint32(self): return self._read_num('<I')
    def read_int64(self): return self._read_num('<q')
    def read_uint64(self): return self._read_num('<Q')

    def write_boolean(self, val): return self.write(chr(1) if val else chr(0))
    def write_int16(self, val): return self._write_num('<h', val)
    def write_uint16(self, val): return self._write_num('<H', val)
    def write_int32(self, val): return self._write_num('<i', val)
    def write_uint32(self, val): return self._write_num('<I', val)
    def write_int64(self, val): return self._write_num('<q', val)
    def write_uint64(self, val): return self._write_num('<Q', val)

    def read_compact_size(self):
        size = ord(self.input[self.read_cursor])
        self.read_cursor += 1
        if size == 253:
            size = self._read_num('<H')
        elif size == 254:
            size = self._read_num('<I')
        elif size == 255:
            size = self._read_num('<Q')
        return size

    def write_compact_size(self, size):
        if size < 0:
            raise SerializationError("attempt to write size < 0")
        elif size < 253:
            self.write(chr(size))
        elif size < 2**16:
            self.write('\xfd')
            self._write_num('<H', size)
        elif size < 2**32:
            self.write('\xfe')
            self._write_num('<I', size)
        elif size < 2**64:
            self.write('\xff')
            self._write_num('<Q', size)

    def _read_num(self, format):
        (i,) = struct.unpack_from(format, self.input, self.read_cursor)
        self.read_cursor += struct.calcsize(format)
        return i

    def _write_num(self, format, num):
        s = struct.pack(format, num)
        self.write(s)

#
# enum-like type
# From the Python Cookbook, downloaded from http://code.activestate.com/recipes/67107/
#
import types, string, exceptions

class EnumException(exceptions.Exception):
    pass

class Enumeration:
    def __init__(self, name, enumList):
        self.__doc__ = name
        lookup = { }
        reverseLookup = { }
        i = 0
        uniqueNames = [ ]
        uniqueValues = [ ]
        for x in enumList:
            if type(x) == types.TupleType:
                x, i = x
            if type(x) != types.StringType:
                raise EnumException, "enum name is not a string: " + x
            if type(i) != types.IntType:
                raise EnumException, "enum value is not an integer: " + i
            if x in uniqueNames:
                raise EnumException, "enum name is not unique: " + x
            if i in uniqueValues:
                raise EnumException, "enum value is not unique for " + x
            uniqueNames.append(x)
            uniqueValues.append(i)
            lookup[x] = i
            reverseLookup[i] = x
            i = i + 1
        self.lookup = lookup
        self.reverseLookup = reverseLookup
    def __getattr__(self, attr):
        if not self.lookup.has_key(attr):
            raise AttributeError
        return self.lookup[attr]
    def whatis(self, value):
        return self.reverseLookup[value]


# This function comes from bitcointools, bct-LICENSE.txt.
def long_hex(bytes):
    return bytes.encode('hex_codec')

# This function comes from bitcointools, bct-LICENSE.txt.
def short_hex(bytes):
    t = bytes.encode('hex_codec')
    if len(t) < 11:
        return t
    return t[0:4]+"..."+t[-4:]



opcodes = Enumeration("Opcodes", [
    ("OP_0", 0), ("OP_PUSHDATA1",76), "OP_PUSHDATA2", "OP_PUSHDATA4", "OP_1NEGATE", "OP_RESERVED",
    "OP_1", "OP_2", "OP_3", "OP_4", "OP_5", "OP_6", "OP_7",
    "OP_8", "OP_9", "OP_10", "OP_11", "OP_12", "OP_13", "OP_14", "OP_15", "OP_16",
    "OP_NOP", "OP_VER", "OP_IF", "OP_NOTIF", "OP_VERIF", "OP_VERNOTIF", "OP_ELSE", "OP_ENDIF", "OP_VERIFY",
    "OP_RETURN", "OP_TOALTSTACK", "OP_FROMALTSTACK", "OP_2DROP", "OP_2DUP", "OP_3DUP", "OP_2OVER", "OP_2ROT", "OP_2SWAP",
    "OP_IFDUP", "OP_DEPTH", "OP_DROP", "OP_DUP", "OP_NIP", "OP_OVER", "OP_PICK", "OP_ROLL", "OP_ROT",
    "OP_SWAP", "OP_TUCK", "OP_CAT", "OP_SUBSTR", "OP_LEFT", "OP_RIGHT", "OP_SIZE", "OP_INVERT", "OP_AND",
    "OP_OR", "OP_XOR", "OP_EQUAL", "OP_EQUALVERIFY", "OP_RESERVED1", "OP_RESERVED2", "OP_1ADD", "OP_1SUB", "OP_2MUL",
    "OP_2DIV", "OP_NEGATE", "OP_ABS", "OP_NOT", "OP_0NOTEQUAL", "OP_ADD", "OP_SUB", "OP_MUL", "OP_DIV",
    "OP_MOD", "OP_LSHIFT", "OP_RSHIFT", "OP_BOOLAND", "OP_BOOLOR",
    "OP_NUMEQUAL", "OP_NUMEQUALVERIFY", "OP_NUMNOTEQUAL", "OP_LESSTHAN",
    "OP_GREATERTHAN", "OP_LESSTHANOREQUAL", "OP_GREATERTHANOREQUAL", "OP_MIN", "OP_MAX",
    "OP_WITHIN", "OP_RIPEMD160", "OP_SHA1", "OP_SHA256", "OP_HASH160",
    "OP_HASH256", "OP_CODESEPARATOR", "OP_CHECKSIG", "OP_CHECKSIGVERIFY", "OP_CHECKMULTISIG",
    "OP_CHECKMULTISIGVERIFY", "OP_NOP1", "OP_NOP2", "OP_NOP3", "OP_NOP4", "OP_NOP5", "OP_CLAIM_NAME",
    "OP_SUPPORT_CLAIM", "OP_UPDATE_CLAIM",
    ("OP_SINGLEBYTE_END", 0xF0),
    ("OP_DOUBLEBYTE_BEGIN", 0xF000),
    "OP_PUBKEY", "OP_PUBKEYHASH",
    ("OP_INVALIDOPCODE", 0xFFFF),
])


def script_GetOp(bytes):
    i = 0
    while i < len(bytes):
        vch = None
        opcode = ord(bytes[i])
        i += 1
        if opcode >= opcodes.OP_SINGLEBYTE_END:
            opcode <<= 8
            opcode |= ord(bytes[i])
            i += 1

        if opcode <= opcodes.OP_PUSHDATA4:
            nSize = opcode
            if opcode == opcodes.OP_PUSHDATA1:
                nSize = ord(bytes[i])
                i += 1
            elif opcode == opcodes.OP_PUSHDATA2:
                (nSize,) = struct.unpack_from('<H', bytes, i)
                i += 2
            elif opcode == opcodes.OP_PUSHDATA4:
                (nSize,) = struct.unpack_from('<I', bytes, i)
                i += 4
            vch = bytes[i:i+nSize]
            i += nSize

        yield (opcode, vch, i)


def script_GetOpName(opcode):
    return (opcodes.whatis(opcode)).replace("OP_", "")


def decode_script(bytes):
    result = ''
    for (opcode, vch, i) in script_GetOp(bytes):
        if len(result) > 0: result += " "
        if opcode <= opcodes.OP_PUSHDATA4:
            result += "%d:"%(opcode,)
            result += short_hex(vch)
        else:
            result += script_GetOpName(opcode)
    return result


def match_decoded(decoded, to_match):
    if len(decoded) != len(to_match):
        return False;
    for i in range(len(decoded)):
        if to_match[i] == opcodes.OP_PUSHDATA4 and opcodes.OP_PUSHDATA4 >= decoded[i][0] > 0:
            continue  # Opcodes below OP_PUSHDATA4 all just push data onto stack, and are equivalent.
        if to_match[i] != decoded[i][0]:
            return False
    return True


def parse_sig(x_sig):
    s = []
    for sig in x_sig:
        if sig[-2:] == '01':
            s.append(sig[:-2])
        else:
            assert sig == NO_SIGNATURE
            s.append(None)
    return s

def is_extended_pubkey(x_pubkey):
    return x_pubkey[0:2] in ['fe', 'ff']

def x_to_xpub(x_pubkey):
    if x_pubkey[0:2] == 'ff':
        from account import BIP32_Account
        xpub, s = BIP32_Account.parse_xpubkey(x_pubkey)
        return xpub



def parse_xpub(x_pubkey):
    if x_pubkey[0:2] in ['02','03','04']:
        pubkey = x_pubkey
    elif x_pubkey[0:2] == 'ff':
        from account import BIP32_Account
        xpub, s = BIP32_Account.parse_xpubkey(x_pubkey)
        pubkey = BIP32_Account.derive_pubkey_from_xpub(xpub, s[0], s[1])
    elif x_pubkey[0:2] == 'fe':
        from account import OldAccount
        mpk, s = OldAccount.parse_xpubkey(x_pubkey)
        pubkey = OldAccount.get_pubkey_from_mpk(mpk.decode('hex'), s[0], s[1])
    elif x_pubkey[0:2] == 'fd':
        addrtype = ord(x_pubkey[2:4].decode('hex'))
        hash160 = x_pubkey[4:].decode('hex')
        pubkey = None
        address = hash_160_to_bc_address(hash160, addrtype)
    else:
        raise BaseException("Cannnot parse pubkey")
    if pubkey:
        address = public_key_to_bc_address(pubkey.decode('hex'))
    return pubkey, address


def parse_scriptSig(d, bytes):
    try:
        decoded = [ x for x in script_GetOp(bytes) ]
    except Exception:
        # coinbase transactions raise an exception
        print_error("cannot find address in input script", bytes.encode('hex'))
        return

    # payto_pubkey
    match = [ opcodes.OP_PUSHDATA4 ]
    if match_decoded(decoded, match):
        sig = decoded[0][1].encode('hex')
        d['address'] = "(pubkey)"
        d['signatures'] = [sig]
        d['num_sig'] = 1
        d['x_pubkeys'] = ["(pubkey)"]
        d['pubkeys'] = ["(pubkey)"]
        return

    # non-generated TxIn transactions push a signature
    # (seventy-something bytes) and then their public key
    # (65 bytes) onto the stack:
    match = [ opcodes.OP_PUSHDATA4, opcodes.OP_PUSHDATA4 ]
    if match_decoded(decoded, match):
        sig = decoded[0][1].encode('hex')
        x_pubkey = decoded[1][1].encode('hex')
        try:
            signatures = parse_sig([sig])
            pubkey, address = parse_xpub(x_pubkey)
        except:
            import traceback
            traceback.print_exc(file=sys.stdout)
            print_error("cannot find address in input script", bytes.encode('hex'))
            return
        d['signatures'] = signatures
        d['x_pubkeys'] = [x_pubkey]
        d['num_sig'] = 1
        d['pubkeys'] = [pubkey]
        d['address'] = address
        return

    # p2sh transaction, m of n
    match = [ opcodes.OP_0 ] + [ opcodes.OP_PUSHDATA4 ] * (len(decoded) - 1)
    if not match_decoded(decoded, match):
        print_error("cannot find address in input script", bytes.encode('hex'))
        return
    x_sig = [x[1].encode('hex') for x in decoded[1:-1]]
    dec2 = [ x for x in script_GetOp(decoded[-1][1]) ]
    m = dec2[0][0] - opcodes.OP_1 + 1
    n = dec2[-2][0] - opcodes.OP_1 + 1
    op_m = opcodes.OP_1 + m - 1
    op_n = opcodes.OP_1 + n - 1
    match_multisig = [ op_m ] + [opcodes.OP_PUSHDATA4]*n + [ op_n, opcodes.OP_CHECKMULTISIG ]
    if not match_decoded(dec2, match_multisig):
        print_error("cannot find address in input script", bytes.encode('hex'))
        return
    x_pubkeys = map(lambda x: x[1].encode('hex'), dec2[1:-2])
    pubkeys = [parse_xpub(x)[0] for x in x_pubkeys]     # xpub, addr = parse_xpub()
    redeemScript = Transaction.multisig_script(pubkeys, m)
    # write result in d
    d['num_sig'] = m
    d['signatures'] = parse_sig(x_sig)
    d['x_pubkeys'] = x_pubkeys
    d['pubkeys'] = pubkeys
    d['redeemScript'] = redeemScript
    d['address'] = hash_160_to_bc_address(hash_160(redeemScript.decode('hex')), 5)


class NameClaim(object):
    def __init__(self, name, value):
        self.name = name
        self.value = value


class ClaimUpdate(object):
    def __init__(self, name, claim_id, value):
        self.name = name
        self.claim_id = claim_id
        self.value = value


class ClaimSupport(object):
    def __init__(self, name, claim_id):
        self.name = name
        self.claim_id = claim_id


def decode_claim_script(decoded_script):
    if len(decoded_script) <= 6:
        return False
    op = 0
    claim_type = decoded_script[op][0]
    if claim_type == opcodes.OP_UPDATE_CLAIM:
        if len(decoded_script) <= 7:
            return False
    if claim_type not in [
        opcodes.OP_CLAIM_NAME,
        opcodes.OP_SUPPORT_CLAIM,
        opcodes.OP_UPDATE_CLAIM
    ]:
        return False
    op += 1
    value = None
    claim_id = None
    claim = None
    if not (0 <= decoded_script[op][0] <= opcodes.OP_PUSHDATA4):
        return False
    name = decoded_script[op][1]
    op += 1
    if not (0 <= decoded_script[op][0] <= opcodes.OP_PUSHDATA4):
        return False
    if decoded_script[0][0] in [
        opcodes.OP_SUPPORT_CLAIM,
        opcodes.OP_UPDATE_CLAIM
    ]:
        claim_id = decoded_script[op][1]
        if len(claim_id) != 20:
            return False
    else:
        value = decoded_script[op][1]
    op += 1
    if decoded_script[0][0] == opcodes.OP_UPDATE_CLAIM:
        value = decoded_script[op][1]
        op += 1
    if decoded_script[op][0] != opcodes.OP_2DROP:
        return False
    op += 1
    if decoded_script[op][0] != opcodes.OP_DROP and decoded_script[0][0] == opcodes.OP_CLAIM_NAME:
        return False
    elif decoded_script[op][0] != opcodes.OP_2DROP and decoded_script[0][0] == opcodes.OP_UPDATE_CLAIM:
        return False
    op += 1
    if decoded_script[0][0] == opcodes.OP_CLAIM_NAME:
        if name is None or value is None:
            return False
        claim = NameClaim(name, value)
    elif decoded_script[0][0] == opcodes.OP_UPDATE_CLAIM:
        if name is None or value is None or claim_id is None:
            return False
        claim = ClaimUpdate(name, claim_id, value)
    elif decoded_script[0][0] == opcodes.OP_SUPPORT_CLAIM:
        if name is None or claim_id is None:
            return False
        claim = ClaimSupport(name, claim_id)
    return claim, decoded_script[op:]


def get_address_from_output_script(script_bytes):
    output_type = 0
    decoded = [ x for x in script_GetOp(script_bytes) ]
    r = decode_claim_script(decoded)
    claim_args = None
    if r is not False:
        claim_info, decoded = r
        if isinstance(claim_info, NameClaim):
            claim_args = (claim_info.name, claim_info.value)
            output_type |= TYPE_CLAIM
        elif isinstance(claim_info, ClaimSupport):
            claim_args = (claim_info.name, claim_info.claim_id)
            output_type |= TYPE_SUPPORT
        elif isinstance(claim_info, ClaimUpdate):
            claim_args = (claim_info.name, claim_info.claim_id, claim_info.value)
            output_type |= TYPE_UPDATE

    # The Genesis Block, self-payments, and pay-by-IP-address payments look like:
    # 65 BYTES:... CHECKSIG
    match_pubkey = [ opcodes.OP_PUSHDATA4, opcodes.OP_CHECKSIG ]

    # Pay-by-Bitcoin-address TxOuts look like:
    # DUP HASH160 20 BYTES:... EQUALVERIFY CHECKSIG
    match_p2pkh = [ opcodes.OP_DUP, opcodes.OP_HASH160, opcodes.OP_PUSHDATA4, opcodes.OP_EQUALVERIFY, opcodes.OP_CHECKSIG ]

    # p2sh
    match_p2sh = [ opcodes.OP_HASH160, opcodes.OP_PUSHDATA4, opcodes.OP_EQUAL ]

    if match_decoded(decoded, match_pubkey):
        output_val = decoded[0][1].encode('hex')
        output_type |= TYPE_PUBKEY
    elif match_decoded(decoded, match_p2pkh):
        output_val = hash_160_to_bc_address(decoded[2][1])
        output_type |= TYPE_ADDRESS
    elif match_decoded(decoded, match_p2sh):
        output_val = hash_160_to_bc_address(decoded[1][1], 5)
        output_type |= TYPE_ADDRESS
    else:
        output_val = bytes
        output_type |= TYPE_SCRIPT

    if output_type & (TYPE_CLAIM | TYPE_SUPPORT | TYPE_UPDATE):
        output_val = (claim_args, output_val)

    return output_type, output_val


def parse_input(vds):
    d = {}
    prevout_hash = hash_encode(vds.read_bytes(32))
    prevout_n = vds.read_uint32()
    scriptSig = vds.read_bytes(vds.read_compact_size())
    d['scriptSig'] = scriptSig.encode('hex')
    sequence = vds.read_uint32()
    if prevout_hash == '00'*32:
        d['is_coinbase'] = True
    else:
        d['is_coinbase'] = False
        d['prevout_hash'] = prevout_hash
        d['prevout_n'] = prevout_n
        d['sequence'] = sequence
        d['pubkeys'] = []
        d['signatures'] = {}
        d['address'] = None
        if scriptSig:
            parse_scriptSig(d, scriptSig)
    return d


def parse_output(vds, i):
    d = {}
    d['value'] = vds.read_int64()
    scriptPubKey = vds.read_bytes(vds.read_compact_size())
    d['type'], d['address'] = get_address_from_output_script(scriptPubKey)
    d['scriptPubKey'] = scriptPubKey.encode('hex')
    d['prevout_n'] = i
    return d


def deserialize(raw):
    vds = BCDataStream()
    vds.write(raw.decode('hex'))
    d = {}
    start = vds.read_cursor
    d['version'] = vds.read_int32()
    n_vin = vds.read_compact_size()
    d['inputs'] = list(parse_input(vds) for i in xrange(n_vin))
    n_vout = vds.read_compact_size()
    d['outputs'] = list(parse_output(vds,i) for i in xrange(n_vout))
    d['lockTime'] = vds.read_uint32()
    return d


def push_script(x):
    return op_push(len(x)/2) + x


class Transaction:

    def __str__(self):
        if self.raw is None:
            self.raw = self.serialize()
        return self.raw

    def __init__(self, raw):
        if raw is None:
            self.raw = None
        elif type(raw) in [str, unicode]:
            self.raw = raw.strip() if raw else None
        elif type(raw) is dict:
            self.raw = raw['hex']
        else:
            raise BaseException("cannot initialize transaction", raw)
        self._inputs = None
        self._outputs = None

    def update(self, raw):
        self.raw = raw
        self._inputs = None
        self.deserialize()

    def inputs(self):
        if self._inputs is None:
            self.deserialize()
        return self._inputs

    def outputs(self):
        if self._outputs is None:
            self.deserialize()
        return self._outputs

    def update_signatures(self, raw):
        """Add new signatures to a transaction"""
        d = deserialize(raw)
        for i, txin in enumerate(self.inputs()):
            sigs1 = txin.get('signatures')
            sigs2 = d['inputs'][i].get('signatures')
            for sig in sigs2:
                if sig in sigs1:
                    continue
                for_sig = Hash(self.tx_for_sig(i).decode('hex'))
                # der to string
                order = ecdsa.ecdsa.generator_secp256k1.order()
                r, s = ecdsa.util.sigdecode_der(sig.decode('hex'), order)
                sig_string = ecdsa.util.sigencode_string(r, s, order)
                pubkeys = txin.get('pubkeys')
                compressed = True
                for recid in range(4):
                    public_key = MyVerifyingKey.from_signature(sig_string, recid, for_sig, curve = SECP256k1)
                    pubkey = point_to_ser(public_key.pubkey.point, compressed).encode('hex')
                    if pubkey in pubkeys:
                        public_key.verify_digest(sig_string, for_sig, sigdecode = ecdsa.util.sigdecode_string)
                        j = pubkeys.index(pubkey)
                        print_error("adding sig", i, j, pubkey, sig)
                        self._inputs[i]['signatures'][j] = sig
                        self._inputs[i]['x_pubkeys'][j] = pubkey
                        break
        # redo raw
        self.raw = self.serialize()


    def deserialize(self):
        if self.raw is None:
            self.raw = self.serialize()
        if self._inputs is not None:
            return
        d = deserialize(self.raw)
        self._inputs = d['inputs']
        self._outputs = [(x['type'], x['address'], x['value']) for x in d['outputs']]
        self.locktime = d['lockTime']
        return d

    @classmethod
    def from_io(klass, inputs, outputs, locktime=0):
        self = klass(None)
        self._inputs = inputs
        self._outputs = outputs
        self.locktime = locktime
        return self

    @classmethod
    def sweep(klass, privkeys, network, to_address, fee):
        inputs = []
        keypairs = {}
        for privkey in privkeys:
            pubkey = public_key_from_private_key(privkey)
            address = address_from_private_key(privkey)
            u = network.synchronous_get(('blockchain.address.listunspent',[address]))
            pay_script = klass.pay_script(TYPE_ADDRESS, address)
            for item in u:
                item['scriptPubKey'] = pay_script
                item['redeemPubkey'] = pubkey
                item['address'] = address
                item['prevout_hash'] = item['tx_hash']
                item['prevout_n'] = item['tx_pos']
                item['pubkeys'] = [pubkey]
                item['x_pubkeys'] = [pubkey]
                item['signatures'] = [None]
                item['num_sig'] = 1
            inputs += u
            keypairs[pubkey] = privkey

        if not inputs:
            return

        total = sum(i.get('value') for i in inputs) - fee
        outputs = [(TYPE_ADDRESS, to_address, total)]
        self = klass.from_io(inputs, outputs)
        self.sign(keypairs)
        return self

    @classmethod
    def multisig_script(klass, public_keys, m):
        n = len(public_keys)
        assert n <= 15
        assert m <= n
        op_m = format(opcodes.OP_1 + m - 1, 'x')
        op_n = format(opcodes.OP_1 + n - 1, 'x')
        keylist = [op_push(len(k)/2) + k for k in public_keys]
        return op_m + ''.join(keylist) + op_n + 'ae'

    @classmethod
    def pay_script(self, output_type, addr):
        script = ''
        if output_type & TYPE_CLAIM:
            claim, addr = addr
            claim_name, claim_value = claim
            script += 'b5'                                          # op_claim_name
            script += push_script(claim_name.encode('hex'))
            script += push_script(claim_value.encode('hex'))
            script += '6d75'                                        # op_2drop, op_drop
        elif output_type & TYPE_SUPPORT:
            claim, addr = addr
            claim_name, claim_id = claim
            script += 'b6'
            script += push_script(claim_name.encode('hex'))
            script += push_script(claim_id.encode('hex'))
            script += '6d75'
        elif output_type & TYPE_UPDATE:
            claim, addr = addr
            claim_name, claim_id, claim_value = claim
            script += 'b7'
            script += push_script(claim_name.encode('hex'))
            script += push_script(claim_id.encode('hex'))
            script += push_script(claim_value.encode('hex'))
            script += '6d6d'

        if output_type & TYPE_SCRIPT:
            script += addr.encode('hex')
        elif output_type & TYPE_ADDRESS:                                      # op_2drop, op_drop
            addrtype, hash_160 = bc_address_to_hash_160(addr)
            if addrtype == 0:
                script += '76a9'                                      # op_dup, op_hash_160
                script += push_script(hash_160.encode('hex'))
                script += '88ac'                                     # op_equalverify, op_checksig
            elif addrtype == 5:
                script += 'a9'                                        # op_hash_160
                script += push_script(hash_160.encode('hex'))
                script += '87'                                       # op_equal
            else:
                raise
        else:
            raise
        return script

    @classmethod
    def input_script(self, txin, i, for_sig):
        # for_sig:
        #   -1   : do not sign, estimate length
        #   i>=0 : serialized tx for signing input i
        #   None : add all known signatures

        p2sh = txin.get('redeemScript') is not None
        num_sig = txin['num_sig'] if p2sh else 1
        address = txin['address']

        x_signatures = txin['signatures']
        signatures = filter(None, x_signatures)
        is_complete = len(signatures) == num_sig

        if for_sig in [-1, None]:
            # if we have enough signatures, we use the actual pubkeys
            # use extended pubkeys (with bip32 derivation)
            if for_sig == -1:
                # we assume that signature will be 0x48 bytes long
                pubkeys = txin['pubkeys']
                sig_list = [ "00" * 0x48 ] * num_sig
            elif is_complete:
                pubkeys = txin['pubkeys']
                sig_list = ((sig + '01') for sig in signatures)
            else:
                pubkeys = txin['x_pubkeys']
                sig_list = ((sig + '01') if sig else NO_SIGNATURE for sig in x_signatures)
            script = ''.join(push_script(x) for x in sig_list)
            if not p2sh:
                x_pubkey = pubkeys[0]
                if x_pubkey is None:
                    addrtype, h160 = bc_address_to_hash_160(txin['address'])
                    x_pubkey = 'fd' + (chr(addrtype) + h160).encode('hex')
                script += push_script(x_pubkey)
            else:
                script = '00' + script          # put op_0 in front of script
                redeem_script = self.multisig_script(pubkeys, num_sig)
                script += push_script(redeem_script)

        elif for_sig==i:
            script_type = TYPE_ADDRESS
            if 'is_claim' in txin and txin['is_claim']:
                script_type |= TYPE_CLAIM
                address = ((txin['claim_name'], txin['claim_value']), address)
            elif 'is_support' in txin and txin['is_support']:
                script_type |= TYPE_SUPPORT
                address = ((txin['claim_name'], txin['claim_id']), address)
            elif 'is_update' in txin and txin['is_update']:
                script_type |= TYPE_UPDATE
                address = ((txin['claim_name'], txin['claim_id'], txin['claim_value']), address)
            script = txin['redeemScript'] if p2sh else self.pay_script(script_type, address)
        else:
            script = ''

        return script

    @classmethod
    def serialize_input(self, txin, i, for_sig):
        # Prev hash and index
        s = txin['prevout_hash'].decode('hex')[::-1].encode('hex')
        s += int_to_hex(txin['prevout_n'], 4)
        # Script length, script, sequence
        script = self.input_script(txin, i, for_sig)
        s += var_int(len(script) / 2)
        s += script
        s += "ffffffff"
        return s

    def BIP_LI01_sort(self):
        # See https://github.com/kristovatlas/rfc/blob/master/bips/bip-li01.mediawiki
        self._inputs.sort(key = lambda i: (i['prevout_hash'], i['prevout_n']))
        self._outputs.sort(key = lambda o: (o[2], self.pay_script(o[0], o[1])))

    def serialize(self, for_sig=None):
        inputs = self.inputs()
        outputs = self.outputs()
        s  = int_to_hex(1,4)                                         # version
        s += var_int( len(inputs) )                                  # number of inputs
        for i, txin in enumerate(inputs):
            s += self.serialize_input(txin, i, for_sig)
        s += var_int( len(outputs) )                                 # number of outputs
        for output in outputs:
            output_type, addr, amount = output
            s += int_to_hex( amount, 8)                              # amount
            script = self.pay_script(output_type, addr)
            s += var_int( len(script)/2 )                           #  script length
            s += script                                             #  script
        s += int_to_hex(0,4)                                        #  lock time
        if for_sig is not None and for_sig != -1:
            s += int_to_hex(1, 4)                                   #  hash type
        return s

    def tx_for_sig(self,i):
        return self.serialize(for_sig = i)

    def hash(self):
        return Hash(self.raw.decode('hex') )[::-1].encode('hex')

    def add_inputs(self, inputs):
        self._inputs.extend(inputs)
        self.raw = None

    def add_outputs(self, outputs):
        self._outputs.extend(outputs)
        self.raw = None

    def input_value(self):
        return sum(x['value'] for x in self.inputs())

    def output_value(self):
        return sum( val for tp,addr,val in self.outputs())

    def get_fee(self):
        return self.input_value() - self.output_value()

    def is_final(self):
        return not any([x.get('sequence') < 0xffffffff - 1 for x in self.inputs()])

    @classmethod
    def fee_for_size(self, relay_fee, fee_per_kb, size):
        '''Given a fee per kB in satoshis, and a tx size in bytes,
        returns the transaction fee.'''
        fee = int(fee_per_kb * size / 1000.)
        if fee < relay_fee:
            fee = relay_fee
        return fee

    @profiler
    def estimated_size(self):
        '''Return an estimated tx size in bytes.'''
        return len(self.serialize(-1)) / 2  # ASCII hex string

    @classmethod
    def estimated_input_size(self, txin):
        '''Return an estimated of serialized input size in bytes.'''
        return len(self.serialize_input(txin, -1, -1)) / 2

    def estimated_fee(self, relay_fee, fee_per_kb):
        '''Return an estimated fee given a fee per kB in satoshis.'''
        return self.fee_for_size(relay_fee, fee_per_kb, self.estimated_size())

    def signature_count(self):
        r = 0
        s = 0
        for txin in self.inputs():
            if txin.get('is_coinbase'):
                continue
            signatures = filter(None, txin.get('signatures',[]))
            s += len(signatures)
            r += txin.get('num_sig',-1)
        return s, r

    def is_complete(self):
        s, r = self.signature_count()
        return r == s

    def inputs_without_script(self):
        out = set()
        for i, txin in enumerate(self.inputs()):
            if txin.get('scriptSig') == '':
                out.add(i)
        return out

    def inputs_to_sign(self):
        out = set()
        for txin in self.inputs():
            num_sig = txin.get('num_sig')
            if num_sig is None:
                continue
            x_signatures = txin['signatures']
            signatures = filter(None, x_signatures)
            if len(signatures) == num_sig:
                # input is complete
                continue
            for k, x_pubkey in enumerate(txin['x_pubkeys']):
                if x_signatures[k] is not None:
                    # this pubkey already signed
                    continue
                out.add(x_pubkey)
        return out

    def sign(self, keypairs):
        for i, txin in enumerate(self.inputs()):
            num = txin['num_sig']
            for x_pubkey in txin['x_pubkeys']:
                signatures = filter(None, txin['signatures'])
                if len(signatures) == num:
                    # txin is complete
                    break
                if x_pubkey in keypairs.keys():
                    print_error("adding signature for", x_pubkey)
                    # add pubkey to txin
                    txin = self._inputs[i]
                    x_pubkeys = txin['x_pubkeys']
                    ii = x_pubkeys.index(x_pubkey)
                    sec = keypairs[x_pubkey]
                    pubkey = public_key_from_private_key(sec)
                    txin['x_pubkeys'][ii] = pubkey
                    txin['pubkeys'][ii] = pubkey
                    self._inputs[i] = txin
                    # add signature
                    for_sig = Hash(self.tx_for_sig(i).decode('hex'))
                    pkey = regenerate_key(sec)
                    secexp = pkey.secret
                    private_key = lbrycrd.MySigningKey.from_secret_exponent(secexp, curve = SECP256k1)
                    public_key = private_key.get_verifying_key()
                    sig = private_key.sign_digest_deterministic( for_sig, hashfunc=hashlib.sha256, sigencode = ecdsa.util.sigencode_der )
                    assert public_key.verify_digest( sig, for_sig, sigdecode = ecdsa.util.sigdecode_der)
                    txin['signatures'][ii] = sig.encode('hex')
                    self._inputs[i] = txin
        print_error("is_complete", self.is_complete())
        self.raw = self.serialize()


    def get_outputs(self):
        """convert pubkeys to addresses"""
        o = []
        for type, x, v in self.outputs():
            if type & (TYPE_CLAIM | TYPE_UPDATE | TYPE_SUPPORT):
                x = x[1]
            if type & TYPE_ADDRESS:
                addr = x
            elif type & TYPE_PUBKEY:
                addr = public_key_to_bc_address(x.decode('hex'))
            else:
                addr = 'SCRIPT ' + x.encode('hex')
            o.append((addr,v))      # consider using yield (addr, v)
        return o

    def get_output_addresses(self):
        return [addr for addr, val in self.get_outputs()]


    def has_address(self, addr):
        return (addr in self.get_output_addresses()) or (addr in (tx.get("address") for tx in self.inputs()))

    def as_dict(self):
        if self.raw is None:
            self.raw = self.serialize()
        self.deserialize()
        out = {
            'hex': self.raw,
            'complete': self.is_complete()
        }
        return out


    def requires_fee(self, wallet):
        # see https://en.bitcoin.it/wiki/Transaction_fees
        #
        # size must be smaller than 1 kbyte for free tx
        size = len(self.serialize(-1))/2
        if size >= 10000:
            return True
        # all outputs must be 0.01 BTC or larger for free tx
        for addr, value in self.get_outputs():
            if value < 1000000:
                return True
        # priority must be large enough for free tx
        threshold = 57600000
        weight = 0
        for txin in self.inputs():
            age = wallet.get_confirmations(txin["prevout_hash"])[0]
            weight += txin["value"] * age
        priority = weight / size
        print_error(priority, threshold)

        return priority < threshold

# Get claim ID in hex, given a transaction in hex containing
# the claim, and the corresponding txid and its nout
def get_claim_id_from_raw_tx(tx_hex, txid_hex, nout):
    tx = deserialize(tx_hex)
    if len(tx.get('outputs')) < nout+1:
        raise Exception("nout {} too large for tx {}".format(nout, tx))
    output = tx.get('outputs')[nout]
    script = output.get('scriptPubKey').decode('hex')
    decoded_script = [s for s in script_GetOp(script)]
    out = decode_claim_script(decoded_script)
    if out is False:
        raise Exception("{}:{}, is not a claim script. {}".format(txid_hex, nout, decoded_script))
    claim,claim_script = out
    # if name claim, calculate claim id from txid nout
    if type(claim) == NameClaim:
        return txid_hex_nout_to_claim_id_hex(txid_hex, nout)
    # if update or support, return the claim id in the script
    else:
        return encode_claim_id_hex(claim.claim_id)



