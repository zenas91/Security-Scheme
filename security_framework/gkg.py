from .aes import AESAlgo
from Crypto.Cipher import AES
import os, binascii
from curve.x25519 import base_point_mult, multscalar
import numpy as np


class IncompatibleValue(Exception):
    pass


class GKG:
    def __init__(self, bit_length=256):
        if bit_length % 8 != 0 or bit_length <= 0:
            raise IncompatibleValue(f"Bit length must be greater than 0 and divisible by 8")
        self.KPS = os.urandom(int(bit_length / 8))
        self.KPP = base_point_mult(self.KPS)

    def generate_id(self, bit_length=256):
        if bit_length % 8 != 0 or bit_length <= 0:
            raise IncompatibleValue(f"Bit length must be greater than 0 and divisible by 8")
        _id = binascii.hexlify(os.urandom(int(bit_length / 8))).decode('utf-8')

        ids, _ = self.read_registry()
        if ids.size != 0:
            while _id in ids:
                _id = binascii.hexlify(os.urandom(int(bit_length / 8))).decode('utf-8')
        return _id

    def generate_pp_ps(self, bit_length=256):
        if bit_length % 8 != 0 or bit_length <= 0:
            raise IncompatibleValue(f"Bit length must be greater than 0 and divisible by 8")
        _ps = os.urandom(int(bit_length / 8))
        _pp = base_point_mult(_ps)

        _, pps = self.read_registry()
        if pps.size != 0:
            while _pp in pps:
                _ps = os.urandom(int(bit_length / 8))
                _pp = base_point_mult(_ps)

        return _ps, _pp

    def save_to_registry(self, record):
        with open('registry.txt', 'a+', encoding="utf-8") as f:
            f.write(record + "\n")

    def read_registry(self, separate=True):
        with open('registry.txt', 'a+', encoding="utf-8") as f:
            f.seek(0)
            registry = f.readlines()
            if not len(registry) == 0:
                for i, r in enumerate(registry):
                    record = r.rstrip()
                    _id, _pp = record.split('|---|', 1)
                    _pp = _pp.replace('|_,_,_|', '\n')
                    _pp = _pp.replace('|_,_|', '\r')
                    _pp = _pp.replace('_|_,_|', '\x1e')
                    registry[i] = (_id, _pp)
        ar = np.array(registry)
        if separate:
            if ar.size == 0:
                return ar, ar
            return ar[:, 0], ar[:, 1]
        else:
            return ar

    def get_pp_using_id(self, _id):
        pp = None
        with open('registry.txt', 'a+', encoding="utf-8") as f:
            f.seek(0)
            registry = f.readlines()
            if not len(registry) == 0:
                for i, r in enumerate(registry):
                    record = r.rstrip()
                    __id, _pp = record.split('|---|', 1)
                    _pp = _pp.replace('|_,_,_|', '\n')
                    _pp = _pp.replace('|_,_|', '\r')
                    _pp = _pp.replace('_|_,_|', '\x1e')
                    if _id == __id:
                        pp = _pp
                        break
        return pp

    def setup(self, id_bit_length, ps_bit_length, otc_pub_key):
        _id = self.generate_id(id_bit_length)
        _ps, _pp = self.generate_pp_ps(ps_bit_length)

        de_pp = _pp.replace('\n', '|_,_,_|')
        de_pp = de_pp.replace('\r', '|_,_|')
        de_pp = de_pp.replace('\x1e', '_|_,_|')
        tup = (_id, de_pp)
        tup_str = '|---|'.join(tup)

        self.save_to_registry(tup_str)
        sym = self.set_one_auth_key(otc_pub_key)
        enc_id = self.encrypt(_id, sym)
        enc_ps = self.encrypt(_ps, sym)
        enc_pp = self.encrypt(_pp, sym)

        return enc_id, enc_ps, enc_pp

    def set_one_auth_key(self, otc_pub_key):
        return multscalar(self.KPS, otc_pub_key)

    def encrypt(self, data, secret):
        if not type(data) == str:
            if not type(data) == bytes:
                bytestream = data.tobytes()
            else:
                bytestream = data
            hex_data = binascii.hexlify(bytestream)
            str_data = hex_data.decode('utf-8')
        else:
            hex_data = binascii.hexlify(data.encode('utf-8'))
            str_data = hex_data.decode('utf-8')
        cipher = AESAlgo(str(secret), AES.MODE_ECB)
        return cipher.encrypt(str_data)
