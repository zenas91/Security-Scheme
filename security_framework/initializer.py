import binascii
import hashlib
import hmac
import os

import numpy as np
from Crypto.Cipher import AES

from .aes import AESAlgo
from curve.x25519 import base_point_mult, multscalar


class IncompatibleValue(Exception):
    pass


class Initializer:
    def __init__(self):
        self.OTCS = os.urandom(32)
        self.OTCP = base_point_mult(self.OTCS)
        self.classifier = None
        self.ID = None
        self.KPS = None
        self.KPP = None
        self.KS = None
        self.KP = None

    def set_init_parameters(self, data, gkg_pub_key):
        sym = self.set_one_auth_key(gkg_pub_key)
        self.ID = self.decrypt(data[0], sym, keys=True).decode('utf-8')
        self.KPS = self.decrypt(data[1], sym, keys=True)
        self.KPP = self.decrypt(data[2], sym, keys=True).decode('utf-8')
        #return self.KPP

    def set_one_auth_key(self, gkg_pub_key):
        return multscalar(self.OTCS, gkg_pub_key)

    def set_auth_key(self, pub_key):
        return multscalar(self.KPS, pub_key)

    def gen_session_keys(self, pub_key, bit_length=256):
        if bit_length % 8 != 0 or bit_length <= 0:
            raise IncompatibleValue(f"Bit length must be greater than 0 and divisible by 8")
        ks = os.urandom(int(bit_length / 8))
        kp = multscalar(ks, multscalar(self.KPS, pub_key))
        self.KS = ks
        self.KP = kp
        return kp

    def gen_session_symmetric_key(self, sess_pub_key):
        return multscalar(self.KS, sess_pub_key)

    def auth_entity(self, pub_key, k_hash):
        hs = self.gen_auth_hash(pub_key)
        return hs == k_hash

    def gen_auth_hash(self, pub_key):
        ks = self.set_auth_key(pub_key)
        return hashlib.sha256(ks.encode()).digest()

    def sign(self, cipher, sk_hash):
        h = hashlib.blake2b(digest_size=16, key=sk_hash)
        h.update(cipher.encode('utf-8'))
        return h.hexdigest().encode('utf-8')

    def gen_mac(self, pub_key, cipher):
        sk_hash = hashlib.sha256(self.gen_session_symmetric_key(pub_key).encode()).digest()
        return self.sign(cipher, sk_hash)

    def verify_mac(self, cipher, pub_key, mac):
        own_mac = self.gen_mac(pub_key, cipher)
        return hmac.compare_digest(own_mac, mac)

    def encrypt(self, data, secret):
        bytestream = data.tobytes()
        hex_data = binascii.hexlify(bytestream)
        str_data = hex_data.decode('utf-8')
        cipher = AESAlgo(str(secret), AES.MODE_ECB)
        return cipher.encrypt(str_data)

    def decrypt(self, cipher_text, secret, dim=5, keys=False):
        cipher = AESAlgo(str(secret), AES.MODE_ECB)
        decrypted = cipher.decrypt(cipher_text)
        if keys:
            return binascii.unhexlify(decrypted.encode('utf-8'))
        return np.frombuffer(binascii.unhexlify(decrypted.encode('utf-8'))).reshape([-1, dim])