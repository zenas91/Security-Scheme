import Padding
import hashlib
from base64 import b64encode, b64decode

from Crypto import Random
from Crypto.Cipher import AES


class AESAlgo(object):
    def __init__(self, key, mode):
        self.block_size = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()
        self.mode = mode
        self.iv = None if mode == AES.MODE_ECB else Random.new().read(self.block_size)

    def encrypt(self, plaintext):
        plaintext = Padding.appendPadding(plaintext, blocksize=self.block_size, mode=0)
        encoder = AES.new(self.key, self.mode) if self.mode == AES.MODE_ECB else AES.new(self.key, self.mode, self.iv)
        cipher_text = encoder.encrypt(plaintext.encode())
        return b64encode(cipher_text).decode("utf-8")

    def decrypt(self, cipher_text):
        decoder = AES.new(self.key, self.mode) if self.mode == AES.MODE_ECB else AES.new(self.key, self.mode, self.iv)
        plaintext = decoder.decrypt(b64decode(cipher_text))
        plaintext = Padding.removePadding(plaintext.decode(), mode=0)
        return plaintext
