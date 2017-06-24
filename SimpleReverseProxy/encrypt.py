#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# author wwqgtxx <wwqgtxx@gmail.com>
from __future__ import (absolute_import, division,
                        print_function, unicode_literals)

from Crypto import Random
from Crypto.Cipher import AES, ChaCha20, Salsa20, ARC4
from Crypto.Util.py3compat import tobytes, tostr
from .utils import SPLIT_BYTES
import hashlib
import zlib

random = Random.new()

cached_keys = {}


def EVP_BytesToKey(password, key_len, iv_len):
    # equivalent to OpenSSL's EVP_BytesToKey() with count 1
    # so that we make the same key and iv as nodejs version
    if hasattr(password, 'encode'):
        password = password.encode('utf-8')
    cached_key = '%s-%d-%d' % (password, key_len, iv_len)
    r = cached_keys.get(cached_key, None)
    if r:
        return r
    m = []
    i = 0
    while len(b''.join(m)) < (key_len + iv_len):
        md5 = hashlib.md5()
        data = password
        if i > 0:
            data = m[i - 1] + password
        md5.update(data)
        m.append(md5.digest())
        i += 1
    ms = b''.join(m)
    key = ms[:key_len]
    iv = ms[key_len:key_len + iv_len]
    cached_keys[cached_key] = (key, iv)
    return key, iv


class BaseCipher(object):
    KEY_LENGTH = 0
    IV_LENGTH = 0

    def get_key(self, password):
        key, iv = EVP_BytesToKey(password, self.KEY_LENGTH, self.IV_LENGTH)
        return key
        # key_buf = []
        # while len(b''.join(key_buf)) < self.KEY_LENGTH:
        #     key_buf.append(hashlib.md5(
        #         (key_buf[-1] if key_buf else b'') + password
        #     ).digest())
        # return b''.join(key_buf)[:self.KEY_LENGTH]

    def __init__(self, password):
        self.key = self.get_key(password)

    def decrypt(self, data):
        iv = data[:self.IV_LENGTH]
        data = data[self.IV_LENGTH:]
        if not data:
            return b''
        data = self.get_cipher(iv).decrypt(data)
        # data = zlib.decompress(data)
        return data

    def encrypt(self, data):
        raw_data = tobytes(data)
        # data = zlib.compress(data)
        iv = random.read(self.IV_LENGTH)
        while SPLIT_BYTES in iv:
            iv = random.read(self.IV_LENGTH)
        data = self.get_cipher(iv).encrypt(raw_data)
        if SPLIT_BYTES in data:
            return self.encrypt(raw_data)
        data = iv + data
        return data

    def get_cipher(self, iv):
        pass


class NoneCipher(BaseCipher):
    def get_key(self, password):
        pass

    def decrypt(self, data):
        return data

    def encrypt(self, data):
        return data


class AES256GCMCipher(BaseCipher):
    KEY_LENGTH = 32
    IV_LENGTH = 16

    def get_cipher(self, iv):
        return AES.new(self.key, mode=AES.MODE_GCM, nonce=iv)


class AES192GCMCipher(AES256GCMCipher):
    KEY_LENGTH = 24


class AES128GCMCipher(AES256GCMCipher):
    KEY_LENGTH = 16


class AES256CFBCipher(BaseCipher):
    KEY_LENGTH = 32
    IV_LENGTH = 16

    def get_cipher(self, iv):
        return AES.new(self.key, mode=AES.MODE_CFB, iv=iv,
                       segment_size=128)


class AES192CFBCipher(AES256CFBCipher):
    KEY_LENGTH = 24


class AES128CFBCipher(AES256CFBCipher):
    KEY_LENGTH = 16


class ChaCha20Cipher(BaseCipher):
    KEY_LENGTH = 32
    IV_LENGTH = 8

    def get_cipher(self, iv):
        return ChaCha20.new(key=self.key, nonce=iv)


class Salsa20Cipher(BaseCipher):
    KEY_LENGTH = 32
    IV_LENGTH = 8

    def get_cipher(self, iv):
        return Salsa20.new(key=self.key, nonce=iv)


class RC4MD5Cipher(BaseCipher):
    KEY_LENGTH = 16
    IV_LENGTH = 0

    def get_cipher(self, iv):
        md5 = hashlib.md5()
        md5.update(self.key)
        md5.update(iv)
        rc4_key = md5.digest()
        return ARC4.new(rc4_key)


ciphers = {
    "aes-256-gcm": AES256GCMCipher,
    "aes-192-gcm": AES192GCMCipher,
    "aes-128-gcm": AES128GCMCipher,
    "aes-256-cfb": AES256CFBCipher,
    "aes-192-cfb": AES192CFBCipher,
    "aes-128-cfb": AES128CFBCipher,
    "salsa20": Salsa20Cipher,
    "chacha20": ChaCha20Cipher,
    "rc4-md5": RC4MD5Cipher,
    "none": NoneCipher
}

default_cipher_name = "chacha20"
default_cipher = ciphers[default_cipher_name]