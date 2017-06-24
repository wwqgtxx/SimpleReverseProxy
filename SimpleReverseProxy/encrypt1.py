#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# author wwqgtxx <wwqgtxx@gmail.com>
from __future__ import (absolute_import, division,
                        print_function, unicode_literals)

try:
    import cffi

    ffi = cffi.FFI
    del cffi.FFI

    from Crypto.Util._raw_api import backend

    cffi.FFI = ffi
except ImportError:
    ffi = None

from Crypto.Cipher import AES, ChaCha20, Salsa20, ARC4

import hashlib
from .encrypt0 import BaseCipher as _BaseCipher, ciphers


class BaseCipher(_BaseCipher):
    def _decrypt(self, iv, raw_data):
        return self.get_cipher(iv).decrypt(raw_data)

    def _encrypt(self, iv, raw_data):
        return self.get_cipher(iv).encrypt(raw_data)


class AES256GCMCipher(BaseCipher):
    KEY_LENGTH = 32
    IV_LENGTH = 16
    MAC_LENGTH = 16

    def _decrypt(self, iv, raw_data):
        if len(raw_data) < self.MAC_LENGTH:
            return b''
        ct = raw_data[self.MAC_LENGTH:]
        mac = raw_data[:self.MAC_LENGTH]

        cipher = self.get_cipher(iv)
        # cipher.update(self.key)
        try:
            data = cipher.decrypt_and_verify(ct, mac)
        except ValueError:
            data = b''
        return data

    def _encrypt(self, iv, raw_data):
        cipher = self.get_cipher(iv)
        # cipher.update(self.key)
        ct, mac = cipher.encrypt_and_digest(raw_data)
        data = mac + ct
        return data

    def get_cipher(self, iv):
        return AES.new(self.key, mode=AES.MODE_GCM, nonce=iv, mac_len=self.MAC_LENGTH)


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


def init():
    ciphers.update({
        "aes-256-gcm": AES256GCMCipher,
        "aes-192-gcm": AES192GCMCipher,
        "aes-128-gcm": AES128GCMCipher,
        "aes-256-cfb": AES256CFBCipher,
        "aes-192-cfb": AES192CFBCipher,
        "aes-128-cfb": AES128CFBCipher,
        "salsa20": Salsa20Cipher,
        "chacha20": ChaCha20Cipher,
        "rc4-md5": RC4MD5Cipher,
    })
