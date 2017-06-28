#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# author wwqgtxx <wwqgtxx@gmail.com>
from __future__ import (absolute_import, division,
                        print_function, unicode_literals)

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)
from cryptography.exceptions import UnsupportedAlgorithm, InvalidTag
import hashlib

from .encrypt0 import BaseCipher as _BaseCipher, ciphers


class BaseCipher(_BaseCipher):
    def _decrypt(self, iv, raw_data):
        cipher = self.get_cipher(iv).decryptor()
        data = cipher.update(raw_data) + cipher.finalize()
        return data

    def _encrypt(self, iv, raw_data):
        cipher = self.get_cipher(iv).encryptor()
        data = cipher.update(raw_data) + cipher.finalize()
        return data


class AES256GCMCipher(BaseCipher):
    KEY_LENGTH = 32
    IV_LENGTH = 16
    MAC_LENGTH = 16

    def get_cipher(self, iv, mac=None):
        return Cipher(
            algorithms.AES(self.key),
            modes.GCM(iv, mac, self.MAC_LENGTH),
            backend=default_backend()
        )

    def _decrypt(self, iv, raw_data):
        if len(raw_data) < self.MAC_LENGTH:
            return b''
        ct = raw_data[self.MAC_LENGTH:]
        mac = raw_data[:self.MAC_LENGTH]

        cipher = self.get_cipher(iv, mac).decryptor()
        # cipher.authenticate_additional_data(b"")
        try:
            data = cipher.update(ct) + cipher.finalize()
        except InvalidTag:
            data = b''
        return data

    def _encrypt(self, iv, raw_data):
        cipher = self.get_cipher(iv).encryptor()
        # cipher.authenticate_additional_data(b"")
        cipher_text = cipher.update(raw_data) + cipher.finalize()
        data = cipher.tag + cipher_text
        return data


class AES192GCMCipher(AES256GCMCipher):
    KEY_LENGTH = 24


class AES128GCMCipher(AES256GCMCipher):
    KEY_LENGTH = 16


class AES256CFBCipher(BaseCipher):
    KEY_LENGTH = 32
    IV_LENGTH = 16

    def get_cipher(self, iv):
        return Cipher(algorithms.AES(self.key), modes.CFB(iv), backend=default_backend())


class AES192CFBCipher(AES256CFBCipher):
    KEY_LENGTH = 24


class AES128CFBCipher(AES256CFBCipher):
    KEY_LENGTH = 16


class RC4MD5Cipher(BaseCipher):
    KEY_LENGTH = 16
    IV_LENGTH = 0

    def get_cipher(self, iv):
        md5 = hashlib.md5()
        md5.update(self.key)
        md5.update(iv)
        rc4_key = md5.digest()
        return Cipher(algorithms.ARC4(rc4_key), None, backend=default_backend())


def init():
    pre_update_ciphers = {
        "aes-256-gcm": AES256GCMCipher,
        "aes-192-gcm": AES192GCMCipher,
        "aes-128-gcm": AES128GCMCipher,
        "aes-256-cfb": AES256CFBCipher,
        "aes-192-cfb": AES192CFBCipher,
        "aes-128-cfb": AES128CFBCipher,
        # "salsa20": Salsa20Cipher,
        # "chacha20": ChaCha20Cipher,
        "rc4-md5": RC4MD5Cipher,
    }
    import os
    password = os.urandom(20)
    for k, v in pre_update_ciphers.items():
        try:
            cipher = v(password, saved_iv=False)
            cipher.encrypt(password)
            ciphers[k] = v
        except UnsupportedAlgorithm:
            pass
