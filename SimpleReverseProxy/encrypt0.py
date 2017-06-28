#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# author wwqgtxx <wwqgtxx@gmail.com>
from __future__ import (absolute_import, division,
                        print_function, unicode_literals)

from .utils import SPLIT_BYTES, crc32, logger, tobytes, tostr
from .py_chacha20 import ChaCha as ChaCha20IETF
from .py_poly1305 import Poly1305
import hashlib
import struct
import os
import time

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

    def get_iv(self):
        iv = os.urandom(self.IV_LENGTH)
        while SPLIT_BYTES in iv:
            iv = os.urandom(self.IV_LENGTH)
        return iv

    def __init__(self, password, iv=None, saved_iv=True):
        self.key = self.get_key(password)
        self.iv = iv
        self.saved_iv = saved_iv

    def clone(self, without_iv=True):
        obj = object.__new__(self.__class__)
        obj.key = self.key
        if without_iv:
            obj.iv = None
        else:
            obj.iv = self.iv
        obj.saved_iv = self.saved_iv
        return obj

    def decrypt(self, data):
        if len(data) < 5:
            return b''
        crc32_bytes = data[:4]
        crc32_value1 = int.from_bytes(crc32_bytes, 'big')
        data = data[4:]
        crc32_value2 = crc32(data)
        data = data[1:]
        if crc32_value1 != crc32_value2:
            return b''
        if self.iv:
            iv = self.iv
        else:
            if len(data) < self.IV_LENGTH:
                return b''
            iv = data[:self.IV_LENGTH]
            data = data[self.IV_LENGTH:]
            if self.saved_iv:
                logger.debug("saved iv:%s" % iv)
                self.iv = iv
        if not data:
            return b''
        data = self._decrypt(iv, data)
        return data

    def encrypt(self, data):
        raw_data = tobytes(data)
        if self.iv:
            data = self._encrypt(self.iv, raw_data)
        else:
            iv = self.get_iv()
            if self.saved_iv:
                logger.debug("saved iv:%s" % iv)
                self.iv = iv
            data = self._encrypt(iv, raw_data)
            data = iv + data
        random_bytes = os.urandom(1)
        data = random_bytes + data
        crc32_bytes = crc32(data).to_bytes(4, 'big')
        data = crc32_bytes + data
        if SPLIT_BYTES in data:
            return self.encrypt(raw_data)
        return data

    def _decrypt(self, iv, raw_data):
        raise NotImplementedError

    def _encrypt(self, iv, raw_data):
        raise NotImplementedError

    def get_cipher(self, iv):
        raise NotImplementedError


class NoneCipher(BaseCipher):
    def get_key(self, password):
        return password

    def decrypt(self, data):
        return data

    def encrypt(self, data):
        return data


class ChaCha20IETFCipher(BaseCipher):
    KEY_LENGTH = 32
    IV_LENGTH = 12

    def get_cipher(self, iv):
        return ChaCha20IETF(self.key, iv)

    def _decrypt(self, iv, raw_data):
        return self.get_cipher(iv).decrypt(raw_data)

    def _encrypt(self, iv, raw_data):
        return self.get_cipher(iv).encrypt(raw_data)


class ChaCha20IETFPoly1305Cipher(BaseCipher):
    KEY_LENGTH = 32
    IV_LENGTH = 12

    def get_cipher(self, iv):
        raise NotImplementedError

    def chacha20_encrypt(self, nonce, plaintext, counter=0):
        return ChaCha20IETF(self.key, nonce, counter).encrypt(plaintext)

    def chacha20_decrypt(self, nonce, ciphertext, counter=0):
        return ChaCha20IETF(self.key, nonce, counter).decrypt(ciphertext)

    def poly1305_create_tag(self, key, ciphertext, data):
        mac_data = data + self.pad16(data)
        mac_data += ciphertext + self.pad16(ciphertext)
        mac_data += struct.pack('<Q', len(data))
        mac_data += struct.pack('<Q', len(ciphertext))
        tag = Poly1305(key).create_tag(mac_data)
        return tag

    def poly1305_key_gen(self, nonce):
        """Generate the key for the Poly1305 authenticator"""
        return self.chacha20_encrypt(nonce, bytearray(32))

    def pad16(self, data):
        """Return padding for the Associated Authenticated Data"""
        if len(data) % 16 == 0:
            return bytearray(0)
        else:
            return bytearray(16 - (len(data) % 16))

    def seal(self, nonce, plaintext, data):
        """
        Encrypts and authenticates plaintext using nonce and data. Returns the
        ciphertext, consisting of the encrypted plaintext and tag concatenated.
        """
        otk = self.poly1305_key_gen(nonce)

        ciphertext = self.chacha20_encrypt(nonce, plaintext, counter=1)
        tag = self.poly1305_create_tag(otk, ciphertext, data)

        return tag + ciphertext

    def open(self, nonce, ciphertext, data):
        """
        Decrypts and authenticates ciphertext using nonce and data. If the
        tag is valid, the plaintext is returned. If the tag is invalid,
        returns None.
        """
        expected_tag = ciphertext[:16]
        ciphertext = ciphertext[16:]

        otk = self.poly1305_key_gen(nonce)
        tag = self.poly1305_create_tag(otk, ciphertext, data)

        if tag != expected_tag:
            return None

        return self.chacha20_decrypt(nonce, ciphertext, counter=1)

    def _decrypt(self, iv, raw_data):
        data = self.open(iv, raw_data, b'')
        if data:
            return data
        return b''

    def _encrypt(self, iv, raw_data):
        return self.seal(iv, raw_data, b'')


ciphers = {
    "none": NoneCipher,
    "chacha20-ietf": ChaCha20IETFCipher,
    "chacha20-ietf-poly1305": ChaCha20IETFPoly1305Cipher
}
