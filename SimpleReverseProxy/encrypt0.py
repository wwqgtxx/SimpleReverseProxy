#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# author wwqgtxx <wwqgtxx@gmail.com>
from __future__ import (absolute_import, division,
                        print_function, unicode_literals)

from .utils import SPLIT_BYTES, crc32, logger, tobytes, tostr
import hashlib
import os

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
        if len(data) < 4:
            return b''
        crc32_bytes = data[:4]
        crc32_value1 = int.from_bytes(crc32_bytes, 'big')
        data = data[4:]
        crc32_value2 = crc32(data)
        if crc32_value1 != crc32_value2:
            return b''
        iv = data[:self.IV_LENGTH]
        data = data[self.IV_LENGTH:]
        if not data:
            return b''
        data = self._decrypt(iv, data)
        return data

    def encrypt(self, data):
        raw_data = tobytes(data)
        iv = os.urandom(self.IV_LENGTH)
        while SPLIT_BYTES in iv:
            iv = os.urandom(self.IV_LENGTH)
        data = self._encrypt(iv, raw_data)
        data = iv + data
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


ciphers = {
    "none": NoneCipher
}
