#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# author wwqgtxx <wwqgtxx@gmail.com>
from __future__ import (absolute_import, division,
                        print_function, unicode_literals)
import unittest
from SimpleReverseProxy.encrypt0 import *


class Test(unittest.TestCase):
    def setUp(self):
        self.password = os.urandom(20)
        self.wrong_password = os.urandom(20)
        self.raw_data = os.urandom(200000)

    def tearDown(self):
        pass

    def testChaCha20IETFCipher(self):
        cipher = ChaCha20IETFCipher(password=self.password, saved_iv=False)
        encrypt_data = cipher.encrypt(self.raw_data)
        decrypt_data = cipher.decrypt(encrypt_data)
        self.assertEqual(self.raw_data, decrypt_data)
        self.assertNotIn(SPLIT_BYTES, encrypt_data)

    def testChaCha20IETFCipherWithWrongPassword(self):
        cipher = ChaCha20IETFCipher(password=self.password, saved_iv=False)
        encrypt_data = cipher.encrypt(self.raw_data)
        cipher = ChaCha20IETFCipher(password=self.wrong_password)
        decrypt_data = cipher.decrypt(encrypt_data)
        self.assertNotEqual(self.raw_data, decrypt_data)

    def testChaCha20IETFPoly1305Cipher(self):
        cipher = ChaCha20IETFPoly1305Cipher(password=self.password, saved_iv=False)
        encrypt_data = cipher.encrypt(self.raw_data)
        decrypt_data = cipher.decrypt(encrypt_data)
        self.assertEqual(self.raw_data, decrypt_data)
        self.assertNotIn(SPLIT_BYTES, encrypt_data)

    def testChaCha20IETFPoly1305CipherWithWrongPassword(self):
        cipher = ChaCha20IETFPoly1305Cipher(password=self.password, saved_iv=False)
        encrypt_data = cipher.encrypt(self.raw_data)
        cipher = ChaCha20IETFPoly1305Cipher(password=self.wrong_password, saved_iv=False)
        decrypt_data = cipher.decrypt(encrypt_data)
        self.assertEqual(b'', decrypt_data)


if __name__ == '__main__':
    unittest.main()
