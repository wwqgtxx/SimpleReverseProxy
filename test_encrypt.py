#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# author wwqgtxx <wwqgtxx@gmail.com>
from __future__ import (absolute_import, division,
                        print_function, unicode_literals)
import unittest
from SimpleReverseProxy.encrypt import *


class Test(unittest.TestCase):
    def setUp(self):
        self.password = random.read(20)
        self.raw_data = random.read(20000000)

    def tearDown(self):
        pass

    def testAES256GCMCipher(self):
        cipher = AES256GCMCipher(password=self.password)
        encrypt_data = cipher.encrypt(self.raw_data)
        decrypt_data = cipher.decrypt(encrypt_data)
        self.assertEqual(self.raw_data, decrypt_data)
        self.assertNotIn(SPLIT_BYTES, encrypt_data)

    def testAES192GCMCipher(self):
        cipher = AES192GCMCipher(password=self.password)
        encrypt_data = cipher.encrypt(self.raw_data)
        decrypt_data = cipher.decrypt(encrypt_data)
        self.assertEqual(self.raw_data, decrypt_data)
        self.assertNotIn(SPLIT_BYTES, encrypt_data)

    def testAES128GCMCipher(self):
        cipher = AES128GCMCipher(password=self.password)
        encrypt_data = cipher.encrypt(self.raw_data)
        decrypt_data = cipher.decrypt(encrypt_data)
        self.assertEqual(self.raw_data, decrypt_data)
        self.assertNotIn(SPLIT_BYTES, encrypt_data)

    def testAES256CFBCipher(self):
        cipher = AES256CFBCipher(password=self.password)
        encrypt_data = cipher.encrypt(self.raw_data)
        decrypt_data = cipher.decrypt(encrypt_data)
        self.assertEqual(self.raw_data, decrypt_data)
        self.assertNotIn(SPLIT_BYTES, encrypt_data)

    def testAES192CFBCipher(self):
        cipher = AES192CFBCipher(password=self.password)
        encrypt_data = cipher.encrypt(self.raw_data)
        decrypt_data = cipher.decrypt(encrypt_data)
        self.assertEqual(self.raw_data, decrypt_data)
        self.assertNotIn(SPLIT_BYTES, encrypt_data)

    def testAES128CFBCipher(self):
        cipher = AES128GCMCipher(password=self.password)
        encrypt_data = cipher.encrypt(self.raw_data)
        decrypt_data = cipher.decrypt(encrypt_data)
        self.assertEqual(self.raw_data, decrypt_data)
        self.assertNotIn(SPLIT_BYTES, encrypt_data)

    def testSalsa20Cipher(self):
        cipher = Salsa20Cipher(password=self.password)
        encrypt_data = cipher.encrypt(self.raw_data)
        decrypt_data = cipher.decrypt(encrypt_data)
        self.assertEqual(self.raw_data, decrypt_data)
        self.assertNotIn(SPLIT_BYTES, encrypt_data)

    def testChaCha20Cipher(self):
        cipher = ChaCha20Cipher(password=self.password)
        encrypt_data = cipher.encrypt(self.raw_data)
        decrypt_data = cipher.decrypt(encrypt_data)
        self.assertEqual(self.raw_data, decrypt_data)
        self.assertNotIn(SPLIT_BYTES, encrypt_data)

    def testRC4MD5Cipher(self):
        cipher = RC4MD5Cipher(password=self.password)
        encrypt_data = cipher.encrypt(self.raw_data)
        decrypt_data = cipher.decrypt(encrypt_data)
        self.assertEqual(self.raw_data, decrypt_data)
        self.assertNotIn(SPLIT_BYTES, encrypt_data)


if __name__ == '__main__':
    unittest.main()
