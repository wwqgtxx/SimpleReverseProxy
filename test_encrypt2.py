#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# author wwqgtxx <wwqgtxx@gmail.com>
from __future__ import (absolute_import, division,
                        print_function, unicode_literals)
import unittest
from SimpleReverseProxy.encrypt0 import *
from SimpleReverseProxy.encrypt2 import *


class Test(unittest.TestCase):
    def setUp(self):
        self.password = os.urandom(20)
        self.wrong_password = os.urandom(20)
        self.raw_data = os.urandom(20000000)

    def tearDown(self):
        pass

    def testAES256GCMCipher(self):
        cipher = AES256GCMCipher(password=self.password, saved_iv=False)
        encrypt_data = cipher.encrypt(self.raw_data)
        decrypt_data = cipher.decrypt(encrypt_data)
        self.assertEqual(self.raw_data, decrypt_data)
        self.assertNotIn(SPLIT_BYTES, encrypt_data)

    def testAES192GCMCipher(self):
        cipher = AES192GCMCipher(password=self.password, saved_iv=False)
        encrypt_data = cipher.encrypt(self.raw_data)
        decrypt_data = cipher.decrypt(encrypt_data)
        self.assertEqual(self.raw_data, decrypt_data)
        self.assertNotIn(SPLIT_BYTES, encrypt_data)

    def testAES128GCMCipher(self):
        cipher = AES128GCMCipher(password=self.password, saved_iv=False)
        encrypt_data = cipher.encrypt(self.raw_data)
        decrypt_data = cipher.decrypt(encrypt_data)
        self.assertEqual(self.raw_data, decrypt_data)
        self.assertNotIn(SPLIT_BYTES, encrypt_data)

    def testAES256GCMCipherWithWrongPassword(self):
        cipher = AES256GCMCipher(password=self.password, saved_iv=False)
        encrypt_data = cipher.encrypt(self.raw_data)
        cipher = AES256GCMCipher(password=self.wrong_password, saved_iv=False)
        decrypt_data = cipher.decrypt(encrypt_data)
        self.assertEqual(b'', decrypt_data)

    def testAES192GCMCipherWithWrongPassword(self):
        cipher = AES192GCMCipher(password=self.password, saved_iv=False)
        encrypt_data = cipher.encrypt(self.raw_data)
        cipher = AES192GCMCipher(password=self.wrong_password, saved_iv=False)
        decrypt_data = cipher.decrypt(encrypt_data)
        self.assertEqual(b'', decrypt_data)

    def testAES128GCMCipherWithWrongPassword(self):
        cipher = AES128GCMCipher(password=self.password, saved_iv=False)
        encrypt_data = cipher.encrypt(self.raw_data)
        cipher = AES128GCMCipher(password=self.wrong_password, saved_iv=False)
        decrypt_data = cipher.decrypt(encrypt_data)
        self.assertEqual(b'', decrypt_data)

    def testAES256CFBCipher(self):
        cipher = AES256CFBCipher(password=self.password, saved_iv=False)
        encrypt_data = cipher.encrypt(self.raw_data)
        decrypt_data = cipher.decrypt(encrypt_data)
        self.assertEqual(self.raw_data, decrypt_data)
        self.assertNotIn(SPLIT_BYTES, encrypt_data)

    def testAES192CFBCipher(self):
        cipher = AES192CFBCipher(password=self.password, saved_iv=False)
        encrypt_data = cipher.encrypt(self.raw_data)
        decrypt_data = cipher.decrypt(encrypt_data)
        self.assertEqual(self.raw_data, decrypt_data)
        self.assertNotIn(SPLIT_BYTES, encrypt_data)

    def testAES128CFBCipher(self):
        cipher = AES128CFBCipher(password=self.password, saved_iv=False)
        encrypt_data = cipher.encrypt(self.raw_data)
        decrypt_data = cipher.decrypt(encrypt_data)
        self.assertEqual(self.raw_data, decrypt_data)
        self.assertNotIn(SPLIT_BYTES, encrypt_data)

    def testAES256CFBCipherWithWrongPassword(self):
        cipher = AES256CFBCipher(password=self.password, saved_iv=False)
        encrypt_data = cipher.encrypt(self.raw_data)
        cipher = AES256CFBCipher(password=self.wrong_password, saved_iv=False)
        decrypt_data = cipher.decrypt(encrypt_data)
        self.assertNotEqual(self.raw_data, decrypt_data)

    def testAES192CFBCipherWithWrongPassword(self):
        cipher = AES192CFBCipher(password=self.password, saved_iv=False)
        encrypt_data = cipher.encrypt(self.raw_data)
        cipher = AES192CFBCipher(password=self.wrong_password, saved_iv=False)
        decrypt_data = cipher.decrypt(encrypt_data)
        self.assertNotEqual(self.raw_data, decrypt_data)

    def testAES128CFBCipherWithWrongPassword(self):
        cipher = AES128CFBCipher(password=self.password, saved_iv=False)
        encrypt_data = cipher.encrypt(self.raw_data)
        cipher = AES128CFBCipher(password=self.wrong_password, saved_iv=False)
        decrypt_data = cipher.decrypt(encrypt_data)
        self.assertNotEqual(self.raw_data, decrypt_data)

    def testRC4MD5Cipher(self):
        cipher = RC4MD5Cipher(password=self.password, saved_iv=False)
        encrypt_data = cipher.encrypt(self.raw_data)
        decrypt_data = cipher.decrypt(encrypt_data)
        self.assertEqual(self.raw_data, decrypt_data)
        self.assertNotIn(SPLIT_BYTES, encrypt_data)

    def testRC4MD5CipherWithWrongPassword(self):
        cipher = RC4MD5Cipher(password=self.password, saved_iv=False)
        encrypt_data = cipher.encrypt(self.raw_data)
        cipher = RC4MD5Cipher(password=self.wrong_password, saved_iv=False)
        decrypt_data = cipher.decrypt(encrypt_data)
        self.assertNotEqual(self.raw_data, decrypt_data)


if __name__ == '__main__':
    unittest.main()
