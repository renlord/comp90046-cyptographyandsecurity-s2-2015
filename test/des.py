import unittest
import random

import reference.crypto.des as candidate
import reference.crypto.des as reference

from timeout import timeout

class TestDESMethods(unittest.TestCase):

	def setUp(self):
		random_dh_key = random.getrandbits(2048)
		self.candidate = candidate.DESCipher(random_dh_key)
		self.reference = reference.DESCipher(random_dh_key)

	@timeout(5)
	def test_cipher_function(self):
		r = random.getrandbits(32)
		k = random.getrandbits(48)
		err = "FAILED: DES Cipher Function"
		self.assertEqual(self.candidate.cipher_function(r, k), self.reference.cipher_function(r, k), err)
		self.assertEqual(self.candidate.cipher_function(long(r), long(k)), self.reference.cipher_function(long(r), long(k)), err)

	@timeout(5)
	def test_key_schedule(self):
		candidate_schedule = self.candidate.key_schedule()
		reference_schedule = self.reference.key_schedule()
		err = "FAILED: DES Key Schedule. Some random key found in Candidate key schedule"
		self.assertTrue(len(list(set(candidate_schedule) ^ set(reference_schedule))) == 0, err)

	@timeout(5)
	def test_encrypt(self):
		input_block = random.getrandbits(64)
		err = "FAILED: DES Encryption. Candidate encrypted input block incorrectly. Cipher Text does not match Reference"
		self.assertEqual(self.candidate.encrypt(input_block), self.reference.encrypt(input_block), err)


	@timeout(5)
	def test_decrypt(self):
		input_block = random.getrandbits(64)
		err = "FAILED: DES Decryption. Candidate decrypted input block incorrectly. Plain Text does not match Reference"
		self.assertEqual(self.candidate.decrypt(input_block), self.reference.decrypt(input_block), err)


