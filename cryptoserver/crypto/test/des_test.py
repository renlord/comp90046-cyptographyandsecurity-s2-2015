import unittest
import random

from timeout import timeout

import project.crypto.des as des

class TestDES(unittest.TestCase):
    def setUp(self):
        self.cipher = des.DES(random.getrandbits(64))

    @timeout(1)
    def test_small_integer(self):
        plainInt = 29
        cipherInt = self.cipher.encrypt(plainInt)
        self.assertEqual(self.cipher.decrypt(cipherInt), plainInt)

    def test_long_integer(self):
        

if __name__ == "__main__":
    unittest.main()