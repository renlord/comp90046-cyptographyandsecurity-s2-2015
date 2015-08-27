import cryptoserver.crypto.supplementary
import cryptoserver.util.bits

from base64 import b64encode, b64decode 

class CustomStream:
    def __init__(self, dh_key, p, p1, p2):
        self.dh_key = dh_key
        self.p = p
        self.a = cryptoserver.crypto.supplementary.deriveSupplementaryKeyA(dh_key, p1)
        self.b = cryptoserver.crypto.supplementary.deriveSupplementaryKeyB(dh_key, p2)
        self.r_i = None

    def updateShiftRegister(self):
        if self.r_i is None:
            self.r_i = cryptoserver.crypto.supplementary.parityWordChecksum(self.dh_key)
        else:
            self.r_i = (self.a * self.r_i + self.b) % self.p
        return None

    def byteCrypt(self, b):
        self.updateShiftRegister()
        return chr(ord(b) ^ cryptoserver.util.bits.msb(self.r_i, 8));

    def _crypt(self, msg):
        new_msg = "";
        for char in msg:
            new_msg += self.byteCrypt(char);
        return new_msg;

    def encrypt(self, msg):
        return b64encode(self._crypt(msg))

    def decrypt(self, msg):
        return self._crypt(b64decode(msg))

    def reset(self):
        self.r_i = None
        return None