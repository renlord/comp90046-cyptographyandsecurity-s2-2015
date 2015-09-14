# COMP90043 Cryptography and Security
# Skeleton for Stream Cipher
# 
# Instructions to candidates:
#   - You may add additional helper functions prior to the declaration of the 
#   class. But I'd advise you to import it from a different file.
#   - Do not modify class declaraction, function declarations or method 
#   declarations.
#   - After you've implemented this, remember to write a few lines to comment
#   on the security of this cipher as specified in the Project Specifications

import reference.crypto.supplementary as auxillary

from base64 import b64encode, b64decode 

# ============== ADD HELPER FUNCTIONS HERE =========================
def get_bit(val, pos, max_bits):
    assert(pos <= max_bits)
    assert(type(max_bits) == type(1))

    return val >> (max_bits - pos) & 1

def set_bit(val, pos, bit, max_bits): 
    assert(pos <= max_bits)
    assert(bit == 1 or bit == 0)
    assert(type(max_bits) == type(1))

    if get_bit(val, pos, max_bits) == bit:
        pass
    else:
        val = val ^ (1 << max_bits - pos)
    return val

def get_bits(val, start_pos, end_pos, val_max_bits, new_max_bits):
    assert(start_pos < val_max_bits and end_pos <= val_max_bits)
    assert(type(val_max_bits) == type(1) and type(new_max_bits) == type(1))
    assert(start_pos < end_pos)
    assert(new_max_bits <= val_max_bits)

    n_bits = (end_pos - start_pos) + 1
    result = 0

    for i in range(0, n_bits):
        result = set_bit(result, i+1, get_bit(val, start_pos + i, val_max_bits), new_max_bits)

    return result

def msb(val, n):
    """
    msb, most significant bits 
    Gets N numbers of bits from the MOST SIGNIFICANT BIT (inclusive).
    """
    max_bits = 0
    if val < (2**n - 1):
        return val
    else:
        max_bits = n
        while(val > 2**max_bits - 1):
            max_bits += n
        bitLocation = 1
        while(get_bit(val, bitLocation, max_bits) != 1):
            bitLocation += 1
        return get_bits(val, bitLocation, (bitLocation + n - 1), max_bits, n)

# ============== END HELPER FUNCTIONS ==============================

class StreamCipher:
    # TODO
    def __init__(self, dh_key, dh_p, p1, p2):
        """
        __init__, constructor for StreamCipher class.
        INPUT:
            dh_key, 2048bit DH Key from Part A1
            p, DH Key Parameter, Prime Modulus
        OUTPUT:
            returns an instantiated StreamCipher object
        """
        # ======== IMPLEMENTATION GOES HERE =========
        self.dh_key = dh_key # 2048bit DH Key from Part A1
        self.p = dh_p # DH Key Parameter, Prime Modulus
        self.a =  auxillary.deriveSupplementaryKey(dh_key, p1)# Supplementary Key A for Stream Cipher
        self.b = auxillary.deriveSupplementaryKey(dh_key, p2) # Supplementary Key B for Stream Cipher
        self.r_i = None # Shift Register 
        # ======== END IMPLEMENTATION ===============

    # =============== ADD CLASS ADDITIONAL METHODS ==================
    def byteCrypt(self, b):
        self.updateShiftRegister()
        return chr(ord(b) ^ msb(self.r_i, 8));
    # =============== END CLASS ADDTIONAL METHODS ===================

    # TODO
    def updateShiftRegister(self):
        """
        updateShiftRegister, updates the shift register for XOR-ing the next 
        byte.
        INPUT:
            nothing
        OUTPUT:
            nothing
        """
        # ======== IMPLEMENTATION GOES HERE =========
        if self.r_i is None:
            self.r_i = auxillary.parityWordChecksum(self.dh_key)
        else:
            self.r_i = (self.a * self.r_i + self.b) % self.p
        # ======== END IMPLEMENTATION ===============
        return None

    # TODO
    def _crypt(self, msg):
        assert(type(msg) == type("hello"))
        """
        _crypt, takes a cipher text/plain text and decrypts/encrypts it.
        INPUT:
            msg, either Plain Text or Cipher Text.
        OUTPUT:
            new_msg, if PT, then output is CT and vice-versa.
        """
        # ======== IMPLEMENTATION GOES HERE =========
        new_msg = "";
        for char in msg:
            new_msg += self.byteCrypt(char);
        # ======== END IMPLEMENTATION ===============
        return new_msg

    # TODO
    def reset(self):
        """
        reset, resets the shift register back to its initial state.
        INPUT:
            nothing
        OUTPUT:
            nothing
        """
        # ======== IMPLEMENTATION GOES HERE =========
        self.r_i = None
        # ======== END IMPLEMENTATION ===============
        return None

    # =============== ADD CLASS ADDITIONAL METHODS ==================
    def encrypt(self, msg):
        return b64encode(self._crypt(msg))

    def decrypt(self, msg):
        return self._crypt(b64decode(msg))
    # =============== END CLASS ADDTIONAL METHODS ===================

# ============== ADD HELPER FUNCTIONS HERE =========================

# ============== END HELPER FUNCTIONS ==============================
