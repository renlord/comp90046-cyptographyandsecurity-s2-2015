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

import cryptoclient.crypto.supplementary as auxillary

from base64 import b64encode, b64decode 

# ============== ADD HELPER FUNCTIONS HERE =========================


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

        self.a =  0 # Supplementary Key A for Stream Cipher
        self.b = 0 # Supplementary Key B for Stream Cipher
        self.r_i = 0 # Shift Register 
        # ======== END IMPLEMENTATION ===============

    # =============== ADD CLASS ADDITIONAL METHODS ==================
    
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

        # ======== END IMPLEMENTATION ===============
        return None

    # =============== ADD CLASS ADDITIONAL METHODS ==================
  
    # =============== END CLASS ADDTIONAL METHODS ===================

# ============== ADD HELPER FUNCTIONS HERE =========================

# ============== END HELPER FUNCTIONS ==============================
