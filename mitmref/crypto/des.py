# COMP90043 Cryptography and Security 2015
# Data Encryption Standard Implementation
# 
# Authored by Renlord Y. 
# Commissioned by Udaya P.

# TEST
# Plaintext: 0x02468aceeca86420
# Ciphertext: 0xda02ce3a89ecac3b
# Key: 0x0f1571c947d9e859

DEBUG = False

class DES:
    # Initial Permutations
    DES_IP = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7]

    DES_FP = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25]

    # Substituition Boxes
    DES_S1 = [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7], [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8], [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0], [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]]

    DES_S2 = [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10], [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5], [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15], [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]]

    DES_S3 = [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8], [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1], [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7], [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]]

    DES_S4 = [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15], [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9], [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4], [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]]

    DES_S5 = [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9], [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6], [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14], [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]]

    DES_S6 = [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11], [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8], [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6], [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]]

    DES_S7 = [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1], [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6], [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2], [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]]

    DES_S8 =[[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7], [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2], [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8], [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]

    DES_S = [DES_S1, DES_S2, DES_S3, DES_S4, DES_S5, DES_S6, DES_S7, DES_S8]

    # Expansion Function (E)
    DES_E = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]

    # Permuted Choice 1
    DES_PC_1_LEFT = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36]
    DES_PC_1_RIGHT = [63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4]

    # Permuted Choice 2 
    DES_PC_2 = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32]

    # Number of Left Shifts
    DES_KS_LS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

    # Half Block Permutation
    DES_P = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25]

    def __init__(self, key):
        key = msb(key, 64)
        self.key = key
        self.key_schedule_list = self.key_schedule()

    def cipher_function(self, r, k):
        """
            The DES Cipher Function
            
            INPUTS:
                r, Integer or Long (32bit)
                k, Int or Long (48bit)
            OUTPUT:
                Integer or Long (32bit)
        """
        assert(type(r) == type(1) or type(r) == type(1L))
        assert(type(k) == type(1) or type(k) == type(1L))

        expanded_r = 0 # 48bit
        for i in range(0, 48):
            expanded_r = bits.set_bit(expanded_r, i+1, bits.get_bit(r, self.DES_E[i], 32), 48)

        output = expanded_r ^ k # 48bit in size

        # Substitution Boxes
        chunks = [] # Each chunk is 6 bits
        for i in range(0, 8):
            chunks.append(bits.get_bits(output, i * 6 + 1, (i + 1) * 6, 48, 6))

        chunk_row = lambda chunk: (bits.get_bit(chunk, 1, 6) << 1) + bits.get_bit(chunk, 6, 6) # 2 Bit Integer

        chunk_col = lambda chunk: bits.get_bits(chunk, 2, 5, 6, 4) # 4 Bit Integer

        substitute_chunk = lambda chunk, box: \
            box[chunk_row(chunk)][chunk_col(chunk)]

        output = 0 # 32bit
        for i in range(0, 8):
            output += substitute_chunk(chunks[i], self.DES_S[i]) << ((7 - i) * 4)

        final_output = 0 #32bit
        for i in range(0, 32):
            final_output = bits.set_bit(final_output, i+1, bits.get_bit(output, self.DES_P[i], 32), 32)

        return final_output

    def key_schedule(self):
        """
        Key Schedule Generation. WARNING: K_{1} ... K_{16}!! 
        Do not ask for K_{0}
        INPUT:
            key, INTEGER or LONG 64 Bits
        OUTPUT:
            [key], LIST of Integer or LONG 48 Bits
        """
        assert(type(self.key) == type(1L) or type(self.key) == type(1))
        error_correction = 0
        keyC = 0 # 28 Bits
        keyD = 0 # 28 Bits

        key_schedule_list = []

        counter = 1
        for i in range(7, 64, 8):
            error_correction = bits.set_bit(error_correction, counter, bits.get_bit(self.key, i, 64), 8)
            counter += 1

        for i in range(0, 28):
            keyC = bits.set_bit(keyC, i+1, bits.get_bit(self.key, self.DES_PC_1_LEFT[i], 64), 28)
            keyD = bits.set_bit(keyD, i+1, bits.get_bit(self.key, self.DES_PC_1_RIGHT[i], 64), 28)

        for i in range(0, 16):
            keyC = bits.rol(keyC, self.DES_KS_LS[i], 28)
            keyD = bits.rol(keyD, self.DES_KS_LS[i], 28)
            temp_key = (keyC << 28) + keyD # 56bits
            key_i = 0 # 48 bits
            for i in range(0, 48):
                key_i = bits.set_bit(key_i, i+1, bits.get_bit(temp_key, self.DES_PC_2[i], 56), 48)
            key_schedule_list.append(key_i)

        assert(len(key_schedule_list) == 16)
        return key_schedule_list

    # INPUT takes a 64 bit block. OUTPUTs a 64 bit block of cipher text.
    def crypt(self, input_block, encrypt_mode):
        """
        DES Encrypt 
        INPUT:
            input_block, Int or Long (64bit)
            encrypt_mode, Bool (True = Encrypt Mode; False = Decrypt Mode)
        OUTPUT:
            output_block, Int or Long (64bit)
        """
        assert(type(input_block) == type(1) or type(input_block) == type(1L))
        assert(type(self.key) == type(1) or type(self.key) == type(1L))
        assert(type(encrypt_mode) == type(True))

        permuted_block = 0
        # Initial Permutation
        for i in range(0, 64):
            permuted_block = bits.set_bit(permuted_block, i+1, bits.get_bit(input_block, self.DES_IP[i], 64), 64)

        if DEBUG is True:
            print("Permuted: {0}".format(hex(permuted_block)))

        # Permuted Input L and R
        left_block = bits.get_bits(permuted_block, 1, 32, 64, 32) # 32bits
        right_block = bits.get_bits(permuted_block, 33, 64, 64, 32) # 32bits

        if DEBUG is True:
            print("Permuted L: {0} | Permuted R: {1}".format(hex(left_block), hex(right_block)))

        # Fiestal Rounds
        for i in range(0, 16):
            temp_left = left_block
            left_block = right_block # 32bits, temporary holder
            if encrypt_mode is True:
                right_block = temp_left ^ self.cipher_function(right_block, self.key_schedule_list[i])
            else:
                right_block = temp_left ^ self.cipher_function(right_block, self.key_schedule_list[15-i])

        # Preoutput Block R'L'
        preoutput_block = (right_block << 32) + left_block # 64bits

        # Inverse Initial Permutation
        output_block = 0
        for i in range(0, 64):
            output_block = bits.set_bit(output_block, i+1, bits.get_bit(preoutput_block, self.DES_FP[i], 64), 64)    

        return output_block

    def encrypt(self, input_block):
        return self.crypt(input_block, True)

    def decrypt(self, input_block):
        return self.crypt(input_block, False)

