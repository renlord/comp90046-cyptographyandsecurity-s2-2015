# COMP90043 Cryptography and Security
# Auxillary Functions Skeleton
# 
# Instructions to candidates:
#	As usual, do not modify function declarations, you may add additional helper functions.
#
# Any enquiries, please email `renlordy[at]unimelb.edu.au`. This code is maintained by Renlord.


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
# ============== END HELPER FUNCTIONS ==============================

# TODO
def parityWordChecksum(key):
	assert(type(key) == type(1L))
	assert(key < (2 ** 2048))
	"""
	parityWordChecksum, takes a 2048 bit key and applies a word by word XOR to yield a 64 bit result at the end. 
	INPUT:
		key, 2048bit Integer from Part A1 Diffie Hellman Key Exchange
	OUTPUT:
		result, 64bit Integer
	"""
	result = 0
	# ======== IMPLEMENTATION GOES HERE =========
	for i in range(0, 2048, 64):
		result ^= get_bits(key, i+1, i+64, 2048, 64) 
	# ======== END IMPLEMENTATION ===============
	return result

# TODO
def deriveSupplementaryKey(key, p):
	assert(type(key) == type(1L))
	assert(type(p) == type(1))
	assert(key < (2 ** 2048))
	assert(p1 < (2 ** 64))
	"""
	deriveSupplementaryKeyA, takes a 2048 bit key and applies the modulo operation to yield the modulo of `p1`. 
	INPUT:
		key, 2048bit Integer from Part A1 Diffie Hellman Key Exchange
		p1, 64bit random prime number
	OUTPUT:
		keyA, 64bit Integer for use as `a` key for Stream Cipher
	"""
	# ======== IMPLEMENTATION GOES HERE =========
	subKey = key % p
	# ======== END IMPLEMENTATION ===============
	assert(type(subKey) == type(1) or type(subKey) == type(1L))
	return subKey


# ============== ADD HELPER FUNCTIONS HERE =========================

# ============== END HELPER FUNCTIONS ==============================