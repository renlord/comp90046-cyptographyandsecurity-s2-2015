# COMP90043 Cryptography and Security
# Diffie Hellman Key Exchange Skeleton
#
# Instructions to candidates:
# 	Copy and paste your implementations from Part A1 of the project into this 
# 	component. 

import random

# TODO
def diffie_hellman_private(numbits):
	return random.getrandbits(numbits)

# TODO
def diffie_hellman_pair(generator, modulus, private):
    public = modexp(generator, private, modulus)
    return (private, public)

# TODO 
def diffie_hellman_shared(private, public, modulus):
    shared_key = modexp(public, private, modulus)
    return shared_key

# TODO
def modexp(base, exponent, modulo):
    return pow(base, exponent, modulo)
