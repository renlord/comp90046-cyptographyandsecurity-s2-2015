import cryptoserver.util.bits

def parityWordChecksum(key):
    # Each word is 64 bits.
    checksum = 0
    for i in range(0, 2048, 64):
        checksum ^= cryptoserver.util.bits.get_bits(key, i+1, i+64, 2048, 64) 
    return checksum

def deriveSupplementaryKeyA(key, p1):
    return key % p1

def deriveSupplementaryKeyB(key, p2):
    return key % p2

"""
def deriveSupplementaryKeyA(key):
    key = project.util.bits.rol(key, 1024, 2048)
    return project.util.bits.msb(key, 16) ^ project.util.bits.lsb(key, 16)

def deriveSupplementaryKeyB(key):
    keyB = 0 
    for i in range(1, 2048, 2):
        keyB = project.util.bits.set_bit(keyB, i/2 + 1, project.util.bits.get_bit(key, i+1, 2048), 1024)
    return project.util.bits.msb(keyB, 64)
"""