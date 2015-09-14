def rol(val, r_bits, max_bits=28):
    return (val << r_bits%max_bits) & (2**max_bits-1) | ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))

def ror(val, r_bits, max_bits=28):
    return ((val & (2**max_bits-1)) >> r_bits%max_bits) | (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))

def get_bit(val, pos, max_bits):
    assert(pos <= max_bits)
    assert(type(max_bits) == type(1))

    return val >> (max_bits - pos) & 1

# Position is counted from LEFT to RIGHT. Ie... Bit 1 is LEFT MOST bit, while Bit N is RIGHT MOST bit.
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

def lsb(val, n):
    max_bits = n
    while(val > 2**max_bits - 1):
        max_bits += n
    return get_bits(val, (max_bits - n + 1), max_bits, max_bits, n)

def tobits(s):
    bs = ""
    for c in s:
        c_bin = bin(ord(c))[2:]
        c_bin_length = len(c_bin)
        c_bin_padding_required = 8 - c_bin_length 
        for i in range(0, c_bin_padding_required):
            c_bin = '0' + c_bin
        bs += c_bin
    return bs


# bs MUST BE 'utf-8' encoded ie... special characters represented as `\xff` 
def tostr(bs):
    if len(bs) > 8:
        return chr(int(bs[0:8], 2)) + tostr(bs[8:])
    else:
        return chr(int(bs[0:8], 2))

