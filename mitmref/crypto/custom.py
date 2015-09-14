import random

def decide_provide_Xc():
    random.seed()
    decision = random.randrange(1)
    if decision == 0:
        return False
    else:
        return True

def generate_private_key(p):
    random.seed()
    return random.getrandbits(2048)

def dh_compute_public(g, X, p):
    return pow(g, X, p)

def compute_dh_key(Y, X, p):
    return pow(Y, X, p)




