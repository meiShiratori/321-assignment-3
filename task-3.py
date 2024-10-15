from Crypto.Util import number
import math
import random
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad,unpad
from hashlib import sha256
from Crypto.PublicKey import RSA

def mod_inverse(a, m):
    def egcd(a, b):
        if a == 0:
            return b, 0, 1
        else:
            g, y, x = egcd(b % a, a)
            return g, x - (b // a) * y, y
    g, x, _ = egcd(m, a)

    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

def generate_key_pair(bits):
    keyP = RSA.generate(bits).n#secret
    keyQ = RSA.generate(bits).n#secret
    n = keyQ * keyP#secret
    phiOfn = (keyP-1)*(keyQ-1)#public
    e = 65537
    d = mod_inverse(e, phiOfn)
    return (n,e),(n,d)

if __name__ == "__main__":

     message = "a ".encode('utf-8')
     message_bits = int(message.hex(), 8)
     n, e = generate_key_pair(message_bits)
     print(n, e)