from Crypto.Util import number


def egcd(a, b):
    if a == 0:
        return b, 0, 1
    else:
        g, y, x = egcd(b % a, a)
        return g, x - (b // a) * y, y


def mod_inverse(a, m):
    g, x, _ = egcd(a, m)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    else:
        return x % m


def generate_keypair(bits):
    p = number.getPrime(bits // 2)
    q = number.getPrime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = mod_inverse(e, phi)
    return (n, e), (n, d)


def encrypt(public_key, message):
    n, e = public_key
    return pow(message, e, n)


def decrypt(private_key, ciphertext):
    n, d = private_key
    return pow(ciphertext, d, n)


if __name__ == "__main__":
    public_key, private_key = generate_keypair(1024)
    n, e = public_key

    s = number.getRandomRange(2, n - 1)

    c = pow(s, e, n)
    print(f"Original ciphertext (c): {c}")

    factor = 2
    c_prime = (c * pow(factor, e, n)) % n
    print(f"Modified ciphertext (c'): {c_prime}")

    s_prime = pow(c_prime, private_key[1], n)
    print(f"Decrypted s' (s * factor): {s_prime}")

    s_mallory = (s_prime * mod_inverse(factor, n)) % n
    print(f"Recovered original s by Mallory: {s_mallory}")

    if s == s_mallory:
        print("Malleability attack successful")
    else:
        print("Malleability attack failed.")
