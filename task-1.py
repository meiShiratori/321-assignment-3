
import math
import random
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad,unpad
from hashlib import sha256


def generate_public_number():
    return random.randint(0, int(math.pow(2, 32)))

def generate_private_key(q, a, X):
    return math.pow(a, X) % q

def compute_shared_secret(Y, X, q):
    """Takes in a computed private key, a random element, and a public key and computes the shared secret."""
    return (Y ** X) % q

def derive_key(s):
    """Takes in a shared secret and returns the symmetric key."""
    return sha256(bytes(s)).digest()[:16]

def encrypt_message(message, aes_key, iv):
    data_bytes = message.encode('utf-8')
    data_blocks = [data_bytes[i:i + 16] for i in range(0, len(data_bytes), 16)]

    encrypted_blocks = []
    cipher = AES.new(aes_key, AES.MODE_ECB)

    previous_block = iv
    for i, block in enumerate(data_blocks):
        if i == len(data_blocks) - 1:
            block = pad(block, 16)
        xor_block = bytes(a ^ b for a, b in zip(block, previous_block))
        enc_block = cipher.encrypt(xor_block)
        encrypted_blocks.append(enc_block)
        previous_block = enc_block

    return  iv + b''.join(encrypted_blocks)

def decrypt_message(encrypted, aes_key):
    iv = encrypted[:16]
    encrypted_blocks = [encrypted[i:i + 16] for i in range(16, len(encrypted), 16)]

    decrypted_blocks = []
    cipher = AES.new(aes_key, AES.MODE_ECB)

    previous_block = iv
    for block in encrypted_blocks:
        dec_block = cipher.decrypt(block)
        xor_block = bytes(a ^ b for a, b in zip(dec_block, previous_block))
        decrypted_blocks.append(unpad(xor_block, 16))
        previous_block = block

    decrypted_message = b''.join(decrypted_blocks).decode('utf-8')
    return decrypted_message

def diffie_hellman_protocol():
    hex_string1 = "B10B8F96A"
    hex_string2 = "A4D1CBD5"
    q = int(hex_string1, 16)
    a = int(hex_string2, 16)
    print(f"Public Keys: q = {q}, a = {a}\n")
    
    Xa = 4
    Xb = 3
    print(f"Alice selected random element a = {Xa}")
    print(f"Bob selected a random element b = {Xb}\n")

    Ya = generate_private_key(q, a, Xa)
    Yb = generate_private_key(q, a, Xb)
    print(f"Alice computes private key Ya = {Ya}")
    print(f"Bob computes private key Yb = {Yb}\n")
    print()

    Sa = compute_shared_secret(Yb, Xa, q)
    Sb = compute_shared_secret(Ya, Xb, q)
    print(f"Alice computes shared secret Sa = {Sa}")
    print(f"Bob computes shared secret Sb  = {Sb}")
    print(f"Shared secret is the same:  {Sa == Sb}\n")

    
    symmetric_key_a = derive_key(int(Sa))
    symmetric_key_b = derive_key(int(Sb))
    print(f"Alice derives symmetric key k = {symmetric_key_a}")
    print(f"Bob derives symmetric key k = {symmetric_key_b}")
    
    #print(f"Shared secret is the same:  {Sa == Sb}\n")

    message = "some test data"
    iv = get_random_bytes(16)
    encrypted_message = encrypt_message(message, symmetric_key_a, iv)
    print("encrypted_message: ", encrypted_message)
    decrypted_message = decrypt_message(encrypted_message, symmetric_key_b)
    print("decrypted message: " + decrypted_message)
    
    

if __name__ == "__main__":
     diffie_hellman_protocol()

    


    