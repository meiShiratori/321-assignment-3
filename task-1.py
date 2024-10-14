import math
import random
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad,unpad
from hashlib import sha256


def generate_public_number():
    return random.randint(0, int(math.pow(2, 32)))

def generate_private_key(public_A, public_B, private_number):
    return math.pow(public_A, private_number) % public_B

def compute_shared_secret(Y, x, q):
    """Takes in a computed private key, a random element, and a public key and computes the shared secret."""
    return (Y ** x) % q
    

def derive_key(s):
    """Takes in a shared secret and returns the symmetric key."""
    return sha256(bytes(s)).digest()

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

    return  b''.join(encrypted_blocks)

def decrypt_message(blocks, aes_key):
    iv = encrypted[:16]
    encrypted_blocks = [encrypted[i:i + 16] for i in range(16, len(encrypted), 16)]

    decrypted_blocks = []
    cipher = AES.new(aes_key, AES.MODE_ECB)

    previous_block = iv
    for block in encrypted_blocks:
        dec_block = cipher.decrypt(block)
        xor_block = bytes(a ^ b for a, b in zip(dec_block, previous_block))
        decrypted_blocks.append(xor_block)
        previous_block = block

    decrypted_message = b''.join(decrypted_blocks).decode('utf-8')
    decrypted_message = decrypted_message.replace('%3B', ';').replace('%3D', '=')

    return decrypted_message

def diffie_hellman_protocol():
    return None

if __name__ == "__main__":
    print(compute_shared_secret(1, 2, 3))
    symmetric_key = derive_key(1)
    print(symmetric_key)

    message = f"hello world"
    
    encrypted = encrypt_message(message, symmetric_key, get_random_bytes(16))
    print(encrypted)
    decrypted = decrypt_message(encrypted, symmetric_key)
    print(decrypted)
    #print(b''.join(decrypted).decode('utf-8'))


    