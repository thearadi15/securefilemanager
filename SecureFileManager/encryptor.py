from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import os

def encrypt_file(file_path, password):
    key = hashlib.sha256(password.encode()).digest()
    cipher = AES.new(key, AES.MODE_CBC)
    with open(file_path, 'rb') as f:
        plaintext = f.read()
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

    encrypted_file_path = file_path + ".enc"
    with open(encrypted_file_path, 'wb') as f:
        f.write(cipher.iv + ciphertext)
    
    return encrypted_file_path

def decrypt_file(file_path, password):
    key = hashlib.sha256(password.encode()).digest()
    with open(file_path, 'rb') as f:
        iv = f.read(16)
        ciphertext = f.read()

    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

    decrypted_file_path = file_path.replace(".enc", "")
    with open(decrypted_file_path, 'wb') as f:
        f.write(plaintext)

    return decrypted_file_path
