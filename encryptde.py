from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# Encryption function
def encrypt_content(plain_text_bytes, key_bytes):
    cipher = AES.new(key_bytes, AES.MODE_CBC)
    padded_data = pad(plain_text_bytes, AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return cipher.iv + encrypted_data

# Decryption function
def decrypt_content(encrypted_data_bytes, key_bytes):
    iv = encrypted_data_bytes[:16]
    encrypted_data = encrypted_data_bytes[16:]
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    padded_data = cipher.decrypt(encrypted_data)
    plain_text = unpad(padded_data, AES.block_size)
    return plain_text

def main():
    key = get_random_bytes(16)

    # Read original content
    with open("example.txt", "rb") as f:
        original_content = f.read()

    print("Original content:\n", original_content.decode())

    # Encrypt the content
    encrypted_content = encrypt_content(original_content, key)
    print("\nEncrypted content (hex):\n", encrypted_content.hex())

    # Decrypt the content
    decrypted_content = decrypt_content(encrypted_content, key)
    print("\nDecrypted content:\n", decrypted_content.decode())

    # Write to encrypted and decrypted files
    with open("example_encrypted.bin", "wb") as f:
        f.write(encrypted_content)

    with open("example_decrypted.txt", "wb") as f:
        f.write(decrypted_content)

if __name__ == "__main__":
    main()
