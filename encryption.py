from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import os

keyfile_path = 'mykey.key'

def check_for_key():
    """Check if key exists"""

    if os.path.exists(keyfile_path):
        print("Key exists.")
    else:
        generate_key()


def generate_key():
    """Generate and save new AES-256 key."""

    key = get_random_bytes(32)
    # Write key to file
    with open(keyfile_path, 'wb') as keyfile:
        keyfile.write(key)
    print("Key has been created.")


def load_key():
    """Load AES key from key file."""

    with open(keyfile_path, 'rb') as keyfile:
        key = keyfile.read()
    return key


def encryption(file_name):
    """Encrypt the content of the given file."""
    try:
        key = load_key()
        cipher = AES.new(key, AES.MODE_CTR)
        with open(file_name, 'rb') as file:
            data = file.read()

        encrypted_data = cipher.encrypt(pad(data, AES.block_size))

        with open(file_name, 'wb') as file:
            file.write(encrypted_data)
        print("File has been encrypted.")
    except FileNotFoundError:
        print("File was not found.")


def decryption(file_name):
    """Decrypt the contents of the given file."""

    try:
        key = load_key()
        decipher = AES.new(key, AES.MODE_CTR)
        with open(file_name, 'rb') as file:
            data = file.read()

        decrypted_text = decipher.decrypt(data)

        with open(file_name, 'wb') as file:
            file.write(decrypted_text)
        print("File has been decrypted.")
    except FileNotFoundError:
        print("File was not found.")


def encrypt_or_decrypt():
    """Prompt to choose"""

    choose = input("(1) Encrypt, (2) Decrypt: ")

    if choose == '1':
        file_name = input("Enter path to file you want to encrypt: ")
        encryption(file_name)
    elif choose == '2':
        file_name = input("Enter path to file you want to decrypt: ")
        decryption(file_name)
    else:
        print("Invalid input!")
        print("Please enter '1' or '2'.")


def main():
    check_for_key()
    encrypt_or_decrypt()

if __name__ == '__main__':
    main()