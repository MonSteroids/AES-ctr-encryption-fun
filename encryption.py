from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import os

keyfile_path = 'mykey.key'

def generate_key():
    """Generate and save new AES-256 key."""



def load_key():
    """Load AES key from key file."""

    

def check_for_key():
    """Check if key exists"""



def encryption(file_name):
    """Encrypt the content of the given file."""



def decryption(file_name):
    """Decrypt the contents of the given file."""



def encrypt_or_decrypt():
    """Prompt to choose"""



def main():
    check_for_key()
    encrypt_or_decrypt()

if __name__ == '__main__':
    main()