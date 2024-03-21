import os
import sys
from encryption import Encryption, Decryption
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Function to encrypt a directory recursively
def encrypt_directory(directory, key):
    for root, _, files in os.walk(directory):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            if not file_path.endswith(".enc"):
                with open(file_path, "rb") as f:
                    data = f.read()
                
                cipher = AES.new(key, AES.MODE_EAX)
                ciphertext, tag = cipher.encrypt_and_digest(data)

                encrypted_file_path = file_path + ".enc"
                with open(encrypted_file_path, "wb") as f:
                    [f.write(x) for x in (cipher.nonce, tag, ciphertext)]

# Function to decrypt a directory recursively
def decrypt_directory(directory, key):
    for root, _, files in os.walk(directory):
        for file_name in files:
            if file_name.endswith(".enc"):
                encrypted_file_path = os.path.join(root,file_name)
                
                with open(encrypted_file_path,"rb") as f:
                    nonce ,tag ,ciphertext =[f.read(x)for x  in (16 ,16 ,-1)]
                    
                    cipher=AES.new(key,AES.MODE_EAX,nounce=nonce)
                    
                    data=cipher.decrypt_and_verify(ciphertext ,tag )
                    
                    decrypted_file=file_name[:-4]
                    
                    decrypted_file=os.path.join(root ,decrypted_file )
                    
                     with open(decryptedfile ,"wb")as f :
                        f.write(data)

# Update the menu interface to include options for directory encryption/decryption

print("Menu:")
print("1. Encrypt File")
print("2. Decrypt File")
print("3. Encrypt Directory")
print("4. Decrypt Directory")

choice = input("Enter your choice: ")

if choice == "3":
    directory_to_encrypt = input("Enter the path of the directory to encrypt: ")
    key=get_random_bytes(16)
    
    # Encrypt the directory using randomly generated key
    encrypt_directory(directory_to_encrypt,key)

elif choice == "4":
    directory_to_decrypt=input ("Enterthe path ofthedirectorytodecrypt :")
    
     #Decryptthedirectoryusingthekey
    
     decryptdirectory (directorytodecrypt,key )



def generate_random_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    return pem

# Generate a random key for encryption and decryption
random_key = generate_random_key()

# Use the random key for encryption and decryption operations
# Add your encryption and decryption logic here using the random key

print("Random Key Generated Successfully!")


def generate_key(length):
    """Generate a random key of the specified length."""
    try:
        key = os.urandom(length)
    except ValueError:
        raise ValueError("Invalid key length.")
    return key

def read_key_file(name):
    """Read a key from a file."""
    try:
        with open(name, "rb") as f:
            key = f.read()
    except FileNotFoundError:
        raise FileNotFoundError("Key file not found.")
    return key

def write_key_file(name, key):
    """Write a key to a file."""
    try:
        with open(name, "wb") as f:
            f.write(key)
    except FileNotFoundError:
        raise FileNotFoundError("Key file not found.")

def encrypt(text, key):
    """Encrypt the given text using the given key."""
    enc = Encryption(key)
    return enc.encrypt(text)

def decrypt(text, key):
    """Decrypt the given text using the given key."""
    dec = Decryption(key)
    return dec.decrypt(text)

def read_file(name):
    """Read the contents of a file."""
    try:
        with open(name, "rb") as f:
            data = f.read()
    except FileNotFoundError:
        raise FileNotFoundError("Input file not found.")
    return data

def write_file(name, data):
    """Write the given data to a file."""
    try:
        with open(name, "wb") as f:
            f.write(data)
    except FileNotFoundError:
        raise FileNotFoundError("Output file not found.")

def show_menu():
    """Display the menu options."""
    print("1. Encrypt a file")
    print("2. Decrypt a file")
    print("3. Generate a key")
    print("4. Quit")

def process_option(option):
    """Process the selected option."""
    if option == "1":
        input_file = input("Enter the name of the file to encrypt: ")
        output_file = input("Enter the name of the output file: ")
        key_file = input("Enter the name of the key file: ")
        try:
            key = read_key_file(key_file)
            data = read_file(input_file)
            encrypted_data = encrypt(data, key)
            write_file(output_file, encrypted_data)
        except Exception as e:
            print(f"Error: {e}")
    elif option == "2":
        input_file = input("Enter the name of the file to decrypt: ")
        output_file = input("Enter the name of the output file: ")
        key_file = input("Enter the name of the key file: ")
        try:
            key = read_key_file(key_file)
            data = read_file(input_file)
            decrypted_data = decrypt(data, key)
            write_file(output_file, decrypted_data)
        except Exception as e:
            print(f"Error: {e}")
    elif option == "3":
        length = int(input("Enter the length of the key to generate: "))
        try:
            key = generate_key(length)
            key_file = input("Enter the name of the file to save the key: ")
            write_key_file(key_file, key)
        except Exception as e:
            print(f"Error: {e}")
    elif option == "4":
        raise SystemExit
    else:
        print("Invalid option. Please enter a number between 1 and 4.")

def main():
    """Main function."""
    while True:
        try:
            show_menu()
            option = input("Enter your choice: ")
            process_option(option)
        except SystemExit:
            break

if __name__ == "__main__":
    main()