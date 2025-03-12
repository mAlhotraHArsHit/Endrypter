from Crypto.Cipher import DES, AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
import hashlib
import os

def encrypt():
    print("Choose Encryption Algorithm")
    print("(1) Base64")
    print("(2) Caesar Cipher")
    print("(3) Monoalphabetic Substitution Cipher")
    print("(4) Vignere Cipher")
    print("(5) DES")
    print("(6) AES")
    print("(7) RSA")
    opt = int(input())
    cipher = b""

    if opt == 1:
        # Base64 encryption logic
        pass

    elif opt == 2:
        # Caesar Cipher encryption logic
        pass

    elif opt == 3:
        # Monoalphabetic Substitution Cipher encryption logic
        pass

    elif opt == 4:
        # Vignere Cipher encryption logic
        pass

    elif opt == 5:
        # DES encryption logic
        pass

    elif opt == 6:
        # AES encryption
        print("Do you want to encrypt a string or a file?")
        print("(1) String")
        print("(2) File")
        choice = int(input())

        if choice == 1:
            s = input("Enter the string to encrypt: ")
            data = s.encode('utf-8')
        elif choice == 2:
            file_path = input("Enter the path to the file to encrypt: ")
            if not os.path.exists(file_path):
                print("Error: File not found.")
                return "FILE NOT FOUND"
            with open(file_path, "rb") as f:
                data = f.read()
        else:
            print("Invalid choice.")
            return "INVALID CHOICE"

        key_choice = input("Do you want to generate a new key or use an existing one? (new/existing): ").strip().lower()

        if key_choice == "new":
            key = get_random_bytes(16)  # 16 bytes for AES-128
            key_file = "aes_key.key"
            with open(key_file, "wb") as f:
                f.write(key)
            print(f"New AES key generated and saved to '{key_file}'.")
        elif key_choice == "existing":
            key_file = input("Enter the name of the existing AES key file (e.g., aes_key.key): ")
            if not os.path.exists(key_file):
                print("Error: Key file not found.")
                return "KEY FILE NOT FOUND"
            with open(key_file, "rb") as f:
                key = f.read()
        else:
            print("Invalid choice. Please enter 'new' or 'existing'.")
            return "INVALID CHOICE"

        # Validate key length
        if len(key) not in [16, 24, 32]:
            print("Error: Invalid key length. AES key must be 16, 24, or 32 bytes long.")
            return "INVALID KEY LENGTH"

        # Encrypt the data
        aes_cipher = AES.new(key, AES.MODE_ECB)
        padded_data = pad(data, AES.block_size)
        cipher = aes_cipher.encrypt(padded_data)

        # Save ciphertext to a file
        if choice == 1:
            cipher_file = "ciphertext_aes.bin"
        else:
            cipher_file = os.path.basename(file_path) + ".enc"

        with open(cipher_file, "wb") as f:
            f.write(cipher)

        print(f"Encryption complete. Ciphertext saved to '{cipher_file}' in the current directory.")
        return "ENCRYPTION SUCCESSFUL"

    elif opt == 7:
        # RSA encryption
        print("Do you want to encrypt a string or a file?")
        print("(1) String")
        print("(2) File")
        choice = int(input())

        if choice == 1:
            s = input("Enter the string to encrypt: ")
            data = s.encode('utf-8')
        elif choice == 2:
            file_path = input("Enter the path to the file to encrypt: ")
            if not os.path.exists(file_path):
                print("Error: File not found.")
                return "FILE NOT FOUND"
            with open(file_path, "rb") as f:
                data = f.read()
        else:
            print("Invalid choice.")
            return "INVALID CHOICE"

        key_choice = input("Do you want to generate a new key pair or use an existing one? (new/existing): ").strip().lower()

        if key_choice == "new":
            key = RSA.generate(2048)
            private_key = key.export_key()
            public_key = key.publickey().export_key()

            with open("private_rsa.pem", "wb") as f:
                f.write(private_key)
            with open("public_rsa.pem", "wb") as f:
                f.write(public_key)

            print("New RSA key pair generated and saved to 'private_rsa.pem' and 'public_rsa.pem'.")
            public_key_file = "public_rsa.pem"
        elif key_choice == "existing":
            public_key_file = input("Enter the name of the existing RSA public key file (e.g., public_rsa.pem): ")
            if not os.path.exists(public_key_file):
                print("Error: Public key file not found.")
                return "KEY FILE NOT FOUND"
        else:
            print("Invalid choice. Please enter 'new' or 'existing'.")
            return "INVALID CHOICE"

        with open(public_key_file, "rb") as f:
            public_key = RSA.import_key(f.read())

        # Encrypt with public key
        rsa_cipher = PKCS1_OAEP.new(public_key)
        chunk_size = 190  # RSA can encrypt only small chunks
        encrypted_chunks = []

        for i in range(0, len(data), chunk_size):
            chunk = data[i:i + chunk_size]
            encrypted_chunks.append(rsa_cipher.encrypt(chunk))

        cipher = b"".join(encrypted_chunks)

        # Save ciphertext to a file
        if choice == 1:
            cipher_file = "ciphertext_rsa.bin"
        else:
            cipher_file = os.path.basename(file_path) + ".enc"

        with open(cipher_file, "wb") as f:
            f.write(cipher)

        print(f"Encryption complete. Ciphertext saved to '{cipher_file}' in the current directory.")
        return "ENCRYPTION SUCCESSFUL"

    return cipher

def decrypt():
    print("Choose Decryption Algorithm")
    print("(1) Base64")
    print("(2) Caesar Cipher")
    print("(3) Monoalphabetic Substitution Cipher")
    print("(4) Vignere Cipher")
    print("(5) DES")
    print("(6) AES")
    print("(7) RSA")
    decipher = ""
    opt = int(input())

    if opt == 1:
        # Base64 decryption logic
        pass

    elif opt == 2:
        # Caesar Cipher decryption logic
        pass

    elif opt == 3:
        # Monoalphabetic Substitution Cipher decryption logic
        pass

    elif opt == 4:
        # Vignere Cipher decryption logic
        pass

    elif opt == 5:
        # DES decryption logic
        pass

    elif opt == 6:
        # AES decryption
        cipher_file = input("Enter the name of the ciphertext file (e.g., ciphertext_aes.bin): ")
        if not os.path.exists(cipher_file):
            print("Error: Ciphertext file not found.")
            return "CIPHERTEXT FILE NOT FOUND"

        key_choice = input("Do you want to use an existing AES key? (yes/no): ").strip().lower()
        if key_choice == "yes":
            key_file = input("Enter the name of the AES key file (e.g., aes_key.key): ")
            if not os.path.exists(key_file):
                print("Error: Key file not found.")
                return "KEY FILE NOT FOUND"
        else:
            print("Error: You must provide an existing AES key for decryption.")
            return "KEY REQUIRED"

        with open(key_file, "rb") as f:
            key = f.read()

        # Validate key length
        if len(key) not in [16, 24, 32]:
            print("Error: Invalid key length. AES key must be 16, 24, or 32 bytes long.")
            return "INVALID KEY LENGTH"

        with open(cipher_file, "rb") as f:
            ciphertext = f.read()

        try:
            aes_cipher = AES.new(key, AES.MODE_ECB)
            padded_plaintext = aes_cipher.decrypt(ciphertext)
            plaintext = unpad(padded_plaintext, AES.block_size)
        except (ValueError, KeyError) as e:
            print("Error during decryption:", e)
            return "DECRYPTION FAILED"

        # Save decrypted data to a file
        if cipher_file.endswith(".enc"):
            output_file = cipher_file[:-4]  # Remove .enc extension
        else:
            output_file = "decrypted_file.txt"

        with open(output_file, "wb") as f:
            f.write(plaintext)

        print(f"Decryption successful. Plaintext saved to '{output_file}' in the current directory.")
        return "DECRYPTION SUCCESSFUL"

    elif opt == 7:
        # RSA decryption
        cipher_file = input("Enter the name of the ciphertext file (e.g., ciphertext_rsa.bin): ")
        if not os.path.exists(cipher_file):
            print("Error: Ciphertext file not found.")
            return "CIPHERTEXT FILE NOT FOUND"

        key_choice = input("Do you want to use an existing RSA private key? (yes/no): ").strip().lower()
        if key_choice == "yes":
            key_file = input("Enter the name of the RSA private key file (e.g., private_rsa.pem): ")
            if not os.path.exists(key_file):
                print("Error: Private key file not found.")
                return "KEY FILE NOT FOUND"
        else:
            print("Error: You must provide an existing RSA private key for decryption.")
            return "KEY REQUIRED"

        with open(cipher_file, "rb") as f:
            ciphertext = f.read()

        with open(key_file, "rb") as f:
            private_key = RSA.import_key(f.read())

        rsa_cipher = PKCS1_OAEP.new(private_key)
        chunk_size = 256  # RSA can decrypt only small chunks
        decrypted_chunks = []

        for i in range(0, len(ciphertext), chunk_size):
            chunk = ciphertext[i:i + chunk_size]
            decrypted_chunks.append(rsa_cipher.decrypt(chunk))

        plaintext = b"".join(decrypted_chunks)

        # Save decrypted data to a file
        if cipher_file.endswith(".enc"):
            output_file = cipher_file[:-4]  # Remove .enc extension
        else:
            output_file = "decrypted_file.txt"

        with open(output_file, "wb") as f:
            f.write(plaintext)

        print(f"Decryption successful. Plaintext saved to '{output_file}' in the current directory.")
        return "DECRYPTION SUCCESSFUL"

    return decipher
def hashh():
    print("Choose hashing algorithm")
    print("(1) MD5")
    print("(2) SHA-1")
    print("(3) SHA-256")
    print("(4) SHA 512")

    opt = int(input())

    print("Do you want to hash a string or a file?")
    print("(1) String")
    print("(2) File")
    choice = int(input())

    if choice == 1:
        s = input("Enter the string to hash: ").encode()
        data = s
    elif choice == 2:
        file_path = input("Enter the path to the file to hash: ")
        if not os.path.exists(file_path):
            print("Error: File not found.")
            return "FILE NOT FOUND"
        with open(file_path, "rb") as f:
            data = f.read()
    else:
        print("Invalid choice.")
        return "INVALID CHOICE"

    if opt == 1:
        result = hashlib.md5(data).hexdigest()
        print("MD5 Hash:", result)
    elif opt == 2:
        result = hashlib.sha1(data).hexdigest()
        print("SHA-1 Hash:", result)
    elif opt == 3:
        result = hashlib.sha256(data).hexdigest()
        print("SHA-256 Hash:", result)
    elif opt == 4:
        result = hashlib.sha512(data).hexdigest()
        print("SHA-512 Hash:", result)
    else:
        print("Invalid option.")

print("Choose\n(1) Encryption\n(2) Decryption\n(3) Hashing")
opt = int(input())

if opt == 1:
    ans = encrypt()
    print(ans)
elif opt == 2:
    ans = decrypt()
    print(ans)
elif opt == 3:
    hashh()
else:
    print("Not a valid option")