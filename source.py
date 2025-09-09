from Crypto.Cipher import DES, AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
import hashlib
import os
import base64

def encrypt():
    print("Choose Encryption Algorithm")
    print("(1) Base64")
    print("(2) Caesar Cipher")
    print("(3) Monoalphabetic Substitution Cipher")
    print("(4) Vigenere Cipher")
    print("(5) DES")
    print("(6) AES")
    opt = int(input("Enter option (1-7): "))
    
    if opt == 1:
        baseChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        binary = ''.join(format(ord(char), '08b') for char in s)
        cipher = ''

        while len(binary) % 6 != 0:
            binary += '0'
        
        for i in range(0, len(binary),6):
            chunk = binary[i:i+6]
            cipher += baseChars[int(chunk, 2)]
        while len(cipher) % 4 != 0:
            cipher += '='
        return cipher

    elif opt == 2:
        s = input("Enter the string: ")
        print("(1) Right shift")
        print("(2) Left shift")
        direction = int(input("Enter direction (1-2): "))
        shift = int(input("Number of shifts: "))
        cipher = ""
        if direction == 1:
            for char in s:
                if char.isalpha():
                    base = ord('A') if char.isupper() else ord('a')
                    cipher += chr((ord(char) + shift - base) % 26 + base)
                else:
                    cipher += char
        elif direction == 2:
            for char in s:
                if char.isalpha():
                    base = ord('A') if char.isupper() else ord('a')
                    cipher += chr((ord(char) - shift - base) % 26 + base)
                else:
                    cipher += char
        else:
            return "Invalid direction"
        return cipher

    elif opt == 3:
        s = input("Enter the string: ")
        key = {
            'A': 'S', 'B': 'Y', 'C': 'E', 'D': 'C', 'E': 'T', 'F': 'B', 'G': 'F',
            'H': 'A', 'I': 'G', 'J': 'H', 'K': 'W', 'L': 'I', 'M': 'N', 'N': 'R',
            'O': 'J', 'P': 'D', 'Q': 'Z', 'R': 'L', 'S': 'U', 'T': 'M', 'U': 'P',
            'V': 'V', 'W': 'Q', 'X': 'X', 'Y': 'O', 'Z': 'K', 'a': 's', 'b': 'y', 
            'c': 'e', 'd': 'c', 'e': 't', 'f': 'b', 'g': 'f', 'h': 'a', 'i': 'g', 
            'j': 'h', 'k': 'w', 'l': 'i', 'm': 'n', 'n': 'r', 'o': 'j', 'p': 'd', 
            'q': 'z', 'r': 'l', 's': 'u', 't': 'm', 'u': 'p', 'v': 'v', 'w': 'q',
            'x': 'x', 'y': 'o', 'z': 'k'
        }
        cipher = "".join(key.get(char, char) for char in s)
        return cipher

    elif opt == 4:
        s = input("Enter the string: ")
        key = "NEITB"
        cipher = ""
        for i in range(len(s)):
            if s[i].isalpha():
                shift = ord(key[i % len(key)]) - ord('A')
                base = ord('A') if s[i].isupper() else ord('a')
                cipher += chr((ord(s[i]) - base + shift) % 26 + base)
            else:
                cipher += s[i]
        return cipher

    elif opt == 5:
        s = input("Enter the string: ")
        key = get_random_bytes(8)
        iv = get_random_bytes(8)
        print("Generated key (hex):", key.hex())
        print("Generated IV (hex):", iv.hex())
        
        cipher = DES.new(key, DES.MODE_CBC, iv)
        padded_s = pad(s.encode('utf-8'), DES.block_size)
        ciphertext = iv + cipher.encrypt(padded_s)  # Prepend IV to ciphertext
        with open("ciphertext_des.bin", "wb") as f:
            f.write(ciphertext)
        print("Ciphertext saved to 'ciphertext_des'")
        return ciphertext.hex()

    elif opt == 6:
        print("Do you want to encrypt a string or a file?")
        choice = int(input("(1) String\n(2) File\nEnter choice (1-2): "))
        if choice == 1:
            s = input("Enter the string to encrypt: ")
            data = s.encode('utf-8')
        elif choice == 2:
            file_path = input("Enter the path to the file: ")
            if not os.path.exists(file_path):
                return "FILE_NOT_FOUND"
            with open(file_path, "rb") as f:
                data = f.read()
        else:
            return "INVALID_CHOICE"

        key_choice = input("Generate new key or use existing? (new/existing): ").strip().lower()
        if key_choice == "new":
            key = get_random_bytes(16)
            with open("aes_key.key", "wb") as f:
                f.write(key)
            print("New AES key saved to 'aes_key.key'")
        elif key_choice == "existing":
            key_file = input("Enter AES key file name: ")
            if not os.path.exists(key_file):
                return "KEY_FILE_NOT_FOUND"
            with open(key_file, "rb") as f:
                key = f.read()
        else:
            return "INVALID_CHOICE"

        if len(key) not in [16, 24, 32]:
            return "INVALID_KEY_LENGTH"

        iv = get_random_bytes(16)
        aes_cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_data = pad(data, AES.block_size)
        ciphertext = iv + aes_cipher.encrypt(padded_data)
        
        cipher_file = "ciphertext_aes.bin" if choice == 1 else os.path.basename(file_path) + ".enc"
        with open(cipher_file, "wb") as f:
            f.write(ciphertext)
        print(f"Ciphertext saved to '{cipher_file}'")
        return "ENCRYPTION_SUCCESSFUL"

def decrypt():
    print("Choose Decryption Algorithm")
    print("(1) Base64")
    print("(2) Caesar Cipher")
    print("(3) Monoalphabetic Substitution Cipher")
    print("(4) Vigenere Cipher")
    print("(5) DES")
    print("(6) AES")
    
    opt = int(input("Enter option (1-7): "))
    decipher = ""

    if opt == 1:
        cipher = input("Enter the Base64 encoded string: ")
        try:
            decipher = base64.b64decode(cipher).decode('utf-8')
        except Exception as e:
            return f"Decoding failed: {e}"
        return decipher

    elif opt == 2:
        cipher = input("Enter the string: ")
        print("(1) By shift")
        print("(2) All 26 combinations")
        how = int(input("Choose how to decrypt (1-2): "))
        if how == 1:
            print("(1) Left Shift")
            print("(2) Right Shift")
            shift = int(input("Choose shift direction (1-2): "))
            shift_value = int(input("Enter shift value: "))
            if shift == 1:
                for char in cipher:
                    if char.isalpha():
                        base = ord('A') if char.isupper() else ord('a')
                        decipher += chr((ord(char) - shift_value - base) % 26 + base)
                    else:
                        decipher += char
            elif shift == 2:
                for char in cipher:
                    if char.isalpha():
                        base = ord('A') if char.isupper() else ord('a')
                        decipher += chr((ord(char) + shift_value - base) % 26 + base)
                    else:
                        decipher += char
            else:
                return "Invalid shift direction"
            return decipher
        else:
            print("All 26 combinations of Caesar cipher decryption:")
            results = []
            for shift_value in range(1, 27):
                deciphe = ""
                for char in cipher:
                    if char.isalpha():
                        base = ord('A') if char.isupper() else ord('a')
                        deciphe += chr((ord(char) - shift_value - base) % 26 + base)
                    else:
                        deciphe += char
                results.append(f"Shift {shift_value}: {deciphe}")
            return "\n".join(results)

    elif opt == 3:
        cipher = input("Enter the string: ")
        key = {
            'A': 'S', 'B': 'Y', 'C': 'E', 'D': 'C', 'E': 'T', 'F': 'B', 'G': 'F',
            'H': 'A', 'I': 'G', 'J': 'H', 'K': 'W', 'L': 'I', 'M': 'N', 'N': 'R',
            'O': 'J', 'P': 'D', 'Q': 'Z', 'R': 'L', 'S': 'U', 'T': 'M', 'U': 'P',
            'V': 'V', 'W': 'Q', 'X': 'X', 'Y': 'O', 'Z': 'K', 'a': 's', 'b': 'y', 
            'c': 'e', 'd': 'c', 'e': 't', 'f': 'b', 'g': 'f', 'h': 'a', 'i': 'g', 
            'j': 'h', 'k': 'w', 'l': 'i', 'm': 'n', 'n': 'r', 'o': 'j', 'p': 'd', 
            'q': 'z', 'r': 'l', 's': 'u', 't': 'm', 'u': 'p', 'v': 'v', 'w': 'q',
            'x': 'x', 'y': 'o', 'z': 'k'
        }
        reverse = {v: k for k, v in key.items()}
        decipher = "".join(reverse.get(char, char) for char in cipher)
        return decipher

    elif opt == 4:
        cipher = input("Enter the string: ")
        key = "NEITB"
        for i in range(len(cipher)):
            if cipher[i].isalpha():
                shift = ord(key[i % len(key)]) - ord('A')
                base = ord('A') if cipher[i].isupper() else ord('a')
                decipher += chr((ord(cipher[i]) - base - shift + 26) % 26 + base)
            else:
                decipher += cipher[i]
        return decipher

    elif opt == 5:
        cipher_file = input("Enter the name of the ciphertext file (e.g., ciphertext_des.bin): ")
        if not os.path.exists(cipher_file):
            return "CIPHERTEXT_FILE_NOT_FOUND"
        key_hex = input("Enter the key (hex): ")
        try:
            key = bytes.fromhex(key_hex)
        except ValueError:
            return "Invalid key format"
        if len(key) != 8:
            return "Invalid key length"

        with open(cipher_file, "rb") as f:
            ciphertext = f.read()
        iv = ciphertext[:8]
        ciphertext = ciphertext[8:]

        try:
            des_cipher = DES.new(key, DES.MODE_CBC, iv)
            padded_plaintext = des_cipher.decrypt(ciphertext)
            plaintext = unpad(padded_plaintext, DES.block_size).decode('utf-8')
        except Exception as e:
            return f"Decryption failed: {e}"

        output_file = "decrypted_des.txt"
        with open(output_file, "w") as f:
            f.write(plaintext)
        print(f"Decryption successful. Plaintext saved to '{output_file}'")
        return plaintext

    elif opt == 6:
        cipher_file = input("Enter the name of the ciphertext file (e.g., ciphertext_aes.bin): ")
        if not os.path.exists(cipher_file):
            return "CIPHERTEXT_FILE_NOT_FOUND"
        key_file = input("Enter the AES key file name (e.g., aes_key.key): ")
        if not os.path.exists(key_file):
            return "KEY_FILE_NOT_FOUND"

        with open(key_file, "rb") as f:
            key = f.read()
        if len(key) not in [16, 24, 32]:
            return "INVALID_KEY_LENGTH"

        with open(cipher_file, "rb") as f:
            ciphertext = f.read()
        iv = ciphertext[:16]
        ciphertext = ciphertext[16:]

        try:
            aes_cipher = AES.new(key, AES.MODE_CBC, iv)
            padded_plaintext = aes_cipher.decrypt(ciphertext)
            plaintext = unpad(padded_plaintext, AES.block_size)
        except Exception as e:
            return f"Decryption failed: {e}"

        output_file = "decrypted_file.txt" if cipher_file == "ciphertext_aes.bin" else cipher_file[:-4]
        with open(output_file, "wb") as f:
            f.write(plaintext)
        print(f"Decryption successful. Plaintext saved to '{output_file}'")
        return "DECRYPTION_SUCCESSFUL"


def hashh():
    print("Choose hashing algorithm")
    print("(1) MD5")
    print("(2) SHA-1")
    print("(3) SHA-256")
    print("(4) SHA-512")
    opt = int(input("Enter option (1-4): "))

    print("Do you want to hash a string or a file?")
    choice = int(input("(1) String\n(2) File\nEnter choice (1-2): "))
    if choice == 1:
        s = input("Enter the string to hash: ").encode('utf-8')
        data = s
    elif choice == 2:
        file_path = input("Enter the path to the file: ")
        if not os.path.exists(file_path):
            return "FILE_NOT_FOUND"
        with open(file_path, "rb") as f:
            data = f.read()
    else:
        return "INVALID_CHOICE"

    if opt == 1:
        result = hashlib.md5(data).hexdigest()
    elif opt == 2:
        result = hashlib.sha1(data).hexdigest()
    elif opt == 3:
        result = hashlib.sha256(data).hexdigest()
    elif opt == 4:
        result = hashlib.sha512(data).hexdigest()
    else:
        return "INVALID_OPTION"
    
    print(f"Hash: {result}")
    return result

def main():
    print("Choose\n(1) Encryption\n(2) Decryption\n(3) Hashing")
    opt = int(input("Enter option (1-3): "))
    if opt == 1:
        ans = encrypt()
        print("Result:", ans)
    elif opt == 2:
        ans = decrypt()
        print("Result:", ans)
    elif opt == 3:
        ans = hashh()
        print("Result:", ans)
    else:
        print("Not a valid option")

if __name__ == "__main__":
    main()
