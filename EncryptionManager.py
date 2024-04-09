from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

class EncryptionManager:
    def __init__(self, encryption_pass, decryption_pass):
        self.encryptionPass = encryption_pass
        self.decryptionPass = decryption_pass

    def decryptFile(self, file):
        try:
            print(f"Decrypting file: {file}")

            key = self.decryptionPass.encode()  # Convert decryption pass to bytes
            cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend()).decryptor()  # Create decryptor

            # Read ciphertext
            with open(file, 'rb') as f:
                ciphertext = f.read()
                print("Ciphertext:", ciphertext)  # Print ciphertext

                plaintext = cipher.update(ciphertext) + cipher.finalize()
                print("Decrypted plaintext:", plaintext)  # Print decrypted plaintext

                unpadder = padding.PKCS7(128).unpadder()
                decrypted_data = unpadder.update(plaintext) + unpadder.finalize()
                print("Decrypted data:", decrypted_data)  # Print decrypted data

            # Write decrypted data to the same file
            with open(file, 'wb') as f:
                f.write(decrypted_data)

            print(f"Decryption completed for file: {file}")
        except Exception as e:
            print(f"Error decrypting {file}: {e}")

    def encryptFile(self, file):
        try:
            print(f"Encrypting file: {file}")

            key = self.encryptionPass.encode()  # Convert encryption pass to bytes
            cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend()).encryptor()  # Create encryptor

            # Read plaintext
            with open(file, 'rb') as f:
                plaintext = f.read()
                print("Original plaintext:", plaintext)  # Print original plaintext

                padder = padding.PKCS7(128).padder()
                padded_plaintext = padder.update(plaintext) + padder.finalize()  # Add padding to plaintext
                print("Padded plaintext:", padded_plaintext)  # Print padded plaintext

                ciphertext = cipher.update(padded_plaintext) + cipher.finalize()  # Encrypt plaintext
                print("Ciphertext:", ciphertext)  # Print ciphertext

            # Write encrypted data to the same file
            with open(file, 'wb') as f:
                f.write(ciphertext)

            print(f"Encryption completed for file: {file}")
        except Exception as e:
            print(f"Error encrypting {file}: {e}")


# Example usages
if __name__ == "__main__":
    manager = EncryptionManager(encryption_pass="MySecretKey123", decryption_pass="MySecretKey123")
    file_to_encrypt = "example.txt"
    file_to_decrypt = "example.txt.enc"

    # Encrypt file
    manager.encryptFile(file_to_encrypt)

    # Decrypt file
    manager.decryptFile(file_to_decrypt)
