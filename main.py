import os
import sys
import getpass
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519

# Dilithium constants
DILITHIUM_PRIVATE_KEY_SIZE = 2528
DILITHIUM_PUBLIC_KEY_SIZE = 1312
DILITHIUM_SIGNATURE_SIZE = 2420


def generate_key_pair(algorithm):
    """Generates a key pair based on the specified algorithm.

    Args:
        algorithm (str): The algorithm to use ('dilithium', 'falcon', 'x25519', 'ed25519').

    Returns:
        tuple: A tuple containing the private key and public key.
    """
    if algorithm == "dilithium":
        # Implement Dilithium key pair generation
        private_key = os.urandom(DILITHIUM_PRIVATE_KEY_SIZE)
        public_key = os.urandom(DILITHIUM_PUBLIC_KEY_SIZE)
    elif algorithm == "falcon":
        # Implement Falcon key pair generation
        private_key = os.urandom(1280)
        public_key = os.urandom(897)
    elif algorithm == "x25519":
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()
    elif algorithm == "ed25519":
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
    else:
        raise ValueError("Invalid algorithm specified.")

    return private_key, public_key


def save_key_to_file(key, filename, is_private=True, algorithm=None):
    """Saves a key to a file.

    Args:
        key: The key to save.
        filename (str): The name of the file to save the key to.
        is_private (bool): True if the key is a private key, False otherwise.
        algorithm (str): Algorithm name for serialization.
    """
    if is_private:
        if isinstance(key, bytes):
            pem = key
        else:
            pem = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
    else:
        if isinstance(key, bytes):
            pem = key
        else:
            pem = key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
    with open(filename, "wb") as f:
        f.write(pem)


def load_key_from_file(filename, is_private=True, algorithm=None):
    """Loads a key from a file.

    Args:
        filename (str): The name of the file to load the key from.
        is_private (bool): True if the key is a private key, False otherwise.
        algorithm (str): Algorithm name is needed for loading keys.

    Returns:
        The loaded key.
    """
    with open(filename, "rb") as f:
        pem = f.read()

    if is_private:
        if algorithm == "dilithium":
            # Implement Dilithium private key loading
            key = pem
        elif algorithm == "falcon":
            # Implement Falcon private key loading
            key = pem
        elif algorithm == "x25519":
            key = serialization.load_pem_private_key(pem, password=None)
        elif algorithm == "ed25519":
            key = serialization.load_pem_private_key(pem, password=None)
        else:
            raise ValueError(
                "Invalid algorithm specified or algorithm needed for loading the key."
            )
    else:
        if algorithm == "dilithium":
            # Implement Dilithium public key loading
            key = pem
        elif algorithm == "falcon":
            # Implement Falcon public key loading
            key = pem
        elif algorithm == "x25519":
            key = serialization.load_pem_public_key(pem)
        elif algorithm == "ed25519":
            key = serialization.load_pem_public_key(pem)
        else:
            raise ValueError(
                "Invalid algorithm specified or algorithm needed for loading the key."
            )

    return key


def encrypt(message, public_key, algorithm, private_key=None, password=None):
    """Encrypts a message using the specified algorithm and a hybrid approach with AES-GCM.

    Args:
        message (str): The message to encrypt.
        public_key: Public key loaded from file or passed otherwise.
        algorithm (str): The algorithm to use ('dilithium', 'falcon', 'x25519', 'ed25519').
        private_key: Optional private key for signing in the case of 'dilithium' or 'falcon'.
        password (str): Password for key derivation when not using key exchange.

    Returns:
        tuple: A tuple containing the encrypted message, salt, nonce, and signature (if applicable).
    """
    message_bytes = message.encode("utf-8")

    # Generate a random salt for key derivation
    salt = os.urandom(16)

    # Derive a shared secret or symmetric key based on the algorithm
    if algorithm == "x25519":
        if not private_key:
            raise ValueError("Private key is required for X25519 key exchange.")
        # Perform key exchange to get a shared secret
        shared_secret = private_key.exchange(public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b"handshake data",
        ).derive(shared_secret)
    else:
        if not password:
            raise ValueError("Password is required for the selected algorithm.")
        # Derive key from password
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b"password-based key derivation",
        ).derive(password.encode("utf-8"))

    # Encrypt the message using AES-GCM
    aesgcm = AESGCM(derived_key)
    nonce = os.urandom(12)
    encrypted_message = aesgcm.encrypt(nonce, message_bytes, None)

    # Sign the encrypted message if using dilithium or falcon
    signature = None
    if algorithm in ["dilithium", "falcon"]:
        if not private_key:
            raise ValueError("Private key is required for signing.")
        # Implement Dilithium or Falcon signing
        signature = os.urandom(DILITHIUM_SIGNATURE_SIZE) if algorithm == "dilithium" else os.urandom(1280)

    return encrypted_message, salt, nonce, signature


def decrypt(
    encrypted_message,
    salt,
    nonce,
    signature,
    private_key,
    algorithm,
    public_key=None,
    password=None,
):
    """Decrypts a message using the specified algorithm.

    Args:
        encrypted_message (bytes): The encrypted message.
        salt (bytes): The salt used for key derivation.
        nonce (bytes): The nonce used for AES-GCM.
        signature (bytes): The signature (if applicable).
        private_key: Private key for decryption and verification.
        algorithm (str): The algorithm to use ('dilithium', 'falcon', 'x25519', 'ed25519').
        public_key: Public key for signature verification (if applicable).
        password (str): Password for key derivation when not using key exchange.

    Returns:
        str: The decrypted message.
    """
    try:
        # Derive the shared secret or AES key based on the algorithm
        if algorithm == "x25519":
            if not private_key or not public_key:
                raise ValueError(
                    "Both private and public keys are required for X25519 key exchange."
                )
            # Perform key exchange to get a shared secret
            shared_secret = private_key.exchange(public_key)
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                info=b"handshake data",
            ).derive(shared_secret)
        else:
            if not password:
                raise ValueError("Password is required for the selected algorithm.")
            # Derive key from password
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                info=b"password-based key derivation",
            ).derive(password.encode("utf-8"))

        # Verify the signature if using dilithium or falcon
        if algorithm in ["dilithium", "falcon"] and signature is not None:
            if not public_key:
                raise ValueError("Public key is required for signature verification.")
            # Implement Dilithium or Falcon signature verification
            is_valid = True
            if not is_valid:
                print("Signature verification failed!")
                return None

        # Decrypt the message using AES-GCM
        aesgcm = AESGCM(derived_key)
        decrypted_message_bytes = aesgcm.decrypt(nonce, encrypted_message, None)

        return decrypted_message_bytes.decode("utf-8")

    except Exception as e:
        print(f"Decryption failed: {str(e)}")
        return None


def main():
    """Main function to handle user input and encryption/decryption."""
    print("Select an option:")
    print("1. Generate Key Pairs")
    print("2. Encrypt")
    print("3. Decrypt")
    option = input("Option (1/2/3): ").strip()

    if option == "1":
        # Generate key pairs
        algorithm = input(
            "Choose an algorithm for key generation (dilithium, falcon, x25519, ed25519): "
        ).lower()

        if algorithm not in ["dilithium", "falcon", "x25519", "ed25519"]:
            print("Invalid algorithm.")
            return

        private_key, public_key = generate_key_pair(algorithm)

        # Save keys to files
        if algorithm in ["x25519", "ed25519"]:
            save_key_to_file(
                private_key,
                f"private_key_{algorithm}.pem",
                is_private=True,
                algorithm=algorithm,
            )
            save_key_to_file(
                public_key,
                f"public_key_{algorithm}.pem",
                is_private=False,
                algorithm=algorithm,
            )
            print(
                f"Key pair generated and saved as 'private_key_{algorithm}.pem' and 'public_key_{algorithm}.pem'"
            )
        else:
            save_key_to_file(
                private_key,
                f"private_key_{algorithm}.pem",
                is_private=True,
                algorithm=algorithm,
            )
            save_key_to_file(
                public_key,
                f"public_key_{algorithm}.pem",
                is_private=False,
                algorithm=algorithm,
            )
            print(
                f"Key pair generated and saved as 'private_key_{algorithm}.pem' and 'public_key_{algorithm}.pem'"
            )

    elif option in ["2", "3"]:
        action = "e" if option == "2" else "d"

        if action == "e":
            # Encrypt
            algorithm = input(
                "Choose an algorithm (dilithium, falcon, x25519, ed25519): "
            ).lower()

            if algorithm not in ["dilithium", "falcon", "x25519", "ed25519"]:
                print("Invalid algorithm.")
                return

            if algorithm in ["x25519", "ed25519"]:
                try:
                    sender_private_key = load_key_from_file(
                        f"private_key_{algorithm}.pem",
                        is_private=True,
                        algorithm=algorithm,
                    )
                except FileNotFoundError:
                    print(
                        f"Private key file 'private_key_{algorithm}.pem' not found. Please generate it first."
                    )
                    return
                try:
                    recipient_public_key = load_key_from_file(
                        f"public_key_{algorithm}.pem",
                        is_private=False,
                        algorithm=algorithm,
                    )
                except FileNotFoundError:
                    print(
                        f"Public key file 'public_key_{algorithm}.pem' not found. Please generate it first."
                    )
                    return
            else:
                try:
                    sender_private_key = load_key_from_file(
                        f"private_key_{algorithm}.pem",
                        is_private=True,
                        algorithm=algorithm,
                    )
                except FileNotFoundError:
                    print(
                        f"Private key file 'private_key_{algorithm}.pem' not found. Please generate it first."
                    )
                    return
                try:
                    recipient_public_key = load_key_from_file(
                        f"public_key_{algorithm}.pem",
                        is_private=False,
                        algorithm=algorithm,
                    )
                except FileNotFoundError:
                    print(
                        f"Public key file 'public_key_{algorithm}.pem' not found. Please generate it first."
                    )
                    return
                password = getpass.getpass("Enter a password for encryption: ")

            message = input("Enter the message to encrypt: ")

            if algorithm in ["x25519", "ed25519"]:
                encrypted_message, salt, nonce, signature = encrypt(
                    message,
                    recipient_public_key,
                    algorithm,
                    private_key=sender_private_key,
                )
            else:
                encrypted_message, salt, nonce, signature = encrypt(
                    message,
                    recipient_public_key,
                    algorithm,
                    private_key=sender_private_key,
                    password=password,
                )

            print("\n--- Encrypted Message ---")
            print("Encrypted message:", encrypted_message.hex())
            print("Salt:", salt.hex())
            print("Nonce:", nonce.hex())
            if signature:
                print("Signature:", signature.hex())

        elif action == "d":
            # Decrypt
            algorithm = input(
                "Choose an algorithm (dilithium, falcon, x25519, ed25519): "
            ).lower()

            if algorithm not in ["dilithium", "falcon", "x25519", "ed25519"]:
                print("Invalid algorithm.")
                return

            if algorithm in ["x25519", "ed25519"]:
                try:
                    recipient_private_key = load_key_from_file(
                        f"private_key_{algorithm}.pem",
                        is_private=True,
                        algorithm=algorithm,
                    )
                except FileNotFoundError:
                    print(
                        f"Private key file 'private_key_{algorithm}.pem' not found. Please generate it first."
                    )
                    return
                try:
                    sender_public_key = load_key_from_file(
                        f"public_key_{algorithm}.pem",
                        is_private=False,
                        algorithm=algorithm,
                    )
                except FileNotFoundError:
                    print(
                        f"Public key file 'public_key_{algorithm}.pem' not found. Please generate it first."
                    )
                    return
            else:
                try:
                    recipient_private_key = load_key_from_file(
                        f"private_key_{algorithm}.pem",
                        is_private=True,
                        algorithm=algorithm,
                    )
                except FileNotFoundError:
                    print(
                        f"Private key file 'private_key_{algorithm}.pem' not found. Please generate it first."
                    )
                    return
                try:
                    sender_public_key = load_key_from_file(
                        f"public_key_{algorithm}.pem",
                        is_private=False,
                        algorithm=algorithm,
                    )
                except FileNotFoundError:
                    print(
                        f"Public key file 'public_key_{algorithm}.pem' not found. Please generate it first."
                    )
                    return
                password = getpass.getpass("Enter the password for decryption: ")

            encrypted_message_hex = input(
                "Enter the encrypted message (in hex): "
            ).strip()
            salt_hex = input("Enter the salt (in hex): ").strip()
            nonce_hex = input("Enter the nonce (in hex): ").strip()
            signature_hex = (
                input("Enter the signature (in hex, if applicable): ").strip()
                if algorithm in ["dilithium", "falcon"]
                else None
            )

            try:
                encrypted_message = bytes.fromhex(encrypted_message_hex)
                salt = bytes.fromhex(salt_hex)
                nonce = bytes.fromhex(nonce_hex)
                signature = bytes.fromhex(signature_hex) if signature_hex else None
            except ValueError:
                print("Invalid hexadecimal format.")
                return

            if algorithm in ["x25519", "ed25519"]:
                decrypted_message = decrypt(
                    encrypted_message,
                    salt,
                    nonce,
                    signature,
                    private_key=recipient_private_key,
                    algorithm=algorithm,
                    public_key=sender_public_key,
                )
            else:
                decrypted_message = decrypt(
                    encrypted_message,
                    salt,
                    nonce,
                    signature,
                    private_key=recipient_private_key,
                    algorithm=algorithm,
                    public_key=sender_public_key,
                    password=password,
                )

            if decrypted_message:
                print("\n--- Decrypted Message ---")
                print("Decrypted message:", decrypted_message)
            else:
                print("Failed to decrypt the message.")

    else:
        print("Invalid option.")


if __name__ == "__main__":
    main()
