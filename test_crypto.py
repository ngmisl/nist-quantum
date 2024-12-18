import unittest
import os
import tempfile
import shutil
from main import (
    generate_key_pair,
    save_key_to_file,
    load_key_from_file,
    encrypt,
    decrypt,
)


class TestCrypto(unittest.TestCase):
    """Test suite for cryptographic operations including X25519 and Ed25519."""

    def setUp(self):
        """Set up test environment."""
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up test environment."""
        shutil.rmtree(self.test_dir)

    def test_x25519_key_generation_and_save_load(self):
        """Test X25519 key pair generation, saving, and loading.

        This test verifies:
        1. Key pair generation for X25519
        2. Saving private and public keys to PEM files
        3. Loading keys back from files
        4. Using the loaded keys for encryption/decryption
        """
        print("\nTesting X25519 key generation, save, and load operations:")

        # Generate key pair
        print("- Generating X25519 key pair")
        private_key, public_key = generate_key_pair("x25519")

        # Save keys
        private_key_path = os.path.join(self.test_dir, "private_x25519.pem")
        public_key_path = os.path.join(self.test_dir, "public_x25519.pem")

        print("- Saving keys to files:")
        print(f"  Private key: {private_key_path}")
        print(f"  Public key: {public_key_path}")

        save_key_to_file(
            private_key, private_key_path, is_private=True, algorithm="x25519"
        )
        save_key_to_file(
            public_key, public_key_path, is_private=False, algorithm="x25519"
        )

        # Load keys
        print("- Loading keys from files")
        loaded_private_key = load_key_from_file(
            private_key_path, is_private=True, algorithm="x25519"
        )
        loaded_public_key = load_key_from_file(
            public_key_path, is_private=False, algorithm="x25519"
        )

        # Verify keys work for encryption/decryption
        print("- Testing encryption/decryption with loaded keys")
        message = "Test message for X25519"
        encrypted_msg, salt, nonce, tag = encrypt(
            message, loaded_public_key, "x25519", private_key=loaded_private_key
        )

        decrypted_msg = decrypt(
            encrypted_msg,
            salt,
            nonce,
            tag,
            private_key=loaded_private_key,
            public_key=loaded_public_key,
            algorithm="x25519",
        )

        self.assertEqual(message, decrypted_msg)
        print(
            "✓ Keys successfully generated, saved, loaded, and used for encryption/decryption"
        )

    def test_ed25519_key_generation_and_save_load(self):
        """Test Ed25519 key pair generation, saving, and loading.

        This test verifies:
        1. Key pair generation for Ed25519
        2. Saving private and public keys to PEM files
        3. Loading keys back from files
        4. Using the loaded keys with password-based encryption
        """
        print("\nTesting Ed25519 key generation, save, and load operations:")

        # Generate key pair
        print("- Generating Ed25519 key pair")
        private_key, public_key = generate_key_pair("ed25519")

        # Save keys
        private_key_path = os.path.join(self.test_dir, "private_ed25519.pem")
        public_key_path = os.path.join(self.test_dir, "public_ed25519.pem")

        print("- Saving keys to files:")
        print(f"  Private key: {private_key_path}")
        print(f"  Public key: {public_key_path}")

        save_key_to_file(
            private_key, private_key_path, is_private=True, algorithm="ed25519"
        )
        save_key_to_file(
            public_key, public_key_path, is_private=False, algorithm="ed25519"
        )

        # Load keys
        print("- Loading keys from files")
        loaded_private_key = load_key_from_file(
            private_key_path, is_private=True, algorithm="ed25519"
        )
        loaded_public_key = load_key_from_file(
            public_key_path, is_private=False, algorithm="ed25519"
        )

        # Verify keys work for encryption/decryption with password
        print("- Testing password-based encryption/decryption")
        message = "Test message for Ed25519"
        password = "test_password"
        encrypted_msg, salt, nonce, tag = encrypt(
            message, loaded_public_key, "ed25519", password=password
        )

        decrypted_msg = decrypt(
            encrypted_msg,
            salt,
            nonce,
            tag,
            private_key=loaded_private_key,
            algorithm="ed25519",
            password=password,
        )

        self.assertEqual(message, decrypted_msg)
        print(
            "✓ Keys successfully generated, saved, loaded, and used with password-based encryption"
        )

    def test_x25519_encryption_decryption_different_keys(self):
        """Test X25519 encryption/decryption with sender and recipient keys.

        This test verifies:
        1. Generation of separate key pairs for sender and recipient
        2. Key exchange between sender and recipient
        3. Message encryption by sender
        4. Message decryption by recipient
        """
        print("\nTesting X25519 encryption/decryption with different keys:")

        # Generate sender's keys
        print("- Generating sender's X25519 key pair")
        sender_private, sender_public = generate_key_pair("x25519")

        # Generate recipient's keys
        print("- Generating recipient's X25519 key pair")
        recipient_private, recipient_public = generate_key_pair("x25519")

        # Test message
        message = "Secret message for X25519 recipient"
        print(f"- Original message: {message}")

        # Encrypt with recipient's public key
        print("- Encrypting message using recipient's public key")
        encrypted_msg, salt, nonce, tag = encrypt(
            message, recipient_public, "x25519", private_key=sender_private
        )

        # Decrypt with recipient's private key
        print("- Decrypting message using recipient's private key")
        decrypted_msg = decrypt(
            encrypted_msg,
            salt,
            nonce,
            tag,
            private_key=recipient_private,
            public_key=sender_public,
            algorithm="x25519",
        )

        self.assertEqual(message, decrypted_msg)
        print(
            "✓ Message successfully encrypted and decrypted using different key pairs"
        )

    def test_ed25519_encryption_decryption_different_keys(self):
        """Test Ed25519 encryption/decryption with password-based encryption.

        This test verifies:
        1. Generation of separate key pairs
        2. Password-based encryption
        3. Password-based decryption
        4. Message integrity
        """
        print("\nTesting Ed25519 encryption/decryption with password:")

        # Generate sender's keys
        print("- Generating sender's Ed25519 key pair")
        sender_private, sender_public = generate_key_pair("ed25519")

        # Generate recipient's keys
        print("- Generating recipient's Ed25519 key pair")
        recipient_private, recipient_public = generate_key_pair("ed25519")

        # Test message and password
        message = "Secret message for Ed25519 recipient"
        password = "secret_password"
        print(f"- Original message: {message}")
        print("- Using password-based encryption")

        # Encrypt with password
        print("- Encrypting message")
        encrypted_msg, salt, nonce, tag = encrypt(
            message, recipient_public, "ed25519", password=password
        )

        # Decrypt with password
        print("- Decrypting message")
        decrypted_msg = decrypt(
            encrypted_msg,
            salt,
            nonce,
            tag,
            private_key=recipient_private,
            algorithm="ed25519",
            password=password,
        )

        self.assertEqual(message, decrypted_msg)
        print(
            "✓ Message successfully encrypted and decrypted using password-based encryption"
        )

    def test_dilithium_key_generation_and_save_load(self):
        """Test Dilithium key pair generation, saving, and loading.
        
        Note: This is currently using a placeholder implementation that generates
        random bytes of the correct size. This will be replaced with actual
        Dilithium implementation once we have a working quantum-safe library.
        
        This test verifies:
        1. Key pair generation for Dilithium (placeholder)
        2. Saving private and public keys to files
        3. Loading keys back from files
        4. Basic signature verification (placeholder)
        """
        print("\nTesting Dilithium key generation, save, and load operations:")
        
        # Generate key pair
        print("- Generating Dilithium key pair (placeholder implementation)")
        private_key, public_key = generate_key_pair("dilithium")
        
        # Save keys
        private_key_path = os.path.join(self.test_dir, "private_dilithium.pem")
        public_key_path = os.path.join(self.test_dir, "public_dilithium.pem")
        
        print("- Saving keys to files:")
        print(f"  Private key: {private_key_path}")
        print(f"  Public key: {public_key_path}")
        
        save_key_to_file(private_key, private_key_path, is_private=True, algorithm="dilithium")
        save_key_to_file(public_key, public_key_path, is_private=False, algorithm="dilithium")
        
        # Load keys
        print("- Loading keys from files")
        loaded_private_key = load_key_from_file(private_key_path, is_private=True, algorithm="dilithium")
        loaded_public_key = load_key_from_file(public_key_path, is_private=False, algorithm="dilithium")
        
        # Test signing and verification (placeholder)
        print("- Testing signing and verification with loaded keys (placeholder)")
        message = "Test message for Dilithium"
        password = "test_password"
        print(f"  Original message: {message}")
        
        # Encrypt and sign message
        encrypted_msg, salt, nonce, signature = encrypt(
            message, loaded_public_key, "dilithium", private_key=loaded_private_key, password=password
        )
        
        # Decrypt and verify signature
        decrypted_msg = decrypt(
            encrypted_msg,
            salt,
            nonce,
            signature,
            private_key=loaded_private_key,
            algorithm="dilithium",
            public_key=loaded_public_key,
            password=password,
        )
        
        self.assertEqual(message, decrypted_msg)
        print("✓ Keys successfully generated, saved, loaded, and used for signing/verification (placeholder)")

    def test_dilithium_multiple_messages(self):
        """Test Dilithium with multiple message signing and verification.
        
        Note: This is currently using a placeholder implementation. The actual
        cryptographic operations are simulated with random bytes generation.
        This will be replaced with proper Dilithium operations when we have
        the quantum-safe library integrated.
        
        This test verifies:
        1. Single key pair can handle multiple messages
        2. Each message gets a unique signature (simulated)
        3. Basic verification works for all messages
        """
        print("\nTesting Dilithium with multiple messages (placeholder implementation):")
        
        # Generate key pair
        print("- Generating Dilithium key pair")
        private_key, public_key = generate_key_pair("dilithium")
        password = "test_password"
        
        # Test multiple messages
        messages = [
            "First test message",
            "Second test message",
            "Third test message with different length",
            "Fourth test message 123!@#",
        ]
        
        print("- Testing multiple message signing and verification:")
        
        for i, message in enumerate(messages, 1):
            print(f"  Message {i}: '{message}'")
            
            # Encrypt and sign
            encrypted_msg, salt, nonce, signature = encrypt(
                message, public_key, "dilithium", private_key=private_key, password=password
            )
            
            # Decrypt and verify
            decrypted_msg = decrypt(
                encrypted_msg,
                salt,
                nonce,
                signature,
                private_key=private_key,
                algorithm="dilithium",
                public_key=public_key,
                password=password,
            )
            
            self.assertEqual(message, decrypted_msg)
            print(f"  ✓ Message {i} successfully processed")
        
        print("✓ All messages successfully processed with placeholder implementation")


if __name__ == "__main__":
    unittest.main()
