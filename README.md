# NIST Cryptography Implementation

This project implements various cryptographic algorithms, including both traditional and post-quantum cryptography methods. It provides a Python-based interface for key generation, encryption, decryption, signing, and verification operations.

## Features

- **Traditional Cryptography**:
  - X25519 for key exchange
  - Ed25519 for digital signatures
  - AES-GCM for symmetric encryption

- **Post-Quantum Cryptography** (Work in Progress):
  - Dilithium for digital signatures (placeholder implementation)
  - Falcon for digital signatures (placeholder implementation)

## Installation

1. Clone the repository:

   ```bash
   git clone <repository-url>
   cd nist
   ```

2. Create and activate a virtual environment:

   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Unix/macOS
   # or
   .venv\Scripts\activate  # On Windows
   ```

3. Install dependencies:

   ```bash
   pip install cryptography
   ```

## Usage

### Key Generation

```python
from main import generate_key_pair

# Generate X25519 key pair
private_key, public_key = generate_key_pair("x25519")

# Generate Ed25519 key pair
private_key, public_key = generate_key_pair("ed25519")

# Generate Dilithium key pair (placeholder)
private_key, public_key = generate_key_pair("dilithium")
```

### Encryption and Decryption

```python
from main import encrypt, decrypt

# Encrypt a message
message = "Hello, World!"
encrypted_msg, salt, nonce, tag = encrypt(
    message, 
    public_key, 
    algorithm="x25519",
    private_key=sender_private_key
)

# Decrypt the message
decrypted_msg = decrypt(
    encrypted_msg,
    salt,
    nonce,
    tag,
    private_key=recipient_private_key,
    algorithm="x25519",
    public_key=sender_public_key
)
```

### Key Storage

```python
from main import save_key_to_file, load_key_from_file

# Save keys
save_key_to_file(private_key, "private_key.pem", is_private=True)
save_key_to_file(public_key, "public_key.pem", is_private=False)

# Load keys
loaded_private_key = load_key_from_file("private_key.pem", is_private=True)
loaded_public_key = load_key_from_file("public_key.pem", is_private=False)
```

## Testing

Run the test suite:

```bash
python -m unittest test_crypto.py -v
```

The test suite includes:

- Key generation tests for all supported algorithms
- Encryption/decryption tests with different key pairs
- Password-based encryption tests
- Key saving and loading tests
- Multiple message handling tests

## Implementation Notes

### Post-Quantum Cryptography Status

- The current Dilithium and Falcon implementations are placeholders that simulate the correct key and signature sizes.
- We plan to integrate a proper quantum-safe library in the future.
- The placeholder implementation maintains the correct API structure for future replacement.

### Security Considerations

- All private keys are handled securely and never exposed
- Password-based encryption is available for additional security
- Keys are stored in PEM format with appropriate encryption

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

MIT

## Acknowledgments

- Cryptography library: [https://cryptography.io/](https://cryptography.io/)
- NIST Post-Quantum Cryptography standardization: [https://csrc.nist.gov/projects/post-quantum-cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
