"""
This script simulates the developer encrypting their proprietary AI model weights
BEFORE distributing the software.
It derives the exact same 32-byte Master Key that PyOuro will embed into valid licenses,
and uses it to encrypt 'weights.bin' into 'weights.bin.enc'.
"""
import os
import sys
from pathlib import Path

try:
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives import hashes, serialization
except ImportError:
    print("Please install cryptography: pip install cryptography")
    sys.exit(1)

def get_developer_master_key():
    vault_dir = Path.cwd() / ".pyouro"
    private_key_path = vault_dir / "private.pem"
    
    if not private_key_path.exists():
        print(f"Error: {private_key_path} not found. Run 'pyouro init' in this directory first.")
        sys.exit(1)
        
    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
        
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # This MUST match the salt and info in license_cmd.py exactly!
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"pyouro_global_master_salt",
        info=b"global_master_key_derivation"
    ).derive(private_bytes)

def main():
    print("--- Developer Tool: Encrypting AI Weights ---")
    
    # 1. Create a dummy AI weights file (In reality, this is your PyTorch/TensorFlow .pt/.h5 file)
    dummy_weights = b"PROPRIETARY_NEURAL_NETWORK_WEIGHTS: {w1: 0.85, w2: -0.14, w3: 0.99}"
    with open("weights.bin", "wb") as f:
        f.write(dummy_weights)
    print("✓ Created dummy 'weights.bin'")
        
    # 2. Get the cryptographic Master Key
    master_key = get_developer_master_key()
    print("✓ Master Key derived from private.pem")
    
    # 3. Encrypt the weights using AES-GCM
    aesgcm = AESGCM(master_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, dummy_weights, None)
    
    # Prepend the 12-byte nonce to the ciphertext for storage
    encrypted_payload = nonce + ciphertext
    
    with open("weights.bin.enc", "wb") as f:
        f.write(encrypted_payload)
        
    print("✓ Weights encrypted to 'weights.bin.enc'")
    print("\nYou can now delete 'weights.bin' and distribute 'weights.bin.enc' alongside your PyOuro build.")
    
    # Clean up the plaintext file to prove it's gone
    os.remove("weights.bin")

if __name__ == "__main__":
    main()
