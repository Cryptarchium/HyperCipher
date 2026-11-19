"""
This script simulates an Enterprise Developer encrypting database connection strings
and admin credentials before distributing their on-premise software.
"""
import os
import sys
import json
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
    print("--- Enterprise DB Connector: Encrypting Credentials ---")
    
    # 1. The highly sensitive corporate database credentials
    db_config = {
        "host": "production-db.internal.corp",
        "port": 5432,
        "username": "admin_root_service",
        "password": "SuperSecretPassword123!@#",
        "database": "financial_records"
    }
    
    plaintext_data = json.dumps(db_config).encode('utf-8')
    print("✓ Created dummy database credentials.")
        
    # 2. Get the cryptographic Master Key
    master_key = get_developer_master_key()
    
    # 3. Encrypt the credentials using AES-GCM
    aesgcm = AESGCM(master_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext_data, None)
    
    # Prepend the 12-byte nonce to the ciphertext for storage
    encrypted_payload = nonce + ciphertext
    
    with open("db_config.enc", "wb") as f:
        f.write(encrypted_payload)
        
    print("✓ Database credentials encrypted to 'db_config.enc'")
    print("  You can now safely ship 'db_config.enc' with your PyOuro build.")
    print("  (The plaintext json is never saved to disk!)")

if __name__ == "__main__":
    main()
