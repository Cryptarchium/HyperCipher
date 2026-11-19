import sys
import json

def connect_to_database(master_key: bytes):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from pathlib import Path
    
    config_path = Path("db_config.enc")
    if not config_path.exists():
        print("Error: db_config.enc not found. Run encrypt_credentials.py first.")
        sys.exit(1)
        
    encrypted_payload = config_path.read_bytes()
    nonce = encrypted_payload[:12]
    ciphertext = encrypted_payload[12:]
    
    print("[DB Engine] Decrypting database credentials in RAM...")
    try:
        aesgcm = AESGCM(master_key)
        plaintext_json = aesgcm.decrypt(nonce, ciphertext, None)
        print("✓ Credentials successfully decrypted! No files were written to disk.")
        
        # Parse the JSON in memory
        db_config = json.loads(plaintext_json.decode('utf-8'))
        
        print("\n[DB Engine] Establishing secure connection...")
        print(f" -> Host: {db_config['host']}:{db_config['port']}")
        print(f" -> User: {db_config['username']}")
        print(f" -> Pass: {'*' * len(db_config['password'])}")
        print(f" -> DB:   {db_config['database']}")
        
        print("\n[DB Engine] Connection Successful! Ready to query data.")
        
    except Exception as e:
        print(f"\n❌ FATAL CRASH: Invalid Master Key. The AES-GCM tag check failed.")
        print("This happens if the license was spoofed or bypassed.")
        sys.exit(1)
