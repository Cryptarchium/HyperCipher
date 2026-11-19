import sys
import os
import json
import base64
import logging
import time
from pathlib import Path

log = logging.getLogger("pyouro.license")

def run(hw_id: str, license_type: str, expiry: str):
    project_root = Path.cwd()
    vault_dir = project_root / ".pyouro"
    private_key_path = vault_dir / "private.pem"
    
    if not private_key_path.exists():
        log.error("private.pem not found. Run 'pyouro init' first.")
        sys.exit(1)
        
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives import serialization
    except ImportError:
        log.critical("'cryptography' library is not installed.")
        sys.exit(1)
        
    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
        
    # Parse expiry
    expiry_timestamp = 0
    if license_type == "DEMO":
        if not expiry:
            print("Error: --expiry is required for DEMO licenses (e.g., 30d)")
            sys.exit(1)
        if expiry.endswith("d"):
            days = int(expiry[:-1])
            expiry_timestamp = time.time() + (days * 86400)
        else:
            log.error("Expiry format not recognized. Use e.g. 30d")
            sys.exit(1)
            
    # Generate Cryptographic Binding
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    
    # The master key MUST be the same for all users of this project, 
    # so we derive it deterministically from the developer's private key.
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    master_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"pyouro_global_master_salt",
        info=b"global_master_key_derivation"
    ).derive(private_bytes)
    
    hkdf_user = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"pyouro_license_salt",
        info=b"license_key_derivation"
    )
    aes_key = hkdf_user.derive(hw_id.encode('utf-8'))
    
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, master_key, None)
            
    payload = {
        "type": license_type,
        "expiry": expiry_timestamp,
        "issued_at": time.time(),
        "nonce": base64.b64encode(nonce).decode('utf-8'),
        "ciphertext": base64.b64encode(ciphertext).decode('utf-8')
    }
    
    payload_bytes = json.dumps(payload).encode('utf-8')
    
    signature = private_key.sign(
        payload_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    # The final license file contains both the payload (in base64) and the RSA signature
    license_data = {
        "data": base64.b64encode(payload_bytes).decode('utf-8'),
        "signature": base64.b64encode(signature).decode('utf-8')
    }
    
    out_file = project_root / "license.sig"
    with open(out_file, "w") as f:
        json.dump(license_data, f, indent=4)
        
    log.info("✓ Generated license.sig for HW ID: %s", hw_id)
    log.info("✓ Type: %s", license_type)
    if expiry_timestamp:
        log.info("✓ Expiry: %s", expiry)
