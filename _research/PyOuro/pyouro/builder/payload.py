import marshal
import os
from pathlib import Path

import pickle

def generate_pyvb(payload_file_path: Path, output_file_path: Path, payload_key: bytes, app_name: str, timestamp: float, secrets_dict: dict) -> bytes:
    """
    Compiles the core_payload.py into structural bytecode, encrypts it with the 
    dedicated .pyob key, and saves it.
    
    Returns the pysb_salt needed for decryption.
    """
    if not payload_file_path.exists():
        raise FileNotFoundError(f"Payload file not found: {payload_file_path}")
        
    # Read the structural payload
    with open(payload_file_path, "r", encoding="utf-8") as f:
        source_code = f.read()
        
    # Compile to bytecode
    # Note: filename is faked to '<frozen core_payload>' to avoid leaking the real absolute path
    # in case of traceback inside the payload (which shouldn't happen, but just in case)
    code_obj = compile(source_code, "<frozen pyouro_payload>", "exec")
    
    # Marshal the bytecode (this is what we will actually inject into RAM)
    marshalled_bytecode = marshal.dumps(code_obj)
    
    # Generate a unique salt for this generation
    import hashlib
    pysb_salt = hashlib.sha256(f"{app_name}_{timestamp}".encode()).digest()[:16]
    
    # In order to avoid circular dependencies in the build process, we pass the 
    # already derived vault_key here, or we use a separate HKDF just for the PYVB.
    # We follow the plan: PYVB has its own independent key derived from the integrity_hash.
    # To keep this module clean, we assume the caller (builder) provides the correct encryption key 
    # that was derived in crypto/vault.py using derive_pysb_key().
    
    from pyouro.crypto.vault import AESGCM
    import secrets
    
    aesgcm = AESGCM(payload_key) # This is the *payload* key, not the vault key!
    nonce = secrets.token_bytes(12)
    # Bundle the bytecode and the secrets securely
    bundle = pickle.dumps({
        "bytecode": marshalled_bytecode,
        "secrets": secrets_dict
    })
    
    ciphertext = aesgcm.encrypt(nonce, bundle, None)
    
    # Save the encrypted bundle
    with open(output_file_path, "wb") as f:
        f.write(nonce + ciphertext)
        
    return pysb_salt
