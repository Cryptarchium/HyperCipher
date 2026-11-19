import os
import json
import secrets
import hashlib
import random
from pathlib import Path
import sys

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError as e:
    try:
        from pyouro.core.diagnostics import pyouro_crash_reporter
        pyouro_crash_reporter("PyOuro", "Vault", str(e))
    except Exception:
        pass
    os._exit(1)

def calculate_integrity_hash(file_order: list, base_dir: Path) -> bytes:
    """
    Calculates the integrity hash of the protected files.
    To defeat I/O monitoring (ProcMon, strace), files are read in a completely 
    random order, stored in memory, and then hashed in the exact secret order (π).
    """
    if not file_order:
        return b""
        
    shuffled_order = list(file_order)
    random.shuffle(shuffled_order)
    
    file_hashes = {}
    for rel_path in shuffled_order:
        full_path = base_dir / rel_path
        # Resolve the actual extension for compiled/source modules
        if not full_path.exists():
            parent_dir = full_path.parent
            stem = full_path.stem
            
            if parent_dir.exists():
                matches = list(parent_dir.glob(f"{stem}.*"))
                valid_matches = [m for m in matches if m.suffix in ('.py', '.pyd', '.so')]
                
                if valid_matches:
                    # Prefer compiled extensions
                    compiled = [m for m in valid_matches if m.suffix in ('.pyd', '.so')]
                    full_path = compiled[0] if compiled else valid_matches[0]
            
            if not full_path.exists():
                raise FileNotFoundError(rel_path)
                
        h = hashlib.sha256()
        with open(full_path, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                h.update(chunk)
        file_hashes[rel_path] = h.digest()
            
    # Hash in the secret order (invisible to OS monitoring)
    hasher = hashlib.sha256()
    for rel_path in file_order:
        hasher.update(file_hashes[rel_path])
    
    return hasher.digest()

def derive_vault_key(keyring_seed: bytes, integrity_hash: bytes, hw_id: str) -> bytes:
    """
    Derives the AES-GCM 256-bit key for the Vault.
    vault_key = HKDF(IKM=keyring_seed, salt=integrity_hash, info=hw_id)
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32, # 256-bit key for AES-GCM
        salt=integrity_hash,
        info=hw_id.encode('utf-8')
    )
    return hkdf.derive(keyring_seed)

def derive_pysb_key(integrity_hash: bytes, pysb_salt: bytes, app_name: str) -> bytes:
    """
    Derives an independent AES-GCM key for the structural payload (.pyob).
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=pysb_salt,
        info=app_name.encode('utf-8')
    )
    return hkdf.derive(integrity_hash) # Using integrity_hash as IKM

def encrypt_vault(data: dict, vault_key: bytes) -> bytes:
    """Encrypts a dictionary of secrets using AES-GCM."""
    aesgcm = AESGCM(vault_key)
    nonce = secrets.token_bytes(12) # 96-bit standard nonce for GCM
    
    serialized_data = json.dumps(data).encode('utf-8')
    ciphertext = aesgcm.encrypt(nonce, serialized_data, None)
    
    # Prepend nonce to ciphertext
    return nonce + ciphertext

def decrypt_vault(encrypted_data: bytes, vault_key: bytes) -> dict:
    """Decrypts AES-GCM vault data."""
    if len(encrypted_data) < 12:
        raise ValueError("E01")
        
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    
    aesgcm = AESGCM(vault_key)
    try:
        decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)
        return json.loads(decrypted_data.decode('utf-8'))
    except Exception:
        raise ValueError("E01")
