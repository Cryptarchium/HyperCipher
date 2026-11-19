"""
Public API for PyOuro protected applications.
This module provides access to secrets, hardware ID, and protection status at runtime.
"""

_secrets = {}
_context = {}
_is_initialized = False

def _init(secrets: dict, context: dict):
    """
    Internal method called by the protected payload to initialize the API.
    Do NOT call this manually.
    """
    global _secrets, _context, _is_initialized
    _secrets = secrets
    _context = context
    _is_initialized = True

def is_protected() -> bool:
    """Returns True if the application is running inside the PyOuro secure environment."""
    return _is_initialized

def get_secret(key: str, default=None):
    """
    Retrieves a decrypted secret by its key.
    If the application is not running in protected mode, it will return the default.
    """
    if not is_protected():
        # Fallback for local development without PyOuro
        return default
    return _secrets.get(key, default)

def get_hardware_id() -> str:
    """
    Returns the unique hardware fingerprint of the current machine.
    Useful for displaying it in the UI so the user can request a license.
    """
    if not is_protected():
        # Generate it on the fly if running in dev mode
        from pyouro.core.hardware import get_hardware_id as _get_hwid
        return _get_hwid()
    return _context.get("hw_id", "UNKNOWN")

def get_license_data() -> dict:
    """
    Placeholder for future license implementations.
    """
    if not is_protected():
        return {}
    return _context.get("license", {})

def get_public_key() -> bytes:
    """
    Returns the RSA public key used to verify licenses.
    """
    if not is_protected():
        from pathlib import Path
        pub_path = Path.cwd() / ".pyouro" / "public.pem"
        if pub_path.exists():
            return pub_path.read_bytes()
        return b""
    return _context.get("public_pem", b"")

def verify_license(license_path: str = "license.sig") -> dict:
    """
    Reads the license file, verifies the RSA signature using the embedded public key,
    and checks if the Hardware ID matches and if the license has expired.
    Returns the decoded license payload if valid.
    Raises ValueError if invalid, tampered, or expired.
    """
    import json
    import base64
    import time
    from pathlib import Path
    
    path = Path(license_path)
    if not path.exists():
        raise ValueError(f"License file {license_path} not found.")
        
    with open(path, "r", encoding="utf-8") as f:
        try:
            lic = json.load(f)
        except json.JSONDecodeError:
            raise ValueError("License file is corrupt (invalid JSON).")
            
    if "data" not in lic or "signature" not in lic:
        raise ValueError("License file is missing 'data' or 'signature' fields.")
        
    payload_bytes = base64.b64decode(lic["data"])
    signature = base64.b64decode(lic["signature"])
    
    public_pem = get_public_key()
    if not public_pem:
        raise ValueError("Public key not available to verify license.")
        
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives import serialization
    except ImportError:
        raise ValueError("cryptography package is required to verify licenses.")
        
    public_key = serialization.load_pem_public_key(public_pem)
    
    try:
        public_key.verify(
            signature,
            payload_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except Exception:
        raise ValueError("License signature is INVALID. Tampering detected!")
        
    payload = json.loads(payload_bytes.decode('utf-8'))
    
    # Verify Expiry and Issued At
    expiry = payload.get("expiry", 0)
    issued_at = payload.get("issued_at", 0)
    current_time = time.time()
    
    if expiry > 0 and current_time > expiry:
        raise ValueError("This license has expired.")
        
    if issued_at > 0 and current_time < issued_at:
        raise ValueError("System time has been tampered with (before license issue date).")
        
    # Cryptographic Binding: Decrypt the Master Key using local HW ID
    try:
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        
        nonce = base64.b64decode(payload["nonce"])
        ciphertext = base64.b64decode(payload["ciphertext"])
        
        local_hw_id = get_hardware_id()
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"pyouro_license_salt",
            info=b"license_key_derivation"
        )
        aes_key = hkdf.derive(local_hw_id.encode('utf-8'))
        
        aesgcm = AESGCM(aes_key)
        master_key_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        
    except Exception:
        raise ValueError("Cryptographic Binding Failed: This license belongs to another machine (AES Decryption Failed).")
        
    # Return the decrypted master key along with metadata
    return {
        "type": payload.get("type"),
        "expiry": expiry,
        "issued_at": payload.get("issued_at"),
        "master_key": master_key_bytes
    }
