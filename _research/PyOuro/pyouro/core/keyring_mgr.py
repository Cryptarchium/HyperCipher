import os
import secrets
import sys
import json
from pathlib import Path

try:
    import keyring
except ImportError as e:
    try:
        from pyouro.core.diagnostics import pyouro_crash_reporter
        pyouro_crash_reporter("PyOuro", "KeyringMgr", str(e))
    except Exception:
        pass
    os._exit(1)

def _get_namespace(app_name: str, developer_hash: str) -> str:
    """Generates an isolated namespace for the keyring to avoid collisions."""
    return f"{app_name}.{developer_hash}"



def get_or_create_seed(app_name: str, developer_hash: str) -> bytes:
    """Gets the OS keyring seed for this app. Will crash if keyring is missing."""
    namespace = _get_namespace(app_name, developer_hash)
    
    seed_hex = None
    try:
        seed_hex = keyring.get_password(namespace, "seed")
    except Exception:
        pass
        
    if not seed_hex:
        new_seed = secrets.token_bytes(32)
        seed_hex = new_seed.hex()
        
        try:
            keyring.set_password(namespace, "seed", seed_hex)
            if keyring.get_password(namespace, "seed") != seed_hex:
                raise RuntimeError("Failed to verify keyring save")
        except Exception as e:
            try:
                from pyouro.core.diagnostics import pyouro_crash_reporter
                pyouro_crash_reporter("PyOuro", "KeyringMgr", f"Seed save failed: {e}")
            except Exception:
                pass
            os._exit(1)
                
    return bytes.fromhex(seed_hex)

def set_time_hwmark(app_name: str, developer_hash: str, timestamp: float):
    """Sets the high-water mark for time (Anti-Rollback)."""
    namespace = _get_namespace(app_name, developer_hash)
    try:
        keyring.set_password(namespace, "time_hwmark", str(timestamp))
        if keyring.get_password(namespace, "time_hwmark") != str(timestamp):
            raise RuntimeError("Failed to verify keyring time_hwmark save")
    except Exception as e:
        try:
            from pyouro.core.diagnostics import pyouro_crash_reporter
            pyouro_crash_reporter("PyOuro", "KeyringMgr", f"Time hwmark save failed: {e}")
        except Exception:
            pass
        os._exit(1)

def get_time_hwmark(app_name: str, developer_hash: str) -> float:
    """Gets the high-water mark for time. Returns 0.0 if none exists."""
    namespace = _get_namespace(app_name, developer_hash)
    try:
        val = keyring.get_password(namespace, "time_hwmark")
        if val:
            return float(val)
    except Exception:
        pass
        
    return 0.0
