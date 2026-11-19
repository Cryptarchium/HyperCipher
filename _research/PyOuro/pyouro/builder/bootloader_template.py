import sys
import os
import marshal
import pickle
import json
import time
import secrets
from pathlib import Path

# --- INJECTED BY BUILDER ---
APP_NAME = "{APP_NAME}"
DEVELOPER_HASH = "{DEVELOPER_HASH}"
PYSB_SALT = {PYSB_SALT_BYTES}
FILE_ORDER_HASHES = {FILE_ORDER_HASHES_LIST}
PUBLIC_PEM = {PUBLIC_PEM_BYTES}
EXPECTED_PYTHON_DLL_HASH = "{EXPECTED_PYTHON_DLL_HASH}"
# ---------------------------

def _crash(reason="Unknown"):
    import sys
    import os
    import ctypes
    import gc
    try:
        # Zero-fill sensitive memory (RAM Wiping) before exit
        frame = sys._getframe(1)
        offset = sys.getsizeof(b"") - 1
        for var in ['payload_key', 'decrypted_data', 'bundle', 'code_obj', 'hw_id']:
            if var in frame.f_locals:
                val = frame.f_locals[var]
                if isinstance(val, bytearray):
                    for i in range(len(val)): val[i] = 0
                elif isinstance(val, bytes):
                    try:
                        ctypes.memset(id(val) + offset, 0, len(val))
                    except Exception:
                        pass
                frame.f_locals[var] = None
        
        # Aggressive garbage collection
        frame.clear()
        gc.collect()
    except Exception:
        pass
        
    try:
        from pyouro.core.diagnostics import pyouro_crash_reporter
        pyouro_crash_reporter("{APP_NAME}", "Bootloader", reason)
    except Exception:
        pass
        
    sys.stderr.write(f"Fatal Error: E01 ({reason})\n")
    os._exit(1)

def _anti_debug():
    if sys.gettrace() is not None:
        _crash("Debugger Trace")
        
    # Native OS Anti-Debug Checks
    if os.name == 'nt':
        try:
            import ctypes
            if ctypes.windll.kernel32.IsDebuggerPresent():
                _crash("IsDebuggerPresent")
        except Exception:
            pass
    elif sys.platform == 'linux':
        try:
            with open("/proc/self/status", "r") as f:
                for line in f:
                    if line.startswith("TracerPid:"):
                        pid = int(line.split(":")[1].strip())
                        if pid != 0:
                            _crash("Linux Trace")
        except Exception:
            pass
    elif sys.platform == 'darwin':
        try:
            import ctypes
            libc = ctypes.CDLL("libc.dylib")
            # PT_DENY_ATTACH = 31
            libc.ptrace(31, 0, 0, 0)
        except Exception:
            pass

def _load():
    _anti_debug()
    
    import pyouro.core.hardware as hardware
    hw_id = hardware.get_hardware_id()
    
    from pyouro.core.keyring_mgr import get_or_create_seed, get_time_hwmark, set_time_hwmark
    keyring_seed = get_or_create_seed(APP_NAME, DEVELOPER_HASH)
    
    import hashlib
    if getattr(sys, 'frozen', False):
        if hasattr(sys, '_MEIPASS'):
            base_dir = Path(sys._MEIPASS).resolve()
        else:
            # Safe fallback for PyInstaller >= 6.0 in --onedir mode
            base_dir = (Path(sys.executable).parent / "_internal").resolve()
            if not base_dir.exists():
                base_dir = Path(sys.executable).parent.resolve()
    else:
        base_dir = Path(__file__).parent.resolve()
    
    if EXPECTED_PYTHON_DLL_HASH:
        dll_found = False
        for p in base_dir.iterdir():
            if p.is_file() and ("python3" in p.name.lower() or "libpython3" in p.name.lower()) and p.suffix in [".dll", ".so", ".dylib"]:
                if p.name.lower() == "python3.dll":
                    continue # Skip the dummy forwarder DLL created by PyInstaller on Windows
                    
                with open(p, "rb") as f:
                    actual_hash = hashlib.sha256(f.read()).hexdigest()
                if actual_hash != EXPECTED_PYTHON_DLL_HASH:
                    _crash(f"DLL Hash Mismatch")
                dll_found = True
                break
        if not dll_found:
            _crash("Python DLL not found")
    
    hashed_name_map = {}
    for p in base_dir.rglob("*"):
        if p.is_file():
            if p.suffix in [".py", ".pyc"] and p.name not in ["pyouro_runner.pyc", "pyouro_runner.py", "base_library.zip", "pyouro_runner.exe"]:
                _crash("Source File Injection Detected")
            if p.suffix in [".pyd", ".so"] and not p.name.startswith("bootloader."):
                rel_path = p.relative_to(base_dir)
                clean_name = p.name.split('.')[0]
                parent_str = str(rel_path.parent).replace("\\", "/")
                stem_path = clean_name if parent_str == "." else f"{parent_str}/{clean_name}"
                h = hashlib.sha256(stem_path.encode('utf-8')).digest()
                hashed_name_map[h] = p
            
    if len(hashed_name_map) != len(FILE_ORDER_HASHES):
        _crash("Unexpected extra files detected in execution directory")
            
    hasher = hashlib.sha256()
    for expected_hash in FILE_ORDER_HASHES:
        if expected_hash not in hashed_name_map:
            _crash("Missing file in hashed_name_map")
            
        file_path = hashed_name_map[expected_hash]
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                h.update(chunk)
        hasher.update(h.digest())
            
    deps_integrity_hash = hasher.digest()
    
    bootloader_hash = None
    for p in base_dir.iterdir():
        if p.is_file() and p.name.startswith("bootloader.") and p.suffix in [".pyd", ".so"]:
            with open(p, "rb") as f:
                bootloader_hash = hashlib.sha256(f.read()).digest()
            break
            
    if not bootloader_hash:
        _crash("Bootloader file missing for verification")
        
    integrity_hash = hashlib.sha256(deps_integrity_hash + bootloader_hash).digest()
    
    from pyouro.crypto.vault import derive_pysb_key, AESGCM
    payload_key = derive_pysb_key(integrity_hash, PYSB_SALT, APP_NAME)
    
    pyvb_path = base_dir / f"{APP_NAME}.pyob"
    if not pyvb_path.exists():
        _crash("Payload pyob missing")
        
    with open(pyvb_path, "rb") as f:
        encrypted_data = f.read()
        
    if len(encrypted_data) < 12:
        _crash("Payload too small")
        
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    
    aesgcm = AESGCM(payload_key)
    try:
        decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception as e:
        _crash(f"AESGCM Decrypt failed")
        
    # --- TIME TAMPERING PROTECTION ---
    lock_path = base_dir / f"{APP_NAME}_time.lock"
    lock_acquired = False
    try:
        lock_fd = open(lock_path, "a")
        for _ in range(20): # Wait up to 2.0 seconds
            try:
                if os.name == 'nt':
                    import msvcrt
                    lock_fd.seek(0)
                    msvcrt.locking(lock_fd.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(lock_fd.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                lock_acquired = True
                break
            except Exception:
                time.sleep(0.1)
    except Exception:
        pass
        
    if not lock_acquired:
        # Timeout lock acquisition (DoS or stale lock) - fail secure
        _crash("Lock timeout")

    time_vault_path = base_dir / f"{APP_NAME}_time.dat"
    current_time = time.time()
    state = {"last_launch_ts": 0.0}
    keyring_time = get_time_hwmark(APP_NAME, DEVELOPER_HASH)
    
    if time_vault_path.exists():
        try:
            with open(time_vault_path, "rb") as f:
                enc_state = f.read()
            if len(enc_state) > 12:
                t_nonce = enc_state[:12]
                t_ct = enc_state[12:]
                state = json.loads(aesgcm.decrypt(t_nonce, t_ct, None).decode('utf-8'))
                
            recorded_time = max(state.get("last_launch_ts", 0.0), keyring_time)
            
            if current_time < recorded_time:
                _crash("Time tampering (rollback)") # Time Tampering detected
                
            if current_time > recorded_time:
                state["last_launch_ts"] = current_time
                new_nonce = secrets.token_bytes(12)
                new_ct = aesgcm.encrypt(new_nonce, json.dumps(state).encode('utf-8'), None)
                with open(time_vault_path, "wb") as f:
                    f.write(new_nonce + new_ct)
                set_time_hwmark(APP_NAME, DEVELOPER_HASH, current_time)
        except Exception as e:
            _crash(f"Time state decrypt/update failed")
    else:
        if keyring_time > 0 and current_time < keyring_time:
             _crash("Time tampering (missing file rollback)")
             
        state["last_launch_ts"] = max(current_time, keyring_time)
        try:
            new_nonce = secrets.token_bytes(12)
            new_ct = aesgcm.encrypt(new_nonce, json.dumps(state).encode('utf-8'), None)
            with open(time_vault_path, "wb") as f:
                f.write(new_nonce + new_ct)
            set_time_hwmark(APP_NAME, DEVELOPER_HASH, state["last_launch_ts"])
        except Exception:
            pass
            
    try:
        if os.name == 'nt':
            import msvcrt
            lock_fd.seek(0)
            msvcrt.locking(lock_fd.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            fcntl.flock(lock_fd.fileno(), fcntl.LOCK_UN)
        lock_fd.close()
    except Exception:
        pass
    # ---------------------------------
        
    bundle = pickle.loads(decrypted_data)
    code_obj = marshal.loads(bundle["bytecode"])
    
    import pyouro.api
    pyouro.api._init(
        secrets=bundle["secrets"],
        context={
            "hw_id": hw_id,
            "keyring_seed": keyring_seed,
            "integrity_hash": integrity_hash,
            "app_name": APP_NAME,
            "developer_hash": DEVELOPER_HASH,
            "base_dir": base_dir,
            "public_pem": PUBLIC_PEM
        }
    )
    
    payload_globals = {
        "__name__": "__main__",
        "__file__": str(pyvb_path),
    }
    
    exec(code_obj, payload_globals)

# Auto-execute on import so it behaves natively when loaded by a launcher stub.
_load()
