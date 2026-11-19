import os
import sys
import json
import logging
import time
import hashlib
import sysconfig
from pathlib import Path

log = logging.getLogger("pyouro.build")

# Provide helpful error if missing dependencies
try:
    import toml
    import yaml
except ImportError:
    logging.critical("Missing dependencies. Please run: pip install toml pyyaml")
    sys.exit(1)

def find_python_dll() -> Path:
    """Locates the Python native library (e.g. python310.dll, libpython3.10.so) dynamically."""
    lib_name = sysconfig.get_config_var('LDLIBRARY')
    if not lib_name:
        return None
        
    paths = [
        Path(sys.executable).parent / lib_name,
        Path(sysconfig.get_config_var('LIBDIR') or "") / lib_name
    ]
    for p in paths:
        if p.exists():
            return p
    return None

def run(compiler_type=None):
    log.info("Building PyOuro project...")
    project_root = Path.cwd()
    vault_dir = project_root / ".pyouro"
    
    if not vault_dir.exists():
        log.error(".pyouro directory not found. Did you run 'pyouro init'?")
        sys.exit(1)
        
    # 1. Load Configurations
    from pyouro.builder.config_validator import ConfigValidator
    validator = ConfigValidator(project_root, vault_dir)
    config = validator.load_toml()
    file_order = validator.load_file_order()
    prod_secrets = validator.load_prod_secrets()
    
    try:
        with open(vault_dir / "public.pem", "rb") as f:
            public_pem = f.read()
            
        with open(vault_dir / "padding_seed.hex", "r", encoding="utf-8") as f:
            padding_seed = f.read().strip()
    except Exception as e:
        log.error("Error loading project configurations: %s", e)
        sys.exit(1)
        
    app_name = config.get("app", {}).get("name", "ProtectedApp")
    payload_file = config.get("payload", {}).get("file")
    enable_floating = config.get("security", {}).get("enable_floating_license", False)
    if not payload_file:
        log.error("pyouro.toml is missing payload.file configuration.")
        sys.exit(1)
        
    developer_hash = hashlib.sha256(b"pyouro_" + public_pem).hexdigest()[:16]
    
    # 2. Inject PyOuro Core into the protected file order
    # This secures PyOuro's own modules from tampering
    pyouro_core_files = [
        "pyouro/__init__.py",
        "pyouro/core/__init__.py",
        "pyouro/core/diagnostics.py",
        "pyouro/core/hardware.py",
        "pyouro/core/keyring_mgr.py",
        "pyouro/crypto/__init__.py",
        "pyouro/crypto/vault.py",
        "pyouro/api.py"
    ]
    file_order.extend(pyouro_core_files)
    
    # 3. Prepare Build Stage
    from pyouro.builder.compiler import prepare_build_stage, compile_modules
    build_stage = prepare_build_stage(project_root, file_order)
    log.info("✓ Staged source files securely")
    
    # 4. Generate Padding using the secret seed, NOT the public key
    from pyouro.crypto.padding import generate_padding_files
    file_order = generate_padding_files(build_stage, file_order, padding_seed)
    log.info("✓ Generated dynamic padding (Total modules: %d)", len(file_order))
    
    # AST Dependency Analyzer (Must run BEFORE Cython deletes .py files)
    from pyouro.builder.dependency_analyzer import DependencyAnalyzer
    ast_deps = DependencyAnalyzer.get_all_dependencies(build_stage, file_order)
    
    # 5. Compile modules via Cython
    compile_modules(file_order, build_stage, compiler_type=compiler_type)
    log.info("✓ Modules compiled to binary extensions")
    
    # 6. Calculate Dependencies Integrity Hash
    from pyouro.crypto.vault import calculate_integrity_hash, derive_pysb_key
    try:
        deps_integrity_hash = calculate_integrity_hash(file_order, build_stage)
    except FileNotFoundError as e:
        log.error("Error during integrity hashing: %s", e)
        sys.exit(1)
    log.info("✓ Calculated in-memory Dependencies Integrity Hash (π)")
    
    # 7. Generate and Compile Bootloader
    import pyouro
    template_path = Path(pyouro.__file__).parent / "builder" / "bootloader_template.py"
    with open(template_path, "r", encoding="utf-8") as f:
        bootloader_code = f.read()
        
    # Generate pysb_salt early for injection
    timestamp = time.time()
    pysb_salt = hashlib.sha256(f"{app_name}_{timestamp}".encode()).digest()[:16]
    
    # Inject constants
    bootloader_code = bootloader_code.replace('"{APP_NAME}"', f'"{app_name}"')
    bootloader_code = bootloader_code.replace('"{DEVELOPER_HASH}"', f'"{developer_hash}"')
    bootloader_code = bootloader_code.replace('{PYSB_SALT_BYTES}', repr(pysb_salt))
    
    # Remove floating license reference entirely
    bootloader_code = bootloader_code.replace('hardware.ENABLE_FLOATING = {ENABLE_FLOATING_LICENSE}', '')
    
    # Generate the Hash-Map of the file order to hide the original filenames
    file_order_hashes = []
    for f_path in file_order:
        stem_path = str(Path(f_path).with_suffix("")).replace("\\", "/")
        h = hashlib.sha256(stem_path.encode('utf-8')).digest()
        file_order_hashes.append(h)
        
    bootloader_code = bootloader_code.replace('{FILE_ORDER_HASHES_LIST}', repr(file_order_hashes))
    bootloader_code = bootloader_code.replace('{PUBLIC_PEM_BYTES}', repr(public_pem))
    
    # Python Interpreter Anti-Tampering
    python_dll_path = find_python_dll()
    expected_dll_hash = ""
    if python_dll_path and python_dll_path.exists():
        with open(python_dll_path, "rb") as f:
            expected_dll_hash = hashlib.sha256(f.read()).hexdigest()
    
    bootloader_code = bootloader_code.replace('"{EXPECTED_PYTHON_DLL_HASH}"', f'"{expected_dll_hash}"')
    
    bootloader_src = build_stage / "bootloader.py"
    with open(bootloader_src, "w", encoding="utf-8") as f:
        f.write(bootloader_code)
        
    compile_modules(["bootloader.py"], build_stage, compiler_type=compiler_type)
    log.info("✓ Bootloader Cython compilation complete")
    
    # 8. Hash Compiled Bootloader and Derive Payload Key
    bootloader_hash = None
    for p in build_stage.iterdir():
        if p.is_file() and p.name.startswith("bootloader.") and p.suffix in [".pyd", ".so"]:
            with open(p, "rb") as f:
                bootloader_hash = hashlib.sha256(f.read()).digest()
            break
            
    if not bootloader_hash:
        log.error("Failed to find compiled bootloader for cryptographic binding.")
        sys.exit(1)
        
    final_integrity_hash = hashlib.sha256(deps_integrity_hash + bootloader_hash).digest()
    log.info("✓ Cryptographically bound bootloader to final integrity hash")
    
    # 9. Generate .pyob Payload
    from pyouro.builder.payload import generate_pyvb
    payload_src_path = project_root / payload_file
    payload_key = derive_pysb_key(final_integrity_hash, pysb_salt, app_name)
    
    pyvb_path = build_stage / f"{app_name}.pyob"
    generate_pyvb(payload_src_path, pyvb_path, payload_key, app_name, timestamp, prod_secrets)
    log.info("✓ Encrypted Core Payload and Secrets to %s.pyob", app_name)
    
    # 7. PyInstaller Orchestration (Forced Standalone Mode)
    print("\n--- Starting PyInstaller Packaging ---")
    runner_code = (
        "import sys, os, platform, subprocess, hashlib, ctypes, json\n"
        "import secrets, time, random, base64, marshal, pickle, pathlib\n"
        "import cryptography, keyring\n"
        "if os.name == 'nt':\n"
        "    import winreg, msvcrt\n"
        "else:\n"
        "    try: import fcntl\n"
        "    except ImportError: pass\n"
        "if getattr(sys, 'frozen', False):\n"
        "    sys.path.insert(0, sys._MEIPASS)\n"
        "import bootloader\n"
    )
    runner_path = build_stage / "pyouro_runner.py"
    with open(runner_path, "w", encoding="utf-8") as f:
        f.write(runner_code)
        
    import sys
    import subprocess
    cmd = [
        sys.executable, "-m", "PyInstaller", "--noconfirm", "--onedir", "--name", app_name,
        "--copy-metadata", "keyring",
        "--copy-metadata", "cryptography"
    ]
    
    build_config = config.get("build", {})
    
    # Check noconsole / console settings
    noconsole = build_config.get("noconsole", config.get("noconsole", False))
    console = build_config.get("console", config.get("console", None))
    if noconsole or (console is False):
        cmd.append("--noconsole")
        log.info("✓ GUI Mode enabled (console window hidden)")
        
    # Check icon settings
    icon = build_config.get("icon", config.get("icon", None))
    if icon:
        icon_path = project_root / icon
        if icon_path.exists():
            cmd.extend(["--icon", str(icon_path)])
            log.info("✓ App icon set to: %s", icon)
        else:
            log.warning("App icon file specified in config not found: %s", icon_path)
            
    # Allow passing custom PyInstaller flags from pyouro.toml
    extra_pyinstaller_args = build_config.get("pyinstaller_args", config.get("pyinstaller_args", []))
    if isinstance(extra_pyinstaller_args, list) and extra_pyinstaller_args:
        cmd.extend(extra_pyinstaller_args)
        log.info("✓ Appended %d custom PyInstaller flags", len(extra_pyinstaller_args))
    
    force_include = build_config.get("force_include", config.get("force_include", []))
    
    all_hidden_imports = ast_deps.union(set(force_include))
    
    for module_name in all_hidden_imports:
        cmd.extend(["--hidden-import", module_name])
        
    # Complex C/Rust libraries need full collection to avoid hazmat primitive misses
    cmd.extend(["--collect-all", "cryptography"])
    cmd.extend(["--collect-all", "keyring"])
    
    sep = ";" if sys.platform == "win32" else ":"
    for p in build_stage.rglob("*"):
        if p.is_file() and p.suffix in [".pyd", ".so", ".pyob"]:
            rel = p.relative_to(build_stage)
            parent_dir = rel.parent
            dest = "." if str(parent_dir) == "." else str(parent_dir)
            cmd.extend(["--add-data", f"{p}{sep}{dest}"])
            
    cmd.append(str(runner_path))
    
    try:
        subprocess.run(cmd, check=True, cwd=build_stage, capture_output=True, text=True)
        dist_path = build_stage / "dist" / app_name
        log.info("✓ PyInstaller standalone bundle created securely at: %s", dist_path)
        log.info("  (The Python Native Interpreter Library is now cryptographically bound!)")
    except FileNotFoundError:
        log.error("'pyinstaller' is not installed or not in PATH. Please run: pip install pyinstaller")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        log.error("PyInstaller build failed.\n%s", e.stderr)
        sys.exit(1)

    log.info("✓ Generated and compiled Bootloader with standalone executable")
    log.info("Build Completed Successfully!")
    log.info("Distribution ready in: %s", build_stage)
