import os
import ast
import json
import logging
import random
import secrets
import sys
from pathlib import Path

log = logging.getLogger("pyouro.init")

# Try importing cryptography, if missing warn the user
try:
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
except ImportError:
    logging.critical("'cryptography' library is not installed. Please run: pip install cryptography")
    sys.exit(1)

def find_local_imports(filepath, project_root):
    """
    AST tracing: find all local imports starting from a file.
    Returns a set of absolute paths to local .py files.
    """
    visited = set()
    to_visit = [Path(filepath).resolve()]
    project_root = Path(project_root).resolve()

    def resolve_import(module_name, level=0, current_file=None):
        if level > 0 and current_file:
            # Handle relative imports (from . import X)
            base_dir = current_file.parent
            for _ in range(level - 1):
                base_dir = base_dir.parent
            if module_name:
                parts = module_name.split('.')
                base_path = base_dir.joinpath(*parts)
            else:
                base_path = base_dir
        else:
            # Absolute import from project root
            if not module_name:
                return []
            parts = module_name.split('.')
            base_path = project_root.joinpath(*parts)
        
        candidates = [
            base_path.with_suffix('.py'),
            base_path / '__init__.py'
        ]
        return [p for p in candidates if p.exists()]

    while to_visit:
        current_file = to_visit.pop(0)
        if current_file in visited or not current_file.exists():
            continue
            
        visited.add(current_file)
        
        try:
            with open(current_file, 'r', encoding='utf-8') as f:
                tree = ast.parse(f.read(), filename=str(current_file))
                
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        for mod_path in resolve_import(alias.name):
                            if mod_path not in visited:
                                to_visit.append(mod_path)
                elif isinstance(node, ast.ImportFrom):
                    # Check the base module
                    base_paths = resolve_import(node.module, node.level, current_file)
                    for mod_path in base_paths:
                        if mod_path not in visited:
                            to_visit.append(mod_path)
                    
                    # Check if the imported names are submodules (e.g., from utils import helper -> utils/helper.py)
                    for alias in node.names:
                        sub_name = f"{node.module}.{alias.name}" if node.module else alias.name
                        sub_paths = resolve_import(sub_name, node.level, current_file)
                        for mod_path in sub_paths:
                            if mod_path not in visited:
                                to_visit.append(mod_path)
        except Exception as e:
            log.warning("Could not parse %s: %s", current_file, e)

    return visited

def generate_rsa_keys(vault_dir: Path):
    """Generates RSA private and public keys."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    with open(vault_dir / "private.pem", "wb") as f:
        f.write(private_pem)
    with open(vault_dir / "public.pem", "wb") as f:
        f.write(public_pem)
        
    padding_seed = secrets.token_hex(32)
    with open(vault_dir / "padding_seed.hex", "w", encoding="utf-8") as f:
        f.write(padding_seed)

def generate_secrets_templates(vault_dir: Path):
    """Creates empty YAML templates for secrets."""
    template = (
        "# PyOuro Secrets File\n"
        "# DO NOT COMMIT THIS FILE TO VERSION CONTROL.\n\n"
        "secrets:\n"
        "  # Add your secret keys here\n"
        "  # EXAMPLE_KEY: \"your_value\"\n"
    )
    with open(vault_dir / "dev_secrets.yaml", "w", encoding='utf-8') as f:
        f.write(template)
        
    with open(vault_dir / "prod_secrets.yaml", "w", encoding='utf-8') as f:
        f.write(template)

def update_gitignore(project_root: Path):
    """Adds .pyouro/ to .gitignore."""
    gitignore = project_root / ".gitignore"
    entry = "\n# PyOuro\n.pyouro/\npyouro_dist/\n"
    
    if gitignore.exists():
        with open(gitignore, "r", encoding='utf-8') as f:
            content = f.read()
        if ".pyouro/" not in content:
            with open(gitignore, "a", encoding='utf-8') as f:
                f.write(entry)
    else:
        with open(gitignore, "w", encoding='utf-8') as f:
            f.write(entry)

def create_pyouro_toml(project_root: Path, entry_point: str, payload_file: str):
    """Generates pyouro.toml configuration."""
    toml_content = f"""[app]
name = "MyProtectedApp"
version = "1.0.0"
entry_point = "{entry_point}"

[payload]
file = "{payload_file}"
entry_function = "bootstrap"

[security]
anti_debug = true

[build]
# noconsole = true          # Set to true to hide the terminal window (GUI apps)
# icon = "assets/icon.ico"  # Path to app icon
# force_include = ["dynamic_module1", "dynamic_module2"]
# pyinstaller_args = []     # Additional PyInstaller flags (e.g. ["--splash", "splash.png"])
"""
    with open(project_root / "pyouro.toml", "w", encoding='utf-8') as f:
        f.write(toml_content)

def run(entry_point: str, payload_file: str):
    """Main execution logic for 'pyouro init'."""
    project_root = Path.cwd()
    vault_dir = project_root / ".pyouro"

    log.info("Initializing PyOuro project...")

    # 1. Create .pyouro directory
    vault_dir.mkdir(exist_ok=True)
    log.info("✓ Created .pyouro/ directory")

    # 2. AST Tracing
    log.info("Analyzing dependencies from %s and %s...", entry_point, payload_file)
    entry_deps = find_local_imports(entry_point, project_root)
    payload_deps = find_local_imports(payload_file, project_root)
    all_deps = entry_deps.union(payload_deps)
    
    # Also add the entry point and payload themselves if not present
    all_deps.add(Path(entry_point).resolve())
    all_deps.add(Path(payload_file).resolve())

    # Filter out anything not in the project root
    local_files = [
        f.relative_to(project_root).as_posix() 
        for f in all_deps 
        if project_root in f.parents
    ]
    
    log.info("✓ Found %d local Python files", len(local_files))

    # 3. Generate Secret Order (file_order.json)
    random.shuffle(local_files)
    with open(vault_dir / "file_order.json", "w", encoding='utf-8') as f:
        json.dump(local_files, f, indent=4)
    log.info("✓ Generated secret file order (π)")

    # 4. Generate RSA Keys
    generate_rsa_keys(vault_dir)
    log.info("✓ Generated RSA Key Pair (private.pem, public.pem)")

    # 5. Generate Secrets Templates
    generate_secrets_templates(vault_dir)
    log.info("✓ Created dev_secrets.yaml and prod_secrets.yaml templates")

    # 6. Create TOML config
    create_pyouro_toml(project_root, entry_point, payload_file)
    log.info("✓ Created pyouro.toml configuration")

    # 7. Update .gitignore
    update_gitignore(project_root)
    log.info("✓ Updated .gitignore")

    log.info("\nInitialization complete! Please review pyouro.toml and fill your secrets in .pyouro/dev_secrets.yaml")
