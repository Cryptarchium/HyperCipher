import sys
import json
import logging
from pathlib import Path

log = logging.getLogger("pyouro.doctor")

def run():
    log.info("Running PyOuro Doctor...")
    project_root = Path.cwd()
    vault_dir = project_root / ".pyouro"
    
    if not vault_dir.exists():
        log.error("❌ .pyouro directory is missing. Project not initialized.")
        sys.exit(1)
        
    log.info("✓ .pyouro directory found.")
    
    required_files = ["private.pem", "public.pem", "padding_seed.hex", "file_order.json", "dev_secrets.yaml", "prod_secrets.yaml", "pyouro.toml"]
    for req in required_files:
        if not (vault_dir / req).exists() and not (project_root / req).exists():
            log.warning("❌ Missing critical file: %s", req)
        else:
            log.info("✓ Found %s", req)
            
    try:
        with open(vault_dir / "file_order.json", "r") as f:
            file_order = json.load(f)
            
        log.info("✓ file_order.json loaded (%d files mapped).", len(file_order))
        
        missing_source = 0
        for rel_path in file_order:
            if not rel_path.startswith("pyouro_padding/") and not rel_path.startswith("pyouro/"):
                full_path = project_root / rel_path
                if not full_path.exists():
                    log.warning("  Warning: Source file mapped in file_order.json is missing from workspace: %s", rel_path)
                    missing_source += 1
                    
        if missing_source == 0:
            log.info("✓ All original source files are intact.")
    except Exception as e:
        log.error("❌ Error reading file_order.json: %s", e)
        
    log.info("PyOuro Health Check Complete.")
