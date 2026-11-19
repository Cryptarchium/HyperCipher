import sys
import shutil
import logging
import time
from pathlib import Path

log = logging.getLogger("pyouro.clean")

def run(force: bool = False):
    if not force:
        log.warning("WARNING: 'pyouro clean' will remove the .pyouro directory and all cryptographic materials.")
        log.warning("If you do not have a backup, you will NEVER be able to issue licenses for previously distributed builds!")
        
        # In a real CLI environment, we'd use input(). For testing automation we can bypass or simulate.
        confirm = input("Type 'YES' in all caps to confirm and proceed: ")
        if confirm != "YES":
            log.info("Aborted.")
            sys.exit(0)
        
    project_root = Path.cwd()
    vault_dir = project_root / ".pyouro"
    
    if not vault_dir.exists():
        print("Nothing to clean. .pyouro not found.")
        sys.exit(0)
        
    backup_dir = project_root / f".pyouro_backup_{int(time.time())}"
    log.info("Creating safety backup at %s...", backup_dir.name)
    shutil.copytree(vault_dir, backup_dir)
    log.info("✓ Backup created.")
    
    shutil.rmtree(vault_dir)
    log.info("✓ Removed .pyouro directory.")
    
    dist_dir = project_root / "pyouro_dist"
    if dist_dir.exists():
        shutil.rmtree(dist_dir)
        log.info("✓ Removed pyouro_dist directory.")
        
    log.info("Clean completed. Run 'pyouro init' to start over.")
