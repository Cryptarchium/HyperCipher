import sys
import logging
from pathlib import Path

# Provide helpful error if missing dependencies
try:
    import toml
except ImportError:
    logging.critical("Missing dependencies. Please run: pip install toml pyyaml")
    sys.exit(1)

from pyouro.core import clean_cmd, init_cmd
from pyouro.builder import build_cmd

log = logging.getLogger("pyouro.rebuild")

def run(compiler_type=None):
    log.warning("'rebuild' resets all cryptographic materials. Previously issued licenses will still work, but a new init is required.")
    
    project_root = Path.cwd()
    toml_path = project_root / "pyouro.toml"
    
    if not toml_path.exists():
        log.error("pyouro.toml not found. Cannot rebuild without it.")
        sys.exit(1)
        
    try:
        with open(toml_path, "r", encoding="utf-8") as f:
            config = toml.load(f)
            
        entry_point = config.get("app", {}).get("entry_point")
        payload_file = config.get("payload", {}).get("file")
        
        if not entry_point or not payload_file:
            log.error("pyouro.toml is missing entry_point or payload_file. Cannot rebuild.")
            sys.exit(1)
    except Exception as e:
        log.error(f"Error reading pyouro.toml: {e}")
        sys.exit(1)

    clean_cmd.run(force=True)
    init_cmd.run(entry_point, payload_file)
    build_cmd.run(compiler_type=compiler_type)
