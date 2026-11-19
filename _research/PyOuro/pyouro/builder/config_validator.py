import toml
import yaml
import json
import logging
from pathlib import Path
import sys

log = logging.getLogger("pyouro.config")

class ConfigValidator:
    def __init__(self, project_root: Path, vault_dir: Path):
        self.project_root = project_root
        self.vault_dir = vault_dir

    def load_toml(self) -> dict:
        toml_path = self.project_root / "pyouro.toml"
        if not toml_path.exists():
            log.error(f"Configuration file {toml_path} not found.")
            sys.exit(1)
            
        try:
            with open(toml_path, "r", encoding="utf-8") as f:
                config = toml.load(f)
            if not isinstance(config, dict):
                raise ValueError("pyouro.toml must be a valid dictionary at root level.")
            return config
        except Exception as e:
            log.error(f"Failed to parse pyouro.toml: {e}")
            sys.exit(1)

    def load_prod_secrets(self) -> dict:
        yaml_path = self.vault_dir / "prod_secrets.yaml"
        if not yaml_path.exists():
            return {}
            
        try:
            with open(yaml_path, "r", encoding="utf-8") as f:
                parsed = yaml.safe_load(f)
                
            # Treat empty file as empty dictionary
            if parsed is None:
                parsed = {}
                
            if not isinstance(parsed, dict):
                raise ValueError("prod_secrets.yaml must contain a valid dictionary mapping.")
                
            return parsed.get("secrets", parsed)
        except Exception as e:
            log.error(f"Failed to parse prod_secrets.yaml: {e}")
            sys.exit(1)

    def load_file_order(self) -> list:
        json_path = self.vault_dir / "file_order.json"
        if not json_path.exists():
            log.error(f"{json_path} not found. Did you run 'pyouro init'?")
            sys.exit(1)
            
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                order = json.load(f)
            if not isinstance(order, list):
                raise ValueError("file_order.json must be a JSON array.")
            return order
        except Exception as e:
            log.error(f"Failed to parse file_order.json: {e}")
            sys.exit(1)
