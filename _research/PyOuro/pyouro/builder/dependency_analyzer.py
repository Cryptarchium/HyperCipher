import ast
import logging
from pathlib import Path

log = logging.getLogger("pyouro.analyzer")

class DependencyAnalyzer:
    @staticmethod
    def extract_imports_from_file(file_path: Path) -> set:
        imports = set()
        if not file_path.exists() or file_path.suffix != ".py":
            return imports
            
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                source = f.read()
            tree = ast.parse(source, filename=str(file_path))
            
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        # Take the full module path to ensure PyInstaller bundles specific submodules
                        imports.add(alias.name)
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        imports.add(node.module)
        except Exception as e:
            log.warning(f"Could not parse AST for {file_path}: {e}")
            
        return imports

    @staticmethod
    def get_all_dependencies(project_root: Path, file_order: list) -> set:
        """
        Scans all files in file_order to extract dependencies.
        Returns a set of top-level modules.
        """
        all_imports = set()
        for rel_path in file_order:
            full_path = project_root / rel_path
            all_imports.update(DependencyAnalyzer.extract_imports_from_file(full_path))
            
        # We exclude PyOuro itself or basic built-ins if we want, but PyInstaller safely ignores them.
        # Removing relative imports (None) or empty strings if any
        all_imports = {m for m in all_imports if m}
        
        return all_imports
