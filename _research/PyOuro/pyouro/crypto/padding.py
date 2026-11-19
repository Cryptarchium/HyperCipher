import random
import hashlib
from pathlib import Path

def _generate_plausible_names(existing_names: list, seed: str, count: int) -> list:
    """
    Generates plausible padding file names based on existing naming conventions.
    """
    prefixes = ["core", "utils", "models", "db", "services", "api", "auth", "cache"]
    suffixes = ["helper", "manager", "monitor", "validator", "parser", "handler"]
    
    # Try to extract prefixes from existing files
    extracted_prefixes = set()
    for name in existing_names:
        parts = name.split('/')[-1].split('_')
        if parts:
            extracted_prefixes.add(parts[0])
            
    if extracted_prefixes:
        prefixes.extend(list(extracted_prefixes))
        
    rng = random.Random(seed)
    
    generated = set()
    attempts = 0
    while len(generated) < count and attempts < count * 10:
        attempts += 1
        prefix = rng.choice(prefixes)
        suffix = rng.choice(suffixes)
        
        name = f"{prefix}_{suffix}"
        if name not in existing_names and name not in generated:
            generated.add(name)
            
    return list(generated)

def generate_padding_files(target_dir: Path, file_order: list, secret_seed: str, target_count: int = 25) -> list:
    """
    Generates Cython-compatible padding files if the project has fewer than target_count files.
    Returns the updated file_order list containing the new padding files.
    """
    current_count = len(file_order)
    if current_count >= target_count:
        return file_order
        
    needed = target_count - current_count
    
    # Deterministic generation based on seed, so clean/build produces same padding names
    # for the same secret order seed, but different for different initializations.
    padding_names = _generate_plausible_names(file_order, secret_seed, needed)
    
    new_order = list(file_order)
    
    padding_dir = target_dir / "pyouro_padding"
    padding_dir.mkdir(exist_ok=True, parents=True)
    
    # Create an empty __init__.py to make it a valid Python package for Cython
    init_file = padding_dir / "__init__.py"
    if not init_file.exists():
        init_file.touch()
        new_order.append("pyouro_padding/__init__.py")
    
    for name in padding_names:
        # Generate valid Cython file content (just a dummy function)
        # Using realistic math and loops to avoid simple regex detection
        content = (
            f"def {name}_process(data: list) -> int:\n"
            f"    result = 0\n"
            f"    for i, item in enumerate(data):\n"
            f"        if i % 2 == 0:\n"
            f"            result += (sum(ord(c) for c in str(item)) % 1000) * {len(name)}\n"
            f"        else:\n"
            f"            result -= len(str(item)) * {sum(ord(c) for c in name)}\n"
            f"    return max(0, result)\n"
        )
        
        padding_file = padding_dir / f"{name}.py"
        with open(padding_file, "w", encoding='utf-8') as f:
            f.write(content)
            
        new_order.append(f"pyouro_padding/{name}.py")
        
    return new_order
