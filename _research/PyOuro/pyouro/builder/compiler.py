import os
import logging
import shutil
import subprocess
import sys
from pathlib import Path

log = logging.getLogger("pyouro.compiler")

def _secure_delete(file_path: Path):
    """Securely wipes the file by overwriting it with random bytes before deleting."""
    if not file_path.exists():
        return
    try:
        size = file_path.stat().st_size
        with open(file_path, "r+b") as f:
            f.write(os.urandom(size))
            f.flush()
            os.fsync(f.fileno())
    except Exception:
        pass
    try:
        file_path.unlink()
    except Exception:
        pass

def prepare_build_stage(project_root: Path, file_list: list) -> Path:
    """
    Prepares a clean build staging directory.
    Does NOT copy plaintext source files to avoid SSD Wear Leveling forensic recovery.
    """
    build_stage = project_root / "pyouro_dist" / "build_stage"
    
    # Fresh stage
    if build_stage.exists():
        shutil.rmtree(build_stage)
    build_stage.mkdir(parents=True)
            
    return build_stage

def compile_modules(source_files: list, build_dir: Path, compiler_type=None):
    """
    Compiles a list of Python files into Cython extensions (.pyd/.so).
    Reads original files from absolute paths and outputs into build_dir.
    """
    setup_script = build_dir / "setup_temp.py"
    project_root = build_dir.parent.parent
    
    import pyouro
    pyouro_pkg_path = Path(pyouro.__file__).parent
    
    # Cython Pre-processing: we inject directives for compatibility
    ext_modules_code = (
        "from setuptools import Extension, setup\n"
        "from Cython.Build import cythonize\n\n"
        "extensions = [\n"
    )
    
    for py_file in source_files:
        path_obj = Path(py_file)
        if path_obj.suffix != '.py':
            continue # Only compile Python files
            
        module_name = path_obj.with_suffix("").as_posix().replace("/", ".")
        
        if py_file.startswith("pyouro/"):
            rel_f = py_file[len("pyouro/"):]
            src_path = (pyouro_pkg_path / rel_f).absolute()
        elif py_file.startswith("pyouro_padding/") or py_file == "bootloader.py":
            src_path = (build_dir / py_file).absolute()
        else:
            src_path = (project_root / py_file).absolute()
            
        ext_modules_code += f'    Extension("{module_name}", [r"{str(src_path)}"]),\n'
        
    ext_modules_code += "]\n\n"
    ext_modules_code += (
        "setup(\n"
        "    ext_modules=cythonize(\n"
        "        extensions, \n"
        "        build_dir='cython_build',\n"
        "        compiler_directives={'language_level': '3', 'linetrace': False, 'binding': True, 'emit_code_comments': False},\n"
        "        quiet=True\n"
        "    )\n"
        ")\n"
    )
    
    with open(setup_script, "w", encoding='utf-8') as f:
        f.write(ext_modules_code)
        
    # Run compilation
    print(f"Compiling {len(source_files)} modules via Cython (this might take a while)...")
    try:
        cmd = [sys.executable, str(setup_script.name), "build_ext", "--build-lib", "."]
        if compiler_type:
            cmd.extend(["--compiler", compiler_type])
            
        result = subprocess.run(
            cmd,
            cwd=str(build_dir),
            capture_output=True,
            text=True,
            check=True
        )
    except subprocess.CalledProcessError as e:
        log.error("Error compiling modules with Cython. Make sure you have a C compiler installed.")
        log.error("--- Compiler Output ---")
        log.error(e.stdout or "")
        log.error(e.stderr or "")
        log.error("-----------------------")
        sys.exit(1)
        
    # Clean up artifacts
    if setup_script.exists():
        setup_script.unlink()
        
    # Delete the cython_build directory securely where .c files were generated
    cython_build_dir = build_dir / "cython_build"
    if cython_build_dir.exists():
        for c_file in cython_build_dir.rglob("*.c"):
            _secure_delete(c_file)
        shutil.rmtree(cython_build_dir)
        
    # Securely delete the dynamically generated padding source files
    padding_dir = build_dir / "pyouro_padding"
    if padding_dir.exists():
        for py_file in padding_dir.rglob("*.py"):
            _secure_delete(py_file)
        shutil.rmtree(padding_dir)
            
    # setuptools `build_ext --build-lib .` still creates a temporary 'build/' directory
    # containing .obj/.o files. We must remove it to leave only the pure binaries.
    temp_build_dir = build_dir / "build"
    if temp_build_dir.exists():
        for f in temp_build_dir.rglob("*"):
            if f.is_file():
                _secure_delete(f)
        shutil.rmtree(temp_build_dir)
