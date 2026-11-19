import os
import sys
from pathlib import Path

def get_crash_dir(app_name: str) -> Path:
    """Resolves a secure, writeable directory for crash logs based on the OS."""
    try:
        if getattr(sys, 'frozen', False):
            base_dir = Path(sys.executable).parent
        else:
            base_dir = Path.cwd()
            
        crash_dir = base_dir / "logs"
        crash_dir.mkdir(parents=True, exist_ok=True)
        return crash_dir
    except Exception:
        # Fallback to temp dir if permissions fail
        import tempfile
        crash_dir = Path(tempfile.gettempdir()) / "PyOuro" / app_name
        try:
            crash_dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
        return crash_dir

def pyouro_crash_reporter(app_name: str, component: str, reason: str):
    """
    Centralized crash reporter for Frozen environments.
    Writes the fatal error to a robust location and exits safely.
    """
    try:
        crash_dir = get_crash_dir(app_name)
        log_file = crash_dir / f"{component}_crash.log"
        
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] FATAL ERROR in {component}: {reason}\n")
    except Exception:
        pass # Absolute fail-safe
        
    try:
        sys.stderr.write(f"Fatal Error: {component} ({reason})\n")
    except Exception:
        pass
        
    os._exit(1)
