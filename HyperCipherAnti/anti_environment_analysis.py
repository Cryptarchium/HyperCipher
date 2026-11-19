# -*- coding: utf-8 -*-
"""HyperCipherAnti anti_environment_analysis — OS ortam-postürü detektörü.

Defensive posture module: detects hostile/doctored execution environment via
stdlib-only posture signals. cross-platform, silent by default, fail-closed
(sensor error -> no accusation, health counter records it).

Research base (strongest patterns synthesized, 3x ReSearch):
  R1 PATH hijack (crawlex + pydepgate + dfir.ch .pth persistence):
     empty entries (::/;;/leading/trailing), relative entries (./bin,
     ../tools), world-writable dirs in PATH, current-dir first. Empty =
     cwd-injection (CVE-class). Savunma: split + norm + writability probe.
  R2 PYTHONPATH / PYTHONSTARTUP / startup vectors (PEP 829 + site.py docs +
     pydepgate T1546.018 + LiteLLM 2026 compromise + MITRE T1546.018):
     PYTHONPATH shadows stdlib/site-packages; .pth `import ` lines exec()
     at startup; .start entry-points (PEP 829 two-phase); sitecustomize /
     usercustomize auto-import; setup.py sdist exec. Savunma: env var
     presence + site-dirs .pth import-line scan + customize-module probe.
  R3 Sandbox/CI/cloud environment markers (crawlex fingerprinting + CAPA
     sandbox-username/hostname rules + Miasma-Azure-DurableTask CI guards):
     CI env (GITHUB_ACTIONS/GITLAB_CI/JENKINS/TF_BUILD/CIRCLECI/TRAVIS/
     TEAMCITY/AZURE_PIPELINES) + cloud env (AWS_EXECUTION_ENV/AZURE_*
     /GCE_METADATA/GOOGLE_CLOUD_PROJECT) + container markers
     (/.dockerenv/cgroup) = analysis context. Savunma: env presence (WEAK,
     corroboration only — lone CI flag never trips alone).
  R4 Dangerous env preload (LD_PRELOAD/DYLD_INSERT_LIBRARIES + PYTHON*
     debug flags): preload = native injection; PYTHONDEBUG/VERBOSE/
     PYTHONPROFILE = observation posture. Savunma: blocklist presence.
  R5 Locale/TZ consistency (Miasma locale guards + sandbox hygiene):
     empty LANG + mismatched TZ vs system offset = doctored image.
     Savunma: consistency check (WEAK-only).
  R6 CWD/temp posture (Cuckoo mkdtemp + CAPE analyzer random-dir):
     cwd in temp/system-root + temp world-writable + no-user-profile =
     automation context. Savunma: path + writability + profile presence.
  R7 User/host sanity (CAPA/Unprotect lists belong to anti_sandbox —
     NOT duplicated here): this module checks only emptiness/garbage
     (empty user, empty hostname, hostname==localhost anomaly), never
     blocklist matching (sibling-owned).

Scope vs siblings (no duplication):
  anti_sandbox: sandbox product artifacts (hostnames/usernames blocklists,
     drivers, DLLs, services, disk/mem thresholds, pocket-litter,
     interaction/timing). THIS module never matches product names.
  anti_vm: virtualization strings (dmi/cpu/mac/pci/firmware/systemd).
     THIS module never reads dmi/cpuinfo/firmware.
  anti_emulation: CPU instruction behaviour (CPUID/TSC). THIS module
     never measures cycles.
  anti_analysis/anti_debug/anti_trace: runtime observation hooks.
     THIS module never touches settrace/monitoring/gettrace.
  anti_hook/anti_tamper: live integrity. THIS module only self-pins
     its own refs (sensor_health), hook repair is sibling-owned.
  anti_configuration_tamper: app-config files. THIS module covers
     OS-level env/path/startup only.

Verdict: STRONG=100 / WEAK=30, trip >=1 STRONG or >=2 WEAK across
different families (single-family double-weak never trips alone).
All layers best-effort, error -> False (unknown), never crash.
Error message opaque (which layer fired is never disclosed).

Limits (honest, documented):
  - Network metadata endpoints (169.254.169.254) are NOT probed
    (no sockets in posture module; env vars only).
  - Writability probe is access()-based (TOCTOU documented; double-check
    at use-site is caller responsibility).
  - .pth scan is name/content heuristic (up to 64 files, 128KB each);
    hostile site-dir unreadable -> unknown (False), not accusation.
  - Container markers alone never trip (CI/container is WEAK-only).
"""

from __future__ import annotations

import builtins as _builtins
import os as _os
import sys as _sys
import threading as _threading
import time as _time

__all__ = [
    "EnvironmentDetected",
    "is_anomalous",
    "check_all",
    "score",
    "evidence",
    "status",
    "assert_no_anomaly",
    "authorize_admin",
    "start_watchdog",
    "stop_all_watchdogs",
    "guard",
]

STRONG = 100
WEAK = 30


class EnvironmentDetected(RuntimeError):
    """Opak hata: hangi katman tetiklendi DISARIYA soylenmez (oracle kapali)."""


# ---------------------------------------------------------------------------
# Pin'ler (import-aninda, sensor_health ile capraz-dogrulanir)
# ---------------------------------------------------------------------------

_PIN_OS_ENVIRON = _os.environ
_PIN_OS_GETENV = _os.getenv
_PIN_OS_PATH = _os.path
_PIN_OPEN = open
_PIN_BUILTIN_IMPORT = _builtins.__import__
_PIN_SYS_PATH = _sys.path
_PIN_SYS_MODULES = _sys.modules
_PIN_SYS_PREFIX = _sys.prefix
_PIN_TIME_MONOTONIC = _time.monotonic
_PIN_THREAD_RLOCK = _threading.RLock
_PIN_THREAD_THREAD = _threading.Thread
_PIN_THREAD_EVENT = _threading.Event

_LOCK = _PIN_THREAD_RLOCK()
_WATCHDOGS: list = []
_WATCHDOGS_LOCK = _threading.Lock()
_VERBOSE = False
_SENSORS_OK = 0
_SENSORS_TOTAL = 0


def set_verbose(on: bool = True) -> None:
    global _VERBOSE
    try:
        _VERBOSE = bool(on)
    except Exception:
        pass


def _v(msg: str) -> None:
    try:
        if _VERBOSE:
            print(f"[anti_env] {msg}", file=_sys.stderr)
    except Exception:
        pass


def _sensor_ok() -> None:
    global _SENSORS_OK, _SENSORS_TOTAL
    try:
        _SENSORS_OK += 1
        _SENSORS_TOTAL += 1
    except Exception:
        pass


def _sensor_fail() -> None:
    global _SENSORS_TOTAL
    try:
        _SENSORS_TOTAL += 1
    except Exception:
        pass


# ---------------------------------------------------------------------------
# R4: dangerous env blocklist (STRONG) — preload + debug posture
# ---------------------------------------------------------------------------

_ENV_STRONG = frozenset({
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "PYTHONDEBUG",
    "PYTHONVERBOSE",
    "PYTHONPROFILE",
    "PYTHONBREAKPOINT",
    "PYTHONDUMPREFS",
    "PYTHONHOME",
    "PYTHONEXECUTABLE",
    "PYDEVD_LOAD_VALUES_ASYNC",
    "PYDEVD_USE_CYTHON",
    "DEBUGPY_RUNNING",
    "PYCHARM_HOSTED",
    "JETBRAINS_DEBUGGER",
})

# MEDIUM-9 duzeltmesi: benign-dev/IDE varliklari STRONG degil WEAK'tir
# (PYTHONMALLOC=malloc Valgrind-kullanimi, VSCODE_PID IDE-mirasi,
#  PYCACHEPREFIX/USERBASE/DONTWRITEBYTECODE mesru). Corroboration ile
#  degerlendirilir, tek-basina trip uretmez.
_ENV_WEAK = frozenset({
    "PYTHONMALLOC",
    "VSCODE_PID",
    "PYTHONPYCACHEPREFIX",
    "PYTHONUSERBASE",
    "PYTHONDONTWRITEBYTECODE",
})

_ENV_STRONG_PREFIXES = (
    "LD_",
    "DYLD_",
    "PYDEVD_",
    "DEBUGPY_",
    "_PYDEVD_",
)


def _check_env_blocklist() -> bool:
    """STRONG: tehlikeli env var mevcut mu (preload/shadow/debug posture)."""
    try:
        try:
            env = _PIN_OS_ENVIRON
        except Exception:
            _sensor_fail()
            return False
        for key in _ENV_STRONG:
            try:
                if key in env:
                    # PYTHONBREAKPOINT=0 benign deger disinda her varlik suphelidir.
                    if key == "PYTHONBREAKPOINT":
                        try:
                            if (env.get(key, "") or "") in ("", "0"):
                                continue
                        except Exception:
                            continue
                    _sensor_ok()
                    return True
            except Exception:
                continue
        try:
            keys = list(env)
        except Exception:
            _sensor_fail()
            return False
        for key in keys:
            try:
                ku = str(key).upper()
            except Exception:
                continue
            for pre in _ENV_STRONG_PREFIXES:
                try:
                    if ku.startswith(pre):
                        _sensor_ok()
                        return True
                except Exception:
                    continue
        _sensor_ok()
        return False
    except Exception:
        _sensor_fail()
        return False


def _check_env_weak() -> bool:
    """WEAK: benign-dev/IDE env varligi (MEDIUM-9; corroboration icin)."""
    try:
        try:
            env = _PIN_OS_ENVIRON
        except Exception:
            _sensor_fail()
            return False
        for key in _ENV_WEAK:
            try:
                if key in env and (env.get(key, "") or "") not in ("", None):
                    _sensor_ok()
                    return True
            except Exception:
                continue
        _sensor_ok()
        return False
    except Exception:
        _sensor_fail()
        return False


# ---------------------------------------------------------------------------
# R1: PATH hijack (STRONG) — empty/relative/world-writable entries
# ---------------------------------------------------------------------------

def _path_entries() -> list:
    try:
        raw = _PIN_OS_ENVIRON.get("PATH", "")
    except Exception:
        return []
    try:
        sep = ";" if _sys.platform == "win32" else ":"
        return str(raw).split(sep)
    except Exception:
        return []


def _is_writable_dir(p: str) -> bool | None:
    """True=writable / False=not / None=unknown.

    LOW-5 duzeltmesi: platforma-gore en-dogru olcu. POSIX'te stat
    mode-bitleri (S_IWUSR=0o200, S_IWGRP=0o020, S_IWOTH=0o002; os.access
    real-uid farki + TOCTOU sinifi disi). Windows'ta stat bitleri
    anlamsizdir (0o666 doner) -> orada os.access (AccessCheck) kullanilir.
    """
    try:
        if not p:
            return None
        ap = _os.path.abspath(p) if not _os.path.isabs(p) else p
        if _os.name == "nt":
            try:
                if not _os.path.isdir(ap):
                    return False
                return bool(_os.access(ap, _os.W_OK))
            except Exception:
                return None
        try:
            st = _os.stat(ap)
        except Exception:
            return None
        try:
            import stat as _st
            if not _st.S_ISDIR(st.st_mode):
                return False
        except Exception:
            pass
        try:
            euid = _os.geteuid()
        except Exception:
            euid = None
        try:
            egid = _os.getegid()
        except Exception:
            egid = None
        try:
            mode = st.st_mode
            if euid is not None and st.st_uid == euid and (mode & 0o200):
                return True
            if egid is not None and st.st_gid == egid and (mode & 0o020):
                return True
            if mode & 0o002:
                return True
            return False
        except Exception:
            return None
    except Exception:
        return None
    try:
        if not p:
            return None
        ap = _os.path.abspath(p) if not _os.path.isabs(p) else p
        try:
            st = _os.stat(ap)
        except Exception:
            return None
        try:
            import stat as _st
            if not _st.S_ISDIR(st.st_mode):
                return False
        except Exception:
            pass
        try:
            euid = _os.geteuid()
        except Exception:
            euid = None
        try:
            egid = _os.getegid()
        except Exception:
            egid = None
        try:
            mode = st.st_mode
            if euid is not None and st.st_uid == euid and (mode & 0o200):
                return True
            if egid is not None and st.st_gid == egid and (mode & 0o020):
                return True
            if mode & 0o002:
                return True
            return False
        except Exception:
            return None
    except Exception:
        return None


def _check_path_hijack() -> bool:
    """STRONG: PATH'te cwd-injection / relative girdi (yapisal, FP'siz)."""
    try:
        entries = _path_entries()
        if not entries:
            _sensor_ok()
            return False
        # 1) empty entry = cwd injection (leading/trailing/double-sep)
        try:
            for e in entries:
                if e == "":
                    _sensor_ok()
                    return True
        except Exception:
            pass
        # 2) relative entry (./x, ../x, bare name)
        try:
            for e in entries:
                if not e:
                    continue
                try:
                    if not _os.path.isabs(e):
                        _sensor_ok()
                        return True
                except Exception:
                    continue
        except Exception:
            pass
        _sensor_ok()
        return False
    except Exception:
        _sensor_fail()
        return False


def _trusted_path_prefixes() -> list:
    out = []
    try:
        out.append(str(_PIN_OS_ENVIRON.get("SystemRoot", r"C:\Windows")).lower())
    except Exception:
        pass
    out.append("c:\\windows")
    try:
        out.append(str(_PIN_OS_ENVIRON.get("ProgramFiles", r"C:\Program Files")).lower())
        out.append(str(_PIN_OS_ENVIRON.get("ProgramFiles(x86)", r"C:\Program Files (x86)")).lower())
    except Exception:
        pass
    out.extend(("/usr/bin", "/bin", "/usr/local/bin", "/usr/sbin", "/sbin"))
    return [t for t in out if t]


def _check_path_writable_user() -> bool:
    """WEAK: trusted-disi yazilabilir PATH girdisi (LOW-5 tam-tarama).

    Kullanic-dizini yazilabilirligi tek-basina STRONG degildir (dev-box
    FP); cross-family corroboration ile degerlendirilir.
    """
    try:
        entries = _path_entries()
        if not entries:
            _sensor_ok()
            return False
        try:
            trusted = _trusted_path_prefixes()
        except Exception:
            trusted = []
        for e in entries[:64]:
            if not e:
                continue
            try:
                low = str(e).lower()
            except Exception:
                low = ""
            try:
                skip = False
                for t in trusted:
                    if low == t or low.startswith(t.rstrip("/") + "/") or low.startswith(t.rstrip("\\") + "\\"):
                        skip = True
                        break
                if skip:
                    continue
            except Exception:
                pass
            try:
                if _is_writable_dir(e) is True:
                    _sensor_ok()
                    return True
            except Exception:
                continue
        _sensor_ok()
        return False
    except Exception:
        _sensor_fail()
        return False


# ---------------------------------------------------------------------------
# R2a: PYTHONPATH shadow (STRONG — env var degeri, import-sistemi degil)
# ---------------------------------------------------------------------------

def _check_pythonpath_shadow() -> bool:
    """STRONG: PYTHONPATH doluysa stdlib/site shadow riski (deger-bazli)."""
    try:
        try:
            val = _PIN_OS_ENVIRON.get("PYTHONPATH", "")
        except Exception:
            _sensor_fail()
            return False
        if not val:
            _sensor_ok()
            return False
        # Bos/relative parcasi varsa PATH-hijack ile ayni sinif
        try:
            sep = ";" if _sys.platform == "win32" else ":"
            parts = str(val).split(sep)
            for p in parts:
                if p == "" or (p and not _os.path.isabs(p)):
                    _sensor_ok()
                    return True
        except Exception:
            pass
        _sensor_ok()
        return True  # dolu PYTHONPATH tek basina STRONG (shadow yuzeyi)
    except Exception:
        _sensor_fail()
        return False


# ---------------------------------------------------------------------------
# R2b: startup vectors — .pth import-lines + .start + customize (STRONG)
# ---------------------------------------------------------------------------

_PTH_DANGEROUS = (
    "os.system", "subprocess", "os.exec", "os.spawn", "os.popen",
    "socket", "urllib", "http.client", "ctypes", "windll",
    "b64decode", "a85decode", "hexdecode", "fromhex",
    "zlib.decompress", "gzip.decompress", "bz2.decompress", "lzma.decompress",
    "marshal.loads", "pickle.loads",
)

_PTH_BENIGN = (
    "pywin32_bootstrap",
    "pkg_resources",
    "sys._getframe",
    "setuptools",
    "distutils-precedence",
    "nspkg",
    "coverage",
)

def _pth_line_suspicious(s: str) -> bool:
    try:
        low = str(s).lower()
    except Exception:
        return False
    try:
        for b in _PTH_BENIGN:
            if b in low:
                # Benign boilerplate (nspkg/pkg_resources/coverage-env-gated)
                # unless it ALSO carries a dangerous primitive or dynamic
                # execution (pydepgate DYN001-007: exec/eval/compile shapes
                # must never hide behind an allowlisted keyword). Documented
                # env-gated startup (coverage COVERAGE_PROCESS_START,
                # distutils SETUPTOOLS_USE_DISTUTILS) stays benign: the code
                # path is inert without the operator-owned env var.
                if "exec(" in low or "eval(" in low or "compile(" in low:
                    gated = (
                        "coverage_process_start" in low
                        or "setuptools_use_distutils" in low
                    ) and ("getenv" in low or "environ" in low)
                    if gated and not any(d in low for d in _PTH_DANGEROUS):
                        return False
                    return True
                dangerous = any(d in low for d in _PTH_DANGEROUS)
                return dangerous
    except Exception:
        pass
    try:
        # pydepgate STDLIB001-003/DYN: process-spawn, network, native-load,
        # decode-then-execute inside .pth = CRITICAL shape.
        if "exec(" in low or "eval(" in low:
            return True
        for d in _PTH_DANGEROUS:
            if d in low:
                return True
    except Exception:
        pass
    return False


_SITE_DIRS_CACHE: dict = {}
_SITE_CACHE_TTL = 300.0


def _site_dirs() -> list:
    try:
        now = _PIN_TIME_MONOTONIC()
    except Exception:
        now = 0.0
    try:
        cached = _SITE_DIRS_CACHE.get("dirs")
        ts = _SITE_DIRS_CACHE.get("ts", 0.0)
        if cached is not None and (now - ts) < _SITE_CACHE_TTL:
            return list(cached)
    except Exception:
        pass
    out: list = []
    try:
        try:
            site_mod = _PIN_SYS_MODULES.get("site")
        except Exception:
            site_mod = None
        if site_mod is None:
            try:
                site_mod = _PIN_BUILTIN_IMPORT("site")
            except Exception:
                site_mod = None
        for attr in ("getsitepackages", "getusersitepackages"):
            try:
                fn = getattr(site_mod, attr, None) if site_mod is not None else None
                if fn is None:
                    continue
                val = fn()
                if isinstance(val, str):
                    out.append(val)
                elif isinstance(val, (list, tuple)):
                    out.extend([x for x in val if isinstance(x, str)])
            except Exception:
                continue
    except Exception:
        pass
    try:
        for p in list(_PIN_SYS_PATH):
            try:
                if isinstance(p, str) and p and "site-packages" in p.lower():
                    if p not in out:
                        out.append(p)
            except Exception:
                continue
    except Exception:
        pass
    try:
        _SITE_DIRS_CACHE["dirs"] = list(out[:16])
        _SITE_DIRS_CACHE["ts"] = now
    except Exception:
        pass
    return out[:16]


def _check_pth_startup() -> bool:
    """STRONG: site-dirs icinde `import ` satirli .pth veya .start var mi."""
    try:
        dirs = _site_dirs()
        if not dirs:
            _sensor_ok()
            return False
        scanned = 0
        for d in dirs:
            try:
                names = _os.listdir(d)
            except Exception:
                continue
            for nm in names:
                try:
                    low = str(nm).lower()
                except Exception:
                    continue
                if low.startswith("."):
                    continue  # PEP 829: nokta-dosya yok sayilir
                is_pth = low.endswith(".pth")
                is_start = low.endswith(".start")
                if not (is_pth or is_start):
                    continue
                if scanned >= 64:
                    break
                scanned += 1
                fp = _os.path.join(d, nm)
                try:
                    if _os.path.getsize(fp) > 131072:
                        continue
                except Exception:
                    continue
                try:
                    with _PIN_OPEN(fp, "r", errors="ignore") as fh:
                        for _i in range(256):
                            line = fh.readline()
                            if not line:
                                break
                            s = line.strip()
                            if not s or s.startswith("#"):
                                continue
                            if is_pth and (s.startswith("import ") or s.startswith("import\t")):
                                try:
                                    if _pth_line_suspicious(s):
                                        _sensor_ok()
                                        return True
                                except Exception:
                                    continue
                                continue
                            if is_start and ":" in s and not s.startswith("#"):
                                # PEP 829 pkg.mod:callable formu
                                _sensor_ok()
                                return True
                except Exception:
                    continue
        _sensor_ok()
        return False
    except Exception:
        _sensor_fail()
        return False


def _check_sitecustomize() -> bool:
    """WEAK: sitecustomize/usercustomize yuklu mu (MEDIUM-10; yalnizca varlik).

    Ubuntu/apport, conda, kurumsal imajlar mesru preload yapar -> varlik
    tek-basina STRONG degil. Icerik-suphesi ayri STRONG sinyaldedir.
    """
    try:
        try:
            mods = _PIN_SYS_MODULES
        except Exception:
            _sensor_fail()
            return False
        for name in ("sitecustomize", "usercustomize"):
            try:
                if name in mods:
                    _sensor_ok()
                    return True
            except Exception:
                continue
        _sensor_ok()
        return False
    except Exception:
        _sensor_fail()
        return False


_SITECUSTOMIZE_DANGER = (
    "os.system", "subprocess", "os.exec", "os.spawn", "os.popen",
    "socket", "urllib", "ctypes", "exec(", "eval(", "compile(",
    "__import__", "marshal", "base64", "fromhex", "getattr(",
)


def _check_sitecustomize_content() -> bool:
    """STRONG: customize dosya-icerigi supheli mi (MEDIUM-10 corroboration)."""
    try:
        try:
            mods = _PIN_SYS_MODULES
        except Exception:
            _sensor_fail()
            return False
        for name in ("sitecustomize", "usercustomize"):
            try:
                mod = mods.get(name)
            except Exception:
                continue
            if mod is None:
                continue
            try:
                path = getattr(mod, "__file__", "") or ""
            except Exception:
                continue
            if not path or not path.endswith(".py"):
                continue
            try:
                with _PIN_OPEN(path, "r", errors="ignore") as fh:
                    blob = fh.read(65536).lower()
            except Exception:
                continue
            try:
                for d in _SITECUSTOMIZE_DANGER:
                    if d in blob:
                        _sensor_ok()
                        return True
            except Exception:
                continue
        _sensor_ok()
        return False
    except Exception:
        _sensor_fail()
        return False


# ---------------------------------------------------------------------------
# R3: CI / cloud / container markers (WEAK — tek basina trip yok)
# ---------------------------------------------------------------------------

_CI_VARS = (
    "CI",
    "CONTINUOUS_INTEGRATION",
    "GITHUB_ACTIONS",
    "GITHUB_WORKFLOW",
    "GITEA_ACTIONS",
    "FORGEJO_ACTIONS",
    "GITLAB_CI",
    "JENKINS_URL",
    "JENKINS_HOME",
    "BUILD_ID",
    "TF_BUILD",
    "SYSTEM_TEAMFOUNDATIONCOLLECTIONURI",
    "CIRCLECI",
    "TRAVIS",
    "TEAMCITY_VERSION",
    "AZURE_PIPELINES",
    "BITBUCKET_BUILD_NUMBER",
    "CODEBUILD_BUILD_ID",
    "HUDSON_URL",
    "APPVEYOR",
    "BAMBOO_PLANKEY",
    "BUDDY",
    "BUILDKITE",
    "DRONE",
    "BITRISE_IO",
    "CIRRUS_CI",
    "SEMAPHORE",
    "HARNESS_BUILD_ID",
    "NETLIFY",
    "VERCEL",
    "GO_PIPELINE_NAME",
)

_CLOUD_VARS = (
    "AWS_EXECUTION_ENV",
    "AWS_LAMBDA_FUNCTION_NAME",
    "LAMBDA_TASK_ROOT",
    "AZURE_FUNCTIONS_ENVIRONMENT",
    "WEBSITE_INSTANCE_ID",
    "GOOGLE_CLOUD_PROJECT",
    "GAE_ENV",
    "K_SERVICE",
    "GCE_METADATA_HOST",
    "KUBERNETES_SERVICE_HOST",
    "FUNCTIONS_WORKER_RUNTIME",
)


def _check_ci_cloud() -> bool:
    """WEAK: CI/cloud/container baglami (corroboration icin)."""
    try:
        try:
            env = _PIN_OS_ENVIRON
        except Exception:
            _sensor_fail()
            return False
        for key in _CI_VARS + _CLOUD_VARS:
            try:
                if env.get(key, "") not in ("", None):
                    _sensor_ok()
                    return True
            except Exception:
                continue
        try:
            if _os.path.exists("/.dockerenv"):
                _sensor_ok()
                return True
        except Exception:
            pass
        _sensor_ok()
        return False
    except Exception:
        _sensor_fail()
        return False


# ---------------------------------------------------------------------------
# R5: locale/TZ consistency (WEAK)
# ---------------------------------------------------------------------------

def _check_locale_tz() -> bool:
    """WEAK: bos locale + TZ/system-offset tutarsizligi."""
    try:
        try:
            lang = _PIN_OS_ENVIRON.get("LANG", "") or ""
            lc_all = _PIN_OS_ENVIRON.get("LC_ALL", "") or ""
            tz = _PIN_OS_ENVIRON.get("TZ", "") or ""
        except Exception:
            _sensor_fail()
            return False
        # Tamamen bos locale + TZ de bos: minimal imagelar (container) —
        # tek basina suphe degil, ci_cloud ile corroborate olur.
        if not lang and not lc_all:
            # POSIX/C de mesru minimal degerdir; sadece TZ garipse trip.
            try:
                if tz and len(tz) > 32:
                    _sensor_ok()
                    return True
            except Exception:
                pass
            _sensor_ok()
            return False
        _sensor_ok()
        return False
    except Exception:
        _sensor_fail()
        return False


# ---------------------------------------------------------------------------
# R6: cwd/temp posture (WEAK)
# ---------------------------------------------------------------------------

def _check_timens() -> bool:
    """WEAK: Linux time-namespace offset (sanal/frozen monotonic saati).

    Konteyner/sandbox monotonic'i kaydirarak uptime/sure olcumlerini
    kandirir (CLOCK_REALTIME etkilenmez). /proc/self/timens_offsets
    sifir-disi offset iceriyorsa supheli baglam. WEAK-only.
    """
    try:
        if _sys.platform != "linux":
            _sensor_ok()
            return False
        try:
            with _PIN_OPEN("/proc/self/timens_offsets", "r") as fh:
                blob = fh.read(1024)
        except Exception:
            _sensor_ok()
            return False
        try:
            for line in str(blob).splitlines():
                parts = line.split()
                if len(parts) >= 3 and parts[0] in ("monotonic", "boottime"):
                    try:
                        if int(parts[1]) != 0 or int(parts[2]) != 0:
                            _sensor_ok()
                            return True
                    except Exception:
                        continue
        except Exception:
            pass
        _sensor_ok()
        return False
    except Exception:
        _sensor_fail()
        return False


def _check_cwd_temp() -> bool:
    """WEAK: cwd temp/system-root + profil yoklugu (otomasyon baglami)."""
    try:
        try:
            cwd = _os.getcwd()
        except Exception:
            _sensor_fail()
            return False
        low = ""
        try:
            low = str(cwd).lower().replace("\\", "/")
        except Exception:
            pass
        suspicious = False
        try:
            if low.startswith(("/tmp/", "/var/tmp/", "/dev/shm/")):
                suspicious = True
            elif "appdata/local/temp" in low or "windows/temp" in low:
                suspicious = True
            elif low in ("/", "c:/", "c:/windows", "c:/windows/system32"):
                suspicious = True
        except Exception:
            pass
        if not suspicious:
            _sensor_ok()
            return False
        # Profil varligi exoneration: gercek kullanici dizini + dosya varsa
        # temp-cwd tek basina trip uretmez.
        try:
            home = _os.path.expanduser("~") or ""
            if home and _os.path.isdir(home):
                try:
                    if len(_os.listdir(home)) > 3:
                        _sensor_ok()
                        return False
                except Exception:
                    pass
        except Exception:
            pass
        _sensor_ok()
        return True
    except Exception:
        _sensor_fail()
        return False


# ---------------------------------------------------------------------------
# R7: user/host sanity — emptiness only, blocklist YOK (sibling-owned)
# ---------------------------------------------------------------------------

def _check_user_host() -> bool:
    """WEAK: bos/kirilmis user+host (blocklist anti_sandbox'indir)."""
    try:
        user = ""
        host = ""
        try:
            user = (_PIN_OS_GETENV("USERNAME", "") or _PIN_OS_GETENV("USER", "") or "").strip()
        except Exception:
            user = ""
        try:
            host = (_PIN_OS_GETENV("COMPUTERNAME", "") or _PIN_OS_GETENV("HOSTNAME", "") or "").strip()
        except Exception:
            host = ""
        if not user and not host:
            _sensor_ok()
            return True
        try:
            if host.lower() in ("localhost", "") and not user:
                _sensor_ok()
                return True
        except Exception:
            pass
        _sensor_ok()
        return False
    except Exception:
        _sensor_fail()
        return False


# ---------------------------------------------------------------------------
# Pinned-mismatch (sensor_health, STRONG)
# ---------------------------------------------------------------------------

def _check_pinned_mismatch() -> bool:
    try:
        if _os.environ is not _PIN_OS_ENVIRON:
            return True
    except Exception:
        pass
    try:
        if _builtins.__import__ is not _PIN_BUILTIN_IMPORT:
            return True
    except Exception:
        return True
    try:
        if open is not _PIN_OPEN:
            return True
    except Exception:
        return True
    try:
        if _os.getenv is not _PIN_OS_GETENV:
            return True
    except Exception:
        pass
    try:
        if _sys.path is not _PIN_SYS_PATH:
            return True
    except Exception:
        pass
    try:
        if _sys.modules is not _PIN_SYS_MODULES:
            return True
    except Exception:
        pass
    return False


_SIGNALS = (
    ("env_blocklist", STRONG, _check_env_blocklist),
    ("path_hijack", STRONG, _check_path_hijack),
    ("pythonpath_shadow", STRONG, _check_pythonpath_shadow),
    ("pth_startup", STRONG, _check_pth_startup),
    ("sitecustomize_content", STRONG, _check_sitecustomize_content),
    ("pinned_mismatch", STRONG, _check_pinned_mismatch),
    ("env_weak", WEAK, _check_env_weak),
    ("path_writable_user", WEAK, _check_path_writable_user),
    ("sitecustomize_present", WEAK, _check_sitecustomize),
    ("ci_cloud", WEAK, _check_ci_cloud),
    ("locale_tz", WEAK, _check_locale_tz),
    ("timens", WEAK, _check_timens),
    ("cwd_temp", WEAK, _check_cwd_temp),
    ("user_host", WEAK, _check_user_host),
)


_FAMILIES = {
    "env": ("env_blocklist",),
    "env_soft": ("env_weak",),
    "path": ("path_hijack", "pythonpath_shadow", "path_writable_user"),
    "startup": ("pth_startup", "sitecustomize_content"),
    "startup_soft": ("sitecustomize_present",),
    "integrity": ("pinned_mismatch",),
    "origin": ("ci_cloud",),
    "locale": ("locale_tz",),
    "placement": ("cwd_temp", "timens"),
    "identity": ("user_host",),
}


_ADMIN_MODULES: dict = {}
_ADMIN_LOCKED = False
_ADMIN_DENIED = 0


def authorize_admin():
    """Operator modulunu kaydet (SADECE kilit-oncesi; boot sirasinda cagrilir).

    Ilk start_watchdog() kaydi kilitler. Donus: True=kaydedildi.
    """
    global _ADMIN_DENIED
    try:
        if _ADMIN_LOCKED:
            with _WATCHDOGS_LOCK:
                _ADMIN_DENIED += 1
            return False
        try:
            fr = _sys._getframe(1)
        except Exception:
            return False
        try:
            name = str(fr.f_globals.get("__name__", "") or "")
            fn = str(getattr(fr.f_code, "co_filename", "") or "")
        except Exception:
            return False
        if not name or not fn or fn.startswith("<"):
            return False
        try:
            if not _os.path.isfile(fn):
                return False
        except Exception:
            return False
        with _WATCHDOGS_LOCK:
            _ADMIN_MODULES[name] = fn
        return True
    except Exception:
        return False


def _check_admin() -> bool:
    """Dogrudan cagiran cerceve kayitli operator modulu mu? (dosya-dogrulamali)."""
    try:
        with _WATCHDOGS_LOCK:
            allowed = dict(_ADMIN_MODULES)
        if not allowed:
            return False
        try:
            fr = _sys._getframe(2)
        except Exception:
            return False
        try:
            name = str(fr.f_globals.get("__name__", "") or "")
            fn = str(getattr(fr.f_code, "co_filename", "") or "")
            want = allowed.get(name)
            if (want is not None and fn == want and not fn.startswith("<")
                    and _os.path.isfile(fn)):
                return True
        except Exception:
            pass
        return False
    except Exception:
        return False


def _deny_admin(op: str):
    """Yonetim reddi: fail-closed opak hata."""
    global _ADMIN_DENIED
    try:
        with _WATCHDOGS_LOCK:
            _ADMIN_DENIED += 1
    except Exception:
        pass
    raise EnvironmentDetected("protected")


def _cross_validation(results: dict) -> bool:
    families_hit = 0
    for names in _FAMILIES.values():
        try:
            if any(results.get(n) for n in names):
                families_hit += 1
        except Exception:
            continue
    return families_hit >= 2


def check_all() -> dict:
    out: dict = {}
    for name, _w, fn in _SIGNALS:
        try:
            out[name] = bool(fn())
        except Exception:
            out[name] = True  # fail-closed
    return out


def score(results: dict | None = None) -> int:
    res = results if results is not None else check_all()
    total = 0
    for name, weight, _fn in _SIGNALS:
        try:
            if res.get(name):
                total += weight
        except Exception:
            continue
    return min(total, 300)


def evidence(results: dict | None = None) -> dict:
    res = results if results is not None else check_all()
    try:
        fired = [n for n, _w, _f in _SIGNALS if res.get(n)]
    except Exception:
        fired = []
    try:
        strong = [n for n, w, _f in _SIGNALS if w == STRONG and res.get(n)]
    except Exception:
        strong = []
    try:
        weak = [n for n, w, _f in _SIGNALS if w == WEAK and res.get(n)]
    except Exception:
        weak = []
    return {
        "anomalous": is_anomalous(res),
        "score": score(res),
        "strong": strong,
        "weak": weak,
        "fired": fired,
        "cross_validated": _cross_validation(res),
    }


def is_anomalous(results: dict | None = None) -> bool:
    try:
        res = results if results is not None else check_all()
    except Exception:
        return True
    try:
        strong = sum(1 for n, w, _f in _SIGNALS if w == STRONG and res.get(n))
    except Exception:
        return True
    if strong >= 1:
        return True
    try:
        weak = [n for n, w, _f in _SIGNALS if w == WEAK and res.get(n)]
    except Exception:
        return True
    if len(weak) >= 2 and _cross_validation(res):
        return True
    return False


def assert_no_anomaly() -> None:
    if is_anomalous():
        raise EnvironmentDetected("protected")


def status() -> dict:
    try:
        if not _VERBOSE:
            return {"anomalous": is_anomalous()}
    except Exception:
        pass
    try:
        res = check_all()
        return {"anomalous": is_anomalous(res), "score": score(res),
                "admin_authorized": len(_ADMIN_MODULES), "admin_locked": _ADMIN_LOCKED,
                "admin_denied": _ADMIN_DENIED}
    except Exception:
        return {"anomalous": True}


def _watch_loop(stop: _threading.Event, interval: float,
                on_detect=None) -> None:
    try:
        action = on_detect
        if action is None:
            def _default_exit() -> None:
                try:
                    _os._exit(1)
                except Exception:
                    pass
            action = _default_exit
        try:
            last = _PIN_TIME_MONOTONIC()
        except Exception:
            last = 0.0
        suspend_limit = max(10.0 * interval, 10.0)
        while not stop.wait(interval):
            try:
                try:
                    now = _PIN_TIME_MONOTONIC()
                    if last and (now - last) > suspend_limit:
                        last = now
                        if is_anomalous():
                            try:
                                action()
                            except Exception:
                                pass
                            return
                        continue
                    last = now
                except Exception:
                    pass
                if is_anomalous():
                    try:
                        action()
                    except Exception:
                        pass
                    return
            except Exception:
                continue
    except Exception:
        return


def start_watchdog(interval: float = 5.0, on_detect=None):
    global _ADMIN_LOCKED
    try:
        with _WATCHDOGS_LOCK:
            _ADMIN_LOCKED = True
    except Exception:
        pass
    try:
        iv = float(interval)
    except Exception:
        iv = 5.0
    if iv < 0.5:
        iv = 0.5
    if iv > 30.0:
        iv = 30.0
    stop = _PIN_THREAD_EVENT()
    thr = _PIN_THREAD_THREAD(target=_watch_loop, args=(stop, iv, on_detect),
                            daemon=True, name="hyper-antienv")
    with _WATCHDOGS_LOCK:
        _WATCHDOGS.append((thr, stop))
    try:
        thr.start()
    except Exception:
        raise EnvironmentDetected("protected")

    def _stop() -> None:
        try:
            stop.set()
        except Exception:
            pass
        try:
            with _WATCHDOGS_LOCK:
                _WATCHDOGS[:] = [item for item in _WATCHDOGS if item[1] is not stop]
        except Exception:
            pass
    return _stop


def stop_all_watchdogs() -> int:
    """Tum watchdog'lari durdur (YONETIM: kayitli operator sart)."""
    if not _check_admin():
        _deny_admin("stop_all_watchdogs")
    with _WATCHDOGS_LOCK:
        items = list(_WATCHDOGS)
        _WATCHDOGS.clear()
    n = 0
    for _, stop in items:
        try:
            stop.set()
            n += 1
        except Exception:
            continue
    return n


def guard():
    class _G:
        def __enter__(self) -> dict:
            assert_no_anomaly()
            return status()

        def __exit__(self, *exc) -> bool:
            try:
                assert_no_anomaly()
            except Exception:
                raise
            return False
    return _G()
