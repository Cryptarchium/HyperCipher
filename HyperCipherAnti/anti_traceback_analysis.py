"""Anti traceback-analysis sensor.

Detects hostile use of the ``traceback`` machinery itself:

- traceback module attribute swap (harvester shim over extract/format APIs)
- live foreign-frame traceback formatting (locals harvesting in progress)
- artificially deep ``tb_next`` chains (fuzzing / probing residue)
- retained raw traceback objects in gc (frames + f_locals kept alive)
- ``sys.tracebacklimit`` anomalies (suppression or full-harvest tuning)

Scope note: exception-hook integrity, post-mortem debuggers and
``sys.last_*`` residue belong to ``anti_exception_analysis`` and are
deliberately NOT duplicated here.  This module only covers the
traceback-module surface: its code objects, its live call stack, the
``tb_next`` chain shape, gc retention and the tracebacklimit knob.

Standard library only. Silent by default, fail-closed.
"""

from __future__ import annotations

import gc
import inspect
import os
import re
import sys
import threading
import traceback as _TB_MOD
from contextlib import contextmanager
from types import ModuleType, TracebackType
from typing import Any, Dict, Iterator, Optional

__all__ = [
    "check_all",
    "is_tripped",
    "is_analyzed",
    "score",
    "evidence",
    "status",
    "set_verbose",
    "guard",
    "sanitize_current",
    "safe_format",
    "start_watchdog",
    "stop_watchdog",
    "watchdog_alive",
    "watchdog_tripped",
    "authorize_admin",
    "arm_frame_watch",
    "frame_watch_armed",
    "reset_frame_latch",
]

_HERE = __file__

_verbose = False


class TracebackHarvestDetected(RuntimeError):
    """Opak hata: hangi sinyal tetiklendi DISARIYA soylenmez (oracle kapali)."""


def set_verbose(on: bool = True) -> None:
    global _verbose
    _verbose = bool(on)


def _log(msg: str) -> None:
    if _verbose:
        sys.stderr.write("[anti_traceback] %s\n" % msg)


# ---------------------------------------------------------------------------
# Pinned references (captured at import; attacker shims compare unequal)
# ---------------------------------------------------------------------------

_PIN_MODULE: ModuleType = _TB_MOD
_PIN_FUNCS: Dict[str, Any] = {}
for _name in (
    "extract_tb",
    "extract_stack",
    "format_tb",
    "format_list",
    "format_exc",
    "format_exception",
    "print_tb",
    "print_exc",
    "print_exception",
    "walk_tb",
    "walk_stack",
    "clear_frames",
):
    try:
        _PIN_FUNCS[_name] = getattr(_TB_MOD, _name)
    except AttributeError:
        continue
try:
    _PIN_STACK_SUMMARY = _TB_MOD.StackSummary
    _PIN_TB_EXCEPTION = _TB_MOD.TracebackException
    _PIN_FRAME_SUMMARY = _TB_MOD.FrameSummary
except AttributeError:  # pragma: no cover - very old interpreters
    _PIN_STACK_SUMMARY = None
    _PIN_TB_EXCEPTION = None
    _PIN_FRAME_SUMMARY = None

try:
    _PIN_LIMIT = sys.tracebacklimit
except AttributeError:
    _PIN_LIMIT = None

# Live traceback format/extract entry points.  A foreign frame executing
# inside any of these while we inspect means harvesting is in progress.
_FORMAT_API = frozenset(
    {
        "extract_tb",
        "extract_stack",
        "format_tb",
        "format_list",
        "format_exc",
        "format_exception",
        "format_exception_only",
        "print_tb",
        "print_exc",
        "print_exception",
        "walk_tb",
        "walk_stack",
        "from_exception",
        "__init__",  # TracebackException.__init__ / StackSummary.extract path
        "extract",
        "format",
        "print",  # TracebackException.print / print_tb family
    }
)

# Expected home of the genuine stdlib traceback code objects.  Pinning alone
# is blind when the swap predates our import; the co_filename check below
# catches a shim even in that case.
_TB_FILE = os.path.basename(getattr(_PIN_MODULE, "__file__", "") or "")

# Tuning thresholds.
_CHAIN_DEPTH_WEAK = 64
_RETENTION_WEAK = 8
_GC_SCAN_CAP = 40000


# ---------------------------------------------------------------------------
# Signal 1 (STRONG): traceback module pin
# ---------------------------------------------------------------------------

def _check_module_pin() -> bool:
    """True when the traceback module or its harvest APIs were swapped."""
    try:
        live = sys.modules.get("traceback", None)
        if live is not _PIN_MODULE:
            _log("module_pin: sys.modules['traceback'] identity changed")
            return True
        # LOW-fix: import-oncesi shim yakalama — pin esitligi yetmez,
        # origin de pinli modulun diziniyle eslesmeli (saf-Python shim
        # baska dosyadan gelir).
        try:
            spec = getattr(live, "__spec__", None)
            origin = (getattr(spec, "origin", "") or "") if spec is not None else ""
            home = getattr(_PIN_MODULE, "__file__", "") or ""
            if origin and home and origin not in ("built-in", "frozen"):
                try:
                    std = os.path.dirname(os.path.abspath(home))
                    here = os.path.dirname(os.path.abspath(origin))
                    if os.path.normcase(here) != os.path.normcase(std):
                        _log("module_pin: alien origin %s" % origin)
                        return True
                except Exception:
                    pass
        except Exception:
            pass
        for name, pinned in _PIN_FUNCS.items():
            try:
                live_fn = getattr(live, name, None)
                if live_fn is not pinned:
                    _log("module_pin: traceback.%s swapped" % name)
                    return True
                try:
                    code = getattr(live_fn, "__code__", None)
                    home = os.path.basename(getattr(code, "co_filename", ""))
                    if code is not None and home != "" and home != _TB_FILE:
                        _log("module_pin: traceback.%s alien code (%s)" % (name, home))
                        return True
                except Exception:
                    pass
            except Exception:
                return True
        for label, pinned in (
            ("StackSummary", _PIN_STACK_SUMMARY),
            ("TracebackException", _PIN_TB_EXCEPTION),
            ("FrameSummary", _PIN_FRAME_SUMMARY),
        ):
            if pinned is None:
                continue
            try:
                if getattr(live, label, None) is not pinned:
                    _log("module_pin: traceback.%s swapped" % label)
                    return True
            except Exception:
                return True
    except Exception:
        return True
    return False


# ---------------------------------------------------------------------------
# Signal 2 (STRONG): live foreign-frame formatting
# ---------------------------------------------------------------------------

def _iter_stack_frames() -> Iterator[Any]:
    try:
        frame = inspect.currentframe()
    except Exception:
        return
    try:
        # Skip this helper frame itself.
        frame = frame.f_back if frame is not None else None
        while frame is not None:
            yield frame
            try:
                frame = frame.f_back
            except Exception:
                break
    finally:
        del frame


def _is_own_frame(frame: Any) -> bool:
    try:
        if frame.f_code.co_filename == _HERE:
            return True
        return frame.f_globals.get("__name__", "") == __name__
    except Exception:
        return False


def _is_stdlib_tb_file(filename: str) -> bool:
    try:
        return bool(filename) and filename == getattr(_PIN_MODULE, "__file__", None)
    except Exception:
        return False


def _check_live_format_abuse() -> bool:
    """True when traceback formatting runs on behalf of a foreign caller."""
    try:
        frames = list(_iter_stack_frames())
    except Exception:
        return True
    try:
        for idx, frame in enumerate(frames):
            try:
                code = frame.f_code
                filename = code.co_filename
                funcname = code.co_name
            except Exception:
                continue
            if _is_own_frame(frame):
                continue
            if _is_stdlib_tb_file(filename or ""):
                try:
                    caller = frames[idx + 1]
                    c_code = caller.f_code
                    c_file = c_code.co_filename
                except Exception:
                    continue
                if not _is_own_frame(caller) and not _is_stdlib_tb_file(c_file or ""):
                    _log("live_format: foreign caller %s drives %s" % (c_file, funcname))
                    return True
                continue
            if funcname in _FORMAT_API:
                _log("live_format: foreign %s in %s" % (filename, funcname))
                return True
    except Exception:
        return True
    return False


# ---------------------------------------------------------------------------
# Signal 3 (WEAK): tb_next chain depth anomaly
# ---------------------------------------------------------------------------

def _live_traceback() -> Optional[TracebackType]:
    try:
        exc = sys.exception()  # type: ignore[attr-defined]
    except AttributeError:
        exc = sys.exc_info()[1]
    except Exception:
        return None
    try:
        tb = getattr(exc, "__traceback__", None)
    except Exception:
        return None
    return tb if isinstance(tb, TracebackType) else None


def _chain_depth(tb: Optional[TracebackType], cap: int = 4096) -> int:
    depth = 0
    seen = set()
    while tb is not None and depth < cap:
        if id(tb) in seen:
            break
        seen.add(id(tb))
        depth += 1
        try:
            tb = tb.tb_next
        except Exception:
            break
    return depth


def _check_format_residue() -> bool:
    """WEAK: canli TracebackException/StackSummary/FrameSummary kalintisi.

    MED-fix (live_format near-dead): mikrosaniyelik canli-format penceresi
    yerine OLUMSUZ kalinti gozlenir — harvester format-sonrasi nesneleri
    tutar (ozellikle capture_locals=True locals-hasadi). Esikler:
    toplam>=8 veya locals-tasiyan>=2. Mesru hata-akisindaki gecici
    nesneler esigin altinda kalir.
    """
    try:
        total = 0
        with_locals = 0
        scanned = 0
        TE = _PIN_TB_EXCEPTION
        SS = _PIN_STACK_SUMMARY
        FS = _PIN_FRAME_SUMMARY
        for obj in gc.get_objects():
            scanned += 1
            if scanned >= _GC_SCAN_CAP:
                break
            try:
                t = type(obj)
                is_te = TE is not None and t is TE
                is_ss = SS is not None and t is SS
                is_fs = FS is not None and t is FS
                if not (is_te or is_ss or is_fs):
                    continue
                total += 1
                try:
                    loc = getattr(obj, "locals", None)
                    if loc:
                        with_locals += 1
                except Exception:
                    pass
                try:
                    stack = getattr(obj, "stack", None)
                    if stack is not None:
                        try:
                            for fr in getattr(stack, "__iter__", lambda: [])():
                                try:
                                    if getattr(fr, "locals", None):
                                        with_locals += 1
                                        break
                                except Exception:
                                    continue
                        except Exception:
                            pass
                except Exception:
                    pass
                if total >= 8 or with_locals >= 2:
                    _log("format_residue: total=%d locals=%d" % (total, with_locals))
                    return True
            except Exception:
                continue
    except Exception:
        return True
    return False


def _check_chain_depth() -> bool:
    tb = _live_traceback()
    if tb is None:
        return False
    try:
        depth = _chain_depth(tb)
    except Exception:
        return True
    if depth >= _CHAIN_DEPTH_WEAK:
        _log("chain_depth: tb_next depth=%d" % depth)
        return True
    return False


# ---------------------------------------------------------------------------
# Signal 4 (WEAK): retained raw traceback objects in gc
# ---------------------------------------------------------------------------

def _check_tb_retention() -> bool:
    """True when more than a handful of raw tracebacks stay alive in gc."""
    try:
        count = 0
        scanned = 0
        for obj in gc.get_objects():
            scanned += 1
            if scanned >= _GC_SCAN_CAP:
                break
            if type(obj) is TracebackType:
                count += 1
                if count > _RETENTION_WEAK:
                    _log("retention: %d live tracebacks" % count)
                    return True
    except Exception:
        return True
    return False


# ---------------------------------------------------------------------------
# Signal 5 (WEAK): sys.tracebacklimit anomaly
# ---------------------------------------------------------------------------

def _check_tracebacklimit() -> bool:
    try:
        if not hasattr(sys, "tracebacklimit"):
            return _PIN_LIMIT is not None
        cur = sys.tracebacklimit
    except Exception:
        return True
    try:
        if cur is None:
            return False
        val = int(cur)
    except Exception:
        _log("tracebacklimit: non-integer value")
        return True
    if val <= 0 or val > 1000:
        _log("tracebacklimit: anomalous value=%r" % (cur,))
        return True
    return False


# ---------------------------------------------------------------------------
# Signal 6 (WEAK, opt-in): audited tb_frame / f_code access by foreign code
# ---------------------------------------------------------------------------

_AUDIT_ATTRS = frozenset(
    {
        "tb_frame",
        "f_code",
        "gi_code",
        "gi_frame",
        "cr_code",
        "cr_frame",
        "ag_code",
        "ag_frame",
    }
)

_audit_armed = False
_frame_access_latched = False


def _audit_hook(event: str, args: Any) -> None:
    global _frame_access_latched
    try:
        if event != "object.__getattr__":
            return
        try:
            name = args[1]
        except Exception:
            return
        if name not in _AUDIT_ATTRS:
            return
        try:
            frame = inspect.currentframe()
        except Exception:
            return
        try:
            frame = frame.f_back if frame is not None else None
            while frame is not None:
                try:
                    if frame.f_globals.get("__name__", "") == __name__:
                        return
                except Exception:
                    pass
                try:
                    frame = frame.f_back
                except Exception:
                    break
        finally:
            del frame
        _frame_access_latched = True
    except Exception:
        pass


def arm_frame_watch() -> bool:
    """Arm the process-wide audit listener for frame harvesting.

    Irreversible by interpreter design (audit hooks cannot be removed),
    hence explicit opt-in and OFF by default.  Returns True when armed.
    """
    global _audit_armed
    if _audit_armed:
        return True
    try:
        sys.addaudithook(_audit_hook)
    except Exception:
        return False
    _audit_armed = True
    return True


def frame_watch_armed() -> bool:
    return bool(_audit_armed)


def reset_frame_latch() -> None:
    """Latch sifirla (YONETIM: kayitli operator sart)."""
    if not _tb_check_admin():
        _tb_deny_admin("reset_frame_latch")
    global _frame_access_latched
    _frame_access_latched = False


def _check_frame_access() -> bool:
    if not _audit_armed:
        return False
    return bool(_frame_access_latched)


# ---------------------------------------------------------------------------
# Registry + verdict
# ---------------------------------------------------------------------------

_RAW_CHECKS = (
    ("module_pin", _check_module_pin),
    ("live_format_abuse", _check_live_format_abuse),
    ("format_residue", _check_format_residue),
    ("chain_depth", _check_chain_depth),
    ("tb_retention", _check_tb_retention),
    ("tracebacklimit", _check_tracebacklimit),
    ("frame_access", _check_frame_access),
)

_STRONG = frozenset({"module_pin", "live_format_abuse"})
_WEAK = frozenset({"format_residue", "chain_depth", "tb_retention", "tracebacklimit", "frame_access"})


def _ensure_armed() -> None:
    """MED-fix: ilk kullanimda audit-gozlem otomatik kurulur.

    frame_access/frame-kanali default-kordu (opt-in unutulursa olu sinyal).
    Audit hook geri-alinamaz (interpreter-tasarimi) — tek seferlik,
    best-effort, sessiz.
    """
    try:
        if not _audit_armed:
            try:
                arm_frame_watch()
            except Exception:
                pass
    except Exception:
        pass


def _run_raw() -> Dict[str, bool]:
    _ensure_armed()
    out: Dict[str, bool] = {}
    for name, fn in _RAW_CHECKS:
        try:
            out[name] = bool(fn())
        except Exception:
            out[name] = True
    return out


def _verdict(raw: Dict[str, bool]) -> bool:
    if any(raw.get(name, False) for name in _STRONG):
        return True
    weak_hits = sum(1 for name in _WEAK if raw.get(name, False))
    return weak_hits >= 2


def check_all() -> Dict[str, bool]:
    raw = _run_raw()
    raw["verdict"] = _verdict(raw)
    return raw


def is_tripped() -> bool:
    return _verdict(_run_raw())


def is_analyzed() -> bool:
    return is_tripped()


def score() -> int:
    raw = _run_raw()
    total = sum(2 for n in _STRONG if raw.get(n, False))
    total += sum(1 for n in _WEAK if raw.get(n, False))
    return total


def evidence() -> Dict[str, Any]:
    raw = _run_raw()
    try:
        depth = _chain_depth(_live_traceback())
    except Exception:
        depth = -1
    try:
        limit = getattr(sys, "tracebacklimit", None)
    except Exception:
        limit = "<unreadable>"
    return {
        "raw": raw,
        "verdict": _verdict(raw),
        "chain_depth": depth,
        "tracebacklimit": limit,
    }


def status() -> Dict[str, Any]:
    ev = evidence()
    ev["watchdog"] = watchdog_alive()
    return ev


# ---------------------------------------------------------------------------
# Hygiene helpers (additive; detection of residue stays in exception module)
# ---------------------------------------------------------------------------

def sanitize_current() -> bool:
    """Clear frame locals of the live exception chain + drop last_* residue.

    Uses the stdlib-blessed ``traceback.clear_frames`` so retained frames
    stop pinning secrets.  Returns True when a live chain was sanitized.
    """
    tb = _live_traceback()
    if tb is None:
        return False
    try:
        clear_fn = _PIN_FUNCS.get("clear_frames", None)
        code = getattr(clear_fn, "__code__", None)
        home = os.path.basename(getattr(code, "co_filename", "") or "")
        if clear_fn is None or code is None or (home != "" and home != _TB_FILE):
            return False
        clear_fn(tb)
    except Exception:
        return False
    for attr in ("last_type", "last_value", "last_traceback", "last_exc"):
        try:
            if hasattr(sys, attr):
                delattr(sys, attr)
        except Exception:
            continue
    return True


_SECRET_SCRUB_KEY = re.compile(
    r"(?i)\b(password|passwd|secret|api[_-]?key|auth[_-]?token|private[_-]?key"
    r"|seed|mnemonic|client[_-]?secret)\b['\"]?\s*[:=]\s*['\"]?[^\s,'\"})\]{}>]+"
)
_SECRET_SCRUB_VALUE = re.compile(
    r"Bearer\s+[A-Za-z0-9\-._~+/]{10,}=*"
    r"|\bsk-[A-Za-z0-9\-_]{16,}"
    r"|\b(?:AKIA|ASIA)[0-9A-Z]{16}"
    r"|\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_.\-/+=]+"
    r"|-----BEGIN[A-Z \-]*PRIVATE KEY-----[\s\S]*?-----END[A-Z \-]*PRIVATE KEY-----"
)


def safe_format(exc: BaseException, limit: Optional[int] = None) -> str:
    """Format an exception without touching frame locals.

    ``capture_locals`` is deliberately off: rendering every local calls
    ``repr()`` on attacker-controlled objects.  Secrets in the message
    itself are scrubbed by pattern instead, and paths shrink to basenames.
    """
    try:
        te_cls = _PIN_TB_EXCEPTION if _PIN_TB_EXCEPTION is not None else _TB_MOD.TracebackException
        te = te_cls(
            type(exc), exc, exc.__traceback__, limit=limit, capture_locals=False
        )
        for frame in te.stack:
            try:
                full = getattr(frame, "filename", "")
                if full and full not in ("<unknown>",):
                    frame.filename = os.path.basename(full)
            except Exception:
                continue
        text = "".join(te.format())
    except Exception:
        try:
            text = "".join(_TB_MOD.format_exception_only(type(exc), exc))
        except Exception:
            return "<unformattable exception>"
    try:
        text = _SECRET_SCRUB_KEY.sub(r"\1=***REDACTED***", text)
        text = _SECRET_SCRUB_VALUE.sub("***REDACTED***", text)
    except Exception:
        pass
    return text


# ---------------------------------------------------------------------------
# Guard + watchdog
# ---------------------------------------------------------------------------

@contextmanager
def guard() -> Iterator[Dict[str, bool]]:
    """MED-fix: trip'te YUKSELEN guard — giriste assert, cikista trip-raise.

    tracebacklimit snapshot/restore korunur; trip govde-hatasini yutmaz
    (zincirlenir). Kards-guard paritesi.
    """
    try:
        had = hasattr(sys, "tracebacklimit")
        saved = getattr(sys, "tracebacklimit", None)
    except Exception:
        had, saved = False, None
    try:
        if is_tripped():
            raise TracebackHarvestDetected("protected")
        yield check_all()
        if is_tripped():
            raise TracebackHarvestDetected("protected")
    except TracebackHarvestDetected:
        raise
    except Exception as e:
        try:
            if is_tripped():
                raise TracebackHarvestDetected("protected") from e
        except TracebackHarvestDetected:
            raise
        except Exception:
            pass
        raise
    finally:
        try:
            if had:
                sys.tracebacklimit = saved
            elif hasattr(sys, "tracebacklimit"):
                delattr(sys, "tracebacklimit")
        except Exception:
            pass


_watchdog_thread: Optional[threading.Thread] = None
_watchdog_stop = threading.Event()
_watchdog_tripped = False
_TB_ADMINS: dict = {}
_TB_ADMIN_LOCKED = False
_TB_ADMIN_DENIED = 0


def authorize_admin():
    """Operator modulunu kaydet (SADECE kilit-oncesi; boot sirasinda cagrilir)."""
    global _TB_ADMIN_DENIED
    try:
        if _TB_ADMIN_LOCKED:
            _TB_ADMIN_DENIED += 1
            return False
        try:
            fr = sys._getframe(1)
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
            if not os.path.isfile(fn):
                return False
        except Exception:
            return False
        _TB_ADMINS[name] = fn
        return True
    except Exception:
        return False


def _tb_check_admin() -> bool:
    """Dogrudan cagiran cerceve kayitli operator modulu mu? (dosya-dogrulamali)."""
    try:
        allowed = dict(_TB_ADMINS)
        if not allowed:
            return False
        try:
            fr = sys._getframe(2)
        except Exception:
            return False
        try:
            name = str(fr.f_globals.get("__name__", "") or "")
            fn = str(getattr(fr.f_code, "co_filename", "") or "")
            want = allowed.get(name)
            if (want is not None and fn == want and not fn.startswith("<")
                    and os.path.isfile(fn)):
                return True
        except Exception:
            pass
        return False
    except Exception:
        return False


def _tb_deny_admin(op: str):
    """Yonetim reddi: fail-closed opak hata."""
    global _TB_ADMIN_DENIED
    try:
        _TB_ADMIN_DENIED += 1
    except Exception:
        pass
    raise TracebackHarvestDetected("protected")


def _watchdog_loop(interval: float, on_detect=None) -> None:
    global _watchdog_tripped
    while not _watchdog_stop.is_set():
        try:
            if is_tripped():
                _watchdog_tripped = True
                _log("watchdog: trip latched")
                try:
                    if callable(on_detect):
                        on_detect()
                except Exception:
                    pass
                break
        except Exception:
            _watchdog_tripped = True
            break
        _watchdog_stop.wait(interval)


def start_watchdog(interval: float = 0.5, on_detect=None) -> bool:
    """MED-fix: on_detect callback destegi (pasif-bayrak + dis-aksiyon)."""
    global _watchdog_thread, _watchdog_tripped, _TB_ADMIN_LOCKED
    try:
        _TB_ADMIN_LOCKED = True
    except Exception:
        pass
    if _watchdog_thread is not None and _watchdog_thread.is_alive():
        return True
    _watchdog_tripped = False
    _watchdog_stop.clear()
    th = threading.Thread(
        target=_watchdog_loop, args=(interval, on_detect), name="anti-tb-watchdog", daemon=True
    )
    try:
        th.start()
    except Exception:
        return False
    _watchdog_thread = th
    return True


def stop_watchdog() -> bool:
    """Gozcuyu durdur (YONETIM: kayitli operator sart)."""
    if not _tb_check_admin():
        _tb_deny_admin("stop_watchdog")
    global _watchdog_thread
    _watchdog_stop.set()
    th = _watchdog_thread
    if th is not None:
        try:
            th.join(timeout=5.0)
        except Exception:
            pass
    _watchdog_thread = None
    return True


def watchdog_alive() -> bool:
    th = _watchdog_thread
    try:
        return bool(th is not None and th.is_alive())
    except Exception:
        return False


def watchdog_tripped() -> bool:
    return bool(_watchdog_tripped)
