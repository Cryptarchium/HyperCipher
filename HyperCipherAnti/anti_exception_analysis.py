# -*- coding: utf-8 -*-
"""anti_exception_analysis: exception-kanali gozetim/analiz tespiti.

Tehdit modeli (arastirma sentezi - 3x ReSearch, TUR6):
  - R1 Bilgi-sizintisi (CWE-209/CWE-200 + CodeQL py-stack-trace-exposure +
    OpenSSF pyscg-0050 + FastAPI #16254 + safeguard.sh 2026): ham traceback
    dosya-yolu/satir/fonksiyon/kutuphane-surumu/SQL parcasi sizdirir; debug
    modu (APP_DEBUG/DEBUG=True) .env/SECRET_KEY'i doker; API 500 govdesi
    constraint-adini (PostgreSQL) ele verir. Savunma: SPLIT & FILTER
    (kardes anti_error_leakage) + BU modul: sizintiyi OKUYAN kancayi yakalar.
  - R2 Zincirleme (PEP 3134 + PEP 409/415 + CPython traceback.py): __cause__
    / __context__ / __suppress_context__ / __notes__ (PEP 678) /
    BaseExceptionGroup.exceptions / with_traceback(tb) — zincir, tek
    mesajdan cok daha genis yuzey tasir; formatlanirken chain=True
    varsayilani tum zinciri doker. Savunma: pin'li hook'lar + zincir-derinlik
    cap'i + notes/subgroup redaksiyonu (kardes modulde TUR6 FIX).
  - R3 Kanca/frame (CPython sys docs: sys.excepthook + audit-event
    `sys.excepthook` + sys._current_frames + traceback.walk_tb + clear_frames
    + martinheinz excepthook deseni): saldirgan sys.excepthook'u degistirip
    HER yakalanmamis hatayi (traceback dahil) sessizce kopyalar; pdb post-mortem
    (sys.last_traceback) canli frame'leri introspection'a acar. Savunma:
    hook kimlik-pin'i + post-mortem frame-walk (iki katmanli eslesme).

Kapsam (kardeslerle cakisma yok):
  - anti_error_leakage: DISARIYA sizan icerik (redaksiyon). BU modul:
    sizintiyi YAKALAYAN gozetim altyapisi (hook kimligi + analiz cercevesi).
  - anti_debug: debugger-spesifik. BU modul: exception-kanali (hook pin +
    post-mortem), debugger mekanigine GIRMEZ.
  - anti_trace/anti_instrumentation: trace-mekanigi. BU modul sadece
    exception-hook kimligine bakar.

Sessiz, stdlib-only, fail-closed. True=risk, False=temiz.
Trip >=1 STRONG veya >=2 WEAK.
"""

from __future__ import annotations

import sys as _sys
import threading as _threading

__all__ = [
    "ExceptionAnalysisDetected",
    "is_analyzed",
    "check_all",
    "score",
    "status",
    "assert_no_analysis",
    "pin",
    "restore",
    "install",
    "uninstall",
    "authorize_admin",
    "start_watchdog",
    "stop_all_watchdogs",
    "guard",
]

STRONG = 100
WEAK = 30


class ExceptionAnalysisDetected(RuntimeError):
    """Opak hata: hangi katman tetiklendi DISARIYA soylenmez (oracle kapali)."""


# ---------------------------------------------------------------------------
# Pin (hook kimlikleri pin() aninda alinir; mismatch = STRONG)
# ---------------------------------------------------------------------------

_LOCK = _threading.RLock()
_PINNED: dict = {}
_PINNED_OBJS: dict = {}
_INSTALLED = False
_ORIGINALS: dict = {}
_INSTALL_BLOCKED_LATCH = False
_ADMIN_MODULES: dict = {}
_ADMIN_LOCKED = False
_ADMIN_DENIED = 0


def _hook_id(fn):
    try:
        return (getattr(type(fn), "__name__", "?"),
                getattr(fn, "__module__", "?"),
                getattr(fn, "__qualname__", getattr(fn, "__name__", "?")))
    except Exception:
        return ("?", "?", "?")


def _current_hooks():
    out = {}
    for name in ("excepthook", "__excepthook__", "unraisablehook",
                 "threading_excepthook"):
        try:
            if name == "threading_excepthook":
                import threading as _t
                out[name] = _t.excepthook
            else:
                out[name] = getattr(_sys, name, None)
        except Exception:
            out[name] = None
    return out


def pin() -> int:
    """Mevcut hook kimliklerini muhurle. Donus: pin'lenen sayi."""
    global _PINNED, _PINNED_OBJS
    try:
        cur = _current_hooks()
    except Exception:
        return 0
    ids = {}
    objs = {}
    for k, v in cur.items():
        try:
            ids[k] = _hook_id(v)
            objs[k] = v
        except Exception:
            ids[k] = ("?", "?", "?")
    with _LOCK:
        _PINNED = ids
        _PINNED_OBJS = objs
    return len(ids)


def _pinned_mismatch() -> bool:
    """STRONG: pin sonrasi hook kimligi degismis mi (obje-kimlik + tuple)."""
    try:
        pinned = dict(_PINNED)
    except Exception:
        return False
    if not pinned:
        return False  # pin() cagrilmamis -> bilinmiyor, suphe uretme
    try:
        objs = dict(_PINNED_OBJS)
    except Exception:
        objs = {}
    try:
        cur = _current_hooks()
    except Exception:
        return True
    for k, old_id in pinned.items():
        try:
            if _hook_id(cur.get(k)) != old_id:
                return True
        except Exception:
            return True
        try:
            if k in objs and cur.get(k) is not objs.get(k):
                return True
        except Exception:
            return True
    return False


# ---------------------------------------------------------------------------
# Sinyaller
# ---------------------------------------------------------------------------

# Post-mortem cerceveleri: LOOSE nadir-isim (tek basina yeterli), STRICT
# yaygin-isim (dosya kaniti SART: pdb.py/bdb.py/trace.py).
_PM_FUNCS_LOOSE = frozenset({
    "post_mortem",
    "pm",
    "runpdb",
    "set_post_mortem",
    "do_debug",
})
_PM_FUNCS_STRICT = frozenset({
    "trace_dispatch",
    "user_call",
    "user_exception",
    "interaction",
    "do_continue",
})
_PM_FILE_MARKS = ("pdb.py", "bdb.py", "trace.py", "pydevd", "debugpy")


def _is_default_excepthook(fn) -> bool:
    """Yorumlayici-varsayilan excepthook mu (builtin, sys'e bagli)?"""
    try:
        if fn is None:
            return False
        if type(fn).__name__ != "builtin_function_or_method":
            return False
        if getattr(fn, "__self__", None) is not _sys:
            return False
        return True
    except Exception:
        return False


def _check_hook_tamper() -> bool:
    """STRONG: pin'li exception-hook kimligi bozulmus mu."""
    try:
        return _pinned_mismatch()
    except Exception:
        return True


def _check_prehook_present() -> bool:
    """STRONG: install-oncesi yabanci hook latch'i (MEDIUM-12 kalici iz)."""
    try:
        with _LOCK:
            return bool(_INSTALL_BLOCKED_LATCH)
    except Exception:
        return True
    try:
        return _pinned_mismatch()
    except Exception:
        return True


def _check_hook_suppressed() -> bool:
    """WEAK: excepthook None'a cekilmis (korluk) veya default disi degismis."""
    try:
        cur = _sys.excepthook
    except Exception:
        return False
    try:
        if cur is None:
            return True
        dflt = getattr(_sys, "__excepthook__", None)
        if dflt is not None and cur is not dflt and not _PINNED:
            return True  # pin yok ama default disi -> supheli
        return False
    except Exception:
        return False


def _check_postmortem_frames() -> bool:
    """STRONG: post-mortem/debugger cercevesi stack'te aktif mi."""
    get_frames = getattr(_sys, "_current_frames", None)
    if get_frames is None:
        return False
    try:
        frames = get_frames()
    except Exception:
        return True
    try:
        for _tid, frame in frames.items():
            f = frame
            depth = 0
            while f is not None and depth < 64:
                depth += 1
                try:
                    code = f.f_code
                    fname = code.co_name
                    fpath = (code.co_filename or "").lower().replace(
                        "\\", "/")
                except Exception:
                    break
                try:
                    if fname in _PM_FUNCS_LOOSE:
                        return True
                    if fname in _PM_FUNCS_STRICT:
                        for mark in _PM_FILE_MARKS:
                            if mark in fpath:
                                return True
                except Exception:
                    pass
                try:
                    f = f.f_back
                except Exception:
                    break
        return False
    except Exception:
        return True


_TOOL_MODULES = frozenset({
    "pdb",
    "bdb",
    "trace",
    "pydevd",
    "debugpy",
    "ipdb",
    "pudb",
    "stackprinter",
})


def _check_tool_presence() -> bool:
    """WEAK: post-mortem/debug araci modul yuklu mu."""
    try:
        live = _sys.modules
    except Exception:
        return False
    try:
        for name in _TOOL_MODULES:
            try:
                if name in live:
                    return True
            except Exception:
                continue
        try:
            keys = list(live.keys())
        except Exception:
            keys = []
        for key in keys:
            try:
                top = key.split(".", 1)[0].lower()
            except Exception:
                continue
            if top in _TOOL_MODULES:
                return True
        return False
    except Exception:
        return False


def _check_last_residue() -> bool:
    """WEAK: sys.last_traceback/last_value kalintisi (post-mortem izi)."""
    try:
        if getattr(_sys, "last_traceback", None) is not None:
            return True
    except Exception:
        pass
    try:
        if getattr(_sys, "last_value", None) is not None:
            return True
    except Exception:
        pass
    return False


# ---------------------------------------------------------------------------
# Toplama
# ---------------------------------------------------------------------------

def check_all() -> dict:
    """Tum sinyaller (True=risk). Kritik hata -> True (fail-closed)."""
    out: dict = {}
    try:
        out["hook_tampered"] = _check_hook_tamper()
    except Exception:
        out["hook_tampered"] = True
    try:
        out["prehook_present"] = _check_prehook_present()
    except Exception:
        out["prehook_present"] = True
    try:
        out["postmortem_frame"] = _check_postmortem_frames()
    except Exception:
        out["postmortem_frame"] = True
    try:
        out["hook_suppressed"] = _check_hook_suppressed()
    except Exception:
        out["hook_suppressed"] = False
    try:
        out["tool_present"] = _check_tool_presence()
    except Exception:
        out["tool_present"] = False
    try:
        out["last_residue"] = _check_last_residue()
    except Exception:
        out["last_residue"] = False
    return out


_STRONG_KEYS = ("hook_tampered", "prehook_present", "postmortem_frame")
_WEAK_KEYS = ("hook_suppressed", "tool_present", "last_residue")


def score() -> tuple:
    """(strong_sayisi, weak_sayisi, toplam)."""
    try:
        signals = check_all()
    except Exception:
        return (1, 0, STRONG)
    try:
        s = sum(1 for k in _STRONG_KEYS if signals.get(k))
        w = sum(1 for k in _WEAK_KEYS if signals.get(k))
        return (s, w, s * STRONG + w * WEAK)
    except Exception:
        return (1, 0, STRONG)


def is_analyzed() -> bool:
    """Trip kurali: >=1 STRONG veya >=2 WEAK."""
    try:
        s, w, _ = score()
        return s >= 1 or w >= 2
    except Exception:
        return True


def status() -> dict:
    """Sessiz durum ozeti."""
    try:
        s, w, pts = score()
        return {"tripped": is_analyzed(), "strong": s, "weak": w,
                "points": pts, "results": check_all(),
                "installed": _INSTALLED,
                "admin_authorized": len(_ADMIN_MODULES), "admin_locked": _ADMIN_LOCKED,
                "admin_denied": _ADMIN_DENIED}
    except Exception:
        return {"tripped": True, "strong": 1, "weak": 0, "points": STRONG,
                "results": {}}


def assert_no_analysis() -> None:
    """Trip varsa opak hata (oracle kapali)."""
    if is_analyzed():
        raise ExceptionAnalysisDetected("operation failed")


# ---------------------------------------------------------------------------
# Kurulum (opaque hook: detayi degistirmez, sadece pin'ler)
# ---------------------------------------------------------------------------

def _opaque_hook(exc_type, exc_value, exc_tb):
    try:
        _ORIGINALS.get("excepthook", _sys.__excepthook__)(
            exc_type, exc_value, exc_tb)
    except Exception:
        pass


def authorize_admin():
    """Operator modulunu kaydet (SADECE kilit-oncesi; boot sirasinda cagrilir)."""
    global _ADMIN_DENIED
    try:
        if _ADMIN_LOCKED:
            with _LOCK:
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
            import os as _os
            if not _os.path.isfile(fn):
                return False
        except Exception:
            return False
        with _LOCK:
            _ADMIN_MODULES[name] = fn
        return True
    except Exception:
        return False


def _check_admin() -> bool:
    """Dogrudan cagiran cerceve kayitli operator modulu mu? (dosya-dogrulamali)."""
    try:
        with _LOCK:
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
            if (want is not None and fn == want and not fn.startswith("<")):
                try:
                    import os as _os2
                    if _os2.path.isfile(fn):
                        return True
                except Exception:
                    pass
        except Exception:
            pass
        return False
    except Exception:
        return False


def _deny_admin(op: str):
    """Yonetim reddi: fail-closed opak hata."""
    global _ADMIN_DENIED
    try:
        with _LOCK:
            _ADMIN_DENIED += 1
    except Exception:
        pass
    raise ExceptionAnalysisDetected("protected")


def install() -> bool:
    """Exception-hook'u opak sarmalayiciya al + pin'le.

    MEDIUM-12 duzeltmesi: mevcut hook yorumlayici-varsayilani DEGILSE
    kurulum REDDEDILIR (fail-closed) + `prehook_present` latch kurulur.
    Once-yerlesmis evil hook guvenilir-baseline olamaz.
    """
    global _INSTALLED, _INSTALL_BLOCKED_LATCH
    with _LOCK:
        if _INSTALLED:
            return True
        try:
            cur = _sys.excepthook
        except Exception:
            return False
        try:
            if cur is not _opaque_hook and not _is_default_excepthook(cur):
                _INSTALL_BLOCKED_LATCH = True
                return False
        except Exception:
            with _LOCK:
                _INSTALL_BLOCKED_LATCH = True
            return False
        try:
            _ORIGINALS["excepthook"] = cur
            _sys.excepthook = _opaque_hook
        except Exception:
            return False
        try:
            pin()
        except Exception:
            pass
        _INSTALLED = True
        return True


def uninstall() -> bool:
    """Hook'lari geri yukle (YONETIM: kayitli operator sart; test/temizlik)."""
    if not _check_admin():
        _deny_admin("uninstall")
    global _INSTALLED, _PINNED, _PINNED_OBJS
    with _LOCK:
        try:
            if "excepthook" in _ORIGINALS:
                _sys.excepthook = _ORIGINALS["excepthook"]
        except Exception:
            return False
        _INSTALLED = False
        _PINNED = {}  # stale pin birakma: eski kimlik yeni durumu suclamassin
        _PINNED_OBJS = {}
        return True


def restore() -> bool:
    """uninstall() takma adi (YONETIM gate'li)."""
    return uninstall()


# ---------------------------------------------------------------------------
# Watchdog + guard
# ---------------------------------------------------------------------------

_WATCHDOGS: list = []
_WD_LOCK = _threading.RLock()


def _clamp_interval(v) -> float:
    try:
        f = float(v)
    except Exception:
        return 0.5
    if f < 0.1:
        return 0.1
    if f > 3600.0:
        return 3600.0
    return f


def start_watchdog(interval=0.5):
    """Periyodik check_all; trip'te bayrak kurar. stop fn doner."""
    global _ADMIN_LOCKED
    try:
        with _WD_LOCK:
            _ADMIN_LOCKED = True
    except Exception:
        pass
    iv = _clamp_interval(interval)
    stop_ev = _threading.Event()
    state = {"tripped": False}

    def _loop():
        try:
            while not stop_ev.wait(iv):
                try:
                    if is_analyzed():
                        state["tripped"] = True
                except Exception:
                    state["tripped"] = True
        except Exception:
            pass

    try:
        t = _threading.Thread(target=_loop, name="exc-analysis-wd",
                              daemon=True)
        t.start()
    except Exception:
        return lambda: None

    def _stop():
        try:
            stop_ev.set()
        except Exception:
            pass
        return dict(state)

    with _WD_LOCK:
        _WATCHDOGS.append((_stop, state))
    return _stop


def stop_all_watchdogs() -> int:
    """Tum watchdog'lari durdur (YONETIM: kayitli operator sart). Donus: durdurulan sayi."""
    if not _check_admin():
        _deny_admin("stop_all_watchdogs")
    n = 0
    with _WD_LOCK:
        stops = list(_WATCHDOGS)
        _WATCHDOGS.clear()
    for stop, _state in stops:
        try:
            stop()
            n += 1
        except Exception:
            continue
    return n


class guard:
    """`with guard():` blogunda GIRIS + CIKIS trip kontrolu (fail-closed iki uc).

    LOW-7 duzeltmesi: trip'li halde govde hic calismaz (onceki sadece-cikis
    kontrolu hasari engellemiyordu).
    """

    def __enter__(self):
        try:
            assert_no_analysis()
        except Exception:
            raise
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            assert_no_analysis()
        except Exception:
            if exc is None:
                raise
        return False
