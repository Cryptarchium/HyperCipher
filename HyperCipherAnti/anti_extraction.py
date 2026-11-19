# -*- coding: utf-8 -*-
"""anti_extraction: donmus/paketlenmis uygulama + toplu-sabit cikarma tespiti.

Tehdit modeli (arastirma sentezi - 3x ReSearch, TUR7):
  - R1 Arsiv-cikarma (pyinstxtractor/pyinstxtractor-ng + FLARE-ON9 PyArmor
    + sahl blog 2025): PyInstaller exe = CArchive+PYZ zip; `--info` meta
    (python surumu, dosya sayisi, entry point) + cikarma + pyc header-fix +
    pycdc/uncompyle6 decompile. Savunma (runtime tarafi): cikarma ARACININ
    bu process'te calismasi frame-walk ile yakalanir; toplu marshal-cozumu
    audit-kanca patlamasiyla yakalanir. Statik `.exe` korumasi kapsam-disi
    (build-time gorevi) — BU modul CANLI process'i korur.
  - R2 Sabit-hasadi (CodeQL py/hardcoded-credentials CWE-798 + TruffleHog
    800+ detector + Gitleaks/Betterleaks + SecretBench 2025): regex (AKIA,
    sk_live_, sk-proj_) + Shannon entropi (>4.5 bit/char) + dogrulama.
    FLARE-ON9 bulgusu: PyArmor bile co_consts/co_names'i ACIK birakir;
    "quick and dirty" strings-dump bayragi alir. Ders: sabitler VERI'DIR,
    kilit degil — runtime savunma toplu-okumayi yakalamalidir.
  - R3 Marshal-zinciri (pydecipher + GDATA Pyarmor-Tooling + Fadi002
    pyarmor-research 2026): xdis surum-bagimsiz unmarshal; opcode-remap
    (pytransform 0xD1=IMPORT_NAME, CO_OBFUSCATED); statik AES-GCM cozumu
    (ida_getkey/decrypt_gcm); replica-dist uretimi. Savunma: marshal.loads/
    dumps + compile + exec + code.__new__ olaylarinda burst-esigi; tekil
    mesru kullanim WEAK'ta kalir, toplu-cozum STRONG'a yukselir.

Kapsam (kardeslerle cakisma yok):
  - anti_decompile/anti_bytecode: decompiler/derin-bytecode analizi. BU modul:
    ARSIV-cikarma araci + TOPLU-cozum patlamasi (hacim sinyali).
  - anti_string_extraction/anti_constant_analysis: STATIK sabit yuzeyi
    (kendi kodumuzda secret var mi). BU modul: CALISMA-ANINDA cikarma
    saldirisi (biri const'larimizi toplu okuyor mu).
  - anti_import_analysis: import-kancasi sagligi. BU modul kancalari TAMIR
    ETMEZ, sadece cikarma-sinyali uretir.

Sessiz, stdlib-only, fail-closed. True=risk, False=temiz.
Trip >=1 STRONG veya >=2 WEAK.
"""

from __future__ import annotations

import collections as _collections
import sys as _sys
import threading as _threading
import time as _time

__all__ = [
    "ExtractionDetected",
    "is_extracted",
    "check_all",
    "score",
    "status",
    "assert_no_extraction",
    "enforce_audit_hook",
    "audit_hook_active",
    "reset_audit_flags",
    "audit_log",
    "authorize_admin",
    "start_watchdog",
    "stop_all_watchdogs",
    "guard",
]

STRONG = 100
WEAK = 30


class ExtractionDetected(RuntimeError):
    """Opak hata: hangi katman tetiklendi DISARIYA soylenmez (oracle kapali)."""


# ---------------------------------------------------------------------------
# Audit-kanca (toplu marshal/compile/exec burst tespiti)
# ---------------------------------------------------------------------------

_AUDIT_EVENTS = frozenset({
    "marshal.loads",
    "marshal.load",
    "marshal.dumps",
    "marshal.dump",
    "compile",
    "exec",
    "code.__new__",
})

# Toplu-cozum esigi: pyinstxtractor 100+ dosya cozer; mesru lazy-import
# birkac olay uretir. 5sn pencerede >=25 olay = STRONG.
_BURST_N = 25
_BURST_WINDOW = 5.0
_AUDIT_MAX = 256

_AUDIT_RING: _collections.deque = _collections.deque(maxlen=_AUDIT_MAX)
_AUDIT_LOCK = _threading.RLock()
_AUDIT_INSTALLED = False
_AUDIT_SEEN = 0
_AUDIT_TLS = _threading.local()
# Kumulatif zaman-cizgisi (MEDIUM-14): reset()'ten ETKILENMEZ, slow-drip
# ve toplu-hacim buradan okunur. 1 saat pencere, 4096 cap (prune'lu).
_CUM_TS: _collections.deque = _collections.deque(maxlen=4096)
_CUM_WINDOW_SLOW = 60.0
_CUM_WINDOW_HOUR = 3600.0
_SLOW_N = 12
_HOUR_N = 100
_ADMIN_MODULES: dict = {}
_ADMIN_LOCKED = False
_ADMIN_DENIED = 0


def _audit_hook(event, _args):
    """Hafif kanca: sadece olay adi + zaman damgasi (agir is YOK)."""
    global _AUDIT_SEEN
    try:
        try:
            _AUDIT_SEEN += 1
        except Exception:
            pass
        if getattr(_AUDIT_TLS, "muted", 0):
            return
        if event not in _AUDIT_EVENTS:
            return
        try:
            now = _time.monotonic()
        except Exception:
            return
        try:
            _AUDIT_RING.append((event, now))
        except Exception:
            pass
        try:
            _CUM_TS.append(now)
        except Exception:
            pass
    except Exception:
        pass


def authorize_admin():
    """Operator modulunu kaydet (SADECE kilit-oncesi; boot sirasinda cagrilir).

    Ilk enforce_audit_hook() kaydi kilitler. Donus: True=kaydedildi.
    """
    global _ADMIN_DENIED
    try:
        if _ADMIN_LOCKED:
            with _AUDIT_LOCK:
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
        with _AUDIT_LOCK:
            _ADMIN_MODULES[name] = fn
        return True
    except Exception:
        return False


def _check_admin() -> bool:
    """Dogrudan cagiran cerceve kayitli operator modulu mu? (dosya-dogrulamali)."""
    try:
        with _AUDIT_LOCK:
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
        with _AUDIT_LOCK:
            _ADMIN_DENIED += 1
    except Exception:
        pass
    raise ExtractionDetected("protected")


def enforce_audit_hook() -> bool:
    """Audit-kancayi kur (tum import'lar oturduktan SONRA cagir)."""
    global _AUDIT_INSTALLED, _ADMIN_LOCKED
    if _AUDIT_INSTALLED:
        return True
    try:
        _sys.addaudithook(_audit_hook)
    except Exception:
        return False
    _AUDIT_INSTALLED = True
    with _AUDIT_LOCK:
        _ADMIN_LOCKED = True
    return True


def audit_hook_active() -> bool:
    """Kanca GERCEKTEN canli mi (bayrak + canli prob, smash'e karsi)."""
    try:
        if not _AUDIT_INSTALLED:
            return False
        try:
            before = _AUDIT_SEEN
            audit_fn = getattr(_sys, "audit", None)
            if not callable(audit_fn):
                return True
            try:
                audit_fn("hyper.selftest")
            except Exception:
                pass
            return _AUDIT_SEEN > before
        except Exception:
            return True
    except Exception:
        return False


def reset_audit_flags() -> int:
    """Halka-tamponu temizle (YONETIM: kayitli operator sart).

    MEDIUM-14: kumulatif slow-drip cizelgesine DOKUNMAZ — sayac sifirlama
    hacim-kanitini silmez. Donus: silinen kayit sayisi.
    """
    if not _check_admin():
        _deny_admin("reset_audit_flags")
    try:
        with _AUDIT_LOCK:
            n = len(_AUDIT_RING)
            _AUDIT_RING.clear()
            return n
    except Exception:
        return 0


def audit_log() -> list:
    """Son olaylarin kopyasi (tani icin, sessiz)."""
    try:
        with _AUDIT_LOCK:
            return list(_AUDIT_RING)
    except Exception:
        return []


def _audit_delta() -> int:
    """Penceredeki olay sayisi."""
    try:
        now = _time.monotonic()
    except Exception:
        return 0
    try:
        with _AUDIT_LOCK:
            items = list(_AUDIT_RING)
    except Exception:
        return 0
    try:
        cutoff = now - _BURST_WINDOW
        return sum(1 for _ev, ts in items if ts >= cutoff)
    except Exception:
        return 0


def _cum_counts():
    """(son-60s, son-1saat) kumulatif olay sayilari (prune'lu)."""
    try:
        now = _time.monotonic()
    except Exception:
        return 0, 0
    try:
        with _AUDIT_LOCK:
            items = list(_CUM_TS)
    except Exception:
        return 0, 0
    try:
        slow = sum(1 for ts in items if ts >= now - _CUM_WINDOW_SLOW)
        hour = sum(1 for ts in items if ts >= now - _CUM_WINDOW_HOUR)
        try:
            with _AUDIT_LOCK:
                while _CUM_TS and _CUM_TS[0] < now - _CUM_WINDOW_HOUR:
                    _CUM_TS.popleft()
        except Exception:
            pass
        return slow, hour
    except Exception:
        return 0, 0


def _check_slow_drip() -> bool:
    """WEAK (MEDIUM-14): burst-esigi-alti surdurulen cozumu (60s'de >=12)."""
    try:
        if not _AUDIT_INSTALLED:
            return False
        slow, _hour = _cum_counts()
        return slow >= _SLOW_N
    except Exception:
        return True


def _check_sustained_volume() -> bool:
    """WEAK (MEDIUM-14): 1 saatte >=100 kod-uretim olayi (toplu-hacim)."""
    try:
        if not _AUDIT_INSTALLED:
            return False
        _slow, hour = _cum_counts()
        return hour >= _HOUR_N
    except Exception:
        return True


def _check_unpack_burst() -> bool:
    """STRONG: pencerede toplu marshal/compile/exec patlamasi."""
    try:
        if not _AUDIT_INSTALLED:
            return False  # kanca yok -> bilinmiyor, suphe uretme
        return _audit_delta() >= _BURST_N
    except Exception:
        return True


# ---------------------------------------------------------------------------
# Cikarma-araci cerceveleri (iki katmanli eslesme, FP karsiti)
# ---------------------------------------------------------------------------

_EXTRACT_FUNCS_LOOSE = frozenset({
    "extractPyz",
    "extractCArchive",
    "parseCArchive",
    "extract_all",
    "dump_pyz",
    "unfreeze",
    "deobfuscate",
    "remap_opcodes",
    "decrypt_gcm",
    "show_info",
})
_EXTRACT_FUNCS_STRICT = frozenset({
    "dis",
    "get_instructions",
    "extract",
    "parse",
    "load",
    "decompile",
})
_EXTRACT_FILE_MARKS = ("pyinstxtractor", "pydecipher", "xdis", "uncompyle",
                       "pycdc", "carchive", "pyi-archive", "pyarmor")


def _check_extractor_frames() -> bool:
    """STRONG: cikarma-araci cercevesi stack'te aktif mi."""
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
                    if fname in _EXTRACT_FUNCS_LOOSE:
                        return True
                    if fname in _EXTRACT_FUNCS_STRICT:
                        for mark in _EXTRACT_FILE_MARKS:
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


_EXTRACT_MODULES = frozenset({
    "pyinstxtractor",
    "pydecipher",
    "xdis",
    "uncompyle6",
    "decompyle3",
    "pycdc",
    "pylingual",
})


def _check_tool_presence() -> bool:
    """WEAK: cikarma-araci modul yuklu mu (varlik tek basina suphe degil)."""
    try:
        live = _sys.modules
    except Exception:
        return False
    try:
        for name in _EXTRACT_MODULES:
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
            if top in _EXTRACT_MODULES:
                return True
        return False
    except Exception:
        return False


def _check_frozen_ctx() -> bool:
    """WEAK: donmus-baglam tutarsizligi (capraz-dogrulamali, LOW-8).

    Cift-bayrak + sys.executable + _MEIPASS-dizin + freezer-finder
    caprazlanir; spoof icin hepsi birden taklit edilmeli. cx_Freeze
    (frozen=True, _MEIPASS yok) executable-tutarliysa temiz sayilir.
    """
    try:
        frozen = getattr(_sys, "frozen", False)
        meipass = getattr(_sys, "_MEIPASS", None)
    except Exception:
        return False
    try:
        if frozen and not meipass:
            try:
                exe = str(getattr(_sys, "executable", "") or "")
            except Exception:
                exe = ""
            if not exe or exe.endswith(".py"):
                return True
            try:
                import os as _os
                if not _os.path.isfile(exe):
                    return True
            except Exception:
                return True
            return False
        if meipass and not frozen:
            return True
        if frozen and meipass:
            try:
                import os as _os2
                if not _os2.path.isdir(str(meipass)):
                    return True
            except Exception:
                return True
            try:
                tags = []
                for f in list(_sys.meta_path):
                    try:
                        tags.append(type(f).__module__ + "." + type(f).__name__)
                    except Exception:
                        continue
                blob = " ".join(tags).lower()
                if "pyinstaller" not in blob and "frozen" not in blob and "_pyi" not in blob:
                    return True
            except Exception:
                pass
            return False
        return False
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Toplama
# ---------------------------------------------------------------------------

def check_all() -> dict:
    """Tum sinyaller (True=risk). Kritik hata -> True (fail-closed)."""
    out: dict = {}
    try:
        out["unpack_burst"] = _check_unpack_burst()
    except Exception:
        out["unpack_burst"] = True
    try:
        out["extractor_frame"] = _check_extractor_frames()
    except Exception:
        out["extractor_frame"] = True
    try:
        out["tool_present"] = _check_tool_presence()
    except Exception:
        out["tool_present"] = False
    try:
        out["frozen_ctx"] = _check_frozen_ctx()
    except Exception:
        out["frozen_ctx"] = False
    try:
        out["slow_drip"] = _check_slow_drip()
    except Exception:
        out["slow_drip"] = True
    try:
        out["sustained_volume"] = _check_sustained_volume()
    except Exception:
        out["sustained_volume"] = True
    try:
        out["audit_unarmed"] = not bool(_AUDIT_INSTALLED)
    except Exception:
        out["audit_unarmed"] = True
    return out


_STRONG_KEYS = ("unpack_burst", "extractor_frame")
_WEAK_KEYS = ("tool_present", "frozen_ctx", "slow_drip", "sustained_volume")


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


def is_extracted() -> bool:
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
        return {"extracted": is_extracted(), "strong": s, "weak": w,
                "score": pts, "signals": check_all(),
                "audit_hook": audit_hook_active(),
                "admin_authorized": len(_ADMIN_MODULES), "admin_locked": _ADMIN_LOCKED,
                "admin_denied": _ADMIN_DENIED}
    except Exception:
        return {"extracted": True, "strong": 1, "weak": 0, "score": STRONG,
                "signals": {}, "audit_hook": False}


def assert_no_extraction() -> None:
    """Trip varsa opak hata (oracle kapali)."""
    if is_extracted():
        raise ExtractionDetected("operation failed")


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


def start_watchdog(interval=0.5, on_detect=None):
    """Periyodik check_all; trip'te once on_detect, yoksa os._exit(1).

    LOW-9 duzeltmesi: gozlemci-degil mudahaleci watchdog. stop fn doner
    (cagrinca son-trip durum sozlugunu verir).
    """
    global _ADMIN_LOCKED
    try:
        with _AUDIT_LOCK:
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
                    if is_extracted():
                        state["tripped"] = True
                        try:
                            if on_detect is not None:
                                on_detect()
                            else:
                                import os as _os
                                _os._exit(1)
                        except Exception:
                            pass
                        return
                except Exception:
                    state["tripped"] = True
                    return
        except Exception:
            pass

    try:
        t = _threading.Thread(target=_loop, name="extract-wd", daemon=True)
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
    """`with guard():` blogunda GIRIS + CIKIS trip kontrolu (fail-closed iki uc)."""

    def __enter__(self):
        try:
            assert_no_extraction()
        except Exception:
            raise
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            assert_no_extraction()
        except Exception:
            if exc is None:
                raise
        return False
