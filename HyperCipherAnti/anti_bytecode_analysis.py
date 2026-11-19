# -*- coding: utf-8 -*-
"""
HyperCipherAnti - AntiBytecodeAnalysis (Stage 4)
================================================
Calisma-aninda bytecode analizi tespiti + kod-butunlugu muhafaza.
Stdlib-only, cross-platform, fail-closed, sessiz (oracle vermez).

Arastirma sentezi (3 guclu arastirma + en guclu teknikler):
  [1] Saldirgan zinciri: `marshal.loads + dis.get_instructions + co_consts`
      her surumde calisir (decompiler desteksiz surumde bile); shadow-exec
      yakalama (`exec`'i golgeleyen namespace) payload'u calistirmadan
      ele verir; nested marshal katmanlari tek tek soyulur. Ders: marshal
      blob'u cozulebilir VERI'DIR, kilit degildir; runtime savunma blob'u
      degil CANLI kod nesnesini korumalidir.
      (pyobfuscate.com marshal-testleri + transilienceai senaryo analizi)
  [2] En guclu stdlib kancasi: `sys.addaudithook` ile `marshal.loads`,
      `marshal.dumps`, `compile`, `exec`, `code.__new__` olaylarini gozlemle.
      Sifir ucuncu-parti bagimlilik, C-seviyesi olaylar Python frame'i
      birakmaz -> frame-walk'in kor oldugu yerde audit-hook gorur.
      (CPython marshal.rst denetim-olaylari + capture.py teknigi)
  [3] Butunluk + kendini-iyilestirme: `co_code` sha256 taban-cizgisi,
      periyodik dogrulama, bozulmada otomatik restore (Cynapse deseni:
      bytecode verification + module tracking + import-hook izleme +
      auto-healing, sifir bagimlilik). Dusmanca marshal akisi interpreter'i
      C-seviyesinde oldurebilir -> guvenilmeyen bytecode ASLA bu process'te
      acilmaz; bu modul yalnizca KENDI korumali nesnelerini denetler.
      (cynapse + repo-forensics izole-child deseni)

Entegrasyon prensibi: HICBIR tek kontrole guvenme. Trip kurali: >=1 STRONG
veya >=2 WEAK. Kritik hata -> True (fail-closed). Audit-hook process-global
ve kalicidir (kaldirilamaz); yalnizca tum import'lar oturduktan SONRA
`enforce_audit_hook()` cagrilmali, aksi halde gecikmis .pyc yuklemeleri
yanlis alarm uretebilir. Hata mesaji OP AKTIR.

Kullanim:
    from HyperCipherAnti import anti_bytecode_analysis as aba
    aba.seal(my_func)                 # taban-cizgiyi al
    aba.enforce_audit_hook()          # import'lar oturduktan sonra
    if aba.is_analyzed(): ...         # sessiz kontrol
    aba.assert_no_analysis()          # varsa AnalysisDetected
    aba.heal()                        # bozulan __code__'lari restore et
"""

from __future__ import annotations

import collections
import contextlib
import gc
import hashlib
import os
import sys
import threading
import time
from types import CodeType, FunctionType
from typing import Callable, Dict, List, Optional, Tuple

__all__ = [
    "AnalysisDetected",
    "is_analyzed",
    "check_all",
    "score",
    "status",
    "assert_no_analysis",
    "seal",
    "unseal",
    "verify",
    "heal",
    "enforce_audit_hook",
    "audit_hook_active",
    "reset_audit_flags",
    "audit_log",
    "start_watchdog",
    "stop_all_watchdogs",
    "guard",
]


class AnalysisDetected(RuntimeError):
    """Opak hata: hangi katman tetiklendi DISARIYA soylenmez (oracle kapali)."""


# ---------------------------------------------------------------------------
# Pin'li referanslar (B1 deseni). Audit-hook + gc + hash sabitlenir; canli
# deger tutarsizligi hook suphesi -> STRONG.
# ---------------------------------------------------------------------------
_SYS_MODULES = sys.modules
_SYS_CURRENT_FRAMES = getattr(sys, "_current_frames", None)
_SYS_ADDAUDITHOOK = getattr(sys, "addaudithook", None)
_GC_GET_OBJECTS = gc.get_objects
_OS_EXIT = os._exit
_HASH_SHA256 = hashlib.sha256
_PERF_COUNTER = time.perf_counter
_THREAD_LOCK = threading.Lock()
_THREAD_LOCK_CLS = threading.Lock
_THREAD_EVENT_CLS = threading.Event
_THREAD_THREAD_CLS = threading.Thread
_WATCHDOGS: List[Tuple[threading.Thread, threading.Event]] = []

_STRONG = 100
_WEAK = 30

# Denetim olaylari: kod-nesnesi uretimi/sokumu/yurutmesi.
# 3.10+ marshal.load tek-olay birlestirmesi de kapsanir.
_AUDIT_EVENTS = frozenset({
    "marshal.loads",
    "marshal.load",
    "marshal.dumps",
    "marshal.dump",
    "compile",
    "exec",
    "code.__new__",
})

# Analiz araclari (modul VARLIGI tek basina WEAK; aktif kullanim frame-walk
# + audit-hook ile STRONG'a yukselir). `dis` stdlib oldugu icin varlik
# sinyali bilerek WEAK tutulur (mesru debugger'lar da import eder).
_ANALYSIS_MODULES = frozenset({
    "dis",
    "bytecode",
    "xdis",
    "uncompyle6",
    "decompyle3",
    "pycdc",
    "pylingual",
    "pydecipher",
    "depyf",
})

# Canli analiz cerceveleri: iki katmanli eslesme (FP karsiti).
# LOOSE isimler nadirdir (Bytecode API / gosterim yardimcilari) -> tek basina
# yeterli. STRICT isimler yaygindir (dis/getsource/getfile: mesru utility
# fonksiyon adlariyla cakisabilir) -> dosya kaniti SART (dis.py/inspect.py/
# bytecode/xdis). Boylece `def dis()` yazan masum kod trip uretmez.
_BC_FRAME_FUNCS_LOOSE = frozenset({
    "Bytecode",
    "from_code",
    "to_code",
    "show_code",
    "disassemble",
    "distb",
    "disasm",
})
_BC_FRAME_FUNCS_STRICT = frozenset({
    "dis",
    "get_instructions",
    "getsource",
    "getsourcelines",
    "getfile",
})
_BC_FRAME_FILE_MARKS = ("dis.py", "inspect.py", "bytecode", "xdis",
                        "pycode.py", "pycdc", "uncompyle", "decompyle")

# Audit halka-tamponu (sinirli, kilitli). Hook'un kendisi hicbir agir is
# yapmaz: sadece olay adini isaretler + tampona ekler. AYRI KILIT SART:
# _THREAD_LOCK muhur islerinde tutulurken hook tetiklenirse (ornegin
# seal() icindeki lazy importun `compile` olayi) ayni kilit olumcul
# kilitlenmeye yol acar. Ayrica TLS-bazli bastirma sayaci, kendi
# operasyonlarimizin urettigi olaylari trip bayraklarindan ayirir
# (PEP 578 reentrancy kurali: hook, denetlenen operasyonu tetiklememeli).
_AUDIT_MAX = 64
_AUDIT_RING: collections.deque = collections.deque(maxlen=_AUDIT_MAX)
_AUDIT_FLAGS: Dict[str, int] = {}
_AUDIT_BASELINE = 0
_AUDIT_INSTALLED = False
_AUDIT_SEEN = 0
_AUDIT_LOCK = threading.Lock()
_AUDIT_TLS = threading.local()
_AUDIT_INTERNAL: collections.deque = collections.deque(maxlen=_AUDIT_MAX)
_SUPPRESSED_TOTAL = 0
_SUPPRESS_SPOOF_LATCH = False
_SEAL_ORIGIN: Dict[int, Tuple[str, str]] = {}
_ADMIN_MODULES: Dict[str, str] = {}
_ADMIN_LOCKED = False
_ADMIN_DENIED = 0


def _suppressed() -> bool:
    """Bastirma gecerli mi? Sayaç + stack'ta CANLI _quiet_audit cercevesi sart.

    F9 duzeltmesi: duz yazilabilir TLS sayaci tek basina guvenilmez.
    Saldirgan `_AUDIT_TLS.suppress = 999` yazarsa cerceve bulunamaz ->
    bastirma GECERSIZ sayilir (olay normal sayilir) + spoof latch kurulur.
    """
    global _SUPPRESS_SPOOF_LATCH
    try:
        n = getattr(_AUDIT_TLS, "suppress", 0)
        if not isinstance(n, int) or n <= 0:
            return False
        if _quiet_frame_live():
            return True
        try:
            with _AUDIT_LOCK:
                _SUPPRESS_SPOOF_LATCH = True
        except Exception:
            pass
        return False
    except Exception:
        return False


def _quiet_frame_live() -> bool:
    """Stack'te askida _quiet_audit generator cercevesi var mi?"""
    try:
        try:
            fr = sys._getframe(2)
        except Exception:
            return False
        depth = 0
        while fr is not None and depth < 40:
            depth += 1
            try:
                if fr.f_code.co_name == "_quiet_audit":
                    return True
            except Exception:
                pass
            try:
                fr = fr.f_back
            except Exception:
                break
        return False
    except Exception:
        return False


@contextlib.contextmanager
def _quiet_audit():
    """Kendi denetlenen operasyonlarımızı trip sayaçlarından ayır."""
    try:
        _AUDIT_TLS.suppress = getattr(_AUDIT_TLS, "suppress", 0) + 1
    except Exception:
        pass
    try:
        yield
    finally:
        try:
            _AUDIT_TLS.suppress -= 1
        except Exception:
            pass


def _audit_hook(event: str, _args) -> None:
    global _AUDIT_SEEN, _SUPPRESSED_TOTAL
    try:
        try:
            _AUDIT_SEEN += 1
        except Exception:
            pass
        if event in _AUDIT_EVENTS:
            if _suppressed():
                try:
                    with _AUDIT_LOCK:
                        _AUDIT_INTERNAL.append(event)
                        _SUPPRESSED_TOTAL += 1
                except Exception:
                    pass
                return
            with _AUDIT_LOCK:
                _AUDIT_FLAGS[event] = _AUDIT_FLAGS.get(event, 0) + 1
                _AUDIT_RING.append(event)
    except Exception:
        pass


def enforce_audit_hook() -> bool:
    """Process-global denetim kancasi tak (idempotent, kalici).

    Ilk basarili kurulumda yonetim kaydini kilitler (F8/F10 destegi).
    """
    global _AUDIT_INSTALLED, _AUDIT_BASELINE, _ADMIN_LOCKED
    if _SYS_ADDAUDITHOOK is None:
        return False  # 3.8-oncesi / kisitli runtime
    with _AUDIT_LOCK:
        if _AUDIT_INSTALLED:
            return True
        try:
            with _quiet_audit():
                _SYS_ADDAUDITHOOK(_audit_hook)
        except Exception:
            return False
        _AUDIT_INSTALLED = True
        _ADMIN_LOCKED = True
        total = 0
        try:
            for _k, v in _AUDIT_FLAGS.items():
                total += v
        except Exception:
            total = 0
        _AUDIT_BASELINE = total
        return True


def audit_hook_active() -> bool:
    """Kanca GERCEKTEN canli mi (bayrak + canli prob).

    Smash-saldirisi (ctypes ile hook-listesi bosaltma) bayragi bayat
    birakir; prob sayaci ilerlemiyorsa kanca olmustur -> False.
    """
    try:
        if not _AUDIT_INSTALLED:
            return False
        try:
            before = _AUDIT_SEEN
            audit_fn = getattr(sys, "audit", None)
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
    """Taban-cizgiyi su ana cek (YONETIM: kayitli operator sart).

    F8 duzeltmesi: yetkisiz sifirlama deny+trip uretir; olay delil
    zinciri korunur. Donus: sifirlanan (yutulan) olay sayisi.
    """
    if not _check_admin():
        _deny_admin("reset_audit_flags")
    global _AUDIT_BASELINE
    with _AUDIT_LOCK:
        total = 0
        try:
            for _k, v in _AUDIT_FLAGS.items():
                total += v
        except Exception:
            total = 0
        try:
            swallowed = total - _AUDIT_BASELINE
        except Exception:
            swallowed = 0
        _AUDIT_BASELINE = total
        try:
            _AUDIT_RING.clear()
        except Exception:
            pass
        return swallowed if swallowed >= 0 else 0


def audit_log() -> List[str]:
    """Halka-tamponun kopyasi (olay ADI listesi; arguman ASLA saklanmaz)."""
    try:
        with _AUDIT_LOCK:
            return list(_AUDIT_RING)
    except Exception:
        return []


def _audit_delta() -> int:
    try:
        with _AUDIT_LOCK:
            total = 0
            try:
                for _k, v in _AUDIT_FLAGS.items():
                    total += v
            except Exception:
                return 1  # okunamayan sayac -> fail-closed
            return total - _AUDIT_BASELINE
    except Exception:
        return 1


# ---------------------------------------------------------------------------
# Muhur deposu: id(func) -> (norm_fp_or_None, raw_fp, orijinal CodeType).
# heal() orijinali geri yazar (auto-healing). Agir parmak-izi KILIT DISINDA
# hesaplanir (audit-hook deadlock karsiti); kilit yalnizca sozluk yaziminda
# tutulur. Referanslar tutuldugu icin GC dusuremez; unseal() ile birakilir.
# ---------------------------------------------------------------------------
_SEALS: Dict[int, Tuple[Optional[str], str, CodeType]] = {}
_SEAL_FUNCS: Dict[int, object] = {}


def _normalized_ops(code: CodeType):
    """dis gorunumu (adaptive=False): quicken/cache gurultusunden arinmis akis.

    Donus: ozyinelemeli (opname, argkey) demeti; dis yoksa None. Import
    `_quiet_audit` icinde yapilir (kendi `compile` olayimiz trip uretmesin).
    sys.modules'e BIZ eklediysek geri kaldirilir (kardes WEAK temizligi).
    """
    try:
        added = "dis" not in _SYS_MODULES
        with _quiet_audit():
            import dis as _dis
    except Exception:
        return None
    try:
        try:
            instrs = list(_dis.get_instructions(code, adaptive=False))
        except TypeError:
            try:
                instrs = list(_dis.get_instructions(code))
            except Exception:
                return None
        except Exception:
            return None
        out = []
        try:
            consts = code.co_consts or ()
        except Exception:
            consts = ()
        nested = {}
        for const in consts:
            try:
                if isinstance(const, CodeType):
                    nested[id(const)] = _normalized_ops(const)
            except Exception:
                continue
        for ins in instrs:
            try:
                op = ins.opname
                if op == "CACHE":
                    continue
                try:
                    arg = ins.argval
                except Exception:
                    arg = None
                if isinstance(arg, CodeType):
                    arg = ("<code>", nested.get(id(arg)))
                elif isinstance(arg, (bytes, bytearray)):
                    arg = ("<bytes>", _HASH_SHA256()(bytes(arg)).hexdigest())
                else:
                    try:
                        arg = ("<val>", repr(arg))
                    except Exception:
                        arg = ("<val>", "?")
                out.append((op, arg))
            except Exception:
                continue
        return tuple(out)
    except Exception:
        return None
    finally:
        try:
            import sys as _s
            if added and "dis" in _s.modules:
                try:
                    del _s.modules["dis"]
                except Exception:
                    pass
        except Exception:
            pass


def _fp_tail(h, code: CodeType) -> None:
    """Paylasilan kuyruk: ozyinelemeli sabitler + isimler (her iki modda ortak)."""
    try:
        consts = code.co_consts or ()
    except Exception:
        consts = ()
    for const in consts:
        try:
            if isinstance(const, CodeType):
                try:
                    sub = _fingerprint_pair(const)
                    h.update((sub[0] or sub[1]).encode("ascii"))
                except Exception:
                    continue
            elif isinstance(const, (bytes, bytearray)):
                h.update(bytes(const))
            elif isinstance(const, str):
                h.update(const.encode("utf-8", "ignore"))
            elif isinstance(const, (int, float, complex, bool, type(None))):
                h.update(repr(const).encode("ascii", "ignore"))
            elif isinstance(const, tuple):
                h.update(repr(const).encode("utf-8", "ignore"))
        except Exception:
            continue
    for attr in ("co_names", "co_varnames"):
        try:
            h.update(repr(tuple(getattr(code, attr, ()) or ())).encode("utf-8", "ignore"))
        except Exception:
            continue


def _fingerprint_pair(code: CodeType) -> Tuple[Optional[str], str]:
    """Cift parmak-izi: (normalize-dis, ham-co_code). Ilki yoksa None."""
    tail_norm = _HASH_SHA256()
    tail_raw = _HASH_SHA256()
    try:
        _fp_tail(tail_norm, code)
    except Exception:
        pass
    try:
        _fp_tail(tail_raw, code)
    except Exception:
        pass
    norm = None
    try:
        ops = _normalized_ops(code)
        if ops is not None:
            h = _HASH_SHA256()
            try:
                h.update(repr(ops).encode("utf-8", "ignore"))
            except Exception:
                pass
            try:
                h.update(tail_norm.digest())
            except Exception:
                pass
            norm = h.hexdigest()
    except Exception:
        norm = None
    try:
        h = _HASH_SHA256()
        try:
            h.update(code.co_code)
        except Exception:
            h.update(b"\x00")
        try:
            h.update(tail_raw.digest())
        except Exception:
            pass
        raw = h.hexdigest()
    except Exception:
        raw = ""
    return (norm, raw)


def _code_fingerprint(code: CodeType) -> str:
    """Tekil ozet (geriye-uyumluluk icin)."""
    try:
        norm, raw = _fingerprint_pair(code)
        return norm if norm is not None else raw
    except Exception:
        return ""


def authorize_admin():
    """Operator modulunu kaydet (SADECE kilit-oncesi; boot sirasinda cagrilir).

    enforce_audit_hook() veya lock_admin() kaydi kilitler; kilit-sonrasi
    authorize denemesi reddedilir. Donus: True=kaydedildi.
    """
    global _ADMIN_DENIED
    try:
        if _ADMIN_LOCKED:
            with _THREAD_LOCK:
                _ADMIN_DENIED += 1
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
        with _THREAD_LOCK:
            _ADMIN_MODULES[name] = fn
        return True
    except Exception:
        return False


def lock_admin():
    """Yonetim kaydini kilitle (enforce_audit_hook zaten kilitler)."""
    global _ADMIN_LOCKED
    try:
        with _THREAD_LOCK:
            _ADMIN_LOCKED = True
        return True
    except Exception:
        return False


def _check_admin() -> bool:
    """Dogrudan cagiran cerceve kayitli operator modulu mu? (dosya-dogrulamali)."""
    try:
        with _THREAD_LOCK:
            allowed = dict(_ADMIN_MODULES)
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


def _deny_admin(op: str):
    """Yonetim reddi: fail-closed opak hata."""
    global _ADMIN_DENIED
    try:
        with _THREAD_LOCK:
            _ADMIN_DENIED += 1
    except Exception:
        pass
    raise AnalysisDetected("protected")


def _resolve_origin(fn):
    """Muhurlenen fonksiyonun (modul, attr) kokeni; bulunamazsa None."""
    try:
        for modname, mod in list(sys.modules.items()):
            try:
                if mod is None:
                    continue
                d = getattr(mod, "__dict__", None)
                if not isinstance(d, dict):
                    continue
                for k, v in d.items():
                    if v is fn:
                        return (str(modname), str(k))
            except Exception:
                continue
    except Exception:
        pass
    return None


def seal(*funcs) -> int:
    """Taban-cizgi al + orijinal kodu sakla. Donus: muhur sayisi.

    Not: muhur, fonksiyonu guclu referansla tutar; birakmak icin unseal().
    Koken (modul, attr) de kaydedilir; verify() CANLI baglantiyi da
    cozer (F7: mod.attr = evil rebinding tipi saldiri yakalanir).
    """
    pending = []
    for fn in funcs:
        try:
            if not isinstance(fn, FunctionType):
                continue
            code = fn.__code__
            if not isinstance(code, CodeType):
                continue
            try:
                pair = _fingerprint_pair(code)
            except Exception:
                continue
            pending.append((id(fn), (pair[0], pair[1], code), fn, _resolve_origin(fn)))
        except Exception:
            continue
    with _THREAD_LOCK:
        for key, record, fn, origin in pending:
            try:
                _SEALS[key] = record
                _SEAL_FUNCS[key] = fn
                if origin:
                    _SEAL_ORIGIN[key] = origin
            except Exception:
                continue
    return len(pending)


def unseal(*funcs) -> int:
    """Muhur kaldir (YONETIM: kayitli operator sart; bos cagri = no-op).

    F10 duzeltmesi: argsiz toplu-sifreleme kaldirildi; her unseal
    yetkilendirme ister ve journal etkisi verify/status'ta gorunur.
    """
    if not _check_admin():
        _deny_admin("unseal")
    if not funcs:
        return 0
    removed = 0
    with _THREAD_LOCK:
        for fn in funcs:
            try:
                key = id(fn)
                if key in _SEALS:
                    del _SEALS[key]
                    _SEAL_FUNCS.pop(key, None)
                    _SEAL_ORIGIN.pop(key, None)
                    removed += 1
            except Exception:
                continue
    return removed


def _match_record(record, code: CodeType) -> bool:
    """Cift-kayit eslesme: norm VEYA raw tutarsa True (mod-dayaniklilik)."""
    try:
        if not isinstance(record, (list, tuple)) or len(record) < 3:
            return False  # legacy/bozuk kayit -> fail-closed (asagida False)
        stored_norm, stored_raw = record[0], record[1]
        if not stored_raw:
            return False
    except Exception:
        return False
    try:
        now_norm, now_raw = _fingerprint_pair(code)
    except Exception:
        return False
    try:
        if stored_norm is not None and now_norm is not None and now_norm == stored_norm:
            return True
    except Exception:
        pass
    try:
        if now_raw and now_raw == stored_raw:
            return True
    except Exception:
        pass
    return False


def verify() -> bool:
    """Tum muhurler saglam mi? Bozuk varsa False.

    Iki katman: (a) sakli nesnenin kodu kayda uyar; (b) kokeni bilinen
    muhurlerde CANLI modul baglantisi cozulur ve muurlu nesneyle ayni
    olup kodu tutuyor mu bakilir (F7: rebinding yakalama).
    """
    with _THREAD_LOCK:
        items = list(_SEALS.items())
        live = dict(_SEAL_FUNCS)
        origins = dict(_SEAL_ORIGIN)
    if not items:
        return True
    for key, record in items:
        try:
            fn = live.get(key)
            if fn is None:
                return False  # referans tutulurken kaybolmamali -> supheli
            if not isinstance(fn, FunctionType):
                return False
            code = fn.__code__
            if not isinstance(code, CodeType):
                return False
            if not _match_record(record, code):
                return False
        except Exception:
            return False
        try:
            origin = origins.get(key)
            if origin:
                modname, attr = origin
                mod = sys.modules.get(modname)
                cur = getattr(mod, attr, None) if mod is not None else None
                if cur is not fn or not isinstance(cur, FunctionType):
                    return False
                ccode = cur.__code__
                if not isinstance(ccode, CodeType) or not _match_record(record, ccode):
                    return False
        except Exception:
            return False
    return True


def heal() -> int:
    """Bozulan __code__'lari orijinale restore et. Donus: iyilesen sayisi."""
    healed = 0
    with _THREAD_LOCK:
        items = list(_SEALS.items())
        live = dict(_SEAL_FUNCS)
    for key, record in items:
        try:
            fn = live.get(key)
            if fn is None or not isinstance(fn, FunctionType):
                continue
            try:
                orig = record[2] if len(record) >= 3 else None
            except Exception:
                orig = None
            if not isinstance(orig, CodeType):
                continue  # legacy/bozuk kayit restore edilemez
            try:
                cur = fn.__code__
            except Exception:
                cur = None
            try:
                bad = not isinstance(cur, CodeType) or not _match_record(record, cur)
            except Exception:
                bad = True
            if bad:
                try:
                    fn.__code__ = orig
                    healed += 1
                except Exception:
                    continue
        except Exception:
            continue
    return healed


def _pinned_mismatch() -> bool:
    try:
        if sys.modules is not _SYS_MODULES:
            return True
    except Exception:
        pass
    try:
        if gc.get_objects is not _GC_GET_OBJECTS:
            return True
    except Exception:
        pass
    try:
        if hashlib.sha256 is not _HASH_SHA256:
            return True
    except Exception:
        pass
    try:
        if time.perf_counter is not _PERF_COUNTER:
            return True
    except Exception:
        pass
    try:
        if os._exit is not _OS_EXIT:
            return True
    except Exception:
        pass
    try:
        if threading.Lock is not _THREAD_LOCK_CLS:
            return True
    except Exception:
        pass
    try:
        if threading.Event is not _THREAD_EVENT_CLS:
            return True
    except Exception:
        pass
    try:
        if threading.Thread is not _THREAD_THREAD_CLS:
            return True
    except Exception:
        pass
    try:
        if getattr(sys, "addaudithook", None) is not _SYS_ADDAUDITHOOK:
            return True
    except Exception:
        pass
    return False


def _check_suppress_spoof() -> bool:
    """STRONG: bastirma sayaci cercevesiz siskin mi (F9 aktif somuru)."""
    try:
        with _AUDIT_LOCK:
            return bool(_SUPPRESS_SPOOF_LATCH)
    except Exception:
        return True


def _check_seal_integrity() -> bool:
    """STRONG: muhur kirik mi."""
    try:
        return not verify()
    except Exception:
        return True


def _check_audit_events() -> bool:
    """STRONG: taban-cizgi sonrasi kod-uretimi/sokumu/yurutme olayi var mi."""
    try:
        if not _AUDIT_INSTALLED:
            return False  # kanca yok -> bilinmiyor, suphe uretme
        return _audit_delta() > 0
    except Exception:
        return True


def _check_active_frames() -> bool:
    """STRONG: Bytecode/inspect-exfiltrasyon cercevesi aktif mi."""
    get_frames = _SYS_CURRENT_FRAMES
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
                    fpath = (code.co_filename or "").lower().replace("\\", "/")
                except Exception:
                    break
                try:
                    if fname in _BC_FRAME_FUNCS_LOOSE:
                        return True
                    if fname in _BC_FRAME_FUNCS_STRICT:
                        for mark in _BC_FRAME_FILE_MARKS:
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


def _check_tool_presence() -> bool:
    """WEAK: analiz araci modul yuklu mu (varlik tek basina suphe degil)."""
    try:
        live = sys.modules
    except Exception:
        return False  # okunamiyorsa WEAK uretme (STRONG'lar zaten bakar)
    try:
        for name in _ANALYSIS_MODULES:
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
            if top in _ANALYSIS_MODULES:
                return True
        return False
    except Exception:
        return False


# Bilinen-masum finder etiketleri (tam-eslesme; saldirgan bu modul adlarini
# ele gecirmedikce guvenli). importlib ailesi + setuptools stdlib shim'i +
# NVIDIA NVML yonlendirme shim'i (surucu ile gelen cevresel bilesen).
_TRUSTED_FINDERS = frozenset({
    "_distutils_hack.distutilsmetafinder",
    "_pynvml_redirector.pynvmlfinder",
})


def _finder_tag(finder) -> str:
    try:
        # meta_path siniflari da tutar (BuiltinImporter v.b. sinifin kendisi)
        cls = finder if isinstance(finder, type) else type(finder)
        mod = getattr(cls, "__module__", "") or ""
        name = getattr(cls, "__name__", "") or ""
        return (mod + "." + name).lower()
    except Exception:
        return "?"


def _check_import_hook_tamper() -> bool:
    """WEAK: meta-path'e yabanci finder eklenmis mi (guvenilirler haric)."""
    try:
        path = sys.meta_path
    except Exception:
        return False
    try:
        names = set()
        for finder in path:
            tag = _finder_tag(finder)
            if tag in _TRUSTED_FINDERS:
                continue
            if tag.startswith(("_frozen_importlib", "importlib", "_bootstrap")):
                continue
            if "decompiler" in tag or "blocker" in tag:
                continue  # kardes modul blocker'lari (anti_decompile)
            if tag.startswith(("unittest", "_pytest", "pytest", "mock")):
                continue
            if "hyper cipher" in tag or "hyperct" in tag:
                continue
            names.add(tag)
        return len(names) > 0
    except Exception:
        return False


def check_all() -> Dict[str, bool]:
    """Tum sinyaller (True=risk). Kritik hata -> True (fail-closed)."""
    out: Dict[str, bool] = {}
    try:
        out["pinned_mismatch"] = _pinned_mismatch()
    except Exception:
        out["pinned_mismatch"] = True
    try:
        out["seal_broken"] = _check_seal_integrity()
    except Exception:
        out["seal_broken"] = True
    try:
        out["audit_event"] = _check_audit_events()
    except Exception:
        out["audit_event"] = True
    try:
        out["active_analysis_frame"] = _check_active_frames()
    except Exception:
        out["active_analysis_frame"] = True
    try:
        out["tool_present"] = _check_tool_presence()
    except Exception:
        out["tool_present"] = False
    try:
        out["foreign_import_hook"] = _check_import_hook_tamper()
    except Exception:
        out["foreign_import_hook"] = False
    try:
        out["suppress_spoof"] = _check_suppress_spoof()
    except Exception:
        out["suppress_spoof"] = True
    try:
        out["audit_unarmed"] = not bool(_AUDIT_INSTALLED)
    except Exception:
        out["audit_unarmed"] = True
    return out


def score() -> Tuple[int, int, int]:
    """(strong_sayisi, weak_sayisi, toplam)."""
    try:
        signals = check_all()
    except Exception:
        return (1, 0, _STRONG)
    strong_keys = ("pinned_mismatch", "seal_broken", "audit_event", "active_analysis_frame",
                   "suppress_spoof")
    weak_keys = ("tool_present", "foreign_import_hook")
    strong = 0
    weak = 0
    try:
        for key in strong_keys:
            if signals.get(key):
                strong += 1
        for key in weak_keys:
            if signals.get(key):
                weak += 1
    except Exception:
        return (1, 0, _STRONG)
    return (strong, weak, strong * _STRONG + weak * _WEAK)


def is_analyzed() -> bool:
    """Trip kurali: >=1 STRONG veya >=2 WEAK. Hata -> True."""
    try:
        strong, weak, _total = score()
        return strong >= 1 or weak >= 2
    except Exception:
        return True


def status() -> Dict[str, object]:
    """Durum ozeti (sinyal isimleri acik, degerler bool)."""
    try:
        signals = check_all()
    except Exception:
        signals = {}
    try:
        strong, weak, total = score()
    except Exception:
        strong, weak, total = (1, 0, _STRONG)
    try:
        verdict = is_analyzed()
    except Exception:
        verdict = True
    try:
        seals = len(_SEALS)
    except Exception:
        seals = -1
    try:
        origins = len(_SEAL_ORIGIN)
    except Exception:
        origins = -1
    try:
        with _AUDIT_LOCK:
            suppressed = int(_SUPPRESSED_TOTAL)
    except Exception:
        suppressed = -1
    return {"analyzed": verdict, "strong": strong, "weak": weak,
            "score": total, "signals": signals,
            "audit_hook": audit_hook_active(), "seals": seals,
            "seal_origins": origins, "suppressed_total": suppressed,
            "admin_authorized": len(_ADMIN_MODULES), "admin_locked": _ADMIN_LOCKED,
            "admin_denied": _ADMIN_DENIED}


def assert_no_analysis() -> None:
    """Trip varsa opak hata yukselt."""
    if is_analyzed():
        raise AnalysisDetected("protected")


def _watchdog_loop(stop_event: threading.Event, interval: float,
                   on_trip: Optional[Callable[[], None]]) -> None:
    try:
        while not stop_event.wait(interval):
            try:
                tripped = is_analyzed()
            except Exception:
                tripped = True
            if tripped:
                try:
                    if on_trip is not None:
                        on_trip()
                except Exception:
                    pass
                try:
                    _OS_EXIT(1)
                except Exception:
                    pass
                return
    except Exception:
        pass


def start_watchdog(interval: float = 0.5,
                   on_trip: Optional[Callable[[], None]] = None):
    """Watchdog baslat, durdurma fonksiyonu don (opt-in; uretim profili)."""
    try:
        iv = float(interval)
    except Exception:
        iv = 0.5
    if iv < 0.05:
        iv = 0.05
    if iv > 60.0:
        iv = 60.0
    stop_event = threading.Event()
    thread = threading.Thread(target=_watchdog_loop, args=(stop_event, iv, on_trip), daemon=True)
    with _THREAD_LOCK:
        _WATCHDOGS.append((thread, stop_event))
    try:
        thread.start()
    except Exception:
        pass

    def _stop() -> None:
        try:
            stop_event.set()
        except Exception:
            pass

    return _stop


def stop_all_watchdogs() -> int:
    """Tum watchdog'lari durdur (YONETIM: kayitli operator sart).

    F10 duzeltmesi: yetkisiz durdurma deny+trip uretir.
    Donus: durdurulan sayisi.
    """
    if not _check_admin():
        _deny_admin("stop_all_watchdogs")
    count = 0
    with _THREAD_LOCK:
        items = list(_WATCHDOGS)
        _WATCHDOGS.clear()
    for _thread, stop_event in items:
        try:
            stop_event.set()
            count += 1
        except Exception:
            continue
    return count


def guard(func):
    """Dekorator: cagri oncesi sessiz kontrol, trip varsa opak hata."""
    try:
        if not callable(func):
            return func
    except Exception:
        return func

    def _wrapped(*args, **kwargs):
        if is_analyzed():
            raise AnalysisDetected("protected")
        return func(*args, **kwargs)

    try:
        _wrapped.__name__ = getattr(func, "__name__", "_wrapped")
        _wrapped.__qualname__ = getattr(func, "__qualname__", "_wrapped")
        _wrapped.__doc__ = getattr(func, "__doc__", None)
        try:
            _wrapped.__dict__.update(getattr(func, "__dict__", {}))
        except Exception:
            pass
        try:
            _wrapped.__annotations__ = dict(getattr(func, "__annotations__", {}))
        except Exception:
            pass
    except Exception:
        pass
    return _wrapped
