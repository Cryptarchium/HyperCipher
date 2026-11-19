# -*- coding: utf-8 -*-
"""
HyperCipherAnti - AntiDecompile (Stage 4)
=========================================
Entegre cok katmanli decompiler/disassembler tespiti + bytecode butunlugu.
Stdlib-only, cross-platform, fail-closed, sessiz (oracle vermez).

Arastirma sentezi (3 guclu arastirma + en guclu teknikler):
  [1] Decompiler gercegi: uncompyle6 (<=3.8) / decompyle3 (<=3.9) neredeyse
      birebir kaynak uretir; pycdc (Decompyle++, 2.x-3.14) modern bytecode'u
      okur; desteksiz surumde bile `marshal.loads + dis` ile sabitler ve
      akis okunur. `.pyc` dagitmak koruma DEGILDIR, cache formatidir.
      (pyobfuscate.com 2026 testleri + Medium/Urban Vidergar saha analizi)
  [2] Gercek bar katmanlidir: AST rename + string sifreleme + control-flow
      flattening + opaque predicate + dead-code enjeksiyonu + lazy
      per-function bytecode sifreleme + anti-debug + native compile
      (Cython/Nuitka). Anahtarsiz encoding (base64/zlib/marshal) 0.004ms'de
      cozulur; rename tek basina secret'leri acikta birakir. Bu modul
      runtime tarafidir: build-time obfuscation YERINE gecmez, onu
      denetler + calisma anindaki cozucu saldiriyi yakalar.
      (pyobfus/patchwork/Anubis/obfy mimarileri + PyObfuscator whitepaper)
  [3] Kombine teknikler (BCF + instruction-substitution + CFF) tum
      LLM-tabanli deobfuscator'lari evrensel olarak durdurur; tek teknik
      (ozellikle BCF) zayiftir. Ders: HICBIR tek sinyale guvenme, coklu
      bagimsiz sinyal + capraz dogrulama sart.
      (arxiv 2505.19887 dort-boyut cercevesi + Quarkslab/Miasm bulgulari)

Entegrasyon prensibi: HICBIR tek kontrole guvenme. Tum STRONG kontroller
best-effort kosar, kritik hata -> True (fail-closed) doner, ASLA crash
vermez. Trip kurali: >=1 STRONG veya >=2 WEAK (plaintext_secrets +
foreign_finder). Hata mesaji OP AKTIR (hangi katman tetiklendi soylenmez).
Hijyen denetimi cagiran modulu tarar; aciktaki secret decompiler'a
davetiye oldugu icin WEAK olarak skora girer. Proses-disi cozumleme
(LOW-1: ayri proseste .pyc kopyasi uzerinde uncompyle6/pycdc) mimari
olarak gorunmez, iddia edilmez (tehdit-modeli disi).

Kullanim:
    from HyperCipherAnti import anti_decompile
    anti_decompile.seal(my_func, my_other)   # bytecode muhurle
    anti_decompile.assert_no_decompile()      # varsa DecompileDetected
    if anti_decompile.is_decompiled(): ...    # sessiz kontrol
    findings = anti_decompile.audit_constants(my_module)  # hijyen
    stop = anti_decompile.start_watchdog(interval=0.5)
    stop()
"""

from __future__ import annotations

import gc
import hashlib
import os
import re
import sys
import threading
import time
from types import CodeType, FunctionType, ModuleType
from typing import Callable, Dict, List, Optional, Tuple
import importlib.machinery as _mach

__all__ = [
    "DecompileDetected",
    "is_decompiled",
    "check_all",
    "score",
    "status",
    "assert_no_decompile",
    "seal",
    "unseal",
    "verify",
    "audit_constants",
    "opaque_true",
    "opaque_false",
    "enforce_block_decompilers",
    "remove_blocker",
    "start_watchdog",
    "stop_all_watchdogs",
    "guard",
]


class DecompileDetected(RuntimeError):
    """Opak hata: hangi katman tetiklendi DISARIYA soylenmez (oracle kapali)."""


# ---------------------------------------------------------------------------
# Import-aninda pin'li referanslar (B1 deseni: canli lookup korlugu + hook
# capraz kontrolu). Saldirgan sys.modules/sys.gettrace'i sonradan
# yamarsa pinned kopya ile tutarsizlik -> hook suphesi -> True.
# ---------------------------------------------------------------------------
_SYS_MODULES = sys.modules
_SYS_CURRENT_FRAMES = getattr(sys, "_current_frames", None)
_GC_GET_OBJECTS = gc.get_objects
_OS_EXIT = os._exit
_HASH_SHA256 = hashlib.sha256
_PERF_COUNTER = time.perf_counter
_THREAD_LOCK = threading.Lock()
_WATCHDOGS: List[Tuple[threading.Thread, threading.Event]] = []

_STRONG = 100
_WEAK = 30


# ---------------------------------------------------------------------------
# Bilinen decompiler/disassembler artefaktlari.
# uncompyle6/decompyle3: klasik pip decompiler'lar (<=3.9).
# xdis: rocky'nin cross-version disassembler altyapisi (decompiler'larin kalbi).
# pycdc/pycde/pylingual/pydecipher/unpyc37: modern/alternatif cozucu zincir.
# pyinstxtractor: PyInstaller paketinden pyc cikaran ilk-adim araci.
# ---------------------------------------------------------------------------
_DECOMPILER_MODULES = frozenset({
    "uncompyle6",
    "decompyle3",
    "decompyle",
    "uncompyle2",
    "uncompyle",
    "unpyc37",
    "unpyc3",
    "xdis",
    "pycdc",
    "pycde",
    "pylingual",
    "pydecipher",
    "pycdc_wasm",
    "decompiler",
    "pyinstxtractor",
    "pyi_archive_viewer",
    "frida",  # in-process dump kancasi tasiyabilir
})

# Aktif cozucu cerceveleri: dosya adi + fonksiyon adi imzasi.
# dis.py (stdlib): dis/disassemble/get_instructions/show_code/_disassemble_*
# xdis: show_code + cross-version opcode tablolari uzerinden okuma.
# inspect.getsource: kaynagi henuz .py olarak duran hedefte dogrudan sizinti.
_DIS_FRAME_FILES = ("dis.py", "xdis", "inspect.py", "pycode.py")
_DIS_FRAME_FUNCS = frozenset({
    "dis",
    "disassemble",
    "distb",
    "get_instructions",
    "show_code",
    "disasm",
    "getsource",
    "getsourcelines",
    "findsource",
})

# Sabit-hijyen kalibi: acikta duran secret decompiler ciktisini aninda
# kiymetli kilar. Tespit bilgi amacli + WEAK skor (tek basina trip yok).
_SECRET_RES = (
    re.compile(r"(?i)\bsk-(live|test|ant)-[A-Za-z0-9][A-Za-z0-9\-_]{8,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"(?i)\b(api[_-]?key|apikey|secret|passwd|password|token)\b\s*[:=]\s*\S{4,}"),
    re.compile(r"(?i)\bghp_[A-Za-z0-9]{20,}"),
    re.compile(r"(?i)\bxox[bap]-"),
    re.compile(r"(?i)\bPRO-[0-9]{4}-[A-Z0-9]{3,}"),
)

# Muhur deposu: id(func) -> (norm_fp_or_None, raw_fp, len)
# Cift-kayit: dogrulama ikisinden biriyle gecer (mod-dayaniklilik).
# Fonksiyon nesnesi guclu tutulur; unseal() ile birakilir.
_SEALS: Dict[int, Tuple[int, str, int]] = {}
_SEAL_FUNCS: Dict[int, object] = {}
_SEAL_ORIGIN: Dict[int, Tuple[str, str]] = {}
_CANONICAL_FINDER_TYPES = frozenset({
    _mach.BuiltinImporter, _mach.FrozenImporter, _mach.PathFinder,
})
_BLOCKER_REMOVED_LATCH = False
_ADMIN_MODULES: Dict[str, str] = {}
_ADMIN_LOCKED = False
_ADMIN_DENIED = 0


def _pinned_mismatch() -> bool:
    """Pin'li referanslar canli degerlerle uyusmuyorsa hook suphesi."""
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
    return False


def _check_decompiler_modules() -> bool:
    """STRONG: bilinen cozucu modul yuklu mu (canli + pinned cift okuma)."""
    try:
        live = sys.modules
    except Exception:
        return True  # okunamayan import tablosu -> fail-closed
    try:
        pinned = _SYS_MODULES
    except Exception:
        pinned = {}
    try:
        for name in _DECOMPILER_MODULES:
            try:
                if name in live or name in pinned:
                    return True
            except Exception:
                continue
        # Prefiks supurme: xdis.std, uncompyle6.scanners gibi alt moduller.
        try:
            keys = list(live.keys())
        except Exception:
            keys = []
        for key in keys:
            try:
                top = key.split(".", 1)[0].lower()
            except Exception:
                continue
            if top in _DECOMPILER_MODULES:
                return True
        return False
    except Exception:
        return True


def _check_active_disassembly() -> bool:
    """STRONG: su an bu process icinde aktif disassembly cercevesi var mi."""
    get_frames = _SYS_CURRENT_FRAMES
    if get_frames is None:
        return False  # platform destegi yok -> bilinmiyor (False)
    try:
        frames = get_frames()
    except Exception:
        return True  # cerceve tablosu okunamiyor -> fail-closed
    try:
        for _tid, frame in frames.items():
            f = frame
            depth = 0
            while f is not None and depth < 64:
                depth += 1
                try:
                    code = f.f_code
                    fname = code.co_name
                    fpath = code.co_filename or ""
                except Exception:
                    break
                try:
                    if fname in _DIS_FRAME_FUNCS:
                        low = fpath.lower().replace("\\", "/")
                        base = low.rsplit("/", 1)[-1]
                        if base in _DIS_FRAME_FILES or "xdis" in low or low.endswith("/dis.py"):
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


def _normalized_ops(code: CodeType):
    """dis gorunumu (adaptive=False): quicken/cache gurultusunden arinmis akis.

    Donus: ozyinelemeli (opname, argkey) demeti. dis yoksa None (ham moda dus).
    `dis` LAZY import edilir; sys.modules'e BIZ eklediysek geri kaldirilir
    (kardes WEAK sinyalini kirletmemek icin).
    """
    try:
        added = "dis" not in _SYS_MODULES
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
    """Cift parmak-izi: (normalize-dis, ham-co_code). Ilki yoksa None.

    Cift-kayit: dogrulama IKISINDEN biriyle gecer. Import-sistemi
    perturbasyonu (bozuk finder, dis kaybi) modu degistirir ama kodu
    degistirmez -> diger eslesme FP'yi onler. Gercek patch HER IKISINI
    birden bozar -> trip korunur.
    """
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
    """Tekil ozet (geriye-uyumluluk + hizli karsilastirma icin)."""
    try:
        norm, raw = _fingerprint_pair(code)
        return norm if norm is not None else raw
    except Exception:
        return ""


def authorize_admin():
    """Operator modulunu kaydet (SADECE kilit-oncesi; boot sirasinda cagrilir).

    Ilk start_watchdog() kaydi kilitler. Donus: True=kaydedildi.
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
    raise DecompileDetected("protected")


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
    """Verilen fonksiyonlarin bytecode'unu muhurle. Donus: muhur sayisi.

    Not: muhur, fonksiyonu guclu referansla tutar (heal/verify icin);
    birakmak icin unseal() cagrilmali, aksi halde GC'ye dusmez.
    Koken (modul, attr) de kaydedilir; verify() CANLI baglantiyi da
    cozer (rebinding saldirisi yakalanir).
    """
    count = 0
    with _THREAD_LOCK:
        for fn in funcs:
            try:
                if not isinstance(fn, FunctionType):
                    continue
                code = fn.__code__
                if not isinstance(code, CodeType):
                    continue
                fp = _code_fingerprint(code)
                try:
                    size = len(code.co_code)
                except Exception:
                    size = -1
                key = id(fn)
                try:
                    pair = _fingerprint_pair(code)
                except Exception:
                    pair = (None, fp)
                # Kayit: (norm_or_None, raw, size) - cift-kayit macta kullanilir
                _SEALS[key] = (pair[0], pair[1] or fp, size)
                _SEAL_FUNCS[key] = fn
                try:
                    origin = _resolve_origin(fn)
                    if origin:
                        _SEAL_ORIGIN[key] = origin
                except Exception:
                    pass
                count += 1
            except Exception:
                continue
    return count


def unseal(*funcs) -> int:
    """Muhur kaldir (YONETIM: kayitli operator sart; bos cagri = no-op).

    HIGH-1 duzeltmesi: argsiz toplu-sifreleme kaldirildi.
    Donus: kaldirilan sayisi.
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


def verify() -> bool:
    """Tum muhurler saglam mi? Bozuk/eslesmeyen kayit varsa False.

    Iki katman: (a) sakli nesnenin parmak-izi kayda uyar; (b) kokeni
    bilinen muhurlerde CANLI modul baglantisi cozulur ve muurlu nesneyle
    ayni olup kodu tutuyor mu bakilir (rebinding yakalama).
    """
    with _THREAD_LOCK:
        items = list(_SEALS.items())
        live = dict(_SEAL_FUNCS)
        origins = dict(_SEAL_ORIGIN)
    if not items:
        return True  # muhursuz durum bilgi degil, temiz sayilir
    for key, record in items:
        try:
            fn = live.get(key)
            if fn is None:
                continue  # cop toplanmis -> sessizce dusur
            if not isinstance(fn, FunctionType):
                return False
            code = fn.__code__
            if not isinstance(code, CodeType):
                return False
            try:
                size = record[2] if len(record) >= 3 else -1
            except Exception:
                size = -1
            try:
                if size is not None and size >= 0 and len(code.co_code) != size:
                    return False  # hizli on-elek (hash'tan once)
            except Exception:
                pass
            try:
                now_norm, now_raw = _fingerprint_pair(code)
            except Exception:
                return False
            try:
                if len(record) >= 3:
                    stored_norm, stored_raw = record[0], record[1]
                else:
                    stored_norm, stored_raw = None, None  # legacy kayit
            except Exception:
                return False
            if stored_raw is None:
                return False  # legacy/bozuk kayit -> fail-closed (yeniden muhurle)
            try:
                norm_ok = (stored_norm is not None and now_norm is not None
                           and now_norm == stored_norm)
            except Exception:
                norm_ok = False
            try:
                raw_ok = bool(now_raw) and now_raw == stored_raw
            except Exception:
                raw_ok = False
            if not (norm_ok or raw_ok):
                return False  # co_code degismis: patch/deobfuse suphesi
            try:
                origin = origins.get(key)
                if origin:
                    modname, attr = origin
                    mod = sys.modules.get(modname)
                    cur = getattr(mod, attr, None) if mod is not None else None
                    if cur is not fn or not isinstance(cur, FunctionType):
                        return False
                    ccode = cur.__code__
                    if not isinstance(ccode, CodeType):
                        return False
                    try:
                        c_norm, c_raw = _fingerprint_pair(ccode)
                    except Exception:
                        return False
                    c_norm_ok = (stored_norm is not None and c_norm is not None
                                 and c_norm == stored_norm)
                    c_raw_ok = bool(c_raw) and c_raw == stored_raw
                    if not (c_norm_ok or c_raw_ok):
                        return False
            except Exception:
                return False
        except Exception:
            return False  # fail-closed
    return True


def _check_seal_integrity() -> bool:
    """STRONG: muhur kirik mi (in-memory patch / co_code swap)."""
    try:
        return not verify()
    except Exception:
        return True


def _iter_codes(code: CodeType):
    """Kod nesnesini ozyinelemeli gez (sabitlerdeki ic kodlar dahil)."""
    stack = [code]
    seen = set()
    while stack:
        cur = stack.pop()
        if id(cur) in seen:
            continue
        seen.add(id(cur))
        yield cur
        try:
            consts = cur.co_consts or ()
        except Exception:
            continue
        for const in consts:
            try:
                if isinstance(const, CodeType):
                    stack.append(const)
            except Exception:
                continue


def _collect_strings(code: CodeType) -> List[str]:
    out: List[str] = []
    try:
        for sub in _iter_codes(code):
            try:
                consts = sub.co_consts or ()
            except Exception:
                continue
            for const in consts:
                try:
                    if isinstance(const, str):
                        out.append(const)
                    elif isinstance(const, (bytes, bytearray)):
                        try:
                            out.append(bytes(const).decode("utf-8", "ignore"))
                        except Exception:
                            continue
                except Exception:
                    continue
    except Exception:
        pass
    return out


def audit_constants(target=None) -> List[Dict[str, str]]:
    """WEAK kaynagi: hedefteki acik secret-benzeri sabitleri listele.

    hedef: modul / fonksiyon / fonksiyon listesi / None (cagiran modul).
    Donus: [{"owner": ..., "kind": ..., "mlen": ...}] (eslesen metin ASLA
    disari verilmez, sadece uzunlugu -> oracle kapali).
    """
    findings: List[Dict[str, str]] = []
    owners: List[Tuple[str, object]] = []
    try:
        if target is None:
            try:
                frame = sys._current_frames()[threading.get_ident()]
                mod_name = frame.f_globals.get("__name__", "?")
                mod = _SYS_MODULES.get(mod_name)
                target = mod if mod is not None else frame.f_globals
            except Exception:
                return []
        if isinstance(target, ModuleType):
            try:
                members = list(vars(target).items())
            except Exception:
                members = []
            for name, obj in members:
                try:
                    if isinstance(obj, FunctionType):
                        owners.append(("%s.%s" % (getattr(target, "__name__", "?"), name), obj))
                    elif isinstance(obj, type):
                        # Sinif ici metodlar (duz + static/classmethod cozumlemeli)
                        try:
                            cls_members = list(vars(obj).items())
                        except Exception:
                            cls_members = []
                        for mname, mobj in cls_members:
                            try:
                                fn = mobj
                                if not isinstance(fn, FunctionType):
                                    try:
                                        fn = fn.__func__
                                    except Exception:
                                        continue
                                if isinstance(fn, FunctionType):
                                    owners.append(("%s.%s.%s" % (
                                        getattr(target, "__name__", "?"),
                                        getattr(obj, "__name__", "?"), mname), fn))
                            except Exception:
                                continue
                except Exception:
                    continue
        elif isinstance(target, FunctionType):
            owners.append((getattr(target, "__qualname__", "?"), target))
        elif isinstance(target, type):
            # Dogrudan sinif hedefi: metodlari cozerek tara
            try:
                cls_members = list(vars(target).items())
            except Exception:
                cls_members = []
            for mname, mobj in cls_members:
                try:
                    fn = mobj
                    if not isinstance(fn, FunctionType):
                        try:
                            fn = fn.__func__
                        except Exception:
                            continue
                    if isinstance(fn, FunctionType):
                        owners.append(("%s.%s" % (
                            getattr(target, "__name__", "?"), mname), fn))
                except Exception:
                    continue
        elif isinstance(target, (list, tuple)):
            for obj in target:
                try:
                    if isinstance(obj, FunctionType):
                        owners.append((getattr(obj, "__qualname__", "?"), obj))
                except Exception:
                    continue
        elif isinstance(target, dict):
            for name, obj in target.items():
                try:
                    if isinstance(obj, FunctionType):
                        owners.append((str(name), obj))
                except Exception:
                    continue
        else:
            return []
    except Exception:
        return []
    for owner, fn in owners:
        let_code = None
        try:
            let_code = fn.__code__
        except Exception:
            continue
        if not isinstance(let_code, CodeType):
            continue
        try:
            strings = _collect_strings(let_code)
        except Exception:
            continue
        for text in strings:
            try:
                for rx in _SECRET_RES:
                    try:
                        m = rx.search(text)
                    except Exception:
                        continue
                    if m:
                        try:
                            mlen = str(len(m.group(0)))
                        except Exception:
                            mlen = "?"
                        findings.append({"owner": str(owner)[:120], "kind": "secret-like-const", "mlen": mlen})
                        break
            except Exception:
                continue
    return findings


# Hijyen TTL cache: 1.0s kisa-pencere (MEDIUM-3: 10s kor pencere kapali).
# True bulgular ASLA flush'lanmaz (sadece suresi-dolmus False girdiler
# budanir; research konsensusu: kisa-TTL + hedefli-gecersizleme).
_HYGIENE_TTL = 1.0
_HYGIENE_CACHE: Dict[str, Tuple[float, bool]] = {}


def _caller_module():
    """Kendi cercevelerimizi atlayip ilk YABANCI cagiranin modulunu bul."""
    try:
        get_frames = _SYS_CURRENT_FRAMES
    except Exception:
        get_frames = None
    if get_frames is None:
        try:
            get_frames = sys._current_frames
        except Exception:
            return None
    try:
        frame = get_frames()[threading.get_ident()]
    except Exception:
        return None
    try:
        own = __name__
    except Exception:
        own = ""
    f = frame
    depth = 0
    while f is not None and depth < 64:
        depth += 1
        try:
            mod_name = f.f_globals.get("__name__", "")
        except Exception:
            mod_name = ""
        try:
            if mod_name and mod_name != own and not mod_name.startswith(own + "."):
                try:
                    return _SYS_MODULES.get(mod_name)
                except Exception:
                    return None
        except Exception:
            pass
        try:
            f = f.f_back
        except Exception:
            break
    return None


def _check_hygiene() -> bool:
    """WEAK: cagiran modulde acik secret-benzeri sabit var mi (best-effort)."""
    try:
        mod = _caller_module()
        if mod is None:
            return False
        try:
            mod_name = getattr(mod, "__name__", "?")
        except Exception:
            mod_name = "?"
        try:
            now = _PERF_COUNTER()
        except Exception:
            now = 0.0
        try:
            with _THREAD_LOCK:
                hit = _HYGIENE_CACHE.get(mod_name)
            if hit is not None and (now - hit[0]) < _HYGIENE_TTL:
                return hit[1]
        except Exception:
            pass
        try:
            found = len(audit_constants(mod)) > 0
        except Exception:
            return False
        try:
            with _THREAD_LOCK:
                _HYGIENE_CACHE[mod_name] = (now, found)
                if len(_HYGIENE_CACHE) > 256:
                    try:
                        for _k in [k for k, (_t, _v) in _HYGIENE_CACHE.items()
                                   if not _v and (now - _t) >= _HYGIENE_TTL]:
                            _HYGIENE_CACHE.pop(_k, None)
                    except Exception:
                        pass
                    if len(_HYGIENE_CACHE) > 256:
                        try:
                            for _k in [k for k, (_t, _v) in _HYGIENE_CACHE.items()
                                       if not _v][:16]:
                                _HYGIENE_CACHE.pop(_k, None)
                        except Exception:
                            pass
        except Exception:
            pass
        return found
    except Exception:
        return False  # hijyen olculemedi -> suphe uretme


# Bilinen-masum finder etiketleri (tam-eslesme). importlib ailesi +
# setuptools stdlib shim'i + NVIDIA NVML shim'i + test kosuculari.
# MEDIUM-2 duzeltmesi: "mock" prefix muafiyeti KALDIRILDI (mock_evil
# gizlenme kapisiydi); unittest/pytest korunur (acik test altyapisi).
_TRUSTED_FINDERS = frozenset({
    "_distutils_hack.distutilsmetafinder",
    "_pynvml_redirector.pynvmlfinder",
})
_TRUSTED_PREFIXES = ("_frozen_importlib", "importlib", "_bootstrap",
                     "unittest", "_pytest", "pytest")


def _finder_tag(finder) -> str:
    try:
        cls = finder if isinstance(finder, type) else type(finder)
        mod = getattr(cls, "__module__", "") or ""
        name = getattr(cls, "__name__", "") or ""
        return (mod + "." + name).lower()
    except Exception:
        return "?"


def _check_foreign_finder() -> bool:
    """WEAK: meta-path'te yabanci finder var mi (exact-type + tam-etiket)."""
    try:
        path = sys.meta_path
    except Exception:
        return False
    try:
        for finder in path:
            try:
                if type(finder) in _CANONICAL_FINDER_TYPES:
                    continue
            except Exception:
                pass
            if isinstance(finder, _DecompilerBlocker):
                continue
            tag = _finder_tag(finder)
            if tag in _TRUSTED_FINDERS:
                continue
            if tag.startswith(_TRUSTED_PREFIXES):
                continue
            if "hyper cipher" in tag or "hyperct" in tag:
                continue
            return True  # ilk yabanci yeterli (WEAK)
        return False
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
        out["decompiler_module"] = _check_decompiler_modules()
    except Exception:
        out["decompiler_module"] = True
    try:
        out["active_disassembly"] = _check_active_disassembly()
    except Exception:
        out["active_disassembly"] = True
    try:
        out["seal_broken"] = _check_seal_integrity()
    except Exception:
        out["seal_broken"] = True
    try:
        out["blocker_removed"] = _check_blocker_removed()
    except Exception:
        out["blocker_removed"] = True
    try:
        out["plaintext_secrets"] = _check_hygiene()
    except Exception:
        out["plaintext_secrets"] = False
    try:
        out["foreign_finder"] = _check_foreign_finder()
    except Exception:
        out["foreign_finder"] = False
    return out


def score() -> Tuple[int, int, int]:
    """(strong_sayisi, weak_sayisi, toplam)."""
    try:
        signals = check_all()
    except Exception:
        return (1, 0, _STRONG)
    strong_keys = ("pinned_mismatch", "decompiler_module", "active_disassembly", "seal_broken",
                   "blocker_removed")
    weak_keys = ("plaintext_secrets", "foreign_finder")
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


def is_decompiled() -> bool:
    """Trip kurali: >=1 STRONG veya >=2 WEAK. Hata -> True (fail-closed)."""
    try:
        strong, weak, _total = score()
        return strong >= 1 or weak >= 2
    except Exception:
        return True


def status() -> Dict[str, object]:
    """Opak olmayan durum ozeti (sinyal isimleri debug icin acik, degerler bool)."""
    try:
        signals = check_all()
    except Exception:
        signals = {}
    try:
        strong, weak, total = score()
    except Exception:
        strong, weak, total = (1, 0, _STRONG)
    try:
        verdict = is_decompiled()
    except Exception:
        verdict = True
    return {"decompiled": verdict, "strong": strong, "weak": weak, "score": total, "signals": signals,
            "seals": len(_SEALS), "seal_origins": len(_SEAL_ORIGIN),
            "admin_authorized": len(_ADMIN_MODULES), "admin_locked": _ADMIN_LOCKED,
            "admin_denied": _ADMIN_DENIED}


def assert_no_decompile() -> None:
    """Trip varsa opak hata yukselt."""
    if is_decompiled():
        raise DecompileDetected("protected")


# ---------------------------------------------------------------------------
# Opaque predicate yardimcilari (deterministik, yan-etkisiz, ucuz).
# Degerler onceden hesaplanmis sabit kimliklerdir; statik analizde
# cozumu zaman ister, calisma maliyeti ~ns mertebesindedir. Tek basina
# guvenlik siniri DEGILDIR (deterrent katmani) -> her zaman diger
# katmanlarla birlikte kullan.
# ---------------------------------------------------------------------------
_OPAQUE_A = 0x9E3779B1
_OPAQUE_B = 0x85EBCA6B
_OPAQUE_C = 0xC2B2AE35
# (A * B + C) % 2**32 == 0x54633530  (build-time'da dogrulandi)
_OPAQUE_R = 0x54633530


def opaque_true() -> bool:
    """Her zaman True (sabit aritmetik kimlik)."""
    try:
        return ((_OPAQUE_A * _OPAQUE_B + _OPAQUE_C) & 0xFFFFFFFF) == _OPAQUE_R
    except Exception:
        return True


def opaque_false() -> bool:
    """Her zaman False (yukaridaki kimligin tersi)."""
    try:
        return ((_OPAQUE_A * _OPAQUE_B + _OPAQUE_C) & 0xFFFFFFFF) != _OPAQUE_R
    except Exception:
        return False


def _decoy_decode(_blob: bytes, _key: bytes):  # pragma: no cover
    """OLU KOL: hicbir zaman calismaz; cozucu-analiz yukunu sismeseye yarar.

    Gercekci gorunumlu sahte cozucu; opaque_false() guard'i arkasinda
    tutulur. Arastirma bulgusu: dead-code enjeksiyonu analiz isini 3-5x
    katlar (pyobfus/whitepaper olcumu).
    """
    if opaque_false():  # pragma: no cover - daima False
        import base64 as _b64
        import hashlib as _hl
        _raw = _b64.b64decode(_blob)
        _digest = _hl.sha256(_raw).digest()
        _out = bytes(_c ^ _k for _c, _k in zip(_raw, (_digest + _key) * 16))
        return _out
    return None


# ---------------------------------------------------------------------------
# Import-blocker: bilinen cozucu paketlerin importunu engeller (meta-path).
# Sadece yasakli ust-seviye isimler bloklanir; baska hicbir import etkilenmez.
# ---------------------------------------------------------------------------
class _DecompilerBlocker:
    """Meta-path import engelleyici (dar hedefli, sessiz degil -> ImportError)."""

    def find_module(self, fullname, path=None):  # noqa: D102 - legacy API
        try:
            top = fullname.split(".", 1)[0].lower()
        except Exception:
            return None
        if top in _DECOMPILER_MODULES:
            return self
        return None

    def load_module(self, fullname):  # noqa: D102 - legacy API
        raise ImportError("blocked")

    def find_spec(self, fullname, path=None, target=None):
        try:
            top = fullname.split(".", 1)[0].lower()
        except Exception:
            return None
        if top in _DECOMPILER_MODULES:
            raise ImportError("blocked")
        return None


_BLOCKER = _DecompilerBlocker()


def enforce_block_decompilers() -> bool:
    """Blocker'i meta-path'e tak (idempotent)."""
    try:
        path = sys.meta_path
    except Exception:
        return False
    try:
        for finder in path:
            if finder is _BLOCKER:
                return True
        path.insert(0, _BLOCKER)
        return True
    except Exception:
        return False


def remove_blocker() -> bool:
    """Blocker'i kaldir (YONETIM: kayitli operator sart).

    MEDIUM-1 duzeltmesi: kaldirma sticky latch kurar (`blocker_removed`
    STRONG sinyali) — savunma-indirme gizlenemez, verify/status'ta gorunur.
    """
    if not _check_admin():
        _deny_admin("remove_blocker")
    global _BLOCKER_REMOVED_LATCH
    try:
        path = sys.meta_path
    except Exception:
        return False
    try:
        if _BLOCKER in path:
            path.remove(_BLOCKER)
        with _THREAD_LOCK:
            _BLOCKER_REMOVED_LATCH = True
        return True
    except Exception:
        return False


def _check_blocker_removed() -> bool:
    """STRONG: import-blocker kaldirilmis mi (savunma-indirme izi)."""
    try:
        with _THREAD_LOCK:
            if _BLOCKER_REMOVED_LATCH:
                return True
        try:
            if _BLOCKER not in list(sys.meta_path):
                return False
        except Exception:
            pass
        return False
    except Exception:
        return True


# ---------------------------------------------------------------------------
# Watchdog: arka plan izleme (opt-in). Trip'te varsayilan tepki process
# cikisidir; callback verilirse once o cagrilir. False-positive notu:
# ayni process icinde mesru `dis` kullanimi (debug) trip uretir; watchdog
# sadece uretim profilinde acilmali.
# ---------------------------------------------------------------------------
def _watchdog_loop(stop_event: threading.Event, interval: float,
                   on_trip: Optional[Callable[[], None]]) -> None:
    try:
        while not stop_event.wait(interval):
            try:
                tripped = is_decompiled()
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
    """Watchdog baslat, durdurma fonksiyonu don."""
    global _ADMIN_LOCKED
    try:
        with _THREAD_LOCK:
            _ADMIN_LOCKED = True
    except Exception:
        pass
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
        if is_decompiled():
            raise DecompileDetected("protected")
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
