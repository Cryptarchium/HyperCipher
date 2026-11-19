# -*- coding: utf-8 -*-
"""anti_module_manipulation: modul-kayit manipulasyon aktif-savunma katmani.

Tehdit modeli (arastirma sentezi - 3x ReSearch):
  - R1 MEM-SBOM evasion taksonomisi (arxiv 2606.22827, PEP 451/420):
    A1 module-deletion (sys.modules girdisi silinir, canli referans kalir),
    A2 module-overwrite/alias (iyi-isim kotu-obje: sys.modules["os"]=mal),
    A3 import-hook interception (sys.meta_path'e kotu finder, hedef importu
    custom loader'a yonlendirir), A4 import-bypass creation (importlib/runpy
    ile sys.modules'a KAYITSIZ modul: types.ModuleType+compile+exec),
    A5 sub-interpreter injection (ana interpreter taramasinda gorunmez),
    A6 GC-unlink (ctypes ile gc listesinden dusurme). Savunma: L1 registry
    + L2 frame-namespace + L3 gc-traversal cok-katmanli cikarma.
  - R2 PEP 451 ModuleSpec (finder/loader ayrimi, importlib.machinery):
    saglikli modulde ``mod.__loader__`` + ``mod.__spec__.loader`` kanonik
    kumededir (BuiltinImporter/FrozenImporter/PathFinder/FileFinder/
    SourceFileLoader/SourcelessFileLoader/ExtensionFileLoader/
    NamespaceLoader/zipimporter). wrapt `_ImportHookChainedLoader` deseni
    spec.loader'i geri yazar -> TEK kontrol kor, CIFT kontrol
    (__loader__ VE __spec__.loader) sart.
  - R3 __import__ bypass (Parla.py #10, metapathology, wrapt importer):
    ``builtins.__import__`` override'i C-API (PyImport_*), Cython cimport,
    ``importlib.import_module`` ve ``_frozen_importlib._gcd_import``
    tarafindan bypass edilir. Savunma: ``builtins.__import__`` kimligi
    (builtin-function-type) + ``importlib.import_module`` sarim-kontrolu.

Kapsam (kardeslerle cakisma yok):
  - anti_import_analysis: PASIF tespit+skor (finder sirasi, ghost, shadow,
    .pth). BU modul AKTIF koruma: kritik modul kimlik-pin'i, swap-guard,
    kayitsiz-modul avi (gc), import-fn spoof, reload-istismari.
  - anti_patch: snapshot/restore + pin/verify/seal GENEL cerceve; BU modul
    restore'a DOKUNMAZ, sadece modul-kaydi manipulasyonunu tutar.
  - anti_hook.import_system: genel kanca sagligi; BU modul loader-zinciri
    + __import__ kimligi derin-analizi.
  - Sessiz, stdlib-only, fail-closed. True=risk, False=temiz.
  - Trip >=1 STRONG veya >=2 WEAK.

Sinirlar (bilincli tercihler):
  - Modul importtan ONCE yerlesen saldirgan gorunmez (bootstrap korlugu;
    R1 metapathology ile ayni sinir). Koruma, pin anindan sonraki DEGISIM
    + mevcut anomali uzerinedir.
  - A5 sub-interpreter: stdlib'den gorunmez; belge + sensor_health ile
    karsilanir, iddia edilmez.
  - A6 GC-unlink: gc-disi obje bulunamaz; gc-traversal L3 en iyi-gayrettir.
  - Bilinen-kabul (statik-tarama): split-string/getattr-obfuscation
    ("mod"+"ules") + exec-string yukleri bytecode-sekli birakmaz; ETKI
    runtime-guard'larca (swap/loader/ghost check_all) yakalanir.
    Statik scan tripwire, runtime check enforcement'tir.
"""
from __future__ import annotations
import builtins as _builtins
import gc as _gc
import sys as _sys
import threading as _threading
import time as _time
import types as _types

try:
    import importlib as _importlib
except Exception:
    _importlib = None


class ModuleManipulationDetected(RuntimeError):
    pass


def _raise() -> None:
    raise ModuleManipulationDetected("protected")


def _take_dis_pin(attr: str):
    """dis'i lazy yukle + tahliye et (self-FP onler, kardes konvansiyon)."""
    try:
        added = "dis" not in _sys.modules
        import dis as _d
        try:
            return getattr(_d, attr, None)
        finally:
            try:
                if added and "dis" in _sys.modules:
                    del _sys.modules["dis"]
            except Exception:
                pass
    except Exception:
        return None


_PIN_THREAD_RLOCK = _threading.RLock
_PIN_THREAD_THREAD = _threading.Thread
_PIN_THREAD_EVENT = _threading.Event
_PIN_TIME_MONOTONIC = _time.monotonic
_PIN_GETATTR = getattr
_PIN_HASATTR = hasattr
_PIN_ISINSTANCE = isinstance
_PIN_LEN = len
_PIN_SET = set
_PIN_LIST = list
_PIN_FROZENSET = frozenset
_PIN_STR = str
_PIN_ID = id
_PIN_TYPE = type
_PIN_SYS = _sys
_PIN_GC_GET_OBJECTS = _gc.get_objects
_PIN_DIS_GET_INSTRUCTIONS = _take_dis_pin("get_instructions")
_PIN_MODULE_TYPE = _types.ModuleType
_PIN_BUILTIN_FUNC_TYPE = _PIN_TYPE(_PIN_LEN)
_PIN_IMPORT = _builtins.__import__
_PIN_IMPORTLIB_IMPORT_MODULE = _PIN_GETATTR(_importlib, "import_module", None) if _importlib is not None else None
_PIN_GCD_IMPORT = None
try:
    import importlib._bootstrap as _boot
    _PIN_GCD_IMPORT = _boot._gcd_import
except Exception:
    try:
        import _frozen_importlib as _fi
        _PIN_GCD_IMPORT = getattr(_fi, "_gcd_import", None)
    except Exception:
        _PIN_GCD_IMPORT = None

_LOCK = _PIN_THREAD_RLOCK()

WEIGHTS = {
    "module_swap": 100,
    "loader_chain_spoof": 100,
    "unregistered_shadow": 100,
    "import_fn_spoof": 100,
    "pin_mismatch": 100,
    "sensor_health": 100,
    "submodule_alias": 30,
    "loader_mismatch": 30,
    "registry_anomaly": 30,
    "reload_abuse": 30,
    "loader_obscured": 30,
    "manipulation_probe_anomaly": 30,
}
STRONG = _PIN_FROZENSET({
    "module_swap",
    "loader_chain_spoof",
    "unregistered_shadow",
    "import_fn_spoof",
    "pin_mismatch",
    "sensor_health",
})
_THRESHOLD_TRIP = 100

# Kritik modul kumesi: HyperCipher cekirdegi + anti ailesi + import altyapisi.
_CRITICAL_MODULES = _PIN_FROZENSET({
    "hyper_cipher",
    "builtins",
    "importlib", "importlib._bootstrap", "importlib._bootstrap_external",
    "importlib.machinery", "importlib.util", "importlib.abc",
    "anti_introspection", "anti_reflection", "anti_tamper", "anti_hook",
    "anti_debug", "anti_vm", "anti_sandbox", "anti_emulation", "anti_dump",
    "anti_memory_inspection", "anti_side_channel", "anti_oracle",
    "anti_import_analysis", "anti_patch", "anti_trace", "anti_instrumentation",
    "anti_key_extraction", "anti_string_extraction", "anti_constant_analysis",
    "anti_control_flow_analysis", "anti_data_flow_analysis",
    "anti_bytecode_analysis", "anti_decompile", "anti_error_leakage",
    "anti_configuration_tamper", "anti_symbol_recovery",
    "anti_module_manipulation",
    "os", "sys",
})

_CANONICAL_LOADERS = _PIN_FROZENSET({
    "BuiltinImporter", "FrozenImporter", "PathFinder", "FileFinder",
    "SourceFileLoader", "SourcelessFileLoader", "ExtensionFileLoader",
    "NamespaceLoader", "NamespacePath", "zipimporter",
    "WindowsRegistryFinder", "AppleFrameworkLoader",
    "SourcelessLoader",
})

# Kod-tarama kelime-dagarcigi: modul-kaydi manipulasyon primitifleri.
_MODULES_ATTRS = _PIN_FROZENSET({
    "sys.modules", "modules",
})
_SWAP_VERBS = _PIN_FROZENSET({
    "sys.modules",
    "__import__", "import_module", "_gcd_import",
    "reload", "ModuleType", "spec_from_file_location",
    "module_from_spec", "exec_module", "create_module",
    "find_spec", "find_module", "load_module",
    "meta_path", "path_hooks", "path_importer_cache",
    "del ", "pop(",
})
_LOADER_ATTRS = _PIN_FROZENSET({
    "__loader__", "__spec__", "__package__", "__path__",
})
_GC_VERBS = _PIN_FROZENSET({
    "get_objects", "get_referrers", "get_referents",
})
_DUNDER_MOD = _PIN_FROZENSET({
    "__import__", "__loader__", "__spec__", "__modules__",
})

_WATCH: dict = {}
_PINS: dict = {}
_ALERT_HOOK = None
_PROBE_LOG: dict = {}
_BASELINE: dict = {}
_SWAP_BASELINE: dict = {}
_WATCHDOGS: list = []
_MM_ADMINS: dict = {}
_MM_ADMIN_LOCKED = False
_MM_ADMIN_DENIED = 0


def authorize_admin():
    """Operator modulunu kaydet (SADECE kilit-oncesi; boot sirasinda cagrilir).

    Ilk start_watchdog() kaydi kilitler. Donus: True=kaydedildi.
    """
    global _MM_ADMIN_DENIED
    try:
        if _MM_ADMIN_LOCKED:
            with _LOCK:
                _MM_ADMIN_DENIED += 1
            return False
        try:
            fr = _PIN_SYS._getframe(1)
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
            import os as _o
            if not _o.path.isfile(fn):
                return False
        except Exception:
            return False
        with _LOCK:
            _MM_ADMINS[name] = fn
        return True
    except Exception:
        return False


def _mm_check_admin() -> bool:
    """Dogrudan cagiran cerceve kayitli operator modulu mu? (dosya-dogrulamali)."""
    try:
        with _LOCK:
            allowed = dict(_MM_ADMINS)
        if not allowed:
            return False
        try:
            fr = _PIN_SYS._getframe(2)
        except Exception:
            return False
        try:
            name = str(fr.f_globals.get("__name__", "") or "")
            fn = str(getattr(fr.f_code, "co_filename", "") or "")
            want = allowed.get(name)
            if want is not None and fn == want and not fn.startswith("<"):
                try:
                    import os as _o2
                    if _o2.path.isfile(fn):
                        return True
                except Exception:
                    pass
        except Exception:
            pass
        return False
    except Exception:
        return False


def _mm_deny_admin(op: str):
    """Yonetim reddi: fail-closed opak hata."""
    global _MM_ADMIN_DENIED
    try:
        with _LOCK:
            _MM_ADMIN_DENIED += 1
    except Exception:
        pass
    _raise()

_GC_SCAN_CAP = 50000
_SHADOW_CURSOR = 0
_STDLIB_TOPS = frozenset()
try:
    _STDLIB_TOPS = frozenset(getattr(_sys, "stdlib_module_names", None) or ())
except Exception:
    _STDLIB_TOPS = frozenset()
_PROBE_WINDOW_S = 60.0
_PROBE_THRESHOLD = 50


def _loader_name(loader) -> str:
    try:
        if loader is None:
            return "None"
        return _PIN_GETATTR(loader, "__name__", None) or _PIN_TYPE(loader).__name__
    except Exception:
        return "?"


def _mod_loader_names(mod):
    """(loader-ad, spec-loader-ad) cift-kontrolu (R2: wrapt deseni)."""
    try:
        lname = _loader_name(_PIN_GETATTR(mod, "__loader__", None))
    except Exception:
        lname = "?"
    try:
        spec = _PIN_GETATTR(mod, "__spec__", None)
        sname = _loader_name(_PIN_GETATTR(spec, "loader", None)) if spec is not None else "no-spec"
    except Exception:
        sname = "?"
    try:
        lmod = _PIN_TYPE(_PIN_GETATTR(mod, "__loader__", None)).__module__
    except Exception:
        lmod = "?"
    return lname, sname, lmod


def _snapshot_swap_baseline() -> None:
    """Kritik modul kimlik-pin'i: id() + loader-cifti."""
    try:
        with _LOCK:
            mods = _PIN_GETATTR(_PIN_SYS, "modules", None) or {}
            for name in _CRITICAL_MODULES:
                try:
                    mod = mods.get(name)
                    if mod is None:
                        continue
                    lname, sname, lmod = _mod_loader_names(mod)
                    _SWAP_BASELINE[name] = (_PIN_ID(mod), lname, sname, lmod)
                except Exception:
                    continue
    except Exception:
        pass


def _check_module_swap() -> bool:
    """A2 overwrite/alias + M-4 deletion: pin'li kritik modul kimligi (STRONG).

    M-4: kayip modul artik `continue` DEGIL trip — kritik modulun
    baseline'dan silinmesi (A1 deletion) STRONG'dur; mesru silinme
    kritik kumede pratikte yoktur (strict-by-design).
    """
    try:
        mods = _PIN_GETATTR(_PIN_SYS, "modules", None) or {}
        for name, base in _PIN_LIST(_SWAP_BASELINE.items()):
            try:
                mod = mods.get(name)
                if mod is None:
                    return True
                if _PIN_ID(mod) != base[0]:
                    return True
            except Exception:
                continue
        return False
    except Exception:
        return False


def _check_loader_chain() -> bool:
    """A3+M-3 interception: kritik modul loader-cifti kanonik-disi (STRONG).

    M-3: unknown/None loader artik `continue` DEGIL trip — tek-alan wipe
    (mod.__loader__ = None) STRONG'u atlatamaz. Kritik kume namespace
    paketi icermez (loader-None mesruiyeti yok).
    """
    try:
        mods = _PIN_GETATTR(_PIN_SYS, "modules", None) or {}
        for name in _CRITICAL_MODULES:
            try:
                mod = mods.get(name)
                if mod is None:
                    continue
                lname, sname, _lmod = _mod_loader_names(mod)
                if lname not in _CANONICAL_LOADERS and lname != "no-spec":
                    return True
                if sname not in _CANONICAL_LOADERS and sname not in ("no-spec", "None", "?"):
                    return True
            except Exception:
                continue
        return False
    except Exception:
        return False


def _check_import_fn() -> bool:
    """R3+M-2: import giris-noktalari 3-yonlu kimlik (STRONG).

    M-2: builtins.__import__ + importlib.import_module YANINDA
    _frozen_importlib._gcd_import pinlenir. Research (CPython #116840 +
    PEP 578): tum GERCEK yuklemeler (_gcd_import/C-API/Cython dahil)
    _find_and_load'dan gecer ve `import` audit olayi yayar — __import__
    sarimi tek-basina kor degildir; 3 kimlik + audit-gozlem birlikte
    bypass'i kapatir. _gcd_import'e erisilemezse o dal atlanir (fail-open
    degil: diger iki pin + audit aktif kalir).
    """
    try:
        cur = _PIN_GETATTR(_builtins, "__import__", None)
        if cur is not None and cur is not _PIN_IMPORT:
            return True
        if _PIN_TYPE(cur) is not _PIN_BUILTIN_FUNC_TYPE:
            return True
    except Exception:
        return False
    try:
        if _importlib is not None and _PIN_IMPORTLIB_IMPORT_MODULE is not None:
            cur2 = _PIN_GETATTR(_importlib, "import_module", None)
            if cur2 is not None and cur2 is not _PIN_IMPORTLIB_IMPORT_MODULE:
                return True
    except Exception:
        pass
    try:
        if _PIN_GCD_IMPORT is not None:
            import importlib._bootstrap as _b2
            cur3 = getattr(_b2, "_gcd_import", None)
            if cur3 is not None and cur3 is not _PIN_GCD_IMPORT:
                return True
    except Exception:
        pass
    return False


_IMPORT_LOG: dict = {}
_IMPORT_HOOK_ON = False


def _import_audit_hook(event, args):
    """M-2: `import` audit-olayi gozlemi (tum yukleme-yollari).

    _find_and_load oncesi ateslenir: kritik modul ADI + filename
    kaydedilir (bounded 256). Manuel sys.modules enjeksiyonu (yukleme
    YOK) olay yaymaz — o swap/shadow check'lerinde yakalanir.
    """
    try:
        if event != "import":
            return
        try:
            name = args[0] if len(args) > 0 else ""
            fn = args[1] if len(args) > 1 else None
        except Exception:
            return
        if not isinstance(name, str):
            return
        try:
            top = name.split(".", 1)[0]
        except Exception:
            return
        if top not in _CRITICAL_MODULES and name not in _CRITICAL_MODULES:
            return
        try:
            with _LOCK:
                if len(_IMPORT_LOG) >= 256:
                    try:
                        _IMPORT_LOG.pop(next(iter(_IMPORT_LOG)))
                    except Exception:
                        pass
                _IMPORT_LOG[name] = str(fn) if fn else ""
        except Exception:
            pass
    except Exception:
        pass


def install_import_audit() -> bool:
    """M-2: import-gozlem hook'unu kur (idempotent)."""
    global _IMPORT_HOOK_ON
    try:
        if _IMPORT_HOOK_ON:
            return True
        _PIN_SYS.addaudithook(_import_audit_hook)
        _IMPORT_HOOK_ON = True
        return True
    except Exception:
        return False


def _check_unregistered_shadow() -> bool:
    """M-5: kayitsiz-golge avi — kritik + stdlib-isimli tum ModuleType'lar.

    Filtre genisletildi (kritik-set/os-prefix DEGIL: stdlib-tumu).
    Cap-asimi cozumu: cursor'lu devam — 50K/obje butce biterse kalinan
    yerden sonraki cagrida devam edilir (buyuk heap'te shadow cap
    otesine itilemez). Butce bitmeden tur tamamlanirsa cursor sifirlanir.
    """
    global _SHADOW_CURSOR
    try:
        mods = _PIN_GETATTR(_PIN_SYS, "modules", None) or {}
        try:
            objs = _PIN_GC_GET_OBJECTS()
        except Exception:
            return False
        try:
            total = _PIN_LEN(objs)
        except Exception:
            total = 0
        if total <= 0:
            return False
        start = _SHADOW_CURSOR % total
        seen = 0
        idx = start
        wrapped = False
        while seen < _GC_SCAN_CAP:
            try:
                obj = objs[idx]
            except Exception:
                break
            seen += 1
            idx += 1
            if idx >= total:
                idx = 0
                wrapped = True
            try:
                if not _PIN_ISINSTANCE(obj, _PIN_MODULE_TYPE):
                    continue
                name = _PIN_GETATTR(obj, "__name__", None)
                if not _PIN_ISINSTANCE(name, _PIN_STR) or not name:
                    continue
                try:
                    top = name.split(".", 1)[0]
                except Exception:
                    continue
                if name not in _CRITICAL_MODULES and top not in _STDLIB_TOPS:
                    continue
                try:
                    reg = mods.get(name)
                except Exception:
                    continue
                if reg is None:
                    # Kayitsiz stdlib-adli obje: import-arasi gecici olabilir
                    # (FP kalkani) — sadece kritik-isim kayitsizligi trip'ler.
                    if name in _CRITICAL_MODULES:
                        try:
                            _SHADOW_CURSOR = idx
                        except Exception:
                            pass
                        return True
                    continue
                if _PIN_ID(reg) != _PIN_ID(obj):
                    # Ayni-isimli CANLI kopya: bayat import-artigi (io,
                    # collections.abc ciftleri) mesru loader tasir; saldirgan
                    # golgesi loader'siz/sahte-loader'lidir. Loader-guven
                    # ayirimi FP'yi oldurur, golgeyi tutar.
                    try:
                        lname, _s, _m = _mod_loader_names(obj)
                    except Exception:
                        lname = "?"
                    if lname not in _CANONICAL_LOADERS:
                        try:
                            _SHADOW_CURSOR = idx
                        except Exception:
                            pass
                        return True
                    continue
            except Exception:
                continue
            if wrapped and idx >= start:
                break
        try:
            if wrapped or (start + seen) >= total:
                _SHADOW_CURSOR = 0
            else:
                _SHADOW_CURSOR = idx
        except Exception:
            pass
        return False
    except Exception:
        return False


def _check_loader_obscured() -> bool:
    """Anti-forensics: kritik modulun loader'i VE spec'i BILINMIYOR
    (ikisi birden silinmis/None - WEAK, komboda trip)."""
    try:
        mods = _PIN_GETATTR(_PIN_SYS, "modules", None) or {}
        for name in _CRITICAL_MODULES:
            try:
                mod = mods.get(name)
                if mod is None:
                    continue
                lname, sname, _lmod = _mod_loader_names(mod)
                if lname in ("?", "None") and sname in ("no-spec", "None", "?"):
                    return True
            except Exception:
                continue
        return False
    except Exception:
        return False


def _check_alias() -> bool:
    """A2 alias: iki kritik-isim AYNI objeye mi bagli (WEAK)."""
    try:
        mods = _PIN_GETATTR(_PIN_SYS, "modules", None) or {}
        by_id: dict = {}
        for name in _CRITICAL_MODULES:
            try:
                mod = mods.get(name)
                if mod is None:
                    continue
                key = _PIN_ID(mod)
                if key in by_id and by_id[key] != name:
                    return True
                by_id[key] = name
            except Exception:
                continue
        return False
    except Exception:
        return False


def _check_loader_mismatch() -> bool:
    """__loader__ vs __spec__.loader UYUSMUYOR (wrapt-chain izi, WEAK)."""
    try:
        mods = _PIN_GETATTR(_PIN_SYS, "modules", None) or {}
        for name in _CRITICAL_MODULES:
            try:
                mod = mods.get(name)
                if mod is None:
                    continue
                lname, sname, _lmod = _mod_loader_names(mod)
                if lname in ("?", "None", "no-spec") or sname in ("?", "None", "no-spec"):
                    continue
                if lname != sname:
                    return True
            except Exception:
                continue
        return False
    except Exception:
        return False


def _check_registry_anomaly() -> bool:
    """A1 deletion: baseline'da olup simdi KAYIP kritik modul (WEAK;
    deletion tek-basina trip uretmez, swap/ghost ile kombine olur)."""
    try:
        mods = _PIN_GETATTR(_PIN_SYS, "modules", None) or {}
        for name in _PIN_LIST(_SWAP_BASELINE.keys()):
            try:
                if mods.get(name) is None:
                    return True
            except Exception:
                continue
        return False
    except Exception:
        return False


def _check_reload_abuse() -> bool:
    """importlib.reload ile kritik modulun spec/loader'i degisti mi (WEAK)."""
    try:
        mods = _PIN_GETATTR(_PIN_SYS, "modules", None) or {}
        for name, base in _PIN_LIST(_SWAP_BASELINE.items()):
            try:
                mod = mods.get(name)
                if mod is None:
                    continue
                lname, sname, lmod = _mod_loader_names(mod)
                if (lname, sname) != (base[1], base[2]):
                    return True
                try:
                    if len(base) > 3 and lmod != base[3]:
                        return True
                except Exception:
                    pass
            except Exception:
                continue
        return False
    except Exception:
        return False


def _iter_code(co):
    out = [co]
    try:
        for c in _PIN_GETATTR(co, "co_consts", ()) or ():
            try:
                if _PIN_HASATTR(c, "co_names"):
                    out.extend(_iter_code(c))
            except Exception:
                continue
    except Exception:
        pass
    return out


def _collect(insns):
    attrs, names, ops = _PIN_SET(), _PIN_SET(), _PIN_SET()
    try:
        for ins in insns:
            try:
                ops.add(_PIN_STR(_PIN_GETATTR(ins, "opname", "")))
                arg = _PIN_GETATTR(ins, "argval", None)
                if _PIN_GETATTR(ins, "opname", "") in ("LOAD_ATTR", "STORE_ATTR", "DELETE_ATTR",
                                                       "LOAD_METHOD", "LOAD_GLOBAL", "LOAD_NAME",
                                                       "STORE_NAME", "DELETE_NAME", "IMPORT_NAME",
                                                       "IMPORT_FROM"):
                    if _PIN_ISINSTANCE(arg, _PIN_STR):
                        attrs.add(arg)
                        names.add(arg)
            except Exception:
                continue
    except Exception:
        pass
    return attrs, names, ops


def _snapshot_instructions(co):
    try:
        return _PIN_LIST(_PIN_DIS_GET_INSTRUCTIONS(co))
    except Exception:
        return []


_INSN_CAP = 20000


def _code_fp(fn) -> str:
    """M-6: davranissal parmak-izi (kod+const+isimler sha256).

    co_names SADECE isimleri hash'lerdi — ayni-isimli evil gecerdi.
    Davranis = bytecode + sabitler + isimler birlikte.
    """
    try:
        import hashlib as _h
        code = _PIN_GETATTR(fn, "__code__", None)
        if code is None:
            return ""
        h = _h.sha256()
        try:
            h.update(bytes(_PIN_GETATTR(code, "co_code", b"") or b""))
        except Exception:
            h.update(b"?")
        try:
            for c in _PIN_GETATTR(code, "co_consts", ()) or ():
                try:
                    if isinstance(c, (str, bytes, int, float, bool, type(None))):
                        h.update(repr(c).encode("utf-8", "ignore"))
                    elif isinstance(c, (tuple, frozenset)):
                        h.update(repr(sorted(repr(x) for x in c)).encode("utf-8", "ignore"))
                except Exception:
                    continue
        except Exception:
            pass
        try:
            h.update(repr(tuple(_PIN_GETATTR(code, "co_names", ()) or ())).encode("utf-8", "ignore"))
        except Exception:
            pass
        return h.hexdigest()
    except Exception:
        return ""


def _func_names(fn) -> set:
    try:
        code = _PIN_GETATTR(fn, "__code__", None)
        if code is None:
            return set()
        out = set()
        stack = [code]
        seen = 0
        while stack and seen < 64:
            try:
                co = stack.pop()
                seen += 1
                for n in _PIN_GETATTR(co, "co_names", ()) or ():
                    out.add(n)
                for c in _PIN_GETATTR(co, "co_consts", ()) or ():
                    if _PIN_HASATTR(c, "co_names"):
                        stack.append(c)
            except Exception:
                continue
        return out
    except Exception:
        return set()


def _func_text(fn) -> str:
    try:
        parts = []
        code = _PIN_GETATTR(fn, "__code__", None)
        if code is None:
            return ""
        stack = [code]
        seen = 0
        while stack and seen < 64:
            try:
                co = stack.pop()
                seen += 1
                for n in _PIN_GETATTR(co, "co_names", ()) or ():
                    parts.append(_PIN_STR(n))
                for v in _PIN_GETATTR(co, "co_varnames", ()) or ():
                    parts.append(_PIN_STR(v))
                for c in _PIN_GETATTR(co, "co_consts", ()) or ():
                    if _PIN_ISINSTANCE(c, _PIN_STR):
                        parts.append(c)
                    elif _PIN_HASATTR(c, "co_names"):
                        stack.append(c)
            except Exception:
                continue
        return "\n".join(parts)
    except Exception:
        return ""


def _store_targets_modules(insns) -> bool:
    """STORE/DELETE_SUBSCR gercekten `.modules` attr'ini mi hedefliyor?
    Geriye-dogru pencere: LOAD_ATTR(modules) + STORE_SUBSCR aranir
    (s.modules takma-adi dahil; kendi-dict store'u elenir)."""
    try:
        ops = [(str(getattr(i, "opname", "")), getattr(i, "argval", None)) for i in insns]
        for idx, (op, _a) in enumerate(ops):
            if op != "STORE_SUBSCR":
                continue
            lo = idx - 8 if idx - 8 > 0 else 0
            for op2, arg2 in ops[lo:idx]:
                if op2 in ("LOAD_ATTR", "LOAD_METHOD") and arg2 == "modules":
                    return True
        return False
    except Exception:
        return False


def _method_targets_modules(insns) -> bool:
    """LOAD_ATTR(modules) -> LOAD_METHOD(mutator) -> CALL zinciri aranir
    (kendi-dict .update() FP'si elenir)."""
    try:
        ops = [(str(getattr(i, "opname", "")), getattr(i, "argval", None)) for i in insns]
        muts = {"__setitem__", "__delitem__", "setdefault", "pop", "update", "clear"}
        for idx, (op, arg) in enumerate(ops):
            if op in ("LOAD_METHOD", "LOAD_ATTR") and arg in muts:
                lo = idx - 6 if idx - 6 > 0 else 0
                for op2, arg2 in ops[lo:idx]:
                    if op2 in ("LOAD_ATTR", "LOAD_METHOD") and arg2 == "modules":
                        return True
        return False
    except Exception:
        return False


def _modules_delete_keys(insns) -> set:
    """`.modules` hedefli DELETE_SUBSCR'larin sabit-anahtarlari (A1 analizi)."""
    try:
        ops = [(str(getattr(i, "opname", "")), getattr(i, "argval", None)) for i in insns]
        keys: set = set()
        for idx, (op, _a) in enumerate(ops):
            if op != "DELETE_SUBSCR":
                continue
            lo = idx - 6 if idx - 6 > 0 else 0
            targets_modules = False
            key = None
            for op2, arg2 in ops[lo:idx]:
                if op2 in ("LOAD_ATTR", "LOAD_METHOD") and arg2 == "modules":
                    targets_modules = True
                if op2 == "LOAD_CONST" and isinstance(arg2, str):
                    key = arg2
            if targets_modules:
                keys.add(key)
        return keys
    except Exception:
        return set()


def scan_module(fn) -> dict:
    """Manipulasyon-primitif taramasi: bytecode-korelasyonlu (string-sabit
    tek-basina sinyal DEGILDIR; gercek co_names/op-kombo sart - FP kalkani)."""
    try:
        code = _PIN_GETATTR(fn, "__code__", None)
        attrs: set = _PIN_SET()
        names: set = _PIN_SET()
        ops: set = _PIN_SET()
        co_names_all: set = _PIN_SET()
        all_insns: list = []
        if code is not None:
            try:
                for cc in _iter_code(code):
                    try:
                        if _PIN_LEN(names) >= _INSN_CAP:
                            break
                        insns = _snapshot_instructions(cc)
                        all_insns.extend(insns)
                        a, n, o = _collect(insns)
                        attrs.update(a)
                        names.update(n)
                        ops.update(o)
                        for nm in _PIN_GETATTR(cc, "co_names", ()) or ():
                            co_names_all.add(nm)
                    except Exception:
                        continue
            except Exception:
                pass
        text = _func_text(fn)
        has_sys = "sys" in co_names_all or "sys" in names
        modules_shape = ("modules" in attrs) or ("sys.modules" in text and has_sys)
        mod_store = _store_targets_modules(all_insns)
        stored_attrs: set = set()
        try:
            for i in all_insns:
                try:
                    if str(getattr(i, "opname", "")) in ("STORE_ATTR", "DELETE_ATTR"):
                        a = getattr(i, "argval", None)
                        if isinstance(a, str):
                            stored_attrs.add(a)
                except Exception:
                    continue
        except Exception:
            pass
        store_shape = ("modules" in stored_attrs) or mod_store
        del_keys = _modules_delete_keys(all_insns)
        dis_idiom = bool(del_keys) and del_keys <= {"dis"} and ("dis" in co_names_all or "dis" in names)
        hostile_delete = bool(del_keys - {"dis"}) or (bool(del_keys) and not dis_idiom and del_keys != {"dis"})
        del_shape = bool(hostile_delete) or ("modules" in stored_attrs and "DELETE_ATTR" in ops)
        pop_shape = "pop(" in text and modules_shape
        import_fn_shape = ("__import__" in attrs) or ("import_module" in names) or ("_gcd_import" in names)
        reload_shape = "reload" in names or "reload" in co_names_all
        modtype_shape = "ModuleType" in names or "ModuleType" in co_names_all
        exec_shape = bool({"exec_module", "create_module", "module_from_spec"} & (names | co_names_all))
        find_shape = bool({"find_spec", "find_module", "load_module"} & (names | co_names_all))
        loader_shape = bool({"__loader__", "__spec__", "loader"} & attrs)
        gc_shape = bool({"get_objects", "get_referrers"} & (names | co_names_all))
        method_mutate = _method_targets_modules(all_insns)
        out = {
            "module_swap": bool(modules_shape and (store_shape or pop_shape or hostile_delete or method_mutate)),
            "loader_chain_spoof": bool(loader_shape and (exec_shape or find_shape)),
            "unregistered_shadow": bool(gc_shape and modules_shape and (modtype_shape or exec_shape)),
            "import_fn_spoof": bool({"__import__", "import_module", "_gcd_import"} & stored_attrs) or bool(import_fn_shape and (modules_shape or store_shape)),
            "pin_mismatch": False,
            "sensor_health": False,
            "submodule_alias": bool(modules_shape and not (store_shape or import_fn_shape or reload_shape or exec_shape or hostile_delete or method_mutate)),
            "loader_mismatch": bool(loader_shape and not (exec_shape or find_shape)),
            "registry_anomaly": bool(del_shape or pop_shape or (modules_shape and method_mutate)),
            "reload_abuse": bool(reload_shape and not modules_shape),
            "manipulation_probe_anomaly": False,
            "loader_obscured": False,
        }
        # M-7: statik-tarama hardcode'lari GERCEK runtime-degerlerle doldurulur.
        try:
            out["pin_mismatch"] = not bool(verify_pins())
        except Exception:
            pass
        try:
            out["sensor_health"] = bool(_check_sensor_health())
        except Exception:
            pass
        try:
            out["manipulation_probe_anomaly"] = bool(_check_probe_anomaly())
        except Exception:
            pass
        try:
            if _check_loader_obscured():
                out["loader_obscured"] = True
        except Exception:
            pass
        return out
    except Exception:
        return {k: False for k in WEIGHTS}


def _check_pinned_mismatch() -> bool:
    try:
        if _PIN_IMPORT is not _PIN_GETATTR(_builtins, "__import__", None):
            return True
        if _PIN_GC_GET_OBJECTS is not _PIN_GETATTR(_gc, "get_objects", None):
            return True
        if _PIN_MODULE_TYPE is not _PIN_GETATTR(_types, "ModuleType", None):
            return True
        return False
    except Exception:
        return False


def _check_sensor_health() -> bool:
    try:
        probes = [
            _PIN_GETATTR(_PIN_SYS, "modules", None) is None,
            _PIN_GETATTR(_builtins, "__import__", None) is None,
            _PIN_GETATTR(_gc, "get_objects", None) is None,
        ]
        return any(probes)
    except Exception:
        return True


def _check_probe_anomaly() -> bool:
    try:
        now = _PIN_TIME_MONOTONIC()
        with _LOCK:
            stale = [k for k, t in _PIN_LIST(_PROBE_LOG.items()) if now - t > _PROBE_WINDOW_S]
            for k in stale:
                try:
                    del _PROBE_LOG[k]
                except Exception:
                    pass
            return _PIN_LEN(_PROBE_LOG) >= _PROBE_THRESHOLD
    except Exception:
        return False


def _raw_results() -> dict:
    out = {}
    try:
        out["module_swap"] = bool(_check_module_swap())
    except Exception:
        out["module_swap"] = False
    try:
        out["loader_chain_spoof"] = bool(_check_loader_chain())
    except Exception:
        out["loader_chain_spoof"] = False
    try:
        out["unregistered_shadow"] = bool(_check_unregistered_shadow())
    except Exception:
        out["unregistered_shadow"] = False
    try:
        out["import_fn_spoof"] = bool(_check_import_fn())
    except Exception:
        out["import_fn_spoof"] = False
    try:
        out["pin_mismatch"] = bool(_check_pinned_mismatch())
    except Exception:
        out["pin_mismatch"] = False
    try:
        out["sensor_health"] = bool(_check_sensor_health())
    except Exception:
        out["sensor_health"] = True
    try:
        out["submodule_alias"] = bool(_check_alias())
    except Exception:
        out["submodule_alias"] = False
    try:
        out["loader_mismatch"] = bool(_check_loader_mismatch())
    except Exception:
        out["loader_mismatch"] = False
    try:
        out["registry_anomaly"] = bool(_check_registry_anomaly())
    except Exception:
        out["registry_anomaly"] = False
    try:
        out["reload_abuse"] = bool(_check_reload_abuse())
    except Exception:
        out["reload_abuse"] = False
    try:
        out["loader_obscured"] = bool(_check_loader_obscured())
    except Exception:
        out["loader_obscured"] = False
    try:
        out["manipulation_probe_anomaly"] = bool(_check_probe_anomaly())
    except Exception:
        out["manipulation_probe_anomaly"] = False
    return out


def _score(results: dict) -> int:
    try:
        total = 0
        for k, v in _PIN_LIST(results.items()):
            try:
                if v:
                    total += WEIGHTS.get(k, 0)
            except Exception:
                continue
        return total
    except Exception:
        return 0


def is_tripped(results: dict | None = None) -> bool:
    try:
        res = results if results is not None else _raw_results()
        strong_hit = any(bool(res.get(k)) for k in STRONG)
        if strong_hit:
            return True
        weak_n = sum(1 for k, v in _PIN_LIST(res.items()) if v and k not in STRONG)
        return weak_n >= 2 or _score(res) >= _THRESHOLD_TRIP
    except Exception:
        return True


def check_all() -> dict:
    try:
        return _raw_results()
    except Exception:
        return {k: True for k in WEIGHTS}


def status() -> dict:
    try:
        res = _raw_results()
        return {"tripped": bool(is_tripped(res)), "strong": sum(1 for k in STRONG if res.get(k)),
                "weak": sum(1 for k, v in _PIN_LIST(res.items()) if v and k not in STRONG),
                "points": _score(res), "results": res}
    except Exception:
        return {"tripped": True, "strong": 0, "weak": 0, "points": 0, "results": {}}


def probe(fn) -> dict:
    try:
        res = scan_module(fn)
        try:
            with _LOCK:
                _PROBE_LOG[_PIN_ID(fn)] = _PIN_TIME_MONOTONIC()
        except Exception:
            pass
        return {"tripped": bool(is_tripped(res)), "points": _score(res), "results": res}
    except Exception:
        return {"tripped": True, "points": 0, "results": {}}


def watch(fn, key=None):
    try:
        with _LOCK:
            _WATCH[key or _PIN_ID(fn)] = fn
        return key or _PIN_ID(fn)
    except Exception:
        return None


def unwatch(fn=None, key=None):
    """Izlemeden cikar (YONETIM: kayitli operator sart — korlestirme kapali)."""
    if not _mm_check_admin():
        _mm_deny_admin("unwatch")
    try:
        with _LOCK:
            if key is not None:
                return _WATCH.pop(key, None) is not None
            if fn is not None:
                return _WATCH.pop(_PIN_ID(fn), None) is not None
            return False
    except Exception:
        return False


def pin(fn, key=None):
    """M-6: kimlik + davranis pin'i (id VE kod-fp)."""
    try:
        with _LOCK:
            _PINS[key or _PIN_ID(fn)] = (_PIN_ID(fn), _code_fp(fn))
        return key or _PIN_ID(fn)
    except Exception:
        return None


def verify_pins() -> bool:
    try:
        with _LOCK:
            items = _PIN_LIST(_PINS.items())
            watches = dict(_WATCH)
        for key, (fid, fp) in items:
            try:
                fn = watches.get(key)
                if fn is None:
                    continue
                if _PIN_ID(fn) != fid or _code_fp(fn) != fp:
                    return False
            except Exception:
                return False
        return True
    except Exception:
        return False


def seal() -> dict:
    """Baseline + pin (YONETIM: kayitli operator sart — re-baseline kapali)."""
    if not _mm_check_admin():
        _mm_deny_admin("seal")
    try:
        _snapshot_swap_baseline()
        with _LOCK:
            for key, fn in _PIN_LIST(_WATCH.items()):
                try:
                    _PINS[key] = (_PIN_ID(fn), _code_fp(fn))
                except Exception:
                    continue
        return {"sealed": True, "pins": _PIN_LEN(_PINS), "baseline": _PIN_LEN(_SWAP_BASELINE)}
    except Exception:
        return {"sealed": False, "pins": 0, "baseline": 0}


def harden() -> dict:
    try:
        return seal()
    except Exception:
        return {"sealed": False, "pins": 0, "baseline": 0}


def guard():
    return check_all()


def _watch_loop(stop, interval, heal):
    try:
        while not stop.is_set():
            try:
                res = _raw_results()
                if is_tripped(res):
                    strong = any(bool(res.get(k)) for k in STRONG)
                    if heal and not strong:
                        try:
                            _snapshot_swap_baseline()
                        except Exception:
                            pass
                    try:
                        if _ALERT_HOOK is not None:
                            _ALERT_HOOK(status())
                    except Exception:
                        pass
            except Exception:
                pass
            try:
                stop.wait(interval)
            except Exception:
                break
    except Exception:
        pass


def start_watchdog(interval=2.0, heal=True):
    """M-1: izlenen watchdog — thread registry'e kaydolur, kilitlenir."""
    global _MM_ADMIN_LOCKED
    try:
        with _LOCK:
            _MM_ADMIN_LOCKED = True
    except Exception:
        pass
    try:
        stop = _PIN_THREAD_EVENT()
        t = _PIN_THREAD_THREAD(target=_watch_loop, args=(stop, interval, heal), daemon=True)
        with _LOCK:
            _WATCHDOGS.append((t, stop))
        t.start()
        return stop
    except Exception:
        return None


def stop_all_watchdogs():
    """M-1: GERCEK durdurma — tum kayitli watchdog'lar set+join+temizlik.

    YONETIM: kayitli operator sart. Donus: durdurulan sayi.
    """
    if not _mm_check_admin():
        _mm_deny_admin("stop_all_watchdogs")
    n = 0
    try:
        with _LOCK:
            pairs = list(_WATCHDOGS)
            _WATCHDOGS.clear()
    except Exception:
        pairs = []
    for t, stop in pairs:
        try:
            stop.set()
            n += 1
        except Exception:
            continue
        try:
            t.join(timeout=3.0)
        except Exception:
            pass
    return n


_snapshot_swap_baseline()
