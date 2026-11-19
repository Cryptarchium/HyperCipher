"""HyperCipher runtime tamper-tripwire.

Scope: in-place file modification, bytecode/const/defaults/closure/func-dict
swap, module injection, reload/attr-replace/delete, import-machinery
tampering (meta_path/path_hooks/__import__/sys.path shadowing, sira-duyarli),
loader/spec swap, .pyc-only tampering, attribute monkey-patch
of registered objects, baseline-store poisoning.

Out of scope (diger kardesler): debugger (anti_debug), tracer (anti_trace),
inline-hook trampolines (anti_hook), crash-dump/memory acquisition
(anti_dump), sandbox/vm/emulation.

stdlib-only, cross-platform, fail-closed, sessiz: tespit -> True, hicbir
yuzey detay sizdirmaz; tum hatalar opak TamperDetected.

Guven varsayimi: seal()/harden() cagri-anindaki durumu guvenilir sayar;
muhurleme erken ve guvenilir ortamda yapilmalidir (isletmen sorumlulugu).

THREAT MODEL (bilinen sinirlar, tasarim karari):
- Ayni-process arbitrary code execution: Python'un mutable module globals
  ve writable sys.modules/import-machinery yapisi (resmi dokumante davranis)
  yuzunden mutlak guven koku OLAMAZ. Registry/digest dogrudan ayni
  trust-domain'den yazilabilir; baseline_poison/pin katmanlari citayi
  yukseltir (saldirgan tum registry + digest + pinleri atomik ve tutarli
  yeniden yazmak zorundadir) ama teorik siniri ortadan kaldirmaz.
- Ayni-ayricalik tam-sahtecilik, kernel-duzeyi okuma/yazma, import-oncesi
  sabotaj: kapsama disi (isletim-sistemi/imza-altyapi sorumlulugu).
- harden(): tamper sonrasi OTOMATIK reseal YAPMAZ; operator incelemeden
  seal() cagrilmamalidir.
- Modulu-attr EKLEME default'ta tolere edilir (lazy-loader FP'sizligi);
  katı mod icin set_strict_attrs(True) + seal().
- YENI modul (seal sonrasi ilk import) unknown_module trip uretir; lazy
  importlar icin allow_module(name) kullanilir. Uretimde tum import'lar
  seal'den ONCE tamamlanmalidir.
"""

from __future__ import annotations

import hashlib
import importlib.util
import marshal
import os
import sys
import threading
from typing import Any, Callable, Dict, List, Optional, Tuple


class TamperDetected(RuntimeError):
    pass


def _raise() -> None:
    raise TamperDetected("protected")


_SHA256 = hashlib.sha256
_STAT = os.stat
_OPEN = open
_ABSPATH = os.path.abspath
_REALPATH = os.path.realpath
_GETATTR = getattr
_SETATTR = setattr
_ID = id
_LEN = len
_ISINSTANCE = isinstance
_LIST = list
_DICT = dict
_TUPLE = tuple
_SET = set
_REPR = repr
_STR = str
_INT = int

_PIN = {
    "sha256": hashlib.sha256,
    "stat": os.stat,
    "open": open,
    "abspath": os.path.abspath,
    "realpath": os.path.realpath,
    "getattr": getattr,
    "setattr": setattr,
    "hasattr": hasattr,
    "id": id,
    "len": len,
    "repr": repr,
    "str": str,
    "int": int,
    "isinstance": isinstance,
    "modules_get_self": sys.modules,
    "modules_get_name": sys.modules.get.__name__,
    "meta_path": sys.meta_path,
    "path_hooks": sys.path_hooks,
    "import": __import__,
    "excepthook": sys.__excepthook__,
    "magic": importlib.util.MAGIC_NUMBER,
    "cache_from_source": importlib.util.cache_from_source,
    "marshal_dumps": marshal.dumps,
}

_FILE_BASE: Dict[str, str] = {}
_FUNC_BASE: Dict[int, Tuple[str, int]] = {}
_FUNC_REF: Dict[int, Any] = {}
_FUNC_BIND: Dict[int, Tuple[str, str]] = {}
_MOD_BASE: Dict[str, Tuple[int, str, str]] = {}
_MOD_ATTRS: Dict[str, Dict[str, int]] = {}
_OBJ_BASE: Dict[int, Tuple[Any, Dict[str, int]]] = {}
_OBJ_REF: Dict[int, Any] = {}
_OBJ_BIND: Dict[int, Tuple[str, str]] = {}
_PATH_BASE: Optional[Tuple[str, ...]] = None
_FINDER_BASE: Optional[Tuple[int, ...]] = None
_HOOKS_BASE: Optional[Tuple[int, ...]] = None
_IMPORT_BASE: Optional[Any] = None
_STARTUP_BASE: Optional[Any] = None
_SEALED = False
_STRICT_ATTRS = False
_VERBOSE = False
_RESEAL_VIOLATION = False
_SEAL_EPOCH = 0
_BASELINE_DIGEST: Optional[str] = None
_MODULES_SEALED: Optional[Any] = None
_MODULE_ALLOWLIST: Any = None
_PYC_BASE: Dict[str, str] = {}
_FINDER_BEHAVIOR: Dict[int, Tuple[int, ...]] = {}
_IMPORTER_BASE: Dict[str, Tuple[str, int]] = {}
_LOADER_BASE: Dict[str, Tuple[str, int, int]] = {}
_MOD_CONTENT: Dict[str, Dict[str, str]] = {}
_OBJ_CONTENT: Dict[int, Dict[str, str]] = {}
_SEAL_STATS: Dict[str, int] = {}
# CRIT-defense: hash-chain'li seal-gunlugu + golge-capa (asagida).
_SEAL_JOURNAL: List[Tuple[int, str, str, str, str]] = []
_SEAL_CHAIN = "genesis"
_SEAL_SEQ = 0
_DIGEST_SHADOW_A: Optional[str] = None
_DIGEST_SHADOW_B: Optional[str] = None
_TM_ADMINS: Dict[str, str] = {}
_TM_ADMIN_LOCKED = False
_TM_ADMIN_DENIED = 0


def _journal_append(op: str, key: str, digest: str) -> None:
    """CRIT: append-only hash-chain gunlugu (CT log ruhu).

    Her girdi oncekinin zincir-hash'ini tasir: sessiz silme/duzenleme
    zinciri kirar. Dogrulama _check_journal_integrity'de replay ile.
    """
    global _SEAL_CHAIN, _SEAL_SEQ
    try:
        _SEAL_SEQ += 1
        h = _SHA256()
        h.update(_SEAL_CHAIN.encode("ascii", "ignore"))
        h.update(op.encode("utf-8", "ignore"))
        h.update(key.encode("utf-8", "ignore"))
        h.update(digest.encode("utf-8", "ignore"))
        _SEAL_CHAIN = h.hexdigest()
        _SEAL_JOURNAL.append((_SEAL_SEQ, op, key, digest, _SEAL_CHAIN))
    except Exception:
        pass


def _journal_verify() -> bool:
    """Gunluk zincir-butunlugu: True=saglam."""
    try:
        chain = "genesis"
        seq = 0
        for (s, op, key, digest, ch) in list(_SEAL_JOURNAL):
            try:
                if s != seq + 1:
                    return False
                seq = s
                h = _SHA256()
                h.update(chain.encode("ascii", "ignore"))
                h.update(op.encode("utf-8", "ignore"))
                h.update(key.encode("utf-8", "ignore"))
                h.update(digest.encode("utf-8", "ignore"))
                chain = h.hexdigest()
                if chain != ch:
                    return False
            except Exception:
                return False
        return True
    except Exception:
        return False


def authorize_admin():
    """Operator modulunu kaydet (SADECE kilit-oncesi; boot sirasinda cagrilir)."""
    global _TM_ADMIN_DENIED
    try:
        if _TM_ADMIN_LOCKED:
            with _LOCK:
                _TM_ADMIN_DENIED += 1
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
            import os as _o
            if not _o.path.isfile(fn):
                return False
        except Exception:
            return False
        with _LOCK:
            _TM_ADMINS[name] = fn
        return True
    except Exception:
        return False


def _tm_check_admin() -> bool:
    """Dogrudan cagiran cerceve kayitli operator modulu mu? (dosya-dogrulamali)."""
    try:
        with _LOCK:
            allowed = dict(_TM_ADMINS)
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
            if (want is not None and fn == want and not fn.startswith("<")):
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


def _tm_deny_admin(op: str):
    """Yonetim reddi: fail-closed opak hata + reseal-latch."""
    global _TM_ADMIN_DENIED
    try:
        with _LOCK:
            _TM_ADMIN_DENIED += 1
    except Exception:
        pass
    try:
        global _RESEAL_VIOLATION
        _RESEAL_VIOLATION = True
    except Exception:
        pass
    _raise()

_LOCK = threading.RLock()
_WATCHDOGS: List[threading.Thread] = []
_WATCHDOG_STOPS: List[threading.Event] = []

_CRITICAL_MODS = ("sys", "builtins", "_frozen_importlib",
                  "_frozen_importlib_external", "importlib._bootstrap",
                  "importlib._bootstrap_external")

_DUNDER_DENY = frozenset({"__getattr__", "__getattribute__", "__setattr__",
                          "__delattr__", "__path__", "__all__", "__class__",
                          "__subclasshook__", "__import__"})


def _norm(p: str) -> str:
    try:
        return _REALPATH(_ABSPATH(p))
    except Exception:
        return p


def _hash_bytes(data: bytes) -> str:
    h = _SHA256()
    h.update(data)
    return h.hexdigest()


def _hash_file(path: str) -> Optional[str]:
    try:
        h = _SHA256()
        with _OPEN(path, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def _pyc_body_hash(pyc: str) -> Optional[str]:
    try:
        h = _SHA256()
        with _OPEN(pyc, "rb") as f:
            header = f.read(16)
            if _LEN(header) < 16:
                return None
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def _normalized_head(code: Any) -> Any:
    """Quicken-proof normalize baslik: dis gorunumu (adaptive=False).

    3.11+ hot-code quicken ham co_code'u yerinde degistirir; marshal ham
    byte'lari serilestirdigi icin ham-marshal FP uretir. dis normalize
    gorunum specialization'dan etkilenmez. dis yoksa None (ham moda dus).
    Import LAZY + sys.modules temizlikli (kardes WEAK sinyal temizligi).
    """
    try:
        added = "dis" not in sys.modules
        import dis as _d
    except Exception:
        return None
    try:
        try:
            instrs = list(_d.get_instructions(code, adaptive=False))
        except TypeError:
            instrs = list(_d.get_instructions(code))
        out = []
        for ins in instrs:
            try:
                if ins.opname == "CACHE":
                    continue
                try:
                    arg = ins.argval
                except Exception:
                    arg = None
                if isinstance(arg, type(code)):
                    arg = "<code>"
                elif isinstance(arg, (bytes, bytearray)):
                    arg = "<bytes:%d>" % len(bytes(arg))
                elif isinstance(arg, (bool, int, float, complex, str, type(None))):
                    try:
                        arg = ("<atom>", repr(arg))
                    except Exception:
                        arg = "<atom:?>"
                else:
                    try:
                        arg = ("<obj>", type(arg).__name__)
                    except Exception:
                        arg = "<obj:?>"  # repr() ASLA: evil __repr__ kod calistirir
                out.append((ins.opname, arg))
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


def _code_norm(code: Any) -> Any:
    """Marshal-guvenli karsilastirma demeti (adres/quicken icermez).

    Kapsar: normalize-akim (veya ham co_code fallback), ozyinelemeli
    sabitler, co_names/varnames/freevars/cellvars, flags, arg-sayilari.
    Baglam alanlari (filename/lineno) bilerek DISARIDA.
    """
    try:
        head = _normalized_head(code)
    except Exception:
        head = None
    if head is None:
        try:
            head = ("raw", bytes(getattr(code, "co_code", b"") or b""))
        except Exception:
            head = ("raw", b"")
    else:
        head = ("norm", head)
    try:
        consts = getattr(code, "co_consts", ()) or ()
    except Exception:
        consts = ()
    norm_consts = []
    for c in consts:
        try:
            if isinstance(c, type(code)):
                norm_consts.append(("<code>", _code_norm(c)))
            elif isinstance(c, (bytes, bytearray)):
                norm_consts.append(("<bytes>", bytes(c)))
            elif isinstance(c, str):
                norm_consts.append(("<str>", c))
            elif isinstance(c, (bool, int, float, complex, type(None))):
                norm_consts.append(("<val>", _content_digest(c)))
            elif isinstance(c, tuple):
                norm_consts.append(("<tuple>", _content_digest(c)))
            elif isinstance(c, frozenset):
                try:
                    norm_consts.append(("<frozenset>", _content_digest(c)))
                except Exception:
                    norm_consts.append(("<frozenset>", type(c).__name__))
        except Exception:
            continue
    names = []
    for attr in ("co_names", "co_varnames", "co_freevars", "co_cellvars"):
        try:
            names.append((attr, tuple(getattr(code, attr, ()) or ())))
        except Exception:
            names.append((attr, ()))
    counts = []
    for attr in ("co_flags", "co_argcount", "co_posonlyargcount",
                 "co_kwonlyargcount", "co_stacksize"):
        try:
            counts.append((attr, int(getattr(code, attr, 0))))
        except Exception:
            counts.append((attr, 0))
    return (head, tuple(norm_consts), tuple(names), tuple(counts))


def _func_fp(fn: Any) -> Optional[Tuple[str, int]]:
    try:
        code = _GETATTR(fn, "__code__", None)
        if code is None:
            return None
        try:
            blob = _PIN["marshal_dumps"](_code_norm(code))
        except Exception:
            return None
        if not _ISINSTANCE(blob, bytes):
            return None
        try:
            blob += b"\x00" + _content_digest(
                _GETATTR(fn, "__defaults__", None)).encode(
                "utf-8", "ignore")
        except Exception:
            pass
        try:
            dfl = _GETATTR(fn, "__defaults__", None)
            if dfl:
                for v in dfl:
                    try:
                        blob += b"\x00D:" + type(v).__name__.encode(
                            "utf-8", "ignore")
                        blob += b"#" + _STR(_ID(v)).encode("ascii", "ignore")
                        blob += b"=" + _content_digest(v).encode(
                            "utf-8", "ignore")
                    except Exception:
                        continue
        except Exception:
            pass
        try:
            blob += b"\x00" + _content_digest(
                _GETATTR(fn, "__kwdefaults__", None)).encode(
                "utf-8", "ignore")
        except Exception:
            pass
        try:
            kdfl = _GETATTR(fn, "__kwdefaults__", None)
            if kdfl:
                for kk in sorted([k for k in kdfl.keys() if _ISINSTANCE(k, str)]):
                    try:
                        v = kdfl[kk]
                        blob += b"\x00K:" + kk.encode("utf-8", "ignore")
                        blob += b"=" + type(v).__name__.encode(
                            "utf-8", "ignore")
                        blob += b"#" + _STR(_ID(v)).encode("ascii", "ignore")
                        blob += b"=" + _content_digest(v).encode(
                            "utf-8", "ignore")
                    except Exception:
                        continue
        except Exception:
            pass
        try:
            cells = _GETATTR(fn, "__closure__", None)
            if cells:
                for c in cells:
                    try:
                        blob += b"\x00" + _content_digest(
                            c.cell_contents).encode("utf-8", "ignore")
                    except Exception:
                        continue
                    try:
                        v = c.cell_contents
                        blob += b"\x00C:" + type(v).__name__.encode(
                            "utf-8", "ignore")
                        blob += b"#" + _STR(_ID(v)).encode("ascii", "ignore")
                        blob += b"=" + _content_digest(v).encode(
                            "utf-8", "ignore")
                    except Exception:
                        continue
        except Exception:
            pass
        try:
            fdict = _GETATTR(fn, "__dict__", None)
            if fdict:
                for k in sorted(fdict.keys()):
                    try:
                        blob += b"\x00" + _STR(k).encode("utf-8", "ignore")
                        blob += b"=" + _STR(_ID(fdict[k])).encode(
                            "ascii", "ignore")
                        blob += b"=" + _content_digest(fdict[k]).encode(
                            "utf-8", "ignore")
                    except Exception:
                        continue
        except Exception:
            pass
        try:
            gbl = _GETATTR(fn, "__globals__", None)
            names = _GETATTR(code, "co_names", ())
            if gbl is not None and names:
                for k in names:
                    try:
                        if not _ISINSTANCE(k, str):
                            continue
                        if k not in gbl:
                            continue
                        v = gbl[k]
                        blob += b"\x00g:" + k.encode("utf-8", "ignore")
                        blob += b"=" + type(v).__name__.encode(
                            "utf-8", "ignore")
                        blob += b"#" + _STR(_ID(v)).encode("ascii", "ignore")
                        try:
                            blob += b"=" + _content_digest(v).encode(
                                "utf-8", "ignore")
                        except Exception:
                            pass
                    except Exception:
                        continue
        except Exception:
            pass
        return (_hash_bytes(blob), _ID(fn))
    except Exception:
        return None


def _content_digest(v: Any, depth: int = 0, seen: Any = None, _budget: Any = None) -> str:
    try:
        if _budget is None:
            _budget = [4096]
        try:
            _budget[0] -= 1
            if _budget[0] < 0:
                return "cap"
        except Exception:
            pass
        if depth > 32:
            return "d32:" + type(v).__name__
        if v is None or _ISINSTANCE(v, (bool, int, float, str)):
            try:
                return "v:" + _REPR(v)[:256]
            except Exception:
                return "v:?"
        if _ISINSTANCE(v, bytes):
            try:
                return "b:" + _hash_bytes(v[:4096]) + ":" + _STR(_LEN(v))
            except Exception:
                return "b:?"
        if _ISINSTANCE(v, bytearray):
            try:
                return "b:" + _hash_bytes(bytes(v[:4096])) + ":" + _STR(_LEN(v))
            except Exception:
                return "b:?"
        if seen is None:
            seen = _SET()
        try:
            vid = _ID(v)
            if vid in seen:
                return "cyc"
            seen.add(vid)
        except Exception:
            pass
        if _ISINSTANCE(v, (tuple, list)):
            try:
                parts = []
                for i, item in enumerate(v):
                    if i >= 64:
                        parts.append("..")
                        break
                    parts.append(_content_digest(item, depth + 1, seen, _budget))
                return "s:[" + "|".join(parts) + "]"
            except Exception:
                return "s:?"
        if _ISINSTANCE(v, dict):
            try:
                parts = []
                # HIGH-fix: TUM key'ler (str-disi repr ile) + 64-cap
                # sessiz-dusurme YOK. Key sayisi coksa deger-derinligi
                # kisilir ama key-kumesi tam hash'lenir (64. key degisimi
                # artik gorunur).
                try:
                    all_keys = _LIST(v.keys())
                except Exception:
                    return "m:?"
                try:
                    key_reprs = []
                    for k in all_keys:
                        try:
                            key_reprs.append(_REPR(k))
                        except Exception:
                            key_reprs.append("?")
                    key_reprs.sort()
                except Exception:
                    key_reprs = []
                for kr in key_reprs[:4096]:
                    parts.append("k:" + kr)
                if _LEN(all_keys) > 4096:
                    parts.append("...+%d" % (_LEN(all_keys) - 4096))
                str_keys = sorted([k for k in all_keys if _ISINSTANCE(k, str)])
                for k in str_keys:
                    try:
                        parts.append(k + "=" + _content_digest(v[k], depth + 1, seen, _budget))
                    except Exception:
                        continue
                # Non-str key DEGERLERI de kapsanir (payload gizlenemez).
                for k in all_keys:
                    try:
                        if not _ISINSTANCE(k, str):
                            parts.append("k" + _REPR(k) + "=" + _content_digest(v[k], depth + 1, seen, _budget))
                    except Exception:
                        continue
                return "m:{" + "|".join(parts) + "}"
            except Exception:
                return "m:?"
        if _ISINSTANCE(v, (set, frozenset)):
            try:
                parts = sorted([_content_digest(x, depth + 1, seen, _budget)[:128]
                                for x in v])[:64]
                return "t:{" + "|".join(parts) + "}"
            except Exception:
                return "t:?"
        return "o:" + type(v).__name__ + "#" + _STR(_ID(v))
    except Exception:
        return "e"


def _mod_content(m: Any) -> Dict[str, str]:
    snap: Dict[str, str] = {}
    try:
        d = _GETATTR(m, "__dict__", None)
        if d is None:
            return snap
        try:
            keys = _LIST(d.keys())
        except Exception:
            return snap
        for k in keys:
            try:
                if _ISINSTANCE(k, str):
                    snap[k] = _content_digest(d[k])
            except Exception:
                continue
    except Exception:
        pass
    return snap


def _mod_attrs(m: Any) -> Dict[str, int]:
    snap: Dict[str, int] = {}
    try:
        d = _GETATTR(m, "__dict__", None)
        if d is None:
            return snap
        try:
            keys = _LIST(d.keys())
        except Exception:
            return snap
        for k in keys:
            try:
                if _ISINSTANCE(k, str):
                    snap[k] = _ID(d[k])
            except Exception:
                continue
    except Exception:
        pass
    return snap


def _loader_fp(mod_name: str) -> Tuple[str, int, int]:
    try:
        m = sys.modules.get(mod_name)
        if m is None:
            return ("", -1, -1)
        spec = _GETATTR(m, "__spec__", None)
        if spec is None:
            return ("nospec", _ID(_GETATTR(m, "__loader__", None)), -1)
        loader = _GETATTR(spec, "loader", None)
        try:
            em = _ID(_GETATTR(loader, "exec_module", None))
        except Exception:
            em = -1
        try:
            cm = _ID(_GETATTR(loader, "create_module", None))
        except Exception:
            cm = -1
        return (type(loader).__name__, em, cm)
    except Exception:
        return ("", -1, -1)


def _mod_id(name: str) -> Tuple[int, str, str]:
    try:
        m = sys.modules.get(name)
        if m is None:
            return (-1, "", "")
        spec = _GETATTR(m, "__spec__", None)
        origin = ""
        loader = ""
        if spec is not None:
            try:
                origin = _STR(_GETATTR(spec, "origin", "") or "")
            except Exception:
                origin = ""
            try:
                _ld = _GETATTR(spec, "loader", None)
                loader = (type(_ld).__name__ + "#" + _STR(_ID(_ld))
                          if _ld is not None else "None")
            except Exception:
                loader = ""
        return (_ID(m), origin, loader)
    except Exception:
        return (-1, "", "")


def _method_ident(fn: Any) -> int:
    try:
        if fn is None:
            return -1
        try:
            under = _GETATTR(fn, "__func__", None)
        except Exception:
            under = None
        return _ID(under if under is not None else fn)
    except Exception:
        return -1


def _finder_behavior(f: Any) -> Tuple[int, ...]:
    out: List[int] = []
    try:
        out.append(_ID(type(f)))
        for attr in ("find_spec", "find_module", "exec_module",
                     "create_module", "get_spec"):
            try:
                out.append(_method_ident(_GETATTR(f, attr, None)))
            except Exception:
                out.append(-1)
        try:
            p = _GETATTR(f, "path", None)
            if _ISINSTANCE(p, (list, tuple)):
                out.append(_LEN(p))
                for entry in _LIST(p)[:32]:
                    try:
                        out.append(hash(_STR(entry)) & 0xFFFFFFFF)
                    except Exception:
                        continue
        except Exception:
            pass
    except Exception:
        pass
    return _TUPLE(out)


def _snapshot_importer() -> Dict[str, Tuple[str, int]]:
    snap: Dict[str, Tuple[str, int]] = {}
    try:
        cache = _GETATTR(sys, "path_importer_cache", None)
        if cache is None:
            return snap
        try:
            keys = _LIST(cache.keys())
        except Exception:
            return snap
        for k in keys[:512]:
            try:
                if not _ISINSTANCE(k, str):
                    continue
                v = cache[k]
                snap[k] = (type(v).__name__, _ID(v))
            except Exception:
                continue
    except Exception:
        pass
    return snap


def _snapshot_baseline_digest() -> str:
    h = _SHA256()
    for k in sorted(_FILE_BASE):
        h.update(k.encode("utf-8", "ignore"))
        h.update(_FILE_BASE[k].encode("ascii", "ignore"))
    for k in sorted(_FUNC_BASE):
        h.update(_STR(k).encode("ascii", "ignore"))
        h.update(_FUNC_BASE[k][0].encode("ascii", "ignore"))
    for k in sorted(_FUNC_BIND):
        h.update(_STR(k).encode("ascii", "ignore"))
        h.update(_FUNC_BIND[k][0].encode("utf-8", "ignore"))
        h.update(_FUNC_BIND[k][1].encode("utf-8", "ignore"))
    for k in sorted(_MOD_BASE):
        h.update(k.encode("utf-8", "ignore"))
        try:
            mid, morg, mld = _MOD_BASE[k]
            h.update(_STR(mid).encode("ascii", "ignore"))
            h.update(morg.encode("utf-8", "ignore"))
            h.update(mld.encode("utf-8", "ignore"))
        except Exception:
            h.update(b"\x00")
    for k in sorted(_MOD_ATTRS):
        h.update(k.encode("utf-8", "ignore"))
        try:
            for sk in sorted(_MOD_ATTRS[k]):
                h.update(sk.encode("utf-8", "ignore"))
                h.update(_STR(_MOD_ATTRS[k][sk]).encode("ascii", "ignore"))
        except Exception:
            h.update(b"\x00")
    for k in sorted(_MOD_CONTENT):
        h.update(k.encode("utf-8", "ignore"))
        try:
            for sk in sorted(_MOD_CONTENT[k]):
                h.update(sk.encode("utf-8", "ignore"))
                h.update(_MOD_CONTENT[k][sk].encode("utf-8", "ignore"))
        except Exception:
            h.update(b"\x00")
    for k in sorted(_OBJ_BASE):
        h.update(_STR(k).encode("ascii", "ignore"))
        try:
            _obj, snap = _OBJ_BASE[k]
            for sk in sorted(snap):
                h.update(_STR(sk).encode("utf-8", "ignore"))
                h.update(_STR(snap[sk]).encode("ascii", "ignore"))
        except Exception:
            h.update(b"\x00")
    for k in sorted(_OBJ_BIND):
        h.update(_STR(k).encode("ascii", "ignore"))
        h.update(_OBJ_BIND[k][0].encode("utf-8", "ignore"))
        h.update(_OBJ_BIND[k][1].encode("utf-8", "ignore"))
    for k in sorted(_PYC_BASE):
        h.update(k.encode("utf-8", "ignore"))
        h.update(_PYC_BASE[k].encode("ascii", "ignore"))
    try:
        for k in sorted(_FINDER_BEHAVIOR):
            h.update(_STR(k).encode("ascii", "ignore"))
            h.update(_REPR(_FINDER_BEHAVIOR[k]).encode("utf-8", "ignore")[:512])
    except Exception:
        h.update(b"\x00")
    try:
        for k in sorted(_IMPORTER_BASE):
            h.update(k.encode("utf-8", "ignore")[:256])
            h.update(_IMPORTER_BASE[k][0].encode("utf-8", "ignore"))
            h.update(_STR(_IMPORTER_BASE[k][1]).encode("ascii", "ignore"))
    except Exception:
        h.update(b"\x00")
    try:
        for k in sorted(_LOADER_BASE):
            h.update(k.encode("utf-8", "ignore"))
            h.update(_LOADER_BASE[k][0].encode("utf-8", "ignore"))
            h.update(_STR(_LOADER_BASE[k][1]).encode("ascii", "ignore"))
            h.update(_STR(_LOADER_BASE[k][2]).encode("ascii", "ignore"))
    except Exception:
        h.update(b"\x00")
    h.update(b"\x01" if _STRICT_ATTRS else b"\x00")
    return h.hexdigest()


def _note_reseal() -> bool:
    try:
        if _SEALED:
            global _RESEAL_VIOLATION
            _RESEAL_VIOLATION = True
            return True
        return False
    except Exception:
        return False


def register_file(path: str, digest: Optional[str] = None) -> bool:
    if _note_reseal():
        return False
    p = _norm(path)
    try:
        if digest is None:
            digest = _hash_file(p)
            if digest is None:
                return False
        with _LOCK:
            _FILE_BASE[p] = digest
        _journal_append("file", p, digest)
        return True
    except Exception:
        return False


def register_func(fn: Any) -> bool:
    if _note_reseal():
        return False
    try:
        fp = _func_fp(fn)
        if fp is None:
            return False
        with _LOCK:
            _FUNC_BASE[_ID(fn)] = fp
            _FUNC_REF[_ID(fn)] = fn
            try:
                mod = _GETATTR(fn, "__module__", None)
                qn = _GETATTR(fn, "__qualname__", None)
                if (_ISINSTANCE(mod, str) and _ISINSTANCE(qn, str)
                        and "<locals>" not in qn):
                    _FUNC_BIND[_ID(fn)] = (mod, qn)
            except Exception:
                pass
        _journal_append("func", _STR(_ID(fn)), fp[0] if isinstance(fp, tuple) else _STR(fp))
        return True
    except Exception:
        return False


def register_module_tree(name: str) -> int:
    if _note_reseal():
        return 0
    count = 0
    try:
        prefix = name + "."
        with _LOCK:
            names = _LIST(sys.modules.keys())
        for mod_name in names:
            try:
                if mod_name == name or mod_name.startswith(prefix):
                    m = sys.modules.get(mod_name)
                    if m is None:
                        continue
                    with _LOCK:
                        _MOD_BASE[mod_name] = _mod_id(mod_name)
                        _MOD_ATTRS[mod_name] = _mod_attrs(m)
                        try:
                            _MOD_CONTENT[mod_name] = _mod_content(m)
                        except Exception:
                            pass
                    _journal_append("module", mod_name, "1")
                    count += 1
            except Exception:
                continue
    except Exception:
        pass
    return count


def register_module(name: str) -> bool:
    if _note_reseal():
        return False
    try:
        m = sys.modules.get(name)
        if m is None:
            return False
        with _LOCK:
            _MOD_BASE[name] = _mod_id(name)
            _MOD_ATTRS[name] = _mod_attrs(m)
            try:
                _MOD_CONTENT[name] = _mod_content(m)
            except Exception:
                pass
        _journal_append("module", name, "1")
        return True
    except Exception:
        return False


def register_object(obj: Any) -> bool:
    if _note_reseal():
        return False
    try:
        snap: Dict[str, int] = {}
        try:
            d = _GETATTR(obj, "__dict__", None)
        except Exception:
            d = None
        if d is None:
            return False
        try:
            keys = _LIST(d.keys())
        except Exception:
            return False
        for k in keys:
            try:
                snap[k] = _ID(d[k])
            except Exception:
                continue
        content: Dict[str, str] = {}
        for k in keys:
            try:
                if _ISINSTANCE(k, str):
                    content[k] = _content_digest(d[k])
            except Exception:
                continue
        with _LOCK:
            _OBJ_BASE[_ID(obj)] = (obj, snap)
            _OBJ_REF[_ID(obj)] = obj
            try:
                _OBJ_CONTENT[_ID(obj)] = content
            except Exception:
                pass
            try:
                mod = _GETATTR(obj, "__module__", None)
                qn = _GETATTR(obj, "__qualname__", None)
                if (_ISINSTANCE(mod, str) and _ISINSTANCE(qn, str)
                        and "<locals>" not in qn):
                    _OBJ_BIND[_ID(obj)] = (mod, qn)
            except Exception:
                pass
        _journal_append("object", _STR(_ID(obj)), _STR(_LEN(snap)))
        return True
    except Exception:
        return False


def set_strict_attrs(on: bool) -> bool:
    global _STRICT_ATTRS
    if _note_reseal():
        return False
    try:
        _STRICT_ATTRS = bool(on)
        return True
    except Exception:
        return False


def seal() -> Dict[str, int]:
    global _SEALED, _PATH_BASE, _FINDER_BASE, _HOOKS_BASE, _IMPORT_BASE
    global _BASELINE_DIGEST, _SEAL_EPOCH, _MODULES_SEALED, _STARTUP_BASE
    global _RESEAL_VIOLATION, _DIGEST_SHADOW_A, _DIGEST_SHADOW_B
    out = {"files": 0, "funcs": 0, "modules": 0, "objects": 0}
    with _LOCK:
        if _SEALED:
            _RESEAL_VIOLATION = True
            return out
        try:
            _PATH_BASE = _TUPLE(_LIST(sys.path))
        except Exception:
            _PATH_BASE = None
        try:
            _STARTUP_BASE = _snapshot_startup()
        except Exception:
            _STARTUP_BASE = None
        try:
            _FINDER_BASE = _TUPLE(_ID(f) for f in sys.meta_path)
        except Exception:
            _FINDER_BASE = None
        try:
            _HOOKS_BASE = _TUPLE(_ID(h) for h in sys.path_hooks)
        except Exception:
            _HOOKS_BASE = None
        try:
            import builtins as _bi
            _IMPORT_BASE = _GETATTR(_bi, "__import__", None)
        except Exception:
            _IMPORT_BASE = None
        for m in _CRITICAL_MODS:
            try:
                mod = sys.modules.get(m)
                if mod is not None and m not in _MOD_BASE:
                    _MOD_BASE[m] = _mod_id(m)
                    _MOD_ATTRS[m] = _mod_attrs(mod)
                    try:
                        _MOD_CONTENT[m] = _mod_content(mod)
                    except Exception:
                        pass
                    out["modules"] += 1
            except Exception:
                continue
        try:
            own = _norm(__file__)
            if own not in _FILE_BASE:
                dg = _hash_file(own)
                if dg is not None:
                    _FILE_BASE[own] = dg
                    out["files"] += 1
        except Exception:
            pass
        try:
            for src in _LIST(_FILE_BASE.keys()):
                try:
                    if not src.endswith(".py"):
                        continue
                    pyc = importlib.util.cache_from_source(src)
                    bh = _pyc_body_hash(pyc)
                    if bh is not None:
                        _PYC_BASE[pyc] = bh
                except Exception:
                    continue
        except Exception:
            pass
        try:
            for f in sys.meta_path:
                try:
                    _FINDER_BEHAVIOR[_ID(f)] = _finder_behavior(f)
                except Exception:
                    continue
        except Exception:
            pass
        try:
            _IMPORTER_BASE.clear()
            _IMPORTER_BASE.update(_snapshot_importer())
        except Exception:
            pass
        try:
            for _mn, _mt in _LIST(_MOD_BASE.items()):
                try:
                    _LOADER_BASE[_mn] = _loader_fp(_mn)
                except Exception:
                    continue
        except Exception:
            pass
        _BASELINE_DIGEST = _snapshot_baseline_digest()
        _DIGEST_SHADOW_A = _BASELINE_DIGEST
        _DIGEST_SHADOW_B = _snapshot_baseline_digest()
        _journal_append("seal", "baseline", _BASELINE_DIGEST or "")
        _SEAL_EPOCH = 1
        try:
            _MODULES_SEALED = _SET(sys.modules.keys())
        except Exception:
            _MODULES_SEALED = _SET()
        try:
            _SEAL_STATS["files"] = _LEN(_FILE_BASE)
            _SEAL_STATS["funcs"] = _LEN(_FUNC_BASE)
            _SEAL_STATS["modules"] = _LEN(_MOD_BASE)
            _SEAL_STATS["objects"] = _LEN(_OBJ_BASE)
        except Exception:
            pass
        _SEALED = True
    return out


def allow_module(name: str) -> bool:
    """Allowlist'e modul ekle — HIGH-fix: post-seal cagri REDDEDILIR.

    Diger register_*'lar gibi _note_reseal latch'i + post-seal deny:
    seal-sonrasi allowlist genisletme mesru degildir (PoC: seal-sonrasi
    allow→evil-import kacisi kapanir).
    """
    try:
        if _note_reseal():
            return False
        global _MODULE_ALLOWLIST
        if _MODULE_ALLOWLIST is None:
            _MODULE_ALLOWLIST = _SET()
        _MODULE_ALLOWLIST.add(name)
        return True
    except Exception:
        return False


def set_verbose(on: bool) -> bool:
    try:
        global _VERBOSE
        _VERBOSE = bool(on)
        return True
    except Exception:
        return False


def seal_package(directory: str, suffix: str = ".py") -> int:
    if _note_reseal():
        return 0
    count = 0
    try:
        top = _norm(directory)
    except Exception:
        return 0
    try:
        for root, _dirs, files in os.walk(top):
            for fn in files:
                try:
                    if not fn.endswith(suffix):
                        continue
                    if register_file(os.path.join(root, fn)):
                        count += 1
                except Exception:
                    continue
    except Exception:
        return count
    return count


def _check_file_integrity() -> bool:
    try:
        with _LOCK:
            items = _LIST(_FILE_BASE.items())
        for path, expected in items:
            try:
                actual = _hash_file(path)
            except Exception:
                return True
            if actual is None or actual != expected:
                return True
        return False
    except Exception:
        return True


def _resolve_binding(mod_name: str, qn: str) -> Tuple[bool, Any]:
    try:
        m = sys.modules.get(mod_name)
        if m is None:
            return (False, None)
        cur: Any = m
        for part in qn.split("."):
            cur = _GETATTR(cur, part, None)
            if cur is None:
                return (False, None)
        return (True, cur)
    except Exception:
        return (False, None)


def _check_func_integrity() -> bool:
    try:
        with _LOCK:
            items = _LIST(_FUNC_BASE.items())
            refs = _DICT(_FUNC_REF)
            binds = _DICT(_FUNC_BIND)
        for key, (expected_fp, _old_id) in items:
            try:
                fn = refs.get(key)
                if fn is None:
                    return True
                fp = _func_fp(fn)
                if fp is None or fp[0] != expected_fp:
                    return True
                bind = binds.get(key)
                if bind is not None:
                    found, cur = _resolve_binding(bind[0], bind[1])
                    if not found or cur is not fn:
                        return True
            except Exception:
                return True
        return False
    except Exception:
        return True


def _check_module_integrity() -> bool:
    try:
        with _LOCK:
            items = _LIST(_MOD_BASE.items())
            attr_maps = _DICT(_MOD_ATTRS)
        for name, (old_id, old_origin, old_loader) in items:
            try:
                cur = _mod_id(name)
                if cur[0] == -1:
                    return True
                if cur[0] != old_id or cur[1] != old_origin:
                    return True
                if old_loader and cur[2] != old_loader:
                    return True
                base_attrs = attr_maps.get(name)
                if base_attrs:
                    try:
                        m = sys.modules.get(name)
                        if m is None:
                            return True
                        cur_d = _GETATTR(m, "__dict__", None)
                        if cur_d is None:
                            return True
                        for ak, old_aid in base_attrs.items():
                            try:
                                if ak not in cur_d:
                                    return True
                                if _ID(cur_d[ak]) != old_aid:
                                    return True
                            except Exception:
                                return True
                        try:
                            with _LOCK:
                                base_content = _DICT(_MOD_CONTENT.get(name, {}))
                        except Exception:
                            base_content = {}
                        if base_content:
                            for ak, old_dg in base_content.items():
                                try:
                                    if ak not in cur_d:
                                        return True
                                    if _content_digest(cur_d[ak]) != old_dg:
                                        return True
                                except Exception:
                                    return True
                        if _STRICT_ATTRS:
                            try:
                                for ck in _LIST(cur_d.keys()):
                                    try:
                                        if (_ISINSTANCE(ck, str)
                                                and ck not in base_attrs):
                                            return True
                                    except Exception:
                                        return True
                            except Exception:
                                return True
                        else:
                            try:
                                for ck in _LIST(cur_d.keys()):
                                    try:
                                        if (_ISINSTANCE(ck, str)
                                                and ck not in base_attrs
                                                and ck in _DUNDER_DENY):
                                            return True
                                    except Exception:
                                        return True
                            except Exception:
                                return True
                    except Exception:
                        return True
            except Exception:
                return True
        try:
            bmod = sys.modules.get("builtins")
            smod = sys.modules.get("sys")
        except Exception:
            return True
        if bmod is None or smod is None:
            return True
        return False
    except Exception:
        return True


def _check_import_system() -> bool:
    try:
        if _FINDER_BASE is None or _HOOKS_BASE is None or _IMPORT_BASE is None:
            return _SEALED
        try:
            cur_f = _TUPLE(_ID(f) for f in sys.meta_path)
        except Exception:
            return True
        if cur_f != _FINDER_BASE:
            return True
        try:
            cur_h = _TUPLE(_ID(h) for h in sys.path_hooks)
        except Exception:
            return True
        if cur_h != _HOOKS_BASE:
            return True
        try:
            import builtins as _bi
            if _GETATTR(_bi, "__import__", None) is not _IMPORT_BASE:
                return True
        except Exception:
            return True
        try:
            with _LOCK:
                base_behavior = _DICT(_FINDER_BEHAVIOR)
        except Exception:
            return True
        try:
            for f in sys.meta_path:
                try:
                    if _finder_behavior(f) != base_behavior.get(_ID(f)):
                        return True
                except Exception:
                    return True
        except Exception:
            return True
        try:
            with _LOCK:
                base_importer = _DICT(_IMPORTER_BASE)
        except Exception:
            return True
        try:
            cur_importer = _snapshot_importer()
        except Exception:
            return True
        if cur_importer != base_importer:
            return True
        return False
    except Exception:
        return True


def _snapshot_startup() -> Any:
    try:
        import site as _site
    except Exception:
        return None
    try:
        out: Dict[str, Any] = {}
        try:
            out["pythonpath"] = os.environ.get("PYTHONPATH")
        except Exception:
            out["pythonpath"] = None
        try:
            out["usersite"] = _site.ENABLE_USER_SITE
        except Exception:
            out["usersite"] = None
        try:
            import importlib.util as _ilu
            for _mod in ("sitecustomize", "usercustomize"):
                try:
                    _spec = _ilu.find_spec(_mod)
                    out[_mod] = _GETATTR(_spec, "origin", None) if _spec is not None else None
                except Exception:
                    out[_mod] = "?"
        except Exception:
            out["sitecustomize"] = "?"
            out["usercustomize"] = "?"
        try:
            _dirs = []
            try:
                _dirs.extend(_site.getsitepackages())
            except Exception:
                pass
            try:
                _dirs.append(_site.getusersitepackages())
            except Exception:
                pass
            _pth: Dict[str, Any] = {}
            for _d in _dirs:
                try:
                    for _fn in os.listdir(_d):
                        try:
                            if not _fn.endswith(".pth"):
                                continue
                            _p = os.path.join(_d, _fn)
                            _pth[_p] = _hash_file(_p)
                        except Exception:
                            continue
                except Exception:
                    continue
            out["pth"] = _pth
        except Exception:
            out["pth"] = {}
        return out
    except Exception:
        return None


def _check_path_tamper() -> bool:
    try:
        if _PATH_BASE is None:
            return _SEALED
        try:
            cur = _TUPLE(_LIST(sys.path))
        except Exception:
            return True
        if cur != _PATH_BASE:
            return True
        return False
    except Exception:
        return True


def _check_startup_vectors() -> bool:
    try:
        if _STARTUP_BASE is None:
            return _SEALED
        try:
            cur = _snapshot_startup()
        except Exception:
            return True
        if cur is None or cur != _STARTUP_BASE:
            return True
        return False
    except Exception:
        return True


def _check_loader_tamper() -> bool:
    try:
        with _LOCK:
            names = _LIST(_MOD_BASE.keys())
            base_loaders = _DICT(_LOADER_BASE)
        for name in names:
            try:
                m = sys.modules.get(name)
                if m is None:
                    return True
                spec = _GETATTR(m, "__spec__", None)
                loader = _GETATTR(spec, "loader", None) if spec is not None else None
                if loader is None:
                    loader = _GETATTR(m, "__loader__", None)
                if loader is None:
                    if base_loaders.get(name) is not None:
                        return True
                    continue
                if _GETATTR(m, "__loader__", None) is not None:
                    try:
                        if _GETATTR(m, "__loader__", None) is not loader:
                            return True
                    except Exception:
                        return True
                if name in base_loaders:
                    if _loader_fp(name) != base_loaders[name]:
                        return True
            except Exception:
                return True
        return False
    except Exception:
        return True


def _check_bytecode_cache() -> bool:
    try:
        magic = importlib.util.MAGIC_NUMBER
        with _LOCK:
            paths = _LIST(_FILE_BASE.keys())
        for src in paths:
            try:
                if not src.endswith(".py"):
                    continue
                pyc = _PIN["cache_from_source"](src)
            except Exception:
                continue
            try:
                st = _STAT(pyc)
                if st.st_size < 16:
                    return True
            except FileNotFoundError:
                continue
            except Exception:
                return True
            try:
                with _OPEN(pyc, "rb") as f:
                    header = f.read(16)
            except Exception:
                return True
            try:
                if header[:4] != magic:
                    return True
                flags = _INT.from_bytes(header[4:8], "little")
                if flags == 0:
                    try:
                        sst = _STAT(src)
                    except Exception:
                        return True
                    pyc_mtime = _INT.from_bytes(header[8:12], "little")
                    pyc_size = _INT.from_bytes(header[12:16], "little")
                    if pyc_mtime != _INT(sst.st_mtime) or pyc_size != sst.st_size:
                        return True
                with _LOCK:
                    expected_body = _PYC_BASE.get(pyc)
                if expected_body is not None:
                    try:
                        actual_body = _pyc_body_hash(pyc)
                    except Exception:
                        return True
                    if actual_body is None or actual_body != expected_body:
                        return True
            except Exception:
                return True
        return False
    except Exception:
        return True


def _check_attr_patch() -> bool:
    try:
        with _LOCK:
            items = _LIST(_OBJ_BASE.items())
            binds = _DICT(_OBJ_BIND)
        for key, (_obj, snap) in items:
            try:
                d = _GETATTR(_obj, "__dict__", None)
                if d is None:
                    return True
                for k, old_id in snap.items():
                    try:
                        if k not in d:
                            return True
                        if _ID(d[k]) != old_id:
                            return True
                    except Exception:
                        return True
                try:
                    with _LOCK:
                        base_ocontent = _DICT(_OBJ_CONTENT.get(key, {}))
                except Exception:
                    base_ocontent = {}
                if base_ocontent:
                    for k, old_dg in base_ocontent.items():
                        try:
                            if k not in d:
                                return True
                            if _content_digest(d[k]) != old_dg:
                                return True
                        except Exception:
                            return True
                bind = binds.get(key)
                if bind is not None:
                    found, cur = _resolve_binding(bind[0], bind[1])
                    if not found or cur is not _obj:
                        return True
            except Exception:
                return True
        return False
    except Exception:
        return True


def _check_baseline_poison() -> bool:
    try:
        if not _SEALED or _BASELINE_DIGEST is None:
            return False
        try:
            cur = _snapshot_baseline_digest()
        except Exception:
            return True
        return cur != _BASELINE_DIGEST
    except Exception:
        return True


def _check_pinned_mismatch() -> bool:
    try:
        if _PIN["sha256"] is not hashlib.sha256:
            return True
        if _PIN["stat"] is not os.stat:
            return True
        if _PIN["open"] is not open:
            return True
        if _PIN["abspath"] is not os.path.abspath:
            return True
        if _PIN["realpath"] is not os.path.realpath:
            return True
        if _PIN["getattr"] is not getattr:
            return True
        if _PIN["setattr"] is not setattr:
            return True
        if _PIN["hasattr"] is not hasattr:
            return True
        if _PIN["id"] is not id:
            return True
        if _PIN["len"] is not len:
            return True
        if _PIN["repr"] is not repr:
            return True
        if _PIN["str"] is not str:
            return True
        if _PIN["int"] is not int:
            return True
        if _PIN["isinstance"] is not isinstance:
            return True
        try:
            _mg = sys.modules.get
            if _PIN["modules_get_self"] is not sys.modules:
                return True
            if _PIN["modules_get_self"] is not _GETATTR(_mg, "__self__", None):
                return True
            if _PIN["modules_get_name"] != _GETATTR(_mg, "__name__", None):
                return True
        except Exception:
            return True
        if _PIN["meta_path"] is not sys.meta_path:
            return True
        if _PIN["path_hooks"] is not sys.path_hooks:
            return True
        if _PIN["import"] is not __import__:
            return True
        if _PIN["excepthook"] is not sys.__excepthook__:
            return True
        if _PIN["magic"] != importlib.util.MAGIC_NUMBER:
            return True
        try:
            _cf = _PIN["cache_from_source"]
            if _cf is not importlib.util.cache_from_source:
                return True
        except Exception:
            return True
        try:
            if _PIN["marshal_dumps"] is not marshal.dumps:
                return True
        except Exception:
            return True
        return False
    except Exception:
        return True


def _check_core_posture() -> bool:
    try:
        if not _FILE_BASE:
            return not _SEALED
        return False
    except Exception:
        return True


_SELF_NAMES = ("file_integrity", "func_integrity", "module_integrity",
               "import_system", "path_tamper", "startup_vectors",
               "loader_tamper",
               "bytecode_cache", "attr_patch", "baseline_poison",
               "pinned_mismatch", "core_posture", "self_integrity",
               "reseal_violation", "journal_integrity", "anchor_integrity",
               "unknown_module", "watchdog_liveness",
               "seal_completeness")


def _check_self_integrity() -> bool:
    try:
        if not _ISINSTANCE(_SIGNALS, tuple):
            return True
        try:
            names = _TUPLE(n for n, _f in _SIGNALS)
        except Exception:
            return True
        if _SET(names) != _SET(_SELF_NAMES):
            return True
        if _LEN(names) != _LEN(_SELF_NAMES):
            return True
        if _SHA256 is not hashlib.sha256:
            return True
        if _OPEN is not open:
            return True
        if _STAT is not os.stat:
            return True
        if _GETATTR is not getattr:
            return True
        if _SETATTR is not setattr:
            return True
        if _ID is not id:
            return True
        if _LEN is not len:
            return True
        if _REPR is not repr:
            return True
        if _STR is not str:
            return True
        if _INT is not int:
            return True
        if _ISINSTANCE is not isinstance:
            return True
        if _LIST is not list:
            return True
        if _DICT is not dict:
            return True
        if _TUPLE is not tuple:
            return True
        if _SET is not set:
            return True
        if _ABSPATH is not os.path.abspath:
            return True
        if _REALPATH is not os.path.realpath:
            return True
        try:
            if not _ISINSTANCE(_SEALED, bool):
                return True
        except Exception:
            return True
        try:
            if _BASELINE_DIGEST is not None and not _ISINSTANCE(_BASELINE_DIGEST, str):
                return True
        except Exception:
            return True
        return False
    except Exception:
        return True


def _check_reseal_violation() -> bool:
    try:
        return bool(_RESEAL_VIOLATION)
    except Exception:
        return True


def _check_journal_integrity() -> bool:
    """CRIT-STRONG: seal-gunlugu zincir + replay-tutarliligi.

    Full-rewrite saldirisi (4 dict + digest recompute) gunlugu
    tutarli-yeniden-insa etmeden GECEMEZ: (a) zincir kirikligi,
    (b) gunlukteki func-fp'lerin CANLI _FUNC_BASE ile uyusmazligi,
    (c) gunluk girdi-sayisi ile kayit-sayisi uyusmazligi.
    """
    try:
        if not _SEALED:
            return False
        if not _journal_verify():
            return True
        try:
            with _LOCK:
                journal = list(_SEAL_JOURNAL)
                func_base = dict(_FUNC_BASE)
        except Exception:
            return True
        try:
            logged = {}
            for (_s, op, key, digest, _ch) in journal:
                try:
                    if op == "func":
                        logged[key] = digest
                except Exception:
                    continue
            for key, fp in logged.items():
                try:
                    live = func_base.get(int(key))
                except Exception:
                    continue
                if live is None:
                    continue
                try:
                    if live[0] != fp:
                        return True
                except Exception:
                    return True
            try:
                if len(logged) != len(func_base):
                    return True
            except Exception:
                pass
        except Exception:
            return True
        return False
    except Exception:
        return True


def _check_anchor_integrity() -> bool:
    """CRIT-STRONG: golge-capa uyumu (digest + 2 golge + gunluk-basi).

    Saldirgan 3 capayi + gunlukteki seal-girdisini AYNI ANDA tutarli
    yazmalidir; tek-nokta rewrite yakalanir.
    """
    try:
        if not _SEALED:
            return False
        try:
            with _LOCK:
                d = _BASELINE_DIGEST
                a = _DIGEST_SHADOW_A
                b = _DIGEST_SHADOW_B
                journal = list(_SEAL_JOURNAL)
        except Exception:
            return True
        if not d or not a or not b:
            return True
        if d != a or d != b:
            return True
        try:
            sealed = [j for j in journal if j[1] == "seal"]
            if not sealed:
                return True
            if sealed[-1][3] != d:
                return True
        except Exception:
            return True
        return False
    except Exception:
        return True


def _check_unknown_module() -> bool:
    try:
        if not _SEALED or _MODULES_SEALED is None:
            return False
        try:
            cur = _SET(sys.modules.keys())
        except Exception:
            return True
        try:
            allowed = _MODULE_ALLOWLIST if _MODULE_ALLOWLIST is not None else _SET()
        except Exception:
            allowed = _SET()
        for name in cur:
            try:
                if name not in _MODULES_SEALED and name not in allowed:
                    return True
            except Exception:
                continue
        return False
    except Exception:
        return True


def _check_watchdog_liveness() -> bool:
    try:
        with _LOCK:
            threads = _LIST(_WATCHDOGS)
            stops = _LIST(_WATCHDOG_STOPS)
        for t, s in zip(threads, stops):
            try:
                alive = t.is_alive()
            except Exception:
                continue
            try:
                stop_set = s.is_set()
            except Exception:
                stop_set = True
            if not alive and not stop_set:
                return True
        return False
    except Exception:
        return True


def _check_seal_completeness() -> bool:
    try:
        if not _SEALED:
            return False
        with _LOCK:
            n = (_LEN(_FILE_BASE) + _LEN(_FUNC_BASE) + _LEN(_MOD_BASE)
                 + _LEN(_OBJ_BASE))
        return n == 0
    except Exception:
        return True


_SIGNALS: Tuple[Tuple[str, Callable[[], bool]], ...] = (
    ("file_integrity", _check_file_integrity),
    ("func_integrity", _check_func_integrity),
    ("module_integrity", _check_module_integrity),
    ("import_system", _check_import_system),
    ("path_tamper", _check_path_tamper),
    ("startup_vectors", _check_startup_vectors),
    ("loader_tamper", _check_loader_tamper),
    ("bytecode_cache", _check_bytecode_cache),
    ("attr_patch", _check_attr_patch),
    ("baseline_poison", _check_baseline_poison),
    ("pinned_mismatch", _check_pinned_mismatch),
    ("core_posture", _check_core_posture),
    ("self_integrity", _check_self_integrity),
    ("reseal_violation", _check_reseal_violation),
    ("journal_integrity", _check_journal_integrity),
    ("anchor_integrity", _check_anchor_integrity),
    ("unknown_module", _check_unknown_module),
    ("watchdog_liveness", _check_watchdog_liveness),
    ("seal_completeness", _check_seal_completeness),
)


def _raw_results() -> Dict[str, bool]:
    out: Dict[str, bool] = {}
    try:
        signals = _SIGNALS
    except Exception:
        return out
    try:
        live_names = _TUPLE(n for n, _f in signals)
        if _SET(live_names) != _SET(_SELF_NAMES) or _LEN(live_names) != _LEN(_SELF_NAMES):
            return {"self_integrity": True}
    except Exception:
        return {"self_integrity": True}
    for name, fn in signals:
        try:
            out[name] = bool(fn())
        except Exception:
            out[name] = True
    return out


def check_all() -> Dict[str, bool]:
    try:
        if _VERBOSE:
            return _raw_results()
        return {"tampered": bool(is_tampered())}
    except Exception:
        return {"tampered": True}


def is_tampered() -> bool:
    try:
        return any(_raw_results().values())
    except Exception:
        return True


def break_tamper() -> Dict[str, bool]:
    out = {"path": False, "finders": False, "hooks": False,
           "import": False, "modules": False}
    try:
        if _PATH_BASE is not None:
            try:
                sys.path[:] = _LIST(_PATH_BASE)
            except Exception:
                pass
        if _FINDER_BASE is not None:
            try:
                base_ids = _SET(_FINDER_BASE)
                sys.meta_path[:] = [f for f in sys.meta_path
                                    if _ID(f) in base_ids]
            except Exception:
                pass
        if _HOOKS_BASE is not None:
            try:
                base_ids = _SET(_HOOKS_BASE)
                sys.path_hooks[:] = [h for h in sys.path_hooks
                                     if _ID(h) in base_ids]
            except Exception:
                pass
        if _IMPORT_BASE is not None:
            try:
                import builtins as _bi
                _SETATTR(_bi, "__import__", _IMPORT_BASE)
            except Exception:
                pass
        try:
            out["path"] = not bool(_check_path_tamper())
        except Exception:
            out["path"] = False
        try:
            clean = not bool(_check_import_system())
            out["finders"] = clean
            out["hooks"] = clean
            out["import"] = clean
        except Exception:
            pass
        try:
            out["modules"] = not bool(_check_module_integrity())
        except Exception:
            out["modules"] = False
    except Exception:
        pass
    return out


def harden() -> Dict[str, Any]:
    """MED-fix: honest-rapor — healed/unhealed listeli (healed≠heal yanilgisi kapali)."""
    try:
        if not _SEALED:
            seal()
            return {"sealed": True, "tampered": bool(is_tampered()),
                    "healed": [], "unhealed": []}
        if is_tampered():
            out = break_tamper()
            try:
                healed = sorted([k for k, v in out.items() if v])
                unhealed = sorted([k for k, v in out.items() if not v])
            except Exception:
                healed, unhealed = [], []
            try:
                still = bool(is_tampered())
            except Exception:
                still = True
            if still:
                try:
                    live = _raw_results()
                    unhealed = sorted(set(unhealed) | {k for k, v in live.items() if v})
                except Exception:
                    pass
            return {"sealed": True, "tampered": still,
                    "healed": healed, "unhealed": unhealed}
        return {"sealed": True, "tampered": False, "healed": [], "unhealed": []}
    except Exception:
        return {"sealed": False, "tampered": True, "healed": [], "unhealed": []}


def evidence() -> Dict[str, Any]:
    """INFO-fix: triyaj API — tum sinyal detayi HER ZAMAN (verbose-bagimsiz).

    check_all()/status() oracle-kapali kalir; operator triyaj icin
    evidence() cagirir.
    """
    try:
        return {"tampered": bool(is_tampered()), "signals": _raw_results()}
    except Exception:
        return {"tampered": True, "signals": {}}


def guard() -> Dict[str, bool]:
    try:
        r = check_all()
        bad = [k for k, v in r.items() if v]
        if bad:
            _raise()
        return {"tampered": False}
    except TamperDetected:
        raise
    except Exception:
        _raise()


def _watch_loop(stop: threading.Event, interval: float,
                 on_detect: Optional[Callable[[], None]]) -> None:
    try:
        action = on_detect
        if action is None:
            try:
                _exit = os._exit
            except Exception:
                _exit = None

            def _default_exit() -> None:
                try:
                    if _exit is not None:
                        _exit(1)
                except Exception:
                    pass
            action = _default_exit
        while not stop.wait(interval):
            try:
                if is_tampered():
                    try:
                        action()
                    except Exception:
                        pass
                    return
            except Exception:
                # Gecici sensor-hatasi watchdog'u OLDURMEZ (izlemeye devam).
                continue
    except Exception:
        return


def start_watchdog(interval: float = 2.0,
                   on_detect: Optional[Callable[[], None]] = None):
    global _TM_ADMIN_LOCKED
    try:
        with _LOCK:
            _TM_ADMIN_LOCKED = True
    except Exception:
        pass
    try:
        iv = float(interval)
        if iv < 0.1:
            iv = 0.1
    except Exception:
        iv = 2.0
    stop = threading.Event()
    t = threading.Thread(target=_watch_loop, args=(stop, iv, on_detect),
                         daemon=True)
    with _LOCK:
        _WATCHDOGS.append(t)
        _WATCHDOG_STOPS.append(stop)
    t.start()

    def _stop() -> None:
        try:
            stop.set()
        except Exception:
            pass
        try:
            with _LOCK:
                _WATCHDOGS[:] = [x for x in _WATCHDOGS if x is not t]
                _WATCHDOG_STOPS[:] = [x for x in _WATCHDOG_STOPS if x is not stop]
        except Exception:
            pass

    return _stop


def stop_all_watchdogs() -> int:
    """Tum watchdog'lari durdur (YONETIM: kayitli operator sart)."""
    if not _tm_check_admin():
        _tm_deny_admin("stop_all_watchdogs")
    count = 0
    with _LOCK:
        stops = _LIST(_WATCHDOG_STOPS)
        threads = _LIST(_WATCHDOGS)
        _WATCHDOG_STOPS.clear()
        _WATCHDOGS.clear()
    for s in stops:
        try:
            s.set()
            count += 1
        except Exception:
            continue
    for t in threads:
        try:
            t.join(timeout=2.0)
        except Exception:
            continue
    return count


def status() -> Dict[str, Any]:
    try:
        with _LOCK:
            sealed = _SEALED
        if not _VERBOSE:
            return {"sealed": sealed}
        with _LOCK:
            n_files = _LEN(_FILE_BASE)
            n_funcs = _LEN(_FUNC_BASE)
            n_mods = _LEN(_MOD_BASE)
            n_objs = _LEN(_OBJ_BASE)
        return {"sealed": sealed, "files": n_files, "funcs": n_funcs,
                "modules": n_mods, "objects": n_objs,
                "signals": _LEN(_SIGNALS)}
    except Exception:
        return {"sealed": False, "files": -1, "funcs": -1, "modules": -1,
                "objects": -1, "signals": _LEN(_SIGNALS)}
