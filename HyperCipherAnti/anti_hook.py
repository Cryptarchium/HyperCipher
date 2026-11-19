"""HyperCipher Anti-Hook: Python + native kanca tespiti ve aktif koruma.

Kapsam: monkey-patch (attr rebind, __code__ degisimi, __wrapped__/wrapt zinciri),
import sistemi mudahalesi (meta_path, path_hooks, __import__, kritik modul kimligi),
native inline hook (prologue + opcode siniflandirma + bellek-disk karsilastirma),
EAT menzil disi adres, yuklu hook DLL taramasi, gizli manual-map imaji,
donanim breakpoint (cari + tum threadler), bilinen hooking kutuphaneleri, gc'de yasayan proxy'ler,
hook ortam degiskenleri, pinli referans tutarsizligi.

Sinirlar: saf-Python oldugu icin kernel duzeyi (SSDT/DKOM) gorunmez; disk
karsilastirmasi yalnizca Windows+x64'te calisir, diger platformlarda o katman
pasif doner ama Python katmanlari tam aktiftir. Donus degerleri boolean'dir,
detay uretime sizdirilmaz (oracle yok). Tum hatalar sessiz yutulur (fail-closed
degil fail-silent-check: suphede True, hatada False donen katmanlar ayri tutulur;
karar butunu is_hooked verir).

Not: baseline import aninda alinir, bu modul mumkun olan en erken noktada
import edilmelidir (wrapt-ordering dersi). meta_path/path_hooks degisikligi
pytest gibi mesru araclarla da trip uretir (strict-by-design). YERLESIK
AGRESIFLIK (bilincli tercihler, FP yonetimi operatorde):
- "keyboard"/"mouse" modulleri keylogger yuzeyi sayilir; otomasyon
  makinelerinde mesru yukluyseler trip uretir (kaldirilamaz kural).
- Env degiskeni EKLEME/DEGISIM trip uretir (calisma-aninda env yazan
  framework'ler icin); hook-env anahtarlari ayrica her zaman taranir.
Reziduel:
ctypes seviyesinde sahte temiz-byte donduren native spoof, saf-Python'dan
ayirt edilemez; bu saldiri icin func_integrity/pinned katmanlari savunur.
PEP 669 C-duzeyi PyFunction izleyicileri Python'dan LISTELENEMEZ (API yok);
etkisi (__code__/defaults degisimi) wrapped/pinned katmanlarinca yakalanir.
code.replace() ayni __code__-degisim yuzeyindendir, ayri vektor degildir.
"""

import builtins as _builtins
import gc as _gc
import hashlib as _hashlib
import os as _os
import struct as _struct
import sys as _sys
import threading as _threading
from typing import Any, Callable, Dict, List, Optional, Tuple


class HookDetected(RuntimeError):
    pass


_PIN_GC_OBJECTS = _gc.get_objects
_PIN_MONOTONIC = None
try:
    import time as _time

    _PIN_MONOTONIC = _time.monotonic
except Exception:
    _PIN_MONOTONIC = None
_PIN_OS_EXIT = _os._exit
_PIN_ENVIRON = _os.environ
_PIN_THREAD_EVENT = _threading.Event
_PIN_THREAD = _threading.Thread
_PIN_META_PATH = _sys.meta_path
_PIN_PATH_HOOKS = _sys.path_hooks
_PIN_MODULES = _sys.modules
_PIN_BUILTIN_IMPORT = _builtins.__import__
_PIN_PLATFORM = _sys.platform

try:
    _PIN_MACHINE = __import__("platform").machine().lower()
except Exception:
    _PIN_MACHINE = ""
_PIN_IS_WINDOWS = _PIN_PLATFORM == "win32"
_PIN_IS_X64 = _PIN_MACHINE.endswith("64") or "x86_64" in _PIN_MACHINE or "amd64" in _PIN_MACHINE
_PIN_IS_X86_64 = (
    ("amd64" in _PIN_MACHINE or "x86_64" in _PIN_MACHINE or _PIN_MACHINE in ("x64", "em64t"))
    and "arm" not in _PIN_MACHINE
    and "aarch" not in _PIN_MACHINE
)

_PIN_MOD_OS = _os
_PIN_MOD_SYS = _sys
_PIN_MOD_BUILTINS = _builtins
_PIN_MOD_GC = _gc
_PIN_MOD_THREADING = _threading


_WATCHLIST: Tuple[Tuple[str, str], ...] = (
    ("builtins", "__import__"),
    ("builtins", "open"),
    ("builtins", "exec"),
    ("builtins", "eval"),
    ("builtins", "compile"),
    ("builtins", "setattr"),
    ("builtins", "getattr"),
    ("builtins", "delattr"),
    ("builtins", "exit"),
    ("builtins", "quit"),
    ("threading", "excepthook"),
    ("sys", "addaudithook"),
    ("sys", "exit"),
    ("sys", "audit"),
    ("sys", "excepthook"),
    ("sys", "unraisablehook"),
    ("builtins", "breakpoint"),
    ("os", "system"),
    ("os", "popen"),
    ("os", "execv"),
    ("os", "execve"),
    ("os", "execvp"),
    ("os", "spawnl"),
    ("os", "spawnve"),
    ("os", "environ"),
    ("os", "add_dll_directory"),
    ("io", "open"),
    ("subprocess", "Popen"),
    ("subprocess", "run"),
    ("subprocess", "call"),
    ("socket", "socket"),
    ("socket", "create_connection"),
    ("socket", "getaddrinfo"),
    ("ctypes", "CDLL"),
    ("ctypes", "WinDLL"),
    ("ctypes", "pythonapi"),
    ("ctypes", "windll"),
    ("importlib._bootstrap", "_find_and_load"),
    ("threading", "Event"),
    ("threading", "Thread"),
    ("threading.Thread", "start"),
    ("threading.Thread", "join"),
    ("threading.Thread", "run"),
    ("threading.Event", "wait"),
    ("threading.Event", "set"),
    ("threading.Event", "is_set"),
    ("threading.Event", "clear"),
    ("socket.socket", "connect"),
    ("socket.socket", "send"),
    ("socket.socket", "sendall"),
    ("socket.socket", "recv"),
    ("subprocess.Popen", "communicate"),
    ("subprocess.Popen", "wait"),
    ("ctypes.CDLL", "__getattr__"),
    ("ctypes.WinDLL", "__getattr__"),
    ("gc", "get_objects"),
    ("gc", "collect"),
    ("gc", "disable"),
    ("gc", "enable"),
    ("gc", "callbacks"),
    ("os", "_exit"),
    ("sys", "settrace"),
    ("sys", "setprofile"),
    ("sys", "gettrace"),
    ("sys", "getprofile"),
)

_BASELINE: Dict[Tuple[str, str], Tuple[int, tuple, Optional[int]]] = {}
_SEEN_MODS: Dict[str, Any] = {}
_PIN_BASELINE_KEYS = set()

try:
    import _frozen_importlib as _FI
except Exception:
    _FI = None  # type: ignore[assignment]
_PIN_LOADER_CLASSES: tuple = ()
try:
    _lc = []
    if _FI is not None:
        for _ln in ("BuiltinImporter", "FrozenImporter", "ExtensionFileLoader"):
            try:
                _lc.append(getattr(_FI, _ln))
            except Exception:
                continue
    try:
        import importlib.machinery as _mach
        for _ln in ("ExtensionFileLoader", "SourceFileLoader", "SourcelessFileLoader"):
            try:
                _lc.append(getattr(_mach, _ln))
            except Exception:
                continue
    except Exception:
        pass
    _PIN_LOADER_CLASSES = tuple(_lc)
except Exception:
    _PIN_LOADER_CLASSES = ()


def _seen_import(name: str) -> Any:
    try:
        live = _PIN_MODULES.get(name)
        pinned = _SEEN_MODS.get(name)
        if pinned is not None and live is not None and live is not pinned:
            return pinned
        mod = live
        if mod is None:
            try:
                mod = _PIN_BUILTIN_IMPORT(name)
            except Exception:
                return None
        if name not in _SEEN_MODS:
            try:
                _SEEN_MODS[name] = mod
            except Exception:
                pass
        return mod
    except Exception:
        return None


def _check_module_identity() -> bool:
    """H1: kritik modul kimligi — swap + loader-spoof'a karsi (fail-closed).

    Research (importlib docs + CPython importlib/_bootstrap):
    - sys.modules DICT kimligi degil ENTRY kimligi pinlenir: ilk gorulen
      nesne _SEEN_MODS'ta saklanir, canli entry farkliysa swap trip.
    - loader guveni isinstance ile: saldirgan FakeLoader.__module__
      string'ini taklit edebilir ama baseline'da pinlenmis GERCEK loader
      siniflarina isinstance kontrolunu gecemez (sahte sinif ornek degil).
    - spec/loader YOKSA veya cozulemiyorsa suphe (fail-closed True).
    """
    try:
        for name in ("ctypes",):
            try:
                live = _PIN_MODULES.get(name)
                if live is None:
                    continue
                try:
                    pinned = _SEEN_MODS.get(name)
                except Exception:
                    pinned = None
                if pinned is not None and live is not pinned:
                    return True
                try:
                    spec = getattr(live, "__spec__", None)
                    loader = getattr(spec, "loader", None) if spec is not None else None
                except Exception:
                    return True
                if loader is None:
                    return True
                if _PIN_LOADER_CLASSES:
                    try:
                        if not isinstance(loader, _PIN_LOADER_CLASSES):
                            return True
                    except Exception:
                        return True
                try:
                    lmod = type(loader).__module__ or ""
                    if not (lmod.startswith("_frozen_importlib")
                            or lmod.startswith("importlib")):
                        return True
                except Exception:
                    return True
            except Exception:
                return True
        return False
    except Exception:
        return True


_SAFE_CONST_ATOMICS = (type(None), bool, int, float, complex, str, bytes)


def _const_fp(c: Any, depth: int = 0) -> Any:
    """Sabit fingerprint (repr-spoof-proof).

    Research (behavioral seal): co_consts ayri tablodur, co_code-only
    muhur sabit-takasini kacirir; hash deger-uzerinden olmali. Guclu fix:
    - ic-ice code -> _func_sig recursion (ozyinelemeli muhur)
    - guvenli atomikler (None/bool/int/float/complex/str/bytes) ->
      tip+tam-deger (uzunsa SHA-256, kesme-korluk yok)
    - diger nesnelerde repr() ASLA cagrilmaz (saldurgan __repr__'i
      keyfi kod calistirir / spoof uretir) -> yalnizca tip-adi+boy
    """
    try:
        if depth > 3:
            return type(c).__name__
        if hasattr(c, "co_code") and hasattr(c, "co_consts"):
            try:
                return ("code", _func_sig(c))
            except Exception:
                return ("code", None)
        if isinstance(c, (tuple, frozenset)):
            try:
                return (type(c).__name__, tuple(_const_fp(x, depth + 1) for x in c))
            except Exception:
                return (type(c).__name__, len(c))
        if isinstance(c, _SAFE_CONST_ATOMICS):
            try:
                if isinstance(c, str):
                    if len(c) > 128:
                        try:
                            digest = _hashlib.sha256(c.encode("utf-8", "ignore")).hexdigest()[:32]
                        except Exception:
                            digest = "?"
                        return ("str", len(c), digest)
                    return ("str", c)
                if isinstance(c, bytes):
                    if len(c) > 128:
                        try:
                            digest = _hashlib.sha256(bytes(c)).hexdigest()[:32]
                        except Exception:
                            digest = "?"
                        return ("bytes", len(c), digest)
                    return ("bytes", bytes(c))
                return (type(c).__name__, c)
            except Exception:
                return type(c).__name__
        try:
            size = len(c)  # type: ignore[arg-type]
        except Exception:
            size = None
        if size is None:
            return (type(c).__name__,)
        return (type(c).__name__, size)
    except BaseException:
        return "?"


def _code_head(code: Any) -> Any:
    """Quicken-proof normalize baslik (lazy-dis + sys.modules temizlikli).

    3.11+ hot-code quicken ham co_code'u yerinde degistirir; watchlist'teki
    sicak fonksiyonlar (threading.Event.wait vb.) FP trip uretirdi.
    """
    try:
        import sys as _s
        added = "dis" not in _s.modules
        import dis as _d
    except Exception:
        _d = None
        added = False
    try:
        if _d is not None:
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
                    if hasattr(arg, "co_code"):
                        arg = "<code>"
                    elif isinstance(arg, (bytes, bytearray)):
                        arg = "<bytes:%d>" % len(bytes(arg))
                    else:
                        try:
                            arg = _const_fp(arg)
                        except Exception:
                            arg = "?"
                    out.append((ins.opname, arg))
                except Exception:
                    continue
            return ("norm", tuple(out))
    except Exception:
        pass
    finally:
        try:
            import sys as _s2
            if added and "dis" in _s2.modules:
                try:
                    del _s2.modules["dis"]
                except Exception:
                    pass
        except Exception:
            pass
    try:
        return ("raw", bytes(getattr(code, "co_code", b"") or b""))
    except Exception:
        return ("raw", b"")


def _func_sig(fn: Any) -> Tuple[Any, Optional[tuple], Any]:
    try:
        code = getattr(fn, "__code__", None)
        if code is None:
            return (None, None, None)
        try:
            cb = _code_head(code)
        except Exception:
            cb = None
        try:
            names = tuple(getattr(code, "co_names", ()))
        except Exception:
            names = None
        try:
            consts = getattr(code, "co_consts", None)
            fp = _const_fp(tuple(consts)) if consts is not None else None
        except Exception:
            fp = None
        try:
            # Davranis-belirleyen alanlar (research seal: imza degisimi,
            # free/cell degisimi, flag degisimi, exception-table degisimi
            # yakalanmali; co_filename/co_firstlineno derleme-baglami
            # oldugundan DISLANIR - FP kaynagiydi).
            try:
                exc = getattr(code, "co_exceptiontable", b"")
                exc_fp = _hashlib.sha256(bytes(exc)).hexdigest()[:32] if exc else ""
            except Exception:
                exc_fp = ""
            extra = (
                getattr(code, "co_argcount", None),
                getattr(code, "co_posonlyargcount", None),
                getattr(code, "co_kwonlyargcount", None),
                getattr(code, "co_flags", None),
                tuple(getattr(code, "co_freevars", None) or ()),
                tuple(getattr(code, "co_cellvars", None) or ()),
                getattr(code, "co_stacksize", None),
                exc_fp,
            )
        except Exception:
            extra = None
        return (cb, names, (fp, extra))
    except BaseException:
        return (None, None, None)
    except Exception:
        return (None, None, None)


def _wrapped_id(fn: Any) -> Optional[int]:
    try:
        w = getattr(fn, "__wrapped__", None)
        if w is None:
            return None
        return id(w)
    except BaseException:
        return -1
    except Exception:
        return None


def _resolve_owner(modname: str) -> Any:
    try:
        mod = _PIN_MODULES.get(modname)
        if mod is not None:
            return mod
    except Exception:
        pass
    try:
        parts = modname.split(".")
        for i in range(len(parts), 0, -1):
            try:
                mod = _PIN_MODULES.get(".".join(parts[:i]))
            except Exception:
                mod = None
            if mod is None:
                continue
            try:
                obj: Any = mod
                for p in parts[i:]:
                    obj = getattr(obj, p)
                return obj
            except Exception:
                continue
    except Exception:
        pass
    return None


def _baseline_one(modname: str, attr: str) -> bool:
    try:
        mod = _seen_import(modname)
        if mod is None:
            mod = _resolve_owner(modname)
            if mod is None:
                return False
        try:
            obj = getattr(mod, attr)
        except Exception:
            return False
        _BASELINE[(modname, attr)] = (id(obj), _func_sig(obj), _wrapped_id(obj))
        return True
    except Exception:
        return False


def _capture_baseline() -> int:
    n = 0
    for modname, attr in _WATCHLIST:
        try:
            if _baseline_one(modname, attr):
                n += 1
        except Exception:
            continue
    return n


_CAPTURED = _capture_baseline()
_PIN_BASELINE_OBJ = _BASELINE
_PIN_BASELINE_MIN = len(_BASELINE)


def _baseline_digest() -> str:
    try:
        h = _hashlib.sha256()
        for k in sorted(_BASELINE.keys(), key=repr):
            try:
                h.update(repr(k).encode("utf-8", "ignore"))
                h.update(repr(_BASELINE[k]).encode("utf-8", "ignore"))
            except Exception:
                continue
        return h.hexdigest()
    except Exception:
        return ""


_PIN_BASELINE_DIGEST = _baseline_digest()

_PIN_META_LEN = len(_PIN_META_PATH)
_PIN_HOOKS_LEN = len(_PIN_PATH_HOOKS)
_PIN_META_IDS = tuple(id(f) for f in list(_PIN_META_PATH))
_PIN_HOOK_IDS = tuple(id(f) for f in list(_PIN_PATH_HOOKS))
_PIN_SYS_PATH = tuple(_sys.path)
try:
    _PIN_ENV_SNAP = dict(_os.environ)
except Exception:
    _PIN_ENV_SNAP = {}


def _finder_method_ids(f: Any) -> Tuple[int, int, int, int]:
    try:
        def _mid(o: Any) -> int:
            try:
                if o is None:
                    return -1
                u = getattr(o, "__func__", None)
                return id(u if u is not None else o)
            except Exception:
                return -1
        return (
            _mid(getattr(f, "find_spec", None)),
            _mid(getattr(f, "find_module", None)),
            _mid(getattr(f, "exec_module", None)),
            _mid(getattr(f, "create_module", None)),
        )
    except Exception:
        return (-1, -1, -1, -1)


_PIN_FINDER_METHODS = tuple(
    (id(f), _finder_method_ids(f)) for f in list(_PIN_META_PATH)
)


def watch(modname: str, attr: str) -> bool:
    try:
        if (modname, attr) in _BASELINE:
            return True
        ok = bool(_baseline_one(modname, attr))
        if ok:
            try:
                _PIN_BASELINE_KEYS.add((modname, attr))
            except Exception:
                pass
            try:
                global _PIN_BASELINE_DIGEST
                _PIN_BASELINE_DIGEST = _baseline_digest()
            except Exception:
                pass
        return ok
    except Exception:
        return False


def _unwrap_chain(fn: Any, limit: int = 25) -> List[Any]:
    chain: List[Any] = []
    seen = {id(fn)}
    cur = fn
    try:
        for _ in range(limit):
            try:
                nxt = getattr(cur, "__wrapped__", None)
            except BaseException:
                break
            if nxt is None:
                break
            if id(nxt) in seen:
                break
            seen.add(id(nxt))
            chain.append(nxt)
            cur = nxt
    except BaseException:
        pass
    return chain


def _check_func_integrity() -> bool:
    try:
        try:
            if _BASELINE is not _PIN_BASELINE_OBJ:
                return True
            if len(_BASELINE) < _PIN_BASELINE_MIN:
                return True
            try:
                if set(_BASELINE) != _PIN_BASELINE_KEYS:
                    return True
            except BaseException:
                return True
            except Exception:
                return True
            try:
                if _baseline_digest() != _PIN_BASELINE_DIGEST:
                    return True
            except BaseException:
                return True
            except Exception:
                return True
        except BaseException:
            return True
        except Exception:
            return True
        for (modname, attr), (oid, ocode, _w) in list(_BASELINE.items()):
            try:
                mod = _PIN_MODULES.get(modname)
                if mod is None:
                    try:
                        mod = _resolve_owner(modname)
                    except BaseException:
                        return True
                    except Exception:
                        mod = None
                    if mod is None:
                        continue
                try:
                    cur = getattr(mod, attr)
                except BaseException:
                    return True
                except Exception:
                    return True
                if id(cur) != oid:
                    return True
                if ocode is not None:
                    try:
                        if _func_sig(cur) != ocode:
                            return True
                    except Exception:
                        pass
            except Exception:
                continue
    except Exception:
        pass
    return False


def _check_wrapped_chain() -> bool:
    try:
        for (modname, attr), (_oid, _c, wid) in list(_BASELINE.items()):
            try:
                mod = _PIN_MODULES.get(modname)
                if mod is None:
                    try:
                        mod = _resolve_owner(modname)
                    except Exception:
                        mod = None
                    if mod is None:
                        continue
                try:
                    cur = getattr(mod, attr)
                except Exception:
                    continue
                try:
                    chain = _unwrap_chain(cur)
                except Exception:
                    continue
                if wid is None and chain:
                    return True
                if wid is not None:
                    if not chain:
                        return True
                    try:
                        if id(chain[0]) != wid:
                            return True
                    except Exception:
                        pass
            except Exception:
                continue
    except Exception:
        pass
    return False


def _check_import_system() -> bool:
    try:
        try:
            mp = _sys.meta_path
            if mp is not _PIN_META_PATH:
                return True
            if len(mp) != _PIN_META_LEN:
                return True
            try:
                if tuple(id(f) for f in list(mp)) != _PIN_META_IDS:
                    return True
            except Exception:
                return True
        except Exception:
            return True
        try:
            ph = _sys.path_hooks
            if ph is not _PIN_PATH_HOOKS:
                return True
            if len(ph) != _PIN_HOOKS_LEN:
                return True
            try:
                if tuple(id(f) for f in list(ph)) != _PIN_HOOK_IDS:
                    return True
            except Exception:
                return True
        except Exception:
            return True
        try:
            if _builtins.__import__ is not _PIN_BUILTIN_IMPORT:
                return True
        except Exception:
            return True
        try:
            if tuple(_sys.path) != _PIN_SYS_PATH:
                return True
        except Exception:
            return True
        try:
            cur_ids = tuple(id(f) for f in list(mp))
            if cur_ids != _PIN_META_IDS:
                return True
            try:
                cur_methods = tuple(
                    (id(f), _finder_method_ids(f)) for f in list(mp)
                )
            except Exception:
                return True
            if cur_methods != _PIN_FINDER_METHODS:
                return True
        except Exception:
            return True
        try:
            mods = _sys.modules
            if mods is not _PIN_MODULES:
                return True
            for critical, pinned in (
                ("sys", _PIN_MOD_SYS),
                ("builtins", _PIN_MOD_BUILTINS),
                ("os", _PIN_MOD_OS),
                ("gc", _PIN_MOD_GC),
                ("threading", _PIN_MOD_THREADING),
            ):
                try:
                    if mods.get(critical) is not pinned:
                        return True
                except Exception:
                    continue
            try:
                for sname, spinned in list(_SEEN_MODS.items()):
                    try:
                        if mods.get(sname) is not spinned:
                            return True
                    except Exception:
                        continue
            except Exception:
                pass
        except Exception:
            pass
    except Exception:
        pass
    return False


_HOOK_MODULES = frozenset({
    "frida",
    "_frida_agent",
    "easyhook",
    "easyhook64",
    "pydbg",
    "winappdbg",
    "pydivert",
    "winhook",
    "pyHook",
    "pyhook",
    "keyboard_hook",
    "detours",
    "minhook",
    "deviare",
    "pymem",
    "keyboard",
    "mouse",
    "pynput",
    "pyhooked",
    "sneakysnek",
    "pywinauto.hooks",
})

_HOOK_PREFIXES = (
    "frida",
    "_frida",
    "easyhook",
    "pydbg",
    "winappdbg",
    "pydivert",
    "detours",
    "minhook",
    "deviare",
    "winhook",
    "pyhook",
    "pymem",
    "keyboard",
    "mouse",
    "pynput",
    "pyhooked",
    "sneakysnek",
    "pywinauto.hooks",
)


def _check_hook_modules() -> bool:
    try:
        mods = _PIN_MODULES
        if not mods:
            return False
        for name in _HOOK_MODULES:
            try:
                if name in mods:
                    return True
            except Exception:
                continue
        try:
            try:
                keys = list(mods)
            except Exception:
                return True
            for key in keys:
                try:
                    kl = str(key).lower()
                except Exception:
                    continue
                for pre in _HOOK_PREFIXES:
                    try:
                        if kl == pre or kl.startswith(pre + ".") or kl.startswith(pre + "_"):
                            return True
                    except Exception:
                        continue
                if kl.startswith("frida") or kl.startswith("_frida"):
                    return True
        except Exception:
            pass
    except Exception:
        pass
    return False


_HOOK_INSTALLER_ATTRS = frozenset({
    "SetWindowsHookEx", "SetWindowsHookExA", "SetWindowsHookExW",
    "UnhookWindowsHookEx", "HookKeyboard", "HookMouse",
    "hook_keyboard", "hook_mouse", "keyboard_hook", "mouse_hook",
    "install_hook", "uninstall_hook", "start_hook", "stop_hook",
    "set_hook", "SetWinEventHook", "UnhookWinEvent",
    "RegisterHotKey", "UnregisterHotKey", "add_hotkey", "register_hotkey",
    "InstallHook", "StartHook",
})

_HOOK_LISTENER_ATTRS = frozenset({
    "on_press", "on_release", "on_click", "on_scroll", "on_move",
    "Listener", "KeyListener", "MouseListener", "KeyboardListener",
    "keyDown", "keyUp", "GetAsyncKeyState", "GetKeyState",
})


def _check_hook_behavior() -> bool:
    """H2: isimden-bagimsiz hook-yuzeyi — rename ile atlatilamaz.

    Davranis imzasi: bir modul kurucu (installer) + dinleyici (listener)
    ozniteliklerini BIRLIKTE tasiyorsa kanca yuzeyidir; adi ne olursa
    olsun yakalanir. Esik (installer>=2 veya installer>=1+listener>=3)
    tekil yardimci-fonksiyon FP'lerini eler; otomasyon makinesindeki
    mesru dinleyiciler icin strict-by-design trip dokumante edilir.
    """
    try:
        try:
            items = list(_PIN_MODULES.items())
        except Exception:
            return True
        for _name, mod in items:
            try:
                if mod is None:
                    continue
                try:
                    attrs = set(dir(mod))
                except Exception:
                    continue
                if not attrs:
                    continue
                ni = len(attrs & _HOOK_INSTALLER_ATTRS)
                if not ni:
                    continue
                nl = len(attrs & _HOOK_LISTENER_ATTRS)
                if ni >= 2 or (ni >= 1 and nl >= 3):
                    return True
            except Exception:
                continue
        return False
    except Exception:
        return True


def _check_gc_proxies() -> bool:
    try:
        try:
            objs = _PIN_GC_OBJECTS()
        except Exception:
            return False
        wanted = set()
        try:
            for (_m, _a), (oid, _c, _w) in list(_BASELINE.items()):
                wanted.add(oid)
        except Exception:
            pass
        if not wanted:
            return False
        for ob in objs:
            try:
                t = type(ob)
            except Exception:
                continue
            try:
                tname = getattr(t, "__name__", "") or ""
            except Exception:
                continue
            if tname not in ("FunctionWrapper", "BoundFunctionWrapper", "ObjectProxy",
                             "BaseObjectProxy", "CallableObjectProxy", "LazyObjectProxy",
                             "AutoObjectProxy", "_FunctionWrapperBase"):
                continue
            try:
                chain = _unwrap_chain(ob, limit=12)
            except Exception:
                continue
            for link in chain:
                try:
                    if id(link) in wanted:
                        return True
                except Exception:
                    continue
    except Exception:
        pass
    return False


_HOOK_ENV_PREFIXES = ("FRIDA_", "_FRIDA", "PYHOOK", "EASYHOOK", "DEVIARE", "PYDBG",
                     "COR_", "CORECLR_", "LD_PRELOAD", "DYLD_")
_HOOK_ENV_KEYS = frozenset({
    "FRIDA_TRACE",
    "PYDbg",
    "WINHOOK",
    "LD_PRELOAD",
    "DYLD_INSERT_LIBRARIES",
    "COR_ENABLE_PROFILING",
    "COR_PROFILER",
    "CORECLR_ENABLE_PROFILING",
    "CORECLR_PROFILER",
    "SSLKEYLOGFILE",
    "PYTHONBREAKPOINT",
})


def _check_hook_env() -> bool:
    try:
        env = _PIN_ENVIRON
        for key in _HOOK_ENV_KEYS:
            try:
                if key in env:
                    return True
            except Exception:
                continue
        try:
            try:
                cur = dict(env)
            except Exception:
                return True
            try:
                base = _PIN_ENV_SNAP
            except Exception:
                base = {}
            if set(cur) != set(base):
                return True
            for k, v in cur.items():
                try:
                    if base.get(k) != v:
                        return True
                except Exception:
                    return True
        except Exception:
            return True
        try:
            try:
                ekeys = list(env)
            except Exception:
                return True
            for key in ekeys:
                try:
                    ku = str(key).upper()
                except Exception:
                    continue
                for pre in _HOOK_ENV_PREFIXES:
                    try:
                        if ku.startswith(pre):
                            return True
                    except Exception:
                        continue
        except Exception:
            pass
    except Exception:
        pass
    return False


def _check_py_tracing() -> bool:
    """Python-seviyesi izleme kancasi (settrace/setprofile/PEP 669 monitoring).

    Research: sys.settrace tum cagri/donus/degerleri gozler; 3.12+ PEP 669
    sys.monitoring dusuk-maliyetli secici izlemedir (tool ID 0,1,2,5).
    Guclu fix: gettrace/getprofile None-disi trip + her tool ID icin
    get_events(tool_id) != 0 trip. pinli referans yok, dogrudan _sys
    uzerinden okunur (pinned_mismatch katmani _sys degisimini ayrica yakalar).
    Hata sessiz-yutulur, suphede False (fail-silent-check sinifi).
    """
    try:
        try:
            if _sys.gettrace() is not None:
                return True
        except Exception:
            pass
        try:
            get_thr_trace = getattr(_threading, "gettrace", None)
            if callable(get_thr_trace) and get_thr_trace() is not None:
                return True
        except Exception:
            pass
        try:
            if _sys.getprofile() is not None:
                return True
        except Exception:
            pass
        try:
            mon = getattr(_sys, "monitoring", None)
        except Exception:
            mon = None
        if mon is not None:
            try:
                get_ev = getattr(mon, "get_events", None)
            except Exception:
                get_ev = None
            if callable(get_ev):
                for tool_id in (0, 1, 2, 3, 4, 5):
                    try:
                        if int(get_ev(tool_id)) != 0:
                            return True
                    except Exception:
                        continue
    except Exception:
        pass
    return False


def _check_pinned_mismatch() -> bool:
    try:
        if _builtins.__import__ is not _PIN_BUILTIN_IMPORT:
            return True
    except Exception:
        return True
    try:
        if _sys.meta_path is not _PIN_META_PATH:
            return True
    except Exception:
        return True
    try:
        if _sys.modules is not _PIN_MODULES:
            return True
    except Exception:
        return True
    try:
        if _gc.get_objects is not _PIN_GC_OBJECTS:
            return True
    except Exception:
        return True
    try:
        if _os._exit is not _PIN_OS_EXIT:
            return True
    except Exception:
        return True
    try:
        if _os.environ is not _PIN_ENVIRON:
            return True
    except Exception:
        return True
    try:
        if _threading.Event is not _PIN_THREAD_EVENT:
            return True
    except Exception:
        return True
    try:
        if _threading.Thread is not _PIN_THREAD:
            return True
    except Exception:
        return True
    try:
        if _sys.platform != _PIN_PLATFORM:
            return True
    except Exception:
        return True
    try:
        if _os is not _PIN_MOD_OS:
            return True
    except Exception:
        return True
    try:
        if _sys is not _PIN_MOD_SYS:
            return True
    except Exception:
        return True
    try:
        if _builtins is not _PIN_MOD_BUILTINS:
            return True
    except Exception:
        return True
    try:
        if _gc is not _PIN_MOD_GC:
            return True
    except Exception:
        return True
    try:
        if _threading is not _PIN_MOD_THREADING:
            return True
    except Exception:
        return True
    return False


_NT_WATCH = (
    "NtProtectVirtualMemory",
    "NtWriteVirtualMemory",
    "NtReadVirtualMemory",
    "NtAllocateVirtualMemory",
    "NtCreateThreadEx",
    "NtOpenProcess",
    "NtQueueApcThread",
    "NtCreateUserProcess",
    "NtTerminateProcess",
    "NtMapViewOfSection",
    "NtSetContextThread",
    "NtSuspendThread",
    "NtResumeThread",
    "NtCreateFile",
    "NtWriteFile",
    "NtSetValueKey",
    "NtDuplicateObject",
    "NtOpenProcessToken",
)

_DLL_WATCH: Dict[str, Tuple[str, ...]] = {
    "ntdll.dll": _NT_WATCH,
    "kernel32.dll": (
        "CreateFileW",
        "CreateProcessW",
        "LoadLibraryW",
        "LoadLibraryExW",
        "VirtualAlloc",
        "VirtualProtect",
        "WriteProcessMemory",
        "CreateRemoteThread",
    ),
    "kernelbase.dll": (
        "CreateFileW",
        "CreateProcessW",
        "VirtualAlloc",
        "VirtualProtect",
        "MapViewOfFile",
        "LoadLibraryExW",
    ),
}

_NT_FP_SKIP = frozenset({
    "NtGetTickCount",
    "NtQuerySystemTime",
    "ZwQuerySystemTime",
    "NtdllDefWindowProc_A",
    "NtdllDefWindowProc_W",
    "NtdllDialogWndProc_A",
    "NtdllDialogWndProc_W",
})

_SYSCALL_PROLOGUE = (0x4C, 0x8B, 0xD1, 0xB8)


def _classify_hook(b: bytes) -> str:
    try:
        if len(b) < 2:
            return ""
        if b[0] == 0xE9:
            return "JMP rel32 (E9)"
        if b[0] == 0xEB:
            return "JMP rel8 (EB)"
        if b[0] == 0xCC:
            return "INT3 (CC)"
        if b[0] == 0xFF and b[1] == 0x25:
            return "JMP [RIP+disp32] (FF 25)"
        if len(b) >= 12 and b[0] == 0x48 and b[1] == 0xB8 and b[10] == 0xFF and b[11] == 0xE0:
            return "MOV RAX + JMP RAX"
        if len(b) >= 6 and b[0] == 0x68 and b[5] == 0xC3:
            return "PUSH+RET (6B)"
        if len(b) >= 14 and b[0] == 0x68 and b[5] == 0xC7 and b[13] == 0xC3:
            return "PUSH/MOV/RET (14B)"
    except Exception:
        pass
    return "Unknown Patch"


def _rva_to_raw(pe: bytes, rva: int) -> Optional[int]:
    try:
        if len(pe) < 0x40:
            return None
        e_lfanew = _struct.unpack_from("<I", pe, 0x3C)[0]
        if e_lfanew + 0x100 > len(pe):
            return None
        num_sec = _struct.unpack_from("<H", pe, e_lfanew + 6)[0]
        opt_size = _struct.unpack_from("<H", pe, e_lfanew + 20)[0]
        sec_off = e_lfanew + 24 + opt_size
        for i in range(num_sec):
            off = sec_off + i * 40
            if off + 40 > len(pe):
                break
            vsize, vaddr, rawsize, rawptr = _struct.unpack_from("<IIII", pe, off + 8)
            span = vsize if vsize > rawsize else rawsize
            if vaddr <= rva < vaddr + span:
                return rawptr + (rva - vaddr)
        return None
    except Exception:
        return None


def _export_info(pe: bytes, fname: str) -> Optional[Tuple[int, bool]]:
    try:
        return _export_map(pe).get(fname)
    except Exception:
        return None


def _pe_sane(pe: bytes) -> bool:
    try:
        if len(pe) < 0x40:
            return False
        if pe[0:2] != b"MZ":
            return False
        e_lfanew = _struct.unpack_from("<I", pe, 0x3C)[0]
        if e_lfanew > len(pe):
            return False
        if pe[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            return False
        return True
    except Exception:
        return False


def _pe_digest(pe: bytes) -> str:
    try:
        return _hashlib.sha256(bytes(pe)).hexdigest()
    except Exception:
        return ""


def _export_map(pe: bytes) -> Dict[str, Tuple[int, bool]]:
    try:
        return _build_export_map(pe)
    except Exception:
        return {}


def _build_export_map(pe: bytes) -> Dict[str, Tuple[int, bool]]:
    m: Dict[str, Tuple[int, bool]] = {}
    try:
        if len(pe) < 0x40:
            return m
        e_lfanew = _struct.unpack_from("<I", pe, 0x3C)[0]
        magic = _struct.unpack_from("<H", pe, e_lfanew + 24)[0]
        if magic == 0x20B:
            exp_rva, exp_size = _struct.unpack_from("<II", pe, e_lfanew + 24 + 112)
        else:
            exp_rva, exp_size = _struct.unpack_from("<II", pe, e_lfanew + 24 + 96)
        exp_raw = _rva_to_raw(pe, exp_rva)
        if exp_raw is None:
            return m
        n_names = _struct.unpack_from("<I", pe, exp_raw + 24)[0]
        if n_names > 65536:
            return m
        addr_names = _struct.unpack_from("<I", pe, exp_raw + 32)[0]
        addr_ord = _struct.unpack_from("<I", pe, exp_raw + 36)[0]
        addr_func = _struct.unpack_from("<I", pe, exp_raw + 28)[0]
        for i in range(n_names):
            try:
                nraw = _rva_to_raw(pe, addr_names)
                if nraw is None:
                    break
                nr = _struct.unpack_from("<I", pe, nraw + i * 4)[0]
                noff = _rva_to_raw(pe, nr)
                if noff is None:
                    continue
                end = pe.index(b"\x00", noff, noff + 256)
                try:
                    ename = pe[noff:end].decode("ascii", "ignore")
                except Exception:
                    continue
                if not ename:
                    continue
                oraw = _rva_to_raw(pe, addr_ord)
                fraw = _rva_to_raw(pe, addr_func)
                if oraw is None or fraw is None:
                    return m
                ordinal = _struct.unpack_from("<H", pe, oraw + i * 2)[0]
                frva = _struct.unpack_from("<I", pe, fraw + ordinal * 4)[0]
                forwarded = exp_rva <= frva < exp_rva + exp_size
                try:
                    m[ename] = (frva, forwarded)
                except Exception:
                    pass
            except Exception:
                continue
        return m
    except Exception:
        return m


_DISK_CACHE: Dict[str, Any] = {}
_SENSOR_FAILS: Dict[str, int] = {}
_SENSOR_FAIL_TRIP = 5


def _note_sensor_fail(name: str) -> None:
    try:
        _SENSOR_FAILS[name] = _SENSOR_FAILS.get(name, 0) + 1
    except Exception:
        pass


def _note_sensor_ok(name: str) -> None:
    try:
        if name in _SENSOR_FAILS:
            _SENSOR_FAILS[name] = 0
    except Exception:
        pass


def _check_cache_integrity() -> bool:
    try:
        for _path, ent in list(_DISK_CACHE.items()):
            try:
                if not isinstance(ent, dict):
                    return True
                pe = ent.get("pe")
                if not isinstance(pe, (bytes, bytearray)):
                    return True
                peb = bytes(pe)
                if not _pe_sane(peb):
                    return True
                if ent.get("digest") != _pe_digest(peb):
                    _note_sensor_fail("disk_cache")
                    return True
            except Exception:
                return True
    except Exception:
        pass
    return False


def _check_sensor_health() -> bool:
    try:
        for _name, count in list(_SENSOR_FAILS.items()):
            try:
                if int(count) >= _SENSOR_FAIL_TRIP:
                    return True
            except Exception:
                continue
    except Exception:
        pass
    return False


def _load_disk_pe(disk_path: str) -> bytes:
    try:
        if not disk_path:
            return b""
        try:
            st = _os.stat(disk_path)
            mtime = st.st_mtime
            size = st.st_size
        except Exception:
            return b""
        try:
            ent = _DISK_CACHE.get(disk_path)
            if ent and ent.get("mtime") == mtime and ent.get("size") == size:
                try:
                    cached_pe = ent.get("pe")
                    if (isinstance(cached_pe, (bytes, bytearray))
                            and _pe_sane(bytes(cached_pe))
                            and ent.get("digest") == _pe_digest(bytes(cached_pe))):
                        return bytes(cached_pe)
                except Exception:
                    pass
                try:
                    if _pe_sane(bytes(ent.get("pe") or b"")):
                        _SENSOR_FAILS["disk_cache"] = _SENSOR_FAILS.get("disk_cache", 0) + 1
                except Exception:
                    pass
                try:
                    del _DISK_CACHE[disk_path]
                except Exception:
                    pass
        except Exception:
            pass
        try:
            with open(disk_path, "rb") as f:
                pe = f.read(4 * 1024 * 1024)
        except Exception:
            return b""
        if not _pe_sane(pe):
            return b""
        try:
            _DISK_CACHE[disk_path] = {"mtime": mtime, "size": size,
                                      "pe": pe, "digest": _pe_digest(pe)}
        except Exception:
            pass
        return pe
    except Exception:
        return b""


def _dll_disk_path(dll: str) -> Optional[str]:
    try:
        _ct = _seen_import("ctypes")

        buf = _ct.create_unicode_buffer(260)
        try:
            _ct.windll.kernel32.GetSystemDirectoryW(buf, 260)
            base = buf.value
        except Exception:
            base = ""
        if not base:
            try:
                base = _os.path.join(_os.environ.get("SystemRoot", r"C:\Windows"), "System32")
            except Exception:
                return None
        return _os.path.join(base, dll)
    except Exception:
        return None


def _fix_k32(k32: Any) -> Any:
    try:
        _ct = _seen_import("ctypes")
        if _ct is None:
            return k32
        try:
            k32.GetModuleHandleW.restype = _ct.c_void_p
        except Exception:
            pass
        try:
            k32.GetProcAddress.restype = _ct.c_void_p
            k32.GetProcAddress.argtypes = [_ct.c_void_p, _ct.c_char_p]
        except Exception:
            pass
        try:
            k32.GetCurrentProcess.restype = _ct.c_void_p
        except Exception:
            pass
        try:
            k32.GetCurrentThread.restype = _ct.c_void_p
            k32.GetThreadContext.argtypes = [_ct.c_void_p, _ct.c_void_p]
            k32.GetThreadContext.restype = _ct.c_int
        except Exception:
            pass
        try:
            psapi = _ct.windll.psapi
            psapi.GetModuleInformation.restype = _ct.c_int
            psapi.GetModuleInformation.argtypes = [
                _ct.c_void_p, _ct.c_void_p, _ct.c_void_p, _ct.c_ulong]
        except Exception:
            pass
        try:
            psapi = _ct.windll.psapi
            psapi.EnumProcessModules.restype = _ct.c_int
            psapi.EnumProcessModules.argtypes = [
                _ct.c_void_p, _ct.c_void_p, _ct.c_ulong,
                _ct.POINTER(_ct.c_ulong)]
        except Exception:
            pass
        try:
            psapi = _ct.windll.psapi
            psapi.GetModuleFileNameExW.restype = _ct.c_ulong
            psapi.GetModuleFileNameExW.argtypes = [
                _ct.c_void_p, _ct.c_void_p, _ct.c_wchar_p, _ct.c_ulong]
        except Exception:
            pass
        try:
            k32.VirtualQuery.restype = _ct.c_size_t
            k32.VirtualQuery.argtypes = [_ct.c_void_p, _ct.c_void_p, _ct.c_size_t]
        except Exception:
            pass
        try:
            k32.CreateToolhelp32Snapshot.restype = _ct.c_void_p
            k32.CreateToolhelp32Snapshot.argtypes = [_ct.c_ulong, _ct.c_ulong]
            k32.Thread32First.restype = _ct.c_int
            k32.Thread32First.argtypes = [_ct.c_void_p, _ct.c_void_p]
            k32.Thread32Next.restype = _ct.c_int
            k32.Thread32Next.argtypes = [_ct.c_void_p, _ct.c_void_p]
            k32.OpenThread.restype = _ct.c_void_p
            k32.OpenThread.argtypes = [_ct.c_ulong, _ct.c_int, _ct.c_ulong]
            k32.CloseHandle.restype = _ct.c_int
            k32.CloseHandle.argtypes = [_ct.c_void_p]
            k32.GetCurrentProcessId.restype = _ct.c_ulong
        except Exception:
            pass
    except Exception:
        pass
    return k32


def _module_bounds(k32: Any, hmod: int) -> Optional[Tuple[int, int]]:
    try:
        _ct = _seen_import("ctypes")
        if _ct is None:
            return None
        buf = _ct.create_string_buffer(24)
        try:
            ok = _ct.windll.psapi.GetModuleInformation(
                k32.GetCurrentProcess(), hmod, buf, 24)
        except Exception:
            ok = 0
        if not ok:
            _note_sensor_fail("module_bounds")
            return None
        _note_sensor_ok("module_bounds")
        try:
            base = _struct.unpack_from("<Q", buf, 0)[0]
            size = _struct.unpack_from("<I", buf, 8)[0]
        except Exception:
            return None
        if not base or not size:
            return None
        return (base, size)
    except Exception:
        return None


def _check_native_prologue() -> bool:
    try:
        if not (_PIN_IS_WINDOWS and _PIN_IS_X64):
            return False
        _ct = _seen_import("ctypes")

        try:
            k32 = _fix_k32(_ct.windll.kernel32)
        except Exception:
            return False
        for dll, fnames in _DLL_WATCH.items():
            try:
                try:
                    hmod = k32.GetModuleHandleW(dll)
                    if not hmod:
                        continue
                except Exception:
                    continue
                try:
                    bounds = _module_bounds(k32, hmod)
                except Exception:
                    bounds = None
                try:
                    pe = _load_disk_pe(_dll_disk_path(dll) or "")
                except Exception:
                    pe = b""
                for fname in fnames:
                    try:
                        if fname in _NT_FP_SKIP:
                            continue
                        try:
                            addr = k32.GetProcAddress(hmod, fname.encode("ascii"))
                        except Exception:
                            continue
                        if not addr:
                            continue
                        try:
                            memb = bytes(_ct.string_at(addr, 64))
                        except Exception:
                            continue
                        is_syscall_shape = (
                            len(memb) >= 4
                            and memb[0] == _SYSCALL_PROLOGUE[0]
                            and memb[1] == _SYSCALL_PROLOGUE[1]
                            and memb[2] == _SYSCALL_PROLOGUE[2]
                            and memb[3] == _SYSCALL_PROLOGUE[3]
                        )
                        if pe:
                            try:
                                info = _export_info(pe, fname)
                            except Exception:
                                info = None
                            if info is not None:
                                frva, forwarded = info
                                if forwarded:
                                    continue
                                try:
                                    draw = _rva_to_raw(pe, frva)
                                    diskb = pe[draw:draw + 64] if draw is not None else b""
                                except Exception:
                                    diskb = b""
                                if diskb and memb[:len(diskb)] != diskb:
                                    return True
                                if not diskb:
                                    try:
                                        if _classify_hook(memb):
                                            return True
                                    except Exception:
                                        pass
                                    continue
                        if not is_syscall_shape:
                            try:
                                is_nt = fname.startswith("Nt") or fname.startswith("Zw")
                            except Exception:
                                is_nt = False
                            if not is_nt or not _PIN_IS_X86_64:
                                continue
                            if _classify_hook(memb):
                                try:
                                    if memb[0] == 0xE9 and len(memb) >= 5 and bounds is not None:
                                        rel = _struct.unpack_from("<i", memb, 1)[0]
                                        target = addr + 5 + rel
                                        try:
                                            base, size = bounds
                                            if base <= target < base + size:
                                                continue
                                        except Exception:
                                            pass
                                    return True
                                except Exception:
                                    return True
                    except Exception:
                        continue
            except Exception:
                continue
    except Exception:
        pass
    return False


def _check_eat_range() -> bool:
    try:
        if not _PIN_IS_WINDOWS:
            return False
        _ct = _seen_import("ctypes")

        try:
            k32 = _fix_k32(_ct.windll.kernel32)
        except Exception:
            return False
        for dll, fnames in _DLL_WATCH.items():
            try:
                try:
                    hmod = k32.GetModuleHandleW(dll)
                    if not hmod:
                        continue
                except Exception:
                    continue
                try:
                    bounds = _module_bounds(k32, hmod)
                except Exception:
                    bounds = None
                if bounds is None:
                    continue
                try:
                    base, size = bounds
                except Exception:
                    continue
                try:
                    pe = _load_disk_pe(_dll_disk_path(dll) or "")
                except Exception:
                    pe = b""
                for fname in fnames:
                    try:
                        try:
                            addr = k32.GetProcAddress(hmod, fname.encode("ascii"))
                        except Exception:
                            continue
                        if not addr:
                            continue
                        if base <= addr < base + size:
                            continue
                        if pe:
                            try:
                                info = _export_info(pe, fname)
                            except Exception:
                                info = None
                            if info is not None and info[1]:
                                continue
                        return True
                    except Exception:
                        continue
            except Exception:
                continue
    except Exception:
        pass
    return False


_HOOK_DLLS = (
    "frida-agent",
    "frida-gadget",
    "easyhook",
    "detours",
    "minhook",
    "pyhook",
    "winhook",
    "deviare",
)


def _check_native_modules() -> bool:
    try:
        if not _PIN_IS_WINDOWS:
            return False
        _ct = _seen_import("ctypes")
        if _ct is None:
            return False
        try:
            k32 = _fix_k32(_ct.windll.kernel32)
            psapi = _ct.windll.psapi
            hproc = k32.GetCurrentProcess()
            arr = (_ct.c_void_p * 1024)()
            try:
                needed = _ct.c_ulong(0)
                ok = psapi.EnumProcessModules(
                    hproc, arr, _ct.sizeof(arr), _ct.byref(needed))
            except Exception:
                ok = 0
            if not ok:
                return False
            try:
                count = int(needed.value // _ct.sizeof(_ct.c_void_p))
            except Exception:
                return False
            if count <= 0:
                return False
            buf = _ct.create_unicode_buffer(260)
            for i in range(min(count, 1024)):
                try:
                    hmod = arr[i]
                    if not hmod:
                        continue
                    try:
                        n = psapi.GetModuleFileNameExW(hproc, hmod, buf, 260)
                    except Exception:
                        continue
                    if not n:
                        continue
                    try:
                        base = str(buf.value).lower().rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
                    except Exception:
                        continue
                    if base.endswith(".dll"):
                        base = base[:-4]
                    for bad in _HOOK_DLLS:
                        try:
                            if base == bad or base.startswith(bad):
                                return True
                        except Exception:
                            continue
                except Exception:
                    continue
        except Exception:
            pass
    except Exception:
        pass
    return False


def _check_hidden_image() -> bool:
    try:
        if not _PIN_IS_WINDOWS:
            return False
        _ct = _seen_import("ctypes")
        if _ct is None:
            return False
        try:
            k32 = _fix_k32(_ct.windll.kernel32)
            psapi = _ct.windll.psapi
            hproc = k32.GetCurrentProcess()

            class _MBI(_ct.Structure):
                _fields_ = [("BaseAddress", _ct.c_void_p),
                            ("AllocationBase", _ct.c_void_p),
                            ("AllocationProtect", _ct.c_ulong),
                            ("RegionSize", _ct.c_size_t),
                            ("State", _ct.c_ulong),
                            ("Protect", _ct.c_ulong),
                            ("Type", _ct.c_ulong)]

            try:
                arr = (_ct.c_void_p * 1024)()
                needed = _ct.c_ulong(0)
                ok = psapi.EnumProcessModules(
                    hproc, arr, _ct.sizeof(arr), _ct.byref(needed))
            except Exception:
                ok = 0
            if not ok:
                return False
            try:
                count = int(needed.value // _ct.sizeof(_ct.c_void_p))
            except Exception:
                return False
            ranges = []
            try:
                for i in range(min(count, 1024)):
                    try:
                        hmod = arr[i]
                        if not hmod:
                            continue
                        bnds = _module_bounds(k32, int(hmod))
                        if bnds is not None:
                            ranges.append(bnds)
                    except Exception:
                        continue
            except Exception:
                pass
            if not ranges:
                return False
            mbi = _MBI()
            addr = 0
            limit = 0x7FFFFFFF0000
            steps = 0
            while addr < limit and steps < 200000:
                steps += 1
                try:
                    ret = k32.VirtualQuery(
                        _ct.c_void_p(addr), _ct.byref(mbi), _ct.sizeof(mbi))
                except Exception:
                    break
                if not ret:
                    break
                try:
                    rsize = int(mbi.RegionSize or 0)
                    state = int(mbi.State or 0)
                    mtype = int(mbi.Type or 0)
                    base = int(mbi.BaseAddress or 0)
                except Exception:
                    break
                if rsize <= 0:
                    break
                try:
                    if state == 0x1000 and mtype == 0x1000000 and base:
                        inside = False
                        for (mb, ms) in ranges:
                            try:
                                if mb <= base < mb + ms:
                                    inside = True
                                    break
                            except Exception:
                                continue
                        if not inside:
                            return True
                except Exception:
                    pass
                addr += rsize
        except Exception:
            pass
    except Exception:
        pass
    return False


def _check_hw_threads() -> bool:
    try:
        if not (_PIN_IS_WINDOWS and _PIN_IS_X86_64):
            return False
        _ct = _seen_import("ctypes")
        if _ct is None:
            return False
        try:
            k32 = _fix_k32(_ct.windll.kernel32)
            mypid = k32.GetCurrentProcessId()
            snap = k32.CreateToolhelp32Snapshot(0x4, 0)
            if not snap or snap == 0xFFFFFFFFFFFFFFFF:
                return False
            try:
                te = _ct.create_string_buffer(28)
                _struct.pack_into("<I", te, 0, 28)
                ok = k32.Thread32First(snap, te)
                seen = 0
                while ok and seen < 4096:
                    seen += 1
                    try:
                        tid, owner = _struct.unpack_from("<II", te, 8)
                    except Exception:
                        break
                    if owner == mypid and tid:
                        h = None
                        try:
                            h = k32.OpenThread(0x0018, 0, tid)
                        except Exception:
                            h = None
                        if h:
                            try:
                                ctx = _ct.create_string_buffer(0x4D0)
                                _struct.pack_into("<I", ctx, 48, 0x10)
                                if k32.GetThreadContext(h, ctx):
                                    for off in (72, 80, 88, 96):
                                        try:
                                            if _struct.unpack_from("<Q", ctx, off)[0] != 0:
                                                return True
                                        except Exception:
                                            continue
                            except Exception:
                                pass
                            try:
                                k32.CloseHandle(h)
                            except Exception:
                                pass
                    try:
                        ok = k32.Thread32Next(snap, te)
                    except Exception:
                        break
            finally:
                try:
                    k32.CloseHandle(snap)
                except Exception:
                    pass
        except Exception:
            pass
    except Exception:
        pass
    return False


def _check_hw_breakpoints() -> bool:
    try:
        if not (_PIN_IS_WINDOWS and _PIN_IS_X86_64):
            return False
        _ct = _seen_import("ctypes")

        try:
            k32 = _fix_k32(_ct.windll.kernel32)
            ctx = _ct.create_string_buffer(0x4D0)
            _struct.pack_into("<I", ctx, 48, 0x10)
            h = k32.GetCurrentThread()
            ok = k32.GetThreadContext(h, ctx)
            if not ok:
                return False
            for off in (72, 80, 88, 96):
                try:
                    if _struct.unpack_from("<Q", ctx, off)[0] != 0:
                        return True
                except Exception:
                    continue
        except Exception:
            pass
    except Exception:
        pass
    return False


def break_hooks() -> Dict[str, int]:
    """Izlenen Python attr'larini baseline'a dondurur. KISMIDIR: meta_path
    buluculari, sys.modules girdileri ve env degiskenleri tahliye edilmez
    (mesru araclari kirmamak icin); tam temizlik icin watchdog + exit zinciri
    kullanilir. Donus: restore edilen sayisi (oracle degil, sadece sayi)."""
    report: Dict[str, int] = {"restored": 0}
    try:
        n = 0
        for (modname, attr), (oid, sig, _w) in list(_BASELINE.items()):
            try:
                try:
                    mod = _SEEN_MODS.get(modname, _PIN_MODULES.get(modname))
                except Exception:
                    mod = None
                if mod is None:
                    try:
                        mod = _resolve_owner(modname)
                    except Exception:
                        mod = None
                    if mod is None:
                        continue
                try:
                    cur = getattr(mod, attr)
                except Exception:
                    continue
                if id(cur) == oid:
                    continue
                try:
                    orig = _ctypes_caller_original(modname, attr, oid, sig)
                except Exception:
                    orig = None
                if orig is None:
                    continue
                try:
                    try:
                        mod.__dict__[attr] = orig
                    except Exception:
                        setattr(mod, attr, orig)
                    n += 1
                except Exception:
                    continue
            except Exception:
                continue
        report["restored"] = n
    except Exception:
        pass
    return report


_ORIGINALS: Dict[Tuple[str, str], Any] = {}


def _ctypes_caller_original(modname: str, attr: str, oid: int, sig: tuple) -> Any:
    try:
        key = (modname, attr)
        if key in _ORIGINALS:
            try:
                cand = _ORIGINALS[key]
                if id(cand) == oid and _func_sig(cand) == sig:
                    return cand
                try:
                    del _ORIGINALS[key]
                except Exception:
                    pass
            except Exception:
                pass
        try:
            for ob in _PIN_GC_OBJECTS():
                try:
                    if id(ob) != oid:
                        continue
                    try:
                        if _func_sig(ob) != sig:
                            continue
                    except Exception:
                        continue
                    _ORIGINALS[key] = ob
                    return ob
                except Exception:
                    continue
        except Exception:
            pass
    except Exception:
        pass
    return None


_FRIDA_THREAD_NAMES = (
    b"gum-js-loop",
    b"gmain",
    b"frida",
    b"gadget",
    b"linjector",
)

_FRIDA_MEMFD_MARKERS = (
    b"memfd:frida",
    b"frida-jit",
)


def _check_frida_threads() -> bool:
    """Canli Frida-ajan iplik + memfd isareti (Linux /proc) + Windows DLL izi.

    2026 arastirmasi (hamida/phantom-frida): gum-js-loop (JS motoru) ve
    gmain (GLib olay-dongusu, script YUKLENMEDEN bile gorunur) + JIT
    memfd ismi en erken canli-isaretlerdir. /proc/self/task/*/comm ve
    /proc/self/maps taranir; ad-degistirmis ajan gorunmez (dokumante).
    H3 duzeltmesi: Windows dali artik EnumProcessModules ile frida/
    gadget/gumjs DLL alt-stringlerini arar (Frida'nin kendi gum kutuphanesi
    de modul listesini ayni API ile cikarir — en guclu stdlib-erisimli
    vektor). Yeniden-adlandirilmis DLL kalintisi dokumante edilir.
    """
    try:
        if _PIN_IS_WINDOWS:
            try:
                _ct = _seen_import("ctypes")
                if _ct is None:
                    return True
                k32 = _fix_k32(_ct.windll.kernel32)
                psapi = _ct.windll.psapi
                hproc = k32.GetCurrentProcess()
                arr = (_ct.c_void_p * 1024)()
                try:
                    needed = _ct.c_ulong(0)
                    ok = psapi.EnumProcessModules(
                        hproc, arr, _ct.sizeof(arr), _ct.byref(needed))
                except Exception:
                    return True
                if not ok:
                    return True
                try:
                    count = int(needed.value // _ct.sizeof(_ct.c_void_p))
                except Exception:
                    return True
                if count <= 0:
                    return True
                buf = _ct.create_unicode_buffer(260)
                for i in range(min(count, 1024)):
                    try:
                        hmod = arr[i]
                        if not hmod:
                            continue
                        try:
                            n = psapi.GetModuleFileNameExW(hproc, hmod, buf, 260)
                        except Exception:
                            continue
                        if not n:
                            continue
                        try:
                            base = str(buf.value).lower().rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
                        except Exception:
                            continue
                        if "frida" in base or "gadget" in base or "gumjs" in base:
                            return True
                    except Exception:
                        continue
                return False
            except Exception:
                return True
        try:
            tids = _os.listdir("/proc/self/task")
        except Exception:
            return False
        for tid in tids:
            if not tid.isdigit():
                continue
            try:
                with open("/proc/self/task/%s/comm" % tid, "rb") as f:
                    comm = f.read(64).lower().strip()
            except Exception:
                continue
            for bad in _FRIDA_THREAD_NAMES:
                try:
                    if bad in comm:
                        return True
                except Exception:
                    continue
        try:
            with open("/proc/self/maps", "rb") as f:
                for _i in range(4096):
                    line = f.readline(4096)
                    if not line:
                        break
                    low = line.lower()
                    for bad in _FRIDA_MEMFD_MARKERS:
                        if bad in low:
                            return True
        except Exception:
            pass
    except Exception:
        pass
    return False


def check_all() -> Dict[str, bool]:
    results: Dict[str, bool] = {}
    for name, fn in (
        ("func_integrity", _check_func_integrity),
        ("wrapped_chain", _check_wrapped_chain),
        ("import_system", _check_import_system),
        ("native_prologue", _check_native_prologue),
        ("eat_range", _check_eat_range),
        ("hook_modules", _check_hook_modules),
        ("hook_behavior", _check_hook_behavior),
        ("module_identity", _check_module_identity),
        ("gc_proxies", _check_gc_proxies),
        ("hook_env", _check_hook_env),
        ("py_tracing", _check_py_tracing),
        ("pinned_mismatch", _check_pinned_mismatch),
        ("native_modules", _check_native_modules),
        ("hidden_image", _check_hidden_image),
        ("hw_threads", _check_hw_threads),
        ("frida_threads", _check_frida_threads),
        ("cache_integrity", _check_cache_integrity),
        ("sensor_health", _check_sensor_health),
        ("watchdog_liveness", _check_watchdog_liveness),
    ):
        try:
            results[name] = bool(fn())
        except Exception:
            results[name] = True
    try:
        results["hw_breakpoints"] = bool(_check_hw_breakpoints())
    except Exception:
        results["hw_breakpoints"] = True
    try:
        if not _VERBOSE:
            return {"hooked": any(results.values())}
    except Exception:
        pass
    return results


def is_hooked() -> bool:
    try:
        if _check_func_integrity():
            return True
        if _check_wrapped_chain():
            return True
        if _check_import_system():
            return True
        if _check_native_prologue():
            return True
        if _check_eat_range():
            return True
        if _check_hook_modules():
            return True
        if _check_hook_behavior():
            return True
        if _check_module_identity():
            return True
        if _check_gc_proxies():
            return True
        if _check_hook_env():
            return True
        if _check_py_tracing():
            return True
        if _check_pinned_mismatch():
            return True
        if _check_native_modules():
            return True
        if _check_hidden_image():
            return True
        if _check_hw_threads():
            return True
        if _check_frida_threads():
            return True
        if _check_cache_integrity():
            return True
        if _check_sensor_health():
            return True
        if _check_watchdog_liveness():
            return True
        if _check_hw_breakpoints():
            return True
    except BaseException:
        return True
    except Exception:
        return False
    return False


def assert_no_hook() -> None:
    if is_hooked():
        raise HookDetected("protected")


_WATCHDOGS: list = []
_WATCHDOGS_LOCK = _threading.Lock()
_WATCHDOG_THREADS: list = []
_VERBOSE = False


def set_verbose(on: bool) -> bool:
    try:
        global _VERBOSE
        _VERBOSE = bool(on)
        return True
    except Exception:
        return False


def _check_watchdog_liveness() -> bool:
    try:
        with _WATCHDOGS_LOCK:
            threads = list(_WATCHDOG_THREADS)
            stops = list(_WATCHDOGS)
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
        return False


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
    raise HookDetected("protected")


def start_watchdog(
    interval: float = 0.5,
    on_detect: Optional[Callable[[], None]] = None,
    daemon: bool = True,
    paranoid: bool = False,
) -> Callable[[], None]:
    if interval < 0.1:
        interval = 0.1
    if interval > 10.0:
        interval = 10.0
    global _ADMIN_LOCKED
    try:
        with _WATCHDOGS_LOCK:
            _ADMIN_LOCKED = True
    except Exception:
        pass
    stop_event = _PIN_THREAD_EVENT()
    with _WATCHDOGS_LOCK:
        _WATCHDOGS.append(stop_event)

    def _default_action() -> None:
        try:
            _PIN_OS_EXIT(1)
        except Exception:
            pass

    action = on_detect if callable(on_detect) else _default_action

    def _loop() -> None:
        tick = 0
        try:
            last = _PIN_MONOTONIC() if _PIN_MONOTONIC else 0.0
        except Exception:
            last = 0.0
        suspend_limit = max(10.0 * interval, 10.0)
        while not stop_event.is_set():
            try:
                try:
                    now = _PIN_MONOTONIC() if _PIN_MONOTONIC else 0.0
                    if last and (now - last) > suspend_limit:
                        try:
                            action()
                        except Exception:
                            pass
                        return
                    last = now
                except Exception:
                    pass
                hit = (
                    _check_func_integrity()
                    or _check_wrapped_chain()
                    or _check_import_system()
                    or _check_native_prologue()
                    or _check_eat_range()
                    or _check_hook_modules()
                    or _check_hook_behavior()
                    or _check_module_identity()
                    or _check_gc_proxies()
                    or _check_hook_env()
                    or _check_py_tracing()
                    or _check_pinned_mismatch()
                    or _check_native_modules()
                    or _check_hidden_image()
                    or _check_hw_threads()
                    or _check_frida_threads()
                    or _check_cache_integrity()
                    or _check_sensor_health()
                    or _check_watchdog_liveness()
                    or _check_hw_breakpoints()
                )
                tick += 1
                if paranoid and not hit and tick % 10 == 0:
                    try:
                        break_hooks()
                    except Exception:
                        pass
                if hit:
                    try:
                        break_hooks()
                    except Exception:
                        pass
                    try:
                        action()
                    except Exception:
                        pass
                    return
            except Exception:
                pass
            stop_event.wait(interval)

    th = _PIN_THREAD(target=_loop, name="hyper-antihook", daemon=daemon)
    try:
        th.start()
    except Exception:
        raise HookDetected("protected")
    with _WATCHDOGS_LOCK:
        try:
            _WATCHDOG_THREADS.append(th)
        except Exception:
            pass
    assert_no_hook()

    def _stop() -> None:
        if not _check_admin():
            _deny_admin("_stop")
        stop_event.set()
        with _WATCHDOGS_LOCK:
            try:
                _WATCHDOGS.remove(stop_event)
            except ValueError:
                pass
            try:
                _WATCHDOG_THREADS[:] = [t for t in _WATCHDOG_THREADS if t.is_alive()]
            except Exception:
                pass

    return _stop


def stop_all_watchdogs() -> int:
    if not _check_admin():
        _deny_admin("stop_all_watchdogs")
    n = 0
    with _WATCHDOGS_LOCK:
        events = list(_WATCHDOGS)
    for ev in events:
        try:
            ev.set()
            n += 1
        except Exception:
            continue
    with _WATCHDOGS_LOCK:
        try:
            _WATCHDOG_THREADS[:] = [t for t in _WATCHDOG_THREADS if t.is_alive()]
        except Exception:
            pass
    return n


class _Guard:
    def __enter__(self) -> "_Guard":
        assert_no_hook()
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> bool:
        if exc_type is None:
            assert_no_hook()
            return False
        if is_hooked():
            raise HookDetected("protected") from exc  # type: ignore[misc]
        return False


def guard() -> _Guard:
    return _Guard()


try:
    for __self_fn in (
        "_BASELINE",
        "_SEEN_MODS",
        "_DISK_CACHE",
        "_ORIGINALS",
        "_WATCHDOGS",
        "_PIN_BASELINE_OBJ",
        "_PIN_BASELINE_MIN",
    ):
        try:
            watch(__name__, __self_fn)
        except Exception:
            continue
    try:
        __mod_type = type(_sys)
        for __self_name, __self_obj in list(globals().items()):
            try:
                if __self_name.startswith("__"):
                    continue
                if isinstance(__self_obj, __mod_type):
                    continue
                if not callable(__self_obj):
                    continue
                watch(__name__, __self_name)
            except Exception:
                continue
    except Exception:
        pass
except Exception:
    pass

_PIN_BASELINE_KEYS = set(_BASELINE)
try:
    watch(__name__, "_PIN_BASELINE_KEYS")
except Exception:
    pass
