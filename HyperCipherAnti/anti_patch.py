"""anti_patch: runtime yama (monkey-patch) direnc katmani.

anti_tamper tespite odaklanir; bu modul YAMAYI ETKISIZ kilmaya odaklanir:
kritik baglantilari sabitler (pin), kullanim-oncesi dogrular, import
sistemini ve builtins'i anlik-goruntuyle korur, degisikligi otomatik
geri alir (auto-heal), supheli yama girisimini sessizce trip'ler.

Kapsam (tamper ile cakisma yok):
  - pin(): kritik callable'i hucreye sabitle + parmakizi al
  - guarded(): kullanim-oncesi dogrulamali cagri (fail-closed)
  - sys.modules / sys.meta_path / sys.path_hooks / builtins snapshot+restore
  - audit-hook tripwire: func.__code__ / sinif-attr yama girisimi
  - unittest.mock aktif-yama dedektoru (uretimde mock = supheli)

Sinirlar (bilincli tercihler):
  - sys.modules YENI modulu bayraklamaz (lazy-import FP'sinden kacinmak icin);
    kaybolma/degisim yakalanir.
  - native_memory (ctypes/cffi/mmap varligi) WEAK'tir; kardes moduller ctypes
    kullanir -> birlikte importta bu sinyal yanar, tek basina trip uretmez.
  - restore() sys.modules/path_hooks'a dokunmaz (import zinciri kirilmamasi
    icin); pins otomatik restore edilmez, operator re-pin eder.

Yonetim-duzlemi siniri: unpin/reseal/stop_all_watchdogs/break_patch yalnizca
boot-sirasinda authorize_admin() ile kaydedilmis operator modullerinden
cagrilabilir; seal() kaydi kilitler. Kilit-sonrasi cagrilar deny+trip uretir.
TOCTOU kalintisi: guarded() pre-check ile cagri arasindaki nanosaniye
penceresinde swap+swap-back post-check'i atlatabilir (post-check kalici
degisikligi yakalar). Tick-alti transient builtins add+del: CPython modul-attr
atamada audit olayı yaymadigindan (PEP 578) yalnizca watchdog tick'inde
gorunurse sticky-latch'e takilir; tick-arasi transient mimari-kor (oneri:
yuksek-riskte interval=0.2).

Sessiz, stdlib-only, fail-closed. True=risk, False=temiz.
"""

import sys as _sys
import threading as _threading
import hashlib as _hashlib
import types as _types
import time as _time


class _PatchBlocked(Exception):
    pass


def _raise():
    raise _PatchBlocked()


_LOCK = _threading.RLock()

_SEALED = False
_SEAL_TIME = 0.0

# pin registry: key -> {"ref": callable, "fp": str, "code": bytes|None}
_PINS = {}
# module attr registry: (mod_name, attr) -> {"ref": obj, "fp": str}
_ATTRS = {}
# import-system snapshots
_MOD_SNAPSHOT = {}
_MOD_ATTRS_SNAPSHOT = {}
_LATE_MODULES = {}
_METAPATH_SNAPSHOT = ()
_PATHHOOKS_SNAPSHOT = ()
_BUILTINS_SNAPSHOT = {}
# native-memory baseline: import-aninda yuklu olanlar guvenilir baglam
# (kardes suit ctypes kullanir); SONRADAN gelen ctypes/cffi/mmap suphelidir.
_NATIVE_BASELINE = frozenset(_sys.modules.keys())

_TRIPWIRE_HOOK = None
_TRIPWIRE_COUNT = 0
_CANARY_COUNT = 0
_WATCHDOG_STOP = None
_WATCHDOG_THREAD = None

_JOURNAL = []
_JOURNAL_CAP = 256

# Yonetim-duzlemi siniri (P-1/P-2/P-8): yikici operator API'leri
# (unpin/reseal/stop_all_watchdogs/break_patch) yalnizca boot-sirasinda
# authorize_admin() ile kaydedilmis operator modullerinden cagrilabilir.
# seal() kayit setini kilitler; kilit-sonrasi authorize denemesi deny+trip
# uretir. Ayni-proses saldirgan (late-loaded kod) bu siniri gecemez:
# kendi modul adi kayitli degildir ve kayit kilitlidir.
_BOOT_MODULES = frozenset(_sys.modules.keys())
_ADMIN_MODULES = {}
_ADMIN_LOCKED = False
_ADMIN_DENIED = 0
_BUILTIN_TAMPER_LATCH = False
_LAST_RESTORE = {"restored": 0, "unhealed_sys_modules": [], "path_hooks_dirty": False}
_BI_MOD = None
_RESTORING = 0


def _journal(signal):
    try:
        with _LOCK:
            _JOURNAL.append((_time.time(), str(signal)))
            while len(_JOURNAL) > _JOURNAL_CAP:
                _JOURNAL.pop(0)
    except Exception:
        pass

WEIGHTS = {
    "pinned_bindings": 100,
    "module_attrs": 100,
    "code_objects": 100,
    "import_hooks": 100,
    "builtins": 100,
    "module_rebind": 100,
    "sys_modules": 30,
    "mock_active": 30,
    "tripwire": 100,
    "hook_liveness": 100,
    "native_memory": 30,
}
STRONG_AT = 100
TRIP_NEED = 2


def _code_head(code):
    """Normalize baslik: dis gorunumu (quicken-proof), yoksa ham bytes.

    3.11+ hot-code quicken ham co_code'u yerinde degistirir -> ham hash FP
    uretir. dis `adaptive=False` ile orijinal akisi verir. Import LAZY +
    sys.modules temizlikli (kardes WEAK sinyalini kirletmemek icin).
    """
    try:
        added = "dis" not in _sys.modules
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
                    if isinstance(arg, _types.CodeType):
                        arg = "<code>"
                    elif isinstance(arg, (bytes, bytearray)):
                        arg = "<bytes:%d>" % len(bytes(arg))
                    else:
                        try:
                            arg = repr(arg)
                        except Exception:
                            arg = "?"
                    out.append((ins.opname, arg))
                except Exception:
                    continue
            return ("norm", repr(tuple(out)))
    except Exception:
        pass
    finally:
        try:
            if added and "dis" in _sys.modules:
                try:
                    del _sys.modules["dis"]
                except Exception:
                    pass
        except Exception:
            pass
    try:
        return ("raw", bytes(getattr(code, "co_code", b"") or b""))
    except Exception:
        return ("raw", b"")


def _code_fp(code):
    """Davranis-belirleyen alanlarin ozeti (P2-9 deseni + normalize baslik).

    Kapsar: normalize-akim, ozyinelemeli sabitler, co_names/varnames,
    freevars/cellvars, flags, arg-sayilari, stacksize. Baglam alanlari
    (filename/lineno) bilerek DISARIDA (ortam-degisiminde stabil).
    """
    try:
        h = _hashlib.sha256()
        try:
            mode, head = _code_head(code)
        except Exception:
            mode, head = "raw", b""
        try:
            h.update(mode.encode())
            h.update(head if isinstance(head, bytes) else head.encode("utf-8", "ignore"))
        except Exception:
            pass
        try:
            consts = getattr(code, "co_consts", ()) or ()
        except Exception:
            consts = ()
        for c in consts:
            try:
                if isinstance(c, _types.CodeType):
                    sub = _code_fp(c)
                    if sub:
                        h.update(sub.encode())
                elif isinstance(c, (bytes, bytearray)):
                    h.update(bytes(c))
                elif isinstance(c, str):
                    h.update(c.encode("utf-8", "ignore"))
                elif isinstance(c, (bool, int, float, complex, type(None))):
                    h.update(repr(c).encode("utf-8", "ignore"))
                elif isinstance(c, tuple):
                    h.update(repr(c).encode("utf-8", "ignore"))
                elif isinstance(c, frozenset):
                    try:
                        h.update(repr(sorted(repr(x) for x in c)).encode("utf-8", "ignore"))
                    except Exception:
                        h.update(repr(c).encode("utf-8", "ignore"))
            except Exception:
                continue
        for attr in ("co_names", "co_varnames", "co_freevars", "co_cellvars"):
            try:
                h.update(repr(tuple(getattr(code, attr, ()) or ())).encode("utf-8", "ignore"))
            except Exception:
                continue
        for attr in ("co_flags", "co_argcount", "co_posonlyargcount",
                     "co_kwonlyargcount", "co_stacksize"):
            try:
                h.update(str(getattr(code, attr, 0)).encode())
            except Exception:
                continue
        return h.hexdigest()
    except Exception:
        return None


def _func_fp(fn):
    try:
        code = getattr(fn, "__code__", None)
        if code is None:
            return None
        base = _code_fp(code)
        if not base:
            return None
        h = _hashlib.sha256()
        h.update(base.encode())
        try:
            h.update(repr(getattr(fn, "__defaults__", None)).encode("utf-8", "ignore")[:1024])
        except Exception:
            pass
        try:
            h.update(repr(getattr(fn, "__kwdefaults__", None)).encode("utf-8", "ignore")[:1024])
        except Exception:
            pass
        try:
            closure = getattr(fn, "__closure__", None)
            if closure:
                h.update(str(len(closure)).encode())
                for cell in closure:
                    try:
                        v = cell.cell_contents
                    except Exception:
                        h.update(b"?")
                        continue
                    if v is None or isinstance(v, (bool, int, float, str, bytes)):
                        try:
                            h.update(repr(v).encode("utf-8", "ignore")[:512])
                        except Exception:
                            h.update(b"?")
                    elif isinstance(v, tuple) and all(
                            x is None or isinstance(x, (bool, int, float, str, bytes)) for x in v):
                        try:
                            h.update(repr(v).encode("utf-8", "ignore")[:512])
                        except Exception:
                            h.update(b"?")
                    else:
                        h.update(repr(type(v)).encode("utf-8", "ignore"))
        except Exception:
            pass
        return h.hexdigest()
    except Exception:
        return None


def _obj_fp(v):
    try:
        h = _hashlib.sha256()
        h.update(repr(type(v)).encode("utf-8", "ignore"))
        try:
            h.update(repr(v).encode("utf-8", "ignore")[:4096])
        except Exception:
            h.update(str(id(v)).encode())
        f = _func_fp(v)
        if f:
            h.update(f.encode())
        return h.hexdigest()
    except Exception:
        return None


def _audit_tripwire(event, args):
    global _TRIPWIRE_COUNT, _CANARY_COUNT, _BUILTIN_TAMPER_LATCH
    try:
        if event == "anti_patch.canary":
            _CANARY_COUNT += 1
            return
        if event not in ("object.__setattr__", "object.__delattr__"):
            return
        try:
            if _RESTORING > 0:
                return
        except Exception:
            pass
        try:
            if (event == "object.__setattr__" and _BI_MOD is not None and args
                    and len(args) >= 2 and args[0] is _BI_MOD):
                try:
                    with _LOCK:
                        known = args[1] in _BUILTINS_SNAPSHOT
                    if not known:
                        with _LOCK:
                            _BUILTIN_TAMPER_LATCH = True
                        _journal("builtins.add:" + str(args[1]))
                except Exception:
                    pass
        except Exception:
            pass
        if not args or len(args) < 2:
            return
        obj, attr = args[0], args[1]
        # P-7: modul-seviyesi rebinding (__code__'ya dokunmadan yama).
        # Research (PEP 578 + CPython audit-tests): modul attr atamasi
        # object.__setattr__ olayi yayar. Seal-sonrasi yabanci modul
        # attr yazimi/silimi trip'ler (restore sirasinda _RESTORING
        # baskilar — kendi heal'imiz self-trip uretmez).
        try:
            if type(obj).__name__ == "module":
                try:
                    mname = getattr(obj, "__name__", None)
                except Exception:
                    mname = None
                try:
                    with _LOCK:
                        known = mname in _MOD_SNAPSHOT if mname else False
                except Exception:
                    known = False
                if known:
                    with _LOCK:
                        _TRIPWIRE_COUNT += 1
                    try:
                        _journal(("delattr" if event == "object.__delattr__" else "setattr")
                                 + ".modrebind:" + str(mname) + "." + str(attr))
                    except Exception:
                        pass
                    return
        except Exception:
            pass
        if event == "object.__delattr__":
            with _LOCK:
                for key, pin in _PINS.items():
                    try:
                        if obj is pin.get("ref") and attr == "__code__":
                            _TRIPWIRE_COUNT += 1
                            _journal("delattr.__code__:" + str(key))
                            break
                        target = pin.get("target")
                        if target is not None and obj is target and attr == pin.get("attr"):
                            _TRIPWIRE_COUNT += 1
                            _journal("delattr.pinattr:" + str(key))
                            break
                    except Exception:
                        continue
            return
        with _LOCK:
            for key, pin in _PINS.items():
                try:
                    if obj is pin.get("ref") and attr == "__code__":
                        _TRIPWIRE_COUNT += 1
                        _journal("setattr.__code__:" + str(key))
                        break
                    target = pin.get("target")
                    if target is not None and obj is target and attr == pin.get("attr"):
                        _TRIPWIRE_COUNT += 1
                        _journal("setattr.pinattr:" + str(key))
                        break
                except Exception:
                    continue
    except Exception:
        pass


def _install_tripwire():
    global _TRIPWIRE_HOOK
    try:
        if _TRIPWIRE_HOOK is not None:
            return True
        hook = _audit_tripwire
        _sys.addaudithook(hook)
        _TRIPWIRE_HOOK = hook
        return True
    except Exception:
        return False


def authorize_admin():
    """Operator modulunu yonetim-duzlemine kaydet (SADECE kilit-oncesi).

    Boot sirasinda operator kodundan cagrilir; cagiran cercevenin modul
    adi + gercek dosya yolu kaydedilir. seal() (veya lock_admin()) sonrasi
    cagrilar reddedilir + trip uretir. Donus: True=kaydedildi.
    """
    global _ADMIN_DENIED
    try:
        if _ADMIN_LOCKED:
            with _LOCK:
                _ADMIN_DENIED += 1
            _journal("admin.authorize_denied_locked")
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
        _journal("admin.authorized:" + name)
        return True
    except Exception:
        return False


def lock_admin():
    """Yonetim kaydini kilitle (seal() zaten kilitler)."""
    global _ADMIN_LOCKED
    try:
        with _LOCK:
            _ADMIN_LOCKED = True
        return True
    except Exception:
        return False


def _check_admin():
    """Dogrudan cagiran cerceve kayitli operator modulu mu? (dosya-dogrulamali).

    Bilerek SADECE direkt caller kontrol edilir: zincirdeki herhangi bir
    kayitli cerceve yetmez (operator evil kodu import etmisse zincirde
    operator cercevesi bulunur; late-loaded saldirgan modulunden gelen
    cagri direkt-caller kontrolunde elenir).
    """
    try:
        import os as _os
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
            if (want is not None and fn == want and not fn.startswith("<")
                    and _os.path.isfile(fn)):
                return True
        except Exception:
            pass
        return False
    except Exception:
        return False


def _deny_admin(op):
    """Yonetim reddi: journal + sayac + fail-closed raise."""
    global _ADMIN_DENIED
    try:
        with _LOCK:
            _ADMIN_DENIED += 1
        _journal("admin.denied:" + str(op))
    except Exception:
        pass
    _raise()


def pin(fn, key=None):
    """Kritik callable'i sabitle; donen anahtar guarded() icin kullanilir.

    P-5/P-9: code-object de saklanir — guarded() pinli KODU calistirir
    (canli ref'in o-anki __code__'unu degil), restore() yamayi geri alir.
    """
    try:
        k = key if key else getattr(fn, "__qualname__", None) or getattr(fn, "__name__", None) or str(id(fn))
        fp = _func_fp(fn)
        try:
            code_obj = getattr(fn, "__code__", None)
        except Exception:
            code_obj = None
        with _LOCK:
            old = _PINS.get(k)
            if old is not None and old.get("fp") != fp:
                return None
            _PINS[k] = {"ref": fn, "fp": fp, "code_obj": code_obj,
                        "code": bytes(getattr(getattr(fn, "__code__", None), "co_code", b"") or b"")}
        return k
    except Exception:
        return None


def unpin(key):
    """Pin sil (YONETIM: kayitli operator modulu sart; aksi halde deny+trip)."""
    if not _check_admin():
        _deny_admin("unpin")
    try:
        with _LOCK:
            return _PINS.pop(key, None) is not None
    except Exception:
        return False


def register_attr(mod_name, attr):
    """Modul attr baglantisini sabitle (yama-sonrasi restore icin)."""
    try:
        mod = _sys.modules.get(mod_name)
        if mod is None:
            return False
        ref = getattr(mod, attr, None)
        if ref is None:
            return False
        with _LOCK:
            _ATTRS[(mod_name, attr)] = {"ref": ref, "fp": _obj_fp(ref)}
        return True
    except Exception:
        return False


def guarded(key, *args, **kwargs):
    """Pinned cagri: PINLI KOD calistirilir (P-5 TOCTOU kapali).

    Pre-check dogrular, sonra canli ref DEGIL pinli code-object'ten
    insa edilen proxy calistirilir: pre-check ile cagri arasinda
    ref.__code__'u degistiren paralel thread ZARARLI GOVDEYI
    calistiramaz (proxy pinli kodu tasir). Post-check sapmayi trip'ler.
    """
    try:
        with _LOCK:
            pin_ = _PINS.get(key)
            ref = pin_["ref"] if pin_ else None
            fp = pin_["fp"] if pin_ else None
            code_obj = pin_.get("code_obj") if pin_ else None
    except Exception:
        ref, fp, code_obj = None, None, None
    if ref is None:
        _journal("guarded.nopin:" + str(key))
        _raise()
    if _func_fp(ref) != fp:
        _journal("guarded.pre:" + str(key))
        _raise()
    try:
        import types as _t
        if code_obj is not None:
            try:
                fn = _t.FunctionType(code_obj, getattr(ref, "__globals__", {}),
                                     getattr(ref, "__name__", "<pinned>"),
                                     getattr(ref, "__defaults__", None),
                                     getattr(ref, "__closure__", None))
                try:
                    fn.__kwdefaults__ = getattr(ref, "__kwdefaults__", None)
                except Exception:
                    pass
                call_ref = fn
            except Exception:
                call_ref = ref
        else:
            call_ref = ref
    except Exception:
        call_ref = ref
    try:
        out = call_ref(*args, **kwargs)
    except _PatchBlocked:
        raise
    except Exception:
        try:
            if _func_fp(ref) != fp:
                global _TRIPWIRE_COUNT
                _TRIPWIRE_COUNT += 1
                _journal("guarded.post-err:" + str(key))
                _raise()
        except _PatchBlocked:
            raise
        except Exception:
            pass
        raise
    try:
        if _func_fp(ref) != fp:
            _TRIPWIRE_COUNT += 1
            _journal("guarded.post:" + str(key))
            _raise()
    except _PatchBlocked:
        raise
    except Exception:
        pass
    return out


def verify_pin(key):
    try:
        with _LOCK:
            pin_ = _PINS.get(key)
        if not pin_:
            return None
        cur = _func_fp(pin_["ref"])
        if cur is None or pin_["fp"] is None:
            return None
        return cur == pin_["fp"]
    except Exception:
        return None


def seal():
    """Tum kritik state'i muhurle: snapshot + tripwire. Idempotent.

    Ayrica yonetim kaydini kilitler (P-1/P-2): kilit-sonrasi authorize ve
    kayitsiz yikici-op cagrilari deny+trip uretir. Donus sozlugune
    import-sonrasi eklenen modul sayisi + ORNEK isimler (P-6: pre-seal
    penceresi seffafligi — seal-oncesi eklenen her sey baseline olur,
    operator ornegi denetler).
    """
    global _SEALED, _SEAL_TIME, _ADMIN_LOCKED, _BI_MOD
    try:
        with _LOCK:
            _ADMIN_LOCKED = True
            try:
                _added = [m for m in _sys.modules.keys() if m not in _BOOT_MODULES]
            except Exception:
                _added = []
            if _SEALED:
                _install_tripwire()
                return {"pins": len(_PINS), "attrs": len(_ATTRS),
                        "modules": len(_MOD_SNAPSHOT), "resealed": False,
                        "added_since_import": len(_added),
                        "added_sample": list(_added[:16])}
            _MOD_SNAPSHOT.clear()
            for name, mod in list(_sys.modules.items()):
                try:
                    _MOD_SNAPSHOT[name] = id(mod)
                except Exception:
                    continue
            try:
                _MOD_ATTRS_SNAPSHOT.clear()
                for name, mod in list(_sys.modules.items())[:4096]:
                    try:
                        if name in (__name__, "__main__", "__mp_main__"):
                            continue
                        d = getattr(mod, "__dict__", None)
                        if not isinstance(d, dict):
                            continue
                        items = list(d.items())[:4096]
                        am = {}
                        for ak, av in items:
                            try:
                                am[ak] = id(av)
                            except Exception:
                                continue
                        _MOD_ATTRS_SNAPSHOT[name] = am
                    except Exception:
                        continue
            except Exception:
                pass
            global _METAPATH_SNAPSHOT, _PATHHOOKS_SNAPSHOT, _BUILTINS_SNAPSHOT
            try:
                _METAPATH_SNAPSHOT = tuple(id(f) for f in list(_sys.meta_path))
            except Exception:
                _METAPATH_SNAPSHOT = ()
            try:
                _PATHHOOKS_SNAPSHOT = tuple(id(f) for f in list(_sys.path_hooks))
            except Exception:
                _PATHHOOKS_SNAPSHOT = ()
            try:
                import builtins as _bi
                _BI_MOD = _bi
                snap = {}
                for k in list(dir(_bi)):
                    try:
                        v = getattr(_bi, k)
                        snap[k] = (id(v), _obj_fp(v), v)
                    except Exception:
                        continue
                _BUILTINS_SNAPSHOT = snap
            except Exception:
                _BUILTINS_SNAPSHOT = {}
            _install_tripwire()
            try:
                for _fn in ("is_patched", "check_all", "guarded", "restore"):
                    try:
                        ref = globals().get(_fn)
                        if ref is not None:
                            _ATTRS[(__name__, _fn)] = {"ref": ref, "fp": _obj_fp(ref)}
                    except Exception:
                        continue
            except Exception:
                pass
            _SEALED = True
            _SEAL_TIME = _time.time()
            return {"pins": len(_PINS), "attrs": len(_ATTRS),
                    "modules": len(_MOD_SNAPSHOT), "resealed": True,
                    "added_since_import": len(_added),
                    "added_sample": list(_added[:16])}
    except Exception:
        return {}


def reseal():
    """Bilincli re-baseline (YONETIM: kayitli operator sart).

    Kayitsiz cagri deny+trip uretir; saldirgan kirli state'i boylece
    mesrulastiramaz. Yeni baseline yalnizca operator elinden.
    """
    if not _check_admin():
        _deny_admin("reseal")
    global _SEALED
    try:
        with _LOCK:
            _SEALED = False
        return seal()
    except Exception:
        return {}


def _check_pinned_bindings():
    try:
        with _LOCK:
            items = list(_PINS.items())
        for key, pin_ in items:
            try:
                if verify_pin(key) is False:
                    return True
            except Exception:
                continue
        return False
    except Exception:
        return False


def _check_module_attrs():
    try:
        with _LOCK:
            items = list(_ATTRS.items())
        for (mod_name, attr), rec in items:
            try:
                mod = _sys.modules.get(mod_name)
                if mod is None:
                    return True
                try:
                    cur = getattr(mod, attr, None)
                except Exception:
                    return True
                if cur is not rec["ref"] and _obj_fp(cur) != rec["fp"]:
                    return True
            except Exception:
                return True
        return False
    except Exception:
        return False


def _check_code_objects():
    try:
        with _LOCK:
            items = list(_PINS.items())
        for _, pin_ in items:
            try:
                ref = pin_.get("ref")
                if ref is None:
                    continue
                # Normalize karsilastirma (ham co_code quicken-FP uretir)
                if _func_fp(ref) != pin_.get("fp"):
                    return True
            except Exception:
                continue
        return False
    except Exception:
        return False


def _check_import_hooks():
    try:
        if not _SEALED:
            return False
        try:
            cur = tuple(id(f) for f in list(_sys.meta_path))
        except Exception:
            return False
        if cur != _METAPATH_SNAPSHOT:
            return True
        try:
            cur2 = tuple(id(f) for f in list(_sys.path_hooks))
        except Exception:
            return False
        if cur2 != _PATHHOOKS_SNAPSHOT:
            return True
        return False
    except Exception:
        return False


def _check_builtins():
    global _BUILTIN_TAMPER_LATCH
    try:
        if not _SEALED:
            return False
        import builtins as _bi
        try:
            cur_keys = set(dir(_bi))
        except Exception:
            cur_keys = set()
        try:
            if cur_keys - set(_BUILTINS_SNAPSHOT.keys()):
                with _LOCK:
                    _BUILTIN_TAMPER_LATCH = True
                _journal("builtins.extra_seen")
        except Exception:
            pass
        if set(_BUILTINS_SNAPSHOT.keys()) != cur_keys:
            return True
        if _BUILTIN_TAMPER_LATCH:
            return True
        for k, rec in list(_BUILTINS_SNAPSHOT.items()):
            try:
                old_id, old_fp = rec[0], rec[1]
                cur = getattr(_bi, k, None)
                if cur is None or id(cur) != old_id:
                    if _obj_fp(cur) != old_fp:
                        return True
            except Exception:
                continue
        return False
    except Exception:
        return False


def _check_module_rebind():
    """P-7-STRONG: seal-sonrasi modul-attr rebinding (poll-tabanli).

    Modul attr atamasi bu runtime'da audit OLAYI YAYMAZ (canli dogrulandi:
    object.__setattr__ suskun) — audit-tripwire kor gorur. Cozum: seal'de
    alinan attr-id haritasiyla periyodik karsilastirma (silme/ekleme/
    degisim hepsi trip). Maliyet ~O(attr); watchdog araliginda kabul.
    """
    try:
        if not _SEALED:
            return False
        with _LOCK:
            snap = dict(_MOD_ATTRS_SNAPSHOT)
        for name, am in snap.items():
            try:
                mod = _sys.modules.get(name)
                if mod is None:
                    continue
                try:
                    d = getattr(mod, "__dict__", None)
                except Exception:
                    return True
                if not isinstance(d, dict):
                    continue
                try:
                    cur_keys = set(d.keys())
                except Exception:
                    return True
                if set(am.keys()) != cur_keys:
                    return True
                for ak, old_id in am.items():
                    try:
                        if id(d[ak]) != old_id:
                            return True
                    except Exception:
                        return True
            except Exception:
                continue
        return False
    except Exception:
        return False


def _check_sys_modules():
    try:
        if not _SEALED:
            return False
        for name, old_id in list(_MOD_SNAPSHOT.items()):
            try:
                cur = _sys.modules.get(name)
                if cur is None:
                    return True
                if id(cur) != old_id:
                    return True
            except Exception:
                continue
        # Seal-sonrasi gorulen moduller: trust-on-first-use + swap-tespiti.
        # Ilk goruste kimlik kaydedilir, sonraki degisim trip'ler.
        try:
            with _LOCK:
                late = dict(_LATE_MODULES)
        except Exception:
            late = {}
        try:
            cur_names = set(_sys.modules.keys())
        except Exception:
            return False
        for name in cur_names - set(_MOD_SNAPSHOT.keys()):
            try:
                mod = _sys.modules.get(name)
                if mod is None:
                    continue
                prev = late.get(name)
                if prev is None:
                    try:
                        with _LOCK:
                            _LATE_MODULES[name] = id(mod)
                    except Exception:
                        pass
                elif prev != id(mod):
                    return True
            except Exception:
                continue
        return False
    except Exception:
        return False


def _patcher_started(o):
    try:
        d = getattr(o, "__dict__", None)
        if not isinstance(d, dict):
            return False
        tname = type(o).__name__
        if tname in ("_patch", "_patch_object"):
            return "temp_original" in d
        if tname == "_patch_dict":
            orig = d.get("_original")
            return isinstance(orig, dict) and len(orig) > 0
        if tname == "_patch_multiple":
            for sub in d.get("additional_patchers", []) or []:
                try:
                    if _patcher_started(sub):
                        return True
                except Exception:
                    continue
            return False
        return False
    except Exception:
        return False


def _check_mock_active():
    try:
        if "unittest.mock" not in _sys.modules and "mock" not in _sys.modules:
            return False
        try:
            import gc as _gc
            objs = _gc.get_objects()
        except Exception:
            return False
        try:
            for o in objs:
                try:
                    if getattr(type(o), "__module__", "") not in ("unittest.mock", "mock.mock"):
                        continue
                    if _patcher_started(o):
                        return True
                except Exception:
                    continue
        except Exception:
            pass
        return False
    except Exception:
        return False


def _check_tripwire():
    try:
        return _TRIPWIRE_COUNT > 0
    except Exception:
        return False


def _check_hook_liveness():
    try:
        if not _SEALED:
            return False
        if _TRIPWIRE_HOOK is None:
            return True
        before = _CANARY_COUNT
        try:
            _sys.audit("anti_patch.canary")
        except Exception:
            return True
        return _CANARY_COUNT == before
    except Exception:
        return False


def _check_native_memory():
    try:
        for name in ("ctypes", "_ctypes", "cffi", "mmap"):
            try:
                if name in _sys.modules and name not in _NATIVE_BASELINE:
                    return True
            except Exception:
                continue
        return False
    except Exception:
        return False


def _raw_results():
    return {
        "pinned_bindings": _check_pinned_bindings(),
        "module_attrs": _check_module_attrs(),
        "code_objects": _check_code_objects(),
        "import_hooks": _check_import_hooks(),
        "builtins": _check_builtins(),
        "module_rebind": _check_module_rebind(),
        "sys_modules": _check_sys_modules(),
        "mock_active": _check_mock_active(),
        "tripwire": _check_tripwire(),
        "hook_liveness": _check_hook_liveness(),
        "native_memory": _check_native_memory(),
    }


def check_all():
    try:
        return dict(_raw_results())
    except Exception:
        return {}


def is_patched():
    """Karar: >=1 STRONG veya >=2 WEAK."""
    try:
        res = _raw_results()
        strong = 0
        weak = 0
        for k, v in res.items():
            if not v:
                continue
            if WEIGHTS.get(k, 0) >= STRONG_AT:
                strong += 1
            else:
                weak += 1
        if strong >= 1 or weak >= TRIP_NEED:
            return True
        return False
    except Exception:
        return True  # fail-closed: karar verilemediyse risk varsay


def restore():
    """Snapshot'tan otomatik geri al (auto-heal). Donen: restore sayisi.

    Kapsar: modul attr'lari + pinli __code__ (P-9: pinli kod geri yazilir)
    + meta-path budama + path_hooks budama + builtins (degisen geri
    yazilir, sonradan eklenen silinir). sys.modules silinmeleri/kayip
    moduller BILEREK restore edilmez (calisan import zincirini kirma
    riski) — last_restore_report() seffaflik verir.
    """
    global _RESTORING
    n = 0
    try:
        _RESTORING += 1
    except Exception:
        pass
    try:
        with _LOCK:
            attrs = list(_ATTRS.items())
        for (mod_name, attr), rec in attrs:
            try:
                mod = _sys.modules.get(mod_name)
                if mod is None:
                    continue
                cur = getattr(mod, attr, None)
                if cur is not rec["ref"]:
                    try:
                        setattr(mod, attr, rec["ref"])
                        n += 1
                    except Exception:
                        continue
            except Exception:
                continue
    except Exception:
        pass
    try:
        with _LOCK:
            pins = list(_PINS.items())
        for key, pin_ in pins:
            try:
                ref = pin_.get("ref")
                code_obj = pin_.get("code_obj")
                if ref is None or code_obj is None:
                    continue
                try:
                    cur_code = getattr(ref, "__code__", None)
                except Exception:
                    cur_code = None
                if cur_code is not code_obj:
                    try:
                        ref.__code__ = code_obj
                        n += 1
                        _journal("restore.code:" + str(key))
                    except Exception:
                        continue
            except Exception:
                continue
    except Exception:
        pass
    try:
        cur_meta = list(_sys.meta_path)
        with _LOCK:
            want_ids = set(_METAPATH_SNAPSHOT)
        if want_ids:
            kept = [f for f in cur_meta if id(f) in want_ids]
            if len(kept) != len(cur_meta):
                try:
                    _sys.meta_path[:] = kept
                    n += 1
                except Exception:
                    pass
    except Exception:
        pass
    try:
        cur_ph = list(_sys.path_hooks)
        with _LOCK:
            want_ph = set(_PATHHOOKS_SNAPSHOT)
        if want_ph:
            kept = [f for f in cur_ph if id(f) in want_ph]
            if len(kept) != len(cur_ph):
                try:
                    _sys.path_hooks[:] = kept
                    n += 1
                    _journal("restore.path_hooks")
                except Exception:
                    pass
    except Exception:
        pass
    try:
        import builtins as _bi
        with _LOCK:
            snap = dict(_BUILTINS_SNAPSHOT)
        if snap:
            try:
                cur_keys = set(dir(_bi))
            except Exception:
                cur_keys = set()
            for k in list(cur_keys - set(snap.keys())):
                try:
                    delattr(_bi, k)
                    n += 1
                except Exception:
                    continue
            for k, rec in list(snap.items()):
                try:
                    old_id, old_fp = rec[0], rec[1]
                    ref = rec[2] if len(rec) > 2 else None
                    if ref is None:
                        continue
                    cur = getattr(_bi, k, None)
                    if cur is None or (id(cur) != old_id and _obj_fp(cur) != old_fp):
                        try:
                            setattr(_bi, k, ref)
                            n += 1
                        except Exception:
                            continue
                except Exception:
                    continue
    except Exception:
        pass
    try:
        # Heal tamamlandi: latch + tripwire sayaci temizlenir (olaylar
        # journal'da saklidir — kant delil, durum degil). Temizlenmezse
        # heal hicbir verdict'i dusuremez (P-3/P-9 heal-anlami).
        with _LOCK:
            global _BUILTIN_TAMPER_LATCH, _TRIPWIRE_COUNT
            _BUILTIN_TAMPER_LATCH = False
            _TRIPWIRE_COUNT = 0
    except Exception:
        pass
    try:
        global _LAST_RESTORE
        with _LOCK:
            unmod = [n_ for n_ in list(_MOD_SNAPSHOT.keys()) if _sys.modules.get(n_) is None]
            try:
                cur_ph = [id(f) for f in list(_sys.path_hooks)]
                ph_dirty = cur_ph != list(_PATHHOOKS_SNAPSHOT)
            except Exception:
                ph_dirty = True
            _LAST_RESTORE = {"restored": n, "unhealed_sys_modules": unmod[:32],
                             "path_hooks_dirty": bool(ph_dirty)}
    except Exception:
        pass
    try:
        _RESTORING -= 1
    except Exception:
        pass
    return n


def last_restore_report():
    """Son restore'un iyilesmeyen kalemleri (P-9 seffafligi)."""
    try:
        with _LOCK:
            return dict(_LAST_RESTORE)
    except Exception:
        return {}


def break_patch():
    """Test kancasi: tum risk sinyallerini uret (kalici degisiklik YOK).

    YONETIM: kayitli operator sart (uretim surecinde detection oracle
    olarak kullanilamaz).
    """
    if not _check_admin():
        _deny_admin("break_patch")
    out = {}
    try:
        out["before"] = check_all()
        out["is_patched_before"] = is_patched()
        global _TRIPWIRE_COUNT
        _TRIPWIRE_COUNT += 1
        out["after"] = check_all()
        _TRIPWIRE_COUNT -= 1
        tmp = dict(out["after"])
        tmp["tripwire"] = True
        strong = sum(1 for k, v in tmp.items() if v and WEIGHTS.get(k, 0) >= STRONG_AT)
        out["verdict_sim"] = strong >= 1
    except Exception:
        pass
    return out


def harden():
    try:
        seal()
        restore()
        return check_all()
    except Exception:
        return {}


def guard():
    try:
        return check_all()
    except Exception:
        return {}


def _watch_loop(stop, interval, heal):
    try:
        while not stop.is_set():
            try:
                if is_patched():
                    if heal:
                        try:
                            restore()
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
    global _WATCHDOG_STOP, _WATCHDOG_THREAD
    try:
        if _WATCHDOG_THREAD is not None and _WATCHDOG_THREAD.is_alive():
            return False
        try:
            interval = float(interval)
        except Exception:
            interval = 2.0
        if not (0.2 <= interval <= 60.0):
            interval = 2.0
        stop = _threading.Event()
        t = _threading.Thread(target=_watch_loop, args=(stop, interval, bool(heal)),
                              name="anti-patch-watch", daemon=True)
        _WATCHDOG_STOP = stop
        _WATCHDOG_THREAD = t
        t.start()
        return True
    except Exception:
        return False


def _stop():
    global _WATCHDOG_STOP, _WATCHDOG_THREAD
    try:
        if _WATCHDOG_STOP is not None:
            try:
                _WATCHDOG_STOP.set()
            except Exception:
                pass
        if _WATCHDOG_THREAD is not None:
            try:
                _WATCHDOG_THREAD.join(timeout=3.0)
            except Exception:
                pass
        _WATCHDOG_STOP = None
        _WATCHDOG_THREAD = None
        return True
    except Exception:
        return False


def stop_all_watchdogs():
    """Tum watchdog'lari durdur (YONETIM: kayitli operator sart)."""
    if not _check_admin():
        _deny_admin("stop_all_watchdogs")
    try:
        _stop()
        return 1
    except Exception:
        return 0


def status():
    try:
        with _LOCK:
            pins = len(_PINS)
            attrs = len(_ATTRS)
        return {"sealed": _SEALED, "seal_time": _SEAL_TIME, "pins": pins,
                "attrs": attrs, "tripwire": _TRIPWIRE_COUNT,
                "watchdog": _WATCHDOG_THREAD is not None and _WATCHDOG_THREAD.is_alive(),
                "is_patched": is_patched(), "checks": check_all(),
                "admin_authorized": len(_ADMIN_MODULES), "admin_locked": _ADMIN_LOCKED,
                "admin_denied": _ADMIN_DENIED, "builtin_latch": _BUILTIN_TAMPER_LATCH,
                "last_restore": last_restore_report(),
                "journal": list(_JOURNAL[-32:])}
    except Exception:
        return {}
