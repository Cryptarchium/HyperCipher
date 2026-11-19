"""anti_import_analysis: import-sistemi butunluk katmani.

Tehdit modeli (runtime import saldirilari):
  - sys.meta_path başına/ortasına eklenen yabancı finder (in-memory
    importer, Pyramid/losange deseni, beartype-claw tipi enstrumantasyon
    kisvesi) -> standart PathFinder aramasi hic gormeden modulu kapar.
  - sys.modules zehirlenmesi: hayalet kayit (bilinmeyen loader'li),
    stdlib golgeleme (cwd'ye birakilan os.py/requests.py).
  - sys.path kafa karisikligi: '' / cwd girdisi (CWD hijack; pymanager
    GHSA-jr5x-hgm4-rrm6 deseni), sys.path_hooks'a yabanci kanca.
  - Baslangic vektorleri: `import ...` satirli .pth (LiteLLM 1.82.8 /
    MITRE T1546.018 deseni), sitecustomize/usercustomize enjeksiyonu.

Kapsam (kardeslerle cakisma yok):
  - anti_hook.import_system genel kanca sagligini tutar; BU modul
    import'e ozel derin analizi yapar (finder sirasi, loader kimligi,
    origin dogrulama, .pth taramasi). Ailedeki `_TRUSTED_*` kumelerinin
    MERKEZI de burasidir.
  - anti_patch sys.modules snapshot/restore yapar; bu modul TESPIT
    + skor uretir, restore'a dokunmaz.

Sinirlar (bilincli tercihler):
  - Modul importtan ONCE yerlesen saldirgan gorunmez (bootstrap korlugu;
    R1 metapathology ile ayni sinir). Tespit, modul yuklendikten
    sonraki DEGISIM + mevcut anomali uzerinedir.
  - sys.addaudithook kancalari Python'dan LISTELENEMEZ (getter yok);
    audit-hook korlugu belge + watchdog ile karsilanir, iddia edilmez.
    (PEP 578: audit-hook sandbox DEGILDIR, deny-list'tir; bu modul
    ONLEME degil TESPIT uretir.)
  - Tek WEAK trip uretmez; trip >=1 STRONG veya >=2 WEAK.
  - pytest/一部 editable-install kisveleri trusted-prefixtir; tek WEAK
    dustugu icin saldirganin bunu istismari diger sinyalleri sondurmez.

Sessiz, stdlib-only, fail-closed. True=risk, False=temiz.
"""

import os as _os
import sys as _sys
import site as _site
import threading as _threading

try:
    import sysconfig as _sysconfig
except Exception:
    _sysconfig = None


class ImportAnalysisDetected(RuntimeError):
    pass


def _raise():
    raise ImportAnalysisDetected("protected")


_LOCK = _threading.RLock()

# --- pin: kritik referanslar -----------------------------------------------
_SYS = _sys
_OS_GETCWD = _os.getcwd
_OS_PATH_ABSPATH = _os.path.abspath
_OS_PATH_NORMCASE = _os.path.normcase
_OS_PATH_ISFILE = _os.path.isfile
_OS_LISTDIR = _os.listdir
_SITE_GETSITE = _site.getsitepackages if hasattr(_site, "getsitepackages") else None
_SITE_GETUSER = _site.getusersitepackages if hasattr(_site, "getusersitepackages") else None

# I1: gercek loader siniflari (isinstance-birincil guven; string taklidi gecemez).
# Docs-parite: isinstance(x.__loader__, NamespaceLoader) resmi introspection desenidir.
_PIN_LOADER_CLASSES = ()
_PIN_FILE_FINDER_CLS = None
_PIN_PATH_FINDER_CLS = None
try:
    import importlib.machinery as _mach
    _lc = []
    for _ln in ("BuiltinImporter", "FrozenImporter", "ExtensionFileLoader",
                "SourceFileLoader", "SourcelessFileLoader", "NamespaceLoader",
                "WindowsRegistryFinder", "AppleFrameworkLoader"):
        try:
            _lc.append(getattr(_mach, _ln))
        except Exception:
            continue
    _PIN_LOADER_CLASSES = tuple(_lc)
    try:
        _PIN_FILE_FINDER_CLS = _mach.FileFinder
    except Exception:
        _PIN_FILE_FINDER_CLS = None
    try:
        _PIN_PATH_FINDER_CLS = _mach.PathFinder
    except Exception:
        _PIN_PATH_FINDER_CLS = None
except Exception:
    _PIN_LOADER_CLASSES = ()
_PIN_ZIPIMPORTER_CLS = None
try:
    import zipimport as _zi
    _PIN_ZIPIMPORTER_CLS = _zi.zipimporter
except Exception:
    _PIN_ZIPIMPORTER_CLS = None

# --- guvenilir kumeler (AILE MERKEZI) ---------------------------------------
_TRUSTED_FINDERS = frozenset({
    "_distutils_hack.distutilsmetafinder",
    "_pynvml_redirector.pynvmlfinder",
})
_TRUSTED_PREFIXES = ("_frozen_importlib", "importlib", "_bootstrap",
                     "zipimport", "site", "_sitebuiltins")
# Bilinen iyi huylu on-kesici kisveler (editable-install + test calistirici).
# TEK WEAK dusurur; tek basina trip uretmez, diger sinyaller bagimsiz calisir.
_TRUSTED_INTERCEPTOR_PREFIXES = ("__editable__", "_pytest", "pytest")
_TRUSTED_LOADER_MODULES = frozenset({
    "_frozen_importlib", "_frozen_importlib_external", "importlib._bootstrap",
    "importlib._bootstrap_external", "zipimport",
})
_CANONICAL_LOADERS = frozenset({
    "BuiltinImporter", "FrozenImporter", "PathFinder", "FileFinder",
    "SourceFileLoader", "SourcelessFileLoader", "ExtensionFileLoader",
    "NamespaceLoader", "NamespacePath", "zipimporter",
    "WindowsRegistryFinder", "AppleFrameworkLoader",
})
_TRUSTED_PTH_BASENAMES = frozenset({
    "distutils-precedence.pth",
})

# Kanonik meta_path sirasi (CPython: _install + PathFinder).
_CANONICAL_META_FIRST = ("BuiltinImporter", "FrozenImporter", "PathFinder")

WEIGHTS = {
    "meta_path_empty": 100,
    "canonical_order_broken": 100,
    "modules_ghost": 100,
    "stdlib_shadow": 100,
    "foreign_path_hook": 30,
    "unknown_meta_finder": 30,
    "cwd_in_path": 30,
    "startup_vector": 30,
    "pinned_mismatch": 100,
    "sensor_health": 100,
}
STRONG = frozenset({"meta_path_empty", "canonical_order_broken",
                    "modules_ghost", "stdlib_shadow", "pinned_mismatch",
                    "sensor_health"})
_THRESHOLD_TRIP = 100

# import-ani baseline _finder_id tanimindan SONRA alinir (F6 notu).
# (Tanimlar asagida; snapshot _PINNED bolumunde yapilir.)


def _name_cls(f):
    try:
        return getattr(f, "__name__", None) or type(f).__name__
    except Exception:
        return "?"


def _finder_id(f):
    try:
        mod = getattr(type(f), "__module__", "") or ""
        # F1: kucuk-harf normalizasyon (kardes kumeler lowercase tutar:
        # "_distutils_hack.distutilsmetafinder").
        return ("%s.%s" % (mod, _name_cls(f))).lower()
    except Exception:
        return "?"


def _is_trusted_finder(f):
    try:
        fid = _finder_id(f)
        if fid in _TRUSTED_FINDERS:
            return True
        mod = getattr(type(f), "__module__", "") or ""
        for p in _TRUSTED_PREFIXES + _TRUSTED_INTERCEPTOR_PREFIXES:
            if mod == p or mod.startswith(p + "."):
                return True
        return False
    except Exception:
        return False


def _stdlib_dir():
    try:
        if _sysconfig is not None:
            p = _sysconfig.get_path("stdlib")
            if p:
                return _OS_PATH_NORMCASE(_OS_PATH_ABSPATH(p))
    except Exception:
        pass
    try:
        base = _OS_PATH_NORMCASE(_OS_PATH_ABSPATH(_os.__file__))
        return _os.path.dirname(base)
    except Exception:
        return ""


def _stdlib_names():
    try:
        names = getattr(_SYS, "stdlib_module_names", None)
        if names:
            return frozenset(names)
    except Exception:
        pass
    try:
        return frozenset(getattr(_SYS, "builtin_module_names", ()))
    except Exception:
        return frozenset()


def _cwd():
    try:
        return _OS_PATH_NORMCASE(_OS_PATH_ABSPATH(_OS_GETCWD()))
    except Exception:
        return ""


def _site_dirs():
    out = []
    try:
        if _SITE_GETSITE is not None:
            v = _SITE_GETSITE()
            if isinstance(v, str):
                out.append(v)
            else:
                out.extend(list(v or ()))
    except Exception:
        pass
    try:
        if _SITE_GETUSER is not None:
            v = _SITE_GETUSER()
            if v:
                out.append(v)
    except Exception:
        pass
    norm = []
    for d in out:
        try:
            norm.append(_OS_PATH_NORMCASE(_OS_PATH_ABSPATH(d)))
        except Exception:
            pass
    return norm


# --- sinyaller ----------------------------------------------------------------

def _check_meta_path_empty():
    try:
        return len(list(_SYS.meta_path)) == 0
    except Exception:
        return True


def _check_canonical_order_broken():
    """BuiltinImporter+FrozenImporter+PathFinder sirasi/butunlugu."""
    try:
        names = [_name_cls(f) for f in list(_SYS.meta_path)]
        if "PathFinder" not in names:
            return True
        if "BuiltinImporter" not in names or "FrozenImporter" not in names:
            return True
        # Sira: Builtin < Frozen < PathFinder olmali
        bi = names.index("BuiltinImporter")
        fi = names.index("FrozenImporter")
        pf = names.index("PathFinder")
        if not (bi < fi < pf):
            return True
        return False
    except Exception:
        return True


def _check_unknown_meta_finder():
    """PathFinder ONCESINDE guvenilmeyen kesici (WEAK)."""
    try:
        finders = list(_SYS.meta_path)
        names = [_name_cls(f) for f in finders]
        try:
            pf = names.index("PathFinder")
        except ValueError:
            pf = len(finders)
        for f in finders[:pf]:
            n = _name_cls(f)
            if n in _CANONICAL_META_FIRST:
                continue
            if not _is_trusted_finder(f):
                return True
        return False
    except Exception:
        return False


def _loader_trusted(loader):
    """I1: isinstance-birincil loader guveni (fail-closed: suphede False).

    Research (importlib docs + CPython importlib/_bootstrap):
    FakeLoader.__module__/__name__ string'leri taklit edilebilir ama
    baseline'da pinlenmis GERCEK loader siniflarina isinstance kontrolu
    sahte sinifla gecilemez. Birincil test isinstance'tir; string kume
    yedekleri KALDIRILDI (spoof yuzeyi). Namespace paketi (loader None)
    cagiran tarafindan ele alinir.
    """
    try:
        if loader is None:
            return False
        if isinstance(loader, type):
            if _PIN_LOADER_CLASSES and issubclass(loader, _PIN_LOADER_CLASSES):
                return True
            return False
        if _PIN_LOADER_CLASSES:
            try:
                if isinstance(loader, _PIN_LOADER_CLASSES):
                    return True
            except Exception:
                return False
            return False
        return False
    except Exception:
        return False


def _check_modules_ghost():
    """sys.modules'ta loader'i bilinmeyen calisir kayit (STRONG)."""
    try:
        builtin = frozenset(getattr(_SYS, "builtin_module_names", ()))
        stdtop = _stdlib_names() | builtin
        for name, mod in _modules_snapshot():
            try:
                if mod is None:
                    continue
                if not isinstance(name, str) or not name:
                    continue
                if name in ("__main__", "__mp_main__"):
                    continue
                if name in builtin:
                    continue
                spec = getattr(mod, "__spec__", None)
                loader = getattr(mod, "__loader__", None)
                if spec is not None:
                    # namespace paketi: loader None + konum listesi = mesru
                    smsl = getattr(spec, "submodule_search_locations", None)
                    if loader is None and smsl is not None:
                        continue
                    lad = getattr(spec, "loader", None)
                    if lad is not None:
                        loader = lad
                if loader is None:
                    if spec is None:
                        try:
                            top = name.split(".", 1)[0]
                        except Exception:
                            top = name
                        if top in builtin:
                            continue
                        if top in stdtop and _is_runtime_artifact(name, mod):
                            continue
                        return True
                    continue
                if not _loader_trusted(loader):
                    if _independent_matches_live(name, mod):
                        continue
                    return True
            except Exception:
                continue
        return False
    except Exception:
        return False


def _is_runtime_artifact(name, mod):
    """I2: spec/loader-yoklugunun mesru runtime-artifakti mi (typing.io gibi)?

    Saldirgan sahtesi ModuleType uretir (types.ModuleType) — ModuleType
    ise ASLA artifact sayilmaz. Non-module girdiler (deprecated alias
    nesneleri) icin bagimsiz disk-cozumu gercek modulu buluyorsa canli
    girdi golgeleme degil runtime-artifaktidir. Aksi halde suphe.
    """
    try:
        try:
            import types as _t
            if isinstance(mod, _t.ModuleType):
                return False
        except Exception:
            return False
        try:
            top = name.split(".", 1)[0]
        except Exception:
            top = name
        if _PIN_PATH_FINDER_CLS is None:
            return False
        try:
            spec = _PIN_PATH_FINDER_CLS.find_spec(top)
        except Exception:
            return False
        return spec is not None
    except Exception:
        return False


def _independent_matches_live(name, mod):
    """I2-FP-relief: guvenilmeyen loader'a ragmen bagimsiz cozum CANLI ile
    ayni origin'i gosteriyorsa mesru (ozel-yukleyici toleransi).

    Kosullar (HEPSI): bagimsiz spec var + loader'i isinstance-guvenilir +
    origin'ler birebir esit. Originsiz canli kayit ASLA eslesemez (sahte).
    """
    try:
        if _PIN_PATH_FINDER_CLS is None:
            return False
        try:
            top = name.split(".", 1)[0]
        except Exception:
            top = name
        try:
            spec = _PIN_PATH_FINDER_CLS.find_spec(top)
        except Exception:
            return False
        if spec is None:
            return False
        if not _loader_trusted(getattr(spec, "loader", None)):
            return False
        try:
            indep = getattr(spec, "origin", None)
        except Exception:
            return False
        if not indep or indep in ("built-in", "frozen", "namespace"):
            return False
        try:
            live = getattr(mod, "__file__", None)
            if not live:
                live = getattr(getattr(mod, "__spec__", None), "origin", None)
            if not live:
                return False
            return (_OS_PATH_NORMCASE(_OS_PATH_ABSPATH(str(live)))
                    == _OS_PATH_NORMCASE(_OS_PATH_ABSPATH(str(indep))))
        except Exception:
            return False
    except Exception:
        return False


def _trusted_origin_roots():
    roots = []
    try:
        sd = _stdlib_dir()
        if sd:
            roots.append(sd)
    except Exception:
        pass
    for attr in ("base_prefix", "base_exec_prefix", "prefix", "exec_prefix"):
        try:
            v = getattr(_SYS, attr, "")
            if v:
                roots.append(_OS_PATH_NORMCASE(_OS_PATH_ABSPATH(str(v))))
        except Exception:
            pass
    try:
        roots.extend(_site_dirs())
    except Exception:
        pass
    return roots


def _check_stdlib_shadow():
    """Guvenilir-kok DISINDAN yuklenen stdlib-adi tasiyan modul (STRONG)."""
    try:
        builtin = frozenset(getattr(_SYS, "builtin_module_names", ()))
        stdlib = _stdlib_names()
        if not stdlib:
            return False
        sdir = _stdlib_dir()
        roots = _trusted_origin_roots()
        cwd = _cwd()
        if not cwd:
            return False
        for name, mod in _modules_snapshot():
            try:
                if mod is None or not isinstance(name, str):
                    continue
                top = name.split(".", 1)[0]
                if top not in stdlib:
                    continue
                if top in ("__main__",):
                    continue
                if top in builtin:
                    continue  # gercek builtin: origin yoklugu mesru
                f = getattr(mod, "__file__", None)
                if not f:
                    try:
                        origin = getattr(getattr(mod, "__spec__", None), "origin", None)
                    except Exception:
                        origin = None
                    if not origin:
                        if _is_runtime_artifact(name, mod):
                            continue  # typing.io gibi non-module artifact
                        return True  # I2: builtin OLMAYAN stdlib-adli kayit originsiz = sahte
                    if origin in ("built-in", "frozen"):
                        continue  # donmus/gomulu stdlib: dosya-origin yoklugu mesru
                    f = origin
                try:
                    origin = _OS_PATH_NORMCASE(_OS_PATH_ABSPATH(str(f)))
                except Exception:
                    continue
                if sdir and origin.startswith(sdir + _os.sep):
                    continue
                try:
                    if any(origin.startswith(r + _os.sep) for r in roots):
                        continue
                except Exception:
                    pass
                return True
            except Exception:
                continue
        return False
    except Exception:
        return False


def _hook_cell_ok(v, allowed):
    """Kapanmis-hucre icerigi pinli importlib yuzeyi mi (ozyinelemeli)?

    FileFinder kapamasi loader_details listesini de kapatir: (loader, suffix)
    demetleri + sonek string'leri mesrudur; yabanci nesne/kod degil.
    """
    try:
        if v in allowed:
            return True
    except Exception:
        pass
    try:
        if isinstance(v, str):
            return True
        if isinstance(v, (list, tuple)):
            return all(_hook_cell_ok(x, allowed) for x in v)
    except Exception:
        return False
    return False


def _is_filefinder_equivalent(h):
    """I3: path_hook kapamasinin FileFinder-esdegeri mi (sekil + davranis)?

    Kanonik kanca FileFinder sinifina kapanmis bir fonksiyondur; spoof
    __module__ string'i degil, kapanmis-hucre + kotu-yol sondasi test edilir:
    hucreler yalnizca pinli importlib siniflari OLMALI ve varolmayan yola
    ImportError atmalidir (FileFinder davranisi). Ikisini de taklit eden
    kanca islevsel olarak FileFinder'dir (guvenlik siniri: davranis-esdeger).
    """
    try:
        if not callable(h):
            return False
        try:
            closure = getattr(h, "__closure__", None)
        except Exception:
            return False
        if not closure:
            return False
        try:
            allowed = set(_PIN_LOADER_CLASSES) | {_PIN_FILE_FINDER_CLS, _PIN_PATH_FINDER_CLS}
            allowed.discard(None)
        except Exception:
            return False
        for cell in closure:
            try:
                if not _hook_cell_ok(cell.cell_contents, allowed):
                    return False
            except Exception:
                return False
        try:
            h("/nonexistent-antihook-probe-xyz-123")
        except ImportError:
            return True
        except Exception:
            return False
        return False
    except Exception:
        return False


def _check_foreign_path_hook():
    """I3: path_hook guveni isinstance-birincil (spoof __module__ gecersiz).

    Kanonik kanca FileFinder.path_hook kapamasidir: ya FileFinder sinif
    ozniteliginin kendisi, ya da GERCEK FileFinder ornegine bagli metod.
    String __module__/__qualname__ eslesmeleri KALDIRILDI.
    """
    try:
        hooks = list(getattr(_SYS, "path_hooks", None) or [])
        if not hooks:
            return True  # bos path_hooks: import alt-sistemi olu
        for h in hooks:
            try:
                if _PIN_FILE_FINDER_CLS is not None:
                    try:
                        if h == getattr(_PIN_FILE_FINDER_CLS, "path_hook", None):
                            continue
                    except Exception:
                        pass
                    try:
                        bound = getattr(h, "__self__", None)
                        if bound is not None and (
                                bound is _PIN_FILE_FINDER_CLS
                                or (isinstance(bound, type)
                                    and issubclass(bound, _PIN_FILE_FINDER_CLS))):
                            continue
                    except Exception:
                        pass
                    if _PIN_ZIPIMPORTER_CLS is not None:
                        try:
                            if h is _PIN_ZIPIMPORTER_CLS or (
                                    isinstance(h, type)
                                    and issubclass(h, _PIN_ZIPIMPORTER_CLS)):
                                continue
                        except Exception:
                            pass
                    try:
                        if _is_filefinder_equivalent(h):
                            continue
                    except Exception:
                        pass
                    return True
                mod = getattr(h, "__module__", "") or ""
                qn = getattr(h, "__qualname__", "") or getattr(h, "__name__", "") or "?"
                if "FileFinder" in str(qn) or "path_hook" in str(qn):
                    continue
                trusted = False
                for p in _TRUSTED_PREFIXES + _TRUSTED_INTERCEPTOR_PREFIXES:
                    if mod == p or mod.startswith(p + "."):
                        trusted = True
                        break
                if not trusted:
                    return True
            except Exception:
                continue
        return False
    except Exception:
        return False


def _check_cwd_in_path():
    try:
        cwd = _cwd()
        if not cwd:
            return False
        for entry in list(getattr(_SYS, "path", None) or []):
            try:
                if not isinstance(entry, str):
                    continue
                if entry == "":
                    return True
                if _OS_PATH_NORMCASE(_OS_PATH_ABSPATH(entry)) == cwd:
                    return True
            except Exception:
                continue
        return False
    except Exception:
        return False


_PTH_HIGH_TOKENS = (
    "b64decode", "a85decode", "unhexlify", "fromhex", "rot13", "rot_13",
    "decompress", "deobfuscate", "os.system", "subprocess",
    "popen", "socket", "urlopen", "urlretrieve", "ctypes", "cdll", "windll",
    "loadlibrary", ".ssh/", ".ssh\\", ".aws/", ".aws\\", "wallet.dat",
    "passwd", "shadow", "id_rsa",
)
_PTH_IMPORT_TARGETS_OK = ("importlib", "_distutils_hack")
_PTH_DECODE_HINTS = ("decode", "decrypt", "bytes(", "bytearray", "hex(",
                     "b64", "translate", "unhexlify")

_PTH_BENIGN_MARKERS = (
    "coverage_process_start",
    "setuptools_use_distutils",
    "_distutils_hack",
    "pkg_resources",
    "pywin32_bootstrap",
    "_pynvml_redirector",
    "sys.modules.setdefault",
)

_PTH_DANGER_OVERRIDE = (
    "os.system", "subprocess", "socket", "urllib", "ctypes",
    "marshal", "pickle", "b64decode", "fromhex",
)


def _pth_benign_boilerplate(text):
    try:
        low = text.lower()
    except Exception:
        return False
    try:
        if ("coverage_process_start" in low and "getenv" in low
                and not any(d in low for d in ("os.system", "subprocess",
                                               "socket", "urllib", "ctypes",
                                               "marshal"))):
            return True
        if not any(m in low for m in _PTH_BENIGN_MARKERS):
            return False
        return not any(d in low for d in _PTH_DANGER_OVERRIDE)
    except Exception:
        return False


def _pth_text_risky(text):
    try:
        low = text.lower()
        # I5a: .pth'de import SATIRI = kod-calistirma (pydepgate modeli: mesru
        # .pth yalnizca path girdisidir; allowlist disinda import satiri supheli).
        try:
            import io as _io
            for raw_line in _io.StringIO(text):
                try:
                    s = raw_line.strip()
                except Exception:
                    continue
                if s.startswith("import ") or s.startswith("import\t") or s == "import":
                    return True
        except Exception:
            if "import " in low:
                return True
        for tok in _PTH_HIGH_TOKENS:
            if tok in low:
                return True
        try:
            import re as _re
            for tgt in _re.findall(r"__import__\(\s*['\"]([^'\"]+)", low):
                t = (tgt or "").strip()
                if not any(t == ok or t.startswith(ok + ".") for ok in _PTH_IMPORT_TARGETS_OK):
                    return True
            # I5b: __import__(<literal-olmayan>) = bolunmus/gizli hedef
            if _re.search(r"__import__\(\s*(?![\'\"])", low):
                return True
            # I5c: string-birlestirme gizleme ('ev'+'al', chr(), join)
            if ("__import__" in low or "exec(" in low or "eval(" in low):
                if ("+" in low and ("'" in low or '"' in low)) or "chr(" in low or ".join(" in low:
                    return True
        except Exception:
            if "__import__" in low:
                return True
        has_exec = ("exec(" in low) or ("eval(" in low) or ("compile(" in low)
        if has_exec and any(h in low for h in _PTH_DECODE_HINTS):
            return True
        # I5d: yuksek-entropili uzun literal (gizli blob)
        try:
            import re as _re2
            for lit in _re2.findall(r"['\"]([A-Za-z0-9+/=]{128,})['\"]", text):
                try:
                    if len(set(lit)) >= 32:
                        return True
                except Exception:
                    continue
        except Exception:
            pass
        return False
    except Exception:
        return False


def _check_startup_vector():
    """Yuksek-riskli calistirilabilir .pth / customize enjeksiyonu (WEAK)."""
    try:
        for d in _site_dirs():
            try:
                names = _OS_LISTDIR(d)
            except Exception:
                continue
            for n in names:
                try:
                    if not n.lower().endswith(".pth"):
                        continue
                    if n in _TRUSTED_PTH_BASENAMES:
                        continue
                    p = _os.path.join(d, n)
                    if not _OS_PATH_ISFILE(p):
                        continue
                    text = _read_pth_text(p)
                    if text is None:
                        return True  # I5e: asiri-buyuk/okunamaz .pth = fail-closed
                    if text and _pth_text_risky(text) and not _pth_benign_boilerplate(text):
                        return True
                except Exception:
                    continue
        # sitecustomize / usercustomize: stdlib-disi origin = supheli
        try:
            import importlib.util as _ilu
            sdir = _stdlib_dir()
            for cand in ("sitecustomize", "usercustomize"):
                try:
                    spec = _ilu.find_spec(cand)
                except Exception:
                    spec = None
                if spec is None:
                    continue
                origin = getattr(spec, "origin", None)
                if not origin or origin in ("built-in", "frozen", "namespace"):
                    continue
                try:
                    o = _OS_PATH_NORMCASE(_OS_PATH_ABSPATH(str(origin)))
                except Exception:
                    continue
                if sdir and o.startswith(sdir + _os.sep):
                    continue
                return True
        except Exception:
            pass
        return False
    except Exception:
        return False


_PINNED = {}

_BASE_META = ()


def _snapshot_pins():
    try:
        with _LOCK:
            _PINNED["meta_names"] = tuple(_name_cls(f) for f in list(_SYS.meta_path))
            _PINNED["hooks_n"] = len(list(getattr(_SYS, "path_hooks", None) or []))
            _PINNED["audit"] = bool(getattr(_SYS, "addaudithook", None))
            global _BASE_META
            _BASE_META = tuple(_finder_id(f) for f in list(_SYS.meta_path))
    except Exception:
        pass


_SNAP_ERR = {"failed": False}


def _modules_snapshot():
    try:
        try:
            items = _SYS.modules.copy().items()
        except Exception:
            items = list(_SYS.modules.items())
        return list(items)
    except Exception:
        try:
            _SNAP_ERR["failed"] = True
        except Exception:
            pass
        return []


def _read_pth_text(path):
    """I5e: tam-dosya okuma (4MB cap; asim/okunamaz = fail-closed supheli)."""
    try:
        try:
            sz = _os.path.getsize(path)
            if sz > 4 * 1024 * 1024:
                return None
        except Exception:
            pass
        with open(path, "rb") as fh:
            raw = fh.read(4 * 1024 * 1024 + 1)
    except Exception:
        return ""
    if len(raw) > 4 * 1024 * 1024:
        return None
    try:
        return raw.decode("utf-8-sig")
    except Exception:
        pass
    try:
        import locale as _loc
        return raw.decode(_loc.getpreferredencoding(False) or "utf-8", "ignore")
    except Exception:
        pass
    try:
        return raw.decode("latin-1")
    except Exception:
        return ""


def _check_pinned_mismatch():
    try:
        with _LOCK:
            old = dict(_PINNED)
        if not old:
            _snapshot_pins()
            return False
        try:
            cur = tuple(_name_cls(f) for f in list(_SYS.meta_path))
            if cur != old.get("meta_names"):
                return True
            if len(list(getattr(_SYS, "path_hooks", None) or [])) != old.get("hooks_n"):
                return True
        except Exception:
            return True
        return False
    except Exception:
        return False


def _check_sensor_health():
    """Kritik introspection yuzeyi calisir mi (korluk degil olum)."""
    try:
        _ = list(_SYS.meta_path)
        _ = list(getattr(_SYS, "path_hooks", None) or [])
        _ = list(getattr(_SYS, "modules", {}).items())
        _ = list(getattr(_SYS, "path", None) or [])
        try:
            if _SNAP_ERR.get("failed"):
                return True
        except Exception:
            pass
        return False
    except Exception:
        return True


_CHECKS = (
    ("meta_path_empty", _check_meta_path_empty),
    ("canonical_order_broken", _check_canonical_order_broken),
    ("modules_ghost", _check_modules_ghost),
    ("stdlib_shadow", _check_stdlib_shadow),
    ("foreign_path_hook", _check_foreign_path_hook),
    ("unknown_meta_finder", _check_unknown_meta_finder),
    ("cwd_in_path", _check_cwd_in_path),
    ("startup_vector", _check_startup_vector),
    ("pinned_mismatch", _check_pinned_mismatch),
    ("sensor_health", _check_sensor_health),
)
_LIGHT = frozenset({"meta_path_empty", "canonical_order_broken",
                    "modules_ghost", "stdlib_shadow", "pinned_mismatch",
                    "sensor_health"})

_WATCHDOG_STOP = None
_WATCHDOG_THREAD = None
_ADMIN_MODULES = {}
_ADMIN_LOCKED = False
_ADMIN_DENIED = 0


def authorize_admin():
    """Operator modulunu kaydet (SADECE kilit-oncesi; boot sirasinda cagrilir).

    Ilk start_watchdog() kaydi kilitler. Donus: True=kaydedildi.
    """
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
            if not _OS_PATH_ISFILE(fn):
                return False
        except Exception:
            return False
        with _LOCK:
            _ADMIN_MODULES[name] = fn
        return True
    except Exception:
        return False


def _check_admin():
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
            if (want is not None and fn == want and not fn.startswith("<")
                    and _OS_PATH_ISFILE(fn)):
                return True
        except Exception:
            pass
        return False
    except Exception:
        return False


def _deny_admin(op):
    """Yonetim reddi: fail-closed opak hata."""
    global _ADMIN_DENIED
    try:
        with _LOCK:
            _ADMIN_DENIED += 1
    except Exception:
        pass
    _raise()


def check_all(light_only=False):
    results = {}
    for name, fn in _CHECKS:
        if light_only and name not in _LIGHT:
            continue
        try:
            results[name] = bool(fn())
        except Exception:
            results[name] = True
    return results


def _score_from(results):
    score = 0
    strong_hit = False
    weak_hits = 0
    for k, v in results.items():
        if not v:
            continue
        w = WEIGHTS.get(k, 0)
        score += w
        if k in STRONG:
            strong_hit = True
        else:
            weak_hits += 1
    tripped = bool(strong_hit or weak_hits >= 2)
    return score, _THRESHOLD_TRIP, tripped


def score(light_only=False):
    return _score_from(check_all(light_only=light_only))


def is_compromised(light_only=False):
    try:
        _, _, tripped = _score_from(check_all(light_only=light_only))
        return bool(tripped)
    except Exception:
        return True


def assert_clean(light_only=False):
    if is_compromised(light_only=light_only):
        _raise()
    return True


def guard(func):
    """I6: giris + cikis dogrulamali guard (fail-closed iki uc)."""
    try:
        import functools as _ft

        @_ft.wraps(func)
        def _w(*a, **k):
            assert_clean()
            try:
                r = func(*a, **k)
            except ImportAnalysisDetected:
                raise
            except Exception as e:
                try:
                    if is_compromised():
                        raise ImportAnalysisDetected("protected") from e
                except ImportAnalysisDetected:
                    raise
                except Exception:
                    pass
                raise
            assert_clean()
            return r
        return _w
    except Exception:
        return func


def status(light_only=False):
    try:
        r = check_all(light_only=light_only)
        s, t, trip = _score_from(r)
        try:
            cur = [_finder_id(f) for f in list(_SYS.meta_path)]
            base = list(_BASE_META) if _BASE_META else []
            delta = [x for x in cur if x not in base]
        except Exception:
            delta = []
        return {"signals": r, "score": s, "threshold": t, "tripped": trip,
                "baseline_delta": delta}
    except Exception:
        return {"signals": {}, "score": -1, "threshold": _THRESHOLD_TRIP,
                "tripped": True, "baseline_delta": []}


def _watchdog_loop(stop_ev, interval):
    """I4: iki-katmanli gozetim — LIGHT her tick, FULL her 20 tick (~1sn).

    WEAK persistence (.pth/kanca/CWD) artik gorunur; FULL agir tarama
    her tick calismaz (performans), ama duzenli aralikla kacirilamaz.
    Trip/cokus = fail-closed return (thread biter, watchdog_liveness
    kardes katmanda trip uretir).
    """
    try:
        n = 0
        while not stop_ev.wait(interval):
            try:
                n += 1
                if n % 20 == 0:
                    if is_compromised(light_only=False):
                        return
                elif is_compromised(light_only=True):
                    return
            except Exception:
                return
    except Exception:
        pass


def start_watchdog(interval=0.05):
    global _WATCHDOG_STOP, _WATCHDOG_THREAD, _ADMIN_LOCKED
    try:
        with _LOCK:
            _ADMIN_LOCKED = True
            if _WATCHDOG_THREAD is not None and _WATCHDOG_THREAD.is_alive():
                return True
            stop_ev = _threading.Event()
            th = _threading.Thread(target=_watchdog_loop,
                                   args=(stop_ev, float(interval)),
                                   daemon=True)
            _WATCHDOG_STOP = stop_ev
            _WATCHDOG_THREAD = th
            th.start()
            return True
    except Exception:
        return False


def stop_all_watchdogs():
    global _WATCHDOG_STOP, _WATCHDOG_THREAD
    if not _check_admin():
        _deny_admin("stop_all_watchdogs")
    try:
        with _LOCK:
            ev, th = _WATCHDOG_STOP, _WATCHDOG_THREAD
            _WATCHDOG_STOP, _WATCHDOG_THREAD = None, None
        try:
            if ev is not None:
                ev.set()
        except Exception:
            pass
        try:
            if th is not None and th.is_alive():
                th.join(timeout=1.0)
        except Exception:
            pass
        return True
    except Exception:
        return False


try:
    _snapshot_pins()
except Exception:
    pass

try:
    _s = _SYS.modules.get("dis")
    if _s is not None and getattr(_s, "__spec__", None) is not None:
        if getattr(getattr(_s, "__spec__", None), "name", "") == "dis":
            try:
                del _SYS.modules["dis"]
            except Exception:
                pass
except Exception:
    pass
del _s
