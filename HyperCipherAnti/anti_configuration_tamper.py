"""anti_configuration_tamper: config-dosya + os.environ butunluk katmani.

Tehdit modeli (arastirma sentezi - 3x ReSearch):
  - CWE-15 / CAPEC-13/176/203 (ayar manipülasyonu): saldirgan dis
    ayarlari (env degiskeni, config dosyasi) kontrol ederse davranis
    degisir; cozum guvenli-alan ayirimi + en-az-yetki + degisiklik
    kontrolu (NIST CM-2/CM-3/CM-5).
  - OWASP A08 (2025, butunluk-dogrulama eksikligi): imzasiz/dogrulanmamis
    veri guvenilir sayilmaz; cozum HMAC/imza + basarili-dogrulama-oncesi
    kullanmama + basarisizlikta fail-closed (MASWE-0057: kaynak-butunluk
    dogrulanmamis, dogrulama-sonucu-gozardi-dahil).
  - PYTHONPATH/LD_PRELOAD enjeksiyonu (OpenSSF pyscg-0013, Talos 2026):
    PYTHONPATH/PYTHONHOME/PYTHONPYCACHEPREFIX'i kontrol eden site-hook +
    sitecustomize ile kalici kod-calistirma; cozum izolasyon (-I),
    hash-bazli pyc (`--check-hash-based-pycs always`), kritik
    anahtarlara yazan kodu supheli sayma.
  - python-dotenv CVE-2026-28684 (GHSA-mf9w-mj56-hr94): set_key/unset_key
    symlink izler + cross-device fallback = keyfi dosya-uzerine-yazma;
    fix symlink-izlememe + ayni-dizinde-temp + os.replace (atomik).
    Ders: config-yazma atomik + symlink-reddedici olmali (CWE-59/61).
  - os.environ cache-ayrismasi (3.14 öncesi): os.putenv() os.environ
    önbellegini bypass eder -> gizli durum-ciftligi; tespit-atlatma
    vektörü. Ayrica bool("false")==True tipi-tuzagi + override=True'un
    CI-secret'ini .env ile ezmesi + rollback (gecerli-eski-dosya)
    AES-GCM'in bile yakalayamadigi saldiri (dotenv-encrypt sinir).
  - Tainted-subprocess-env (Sourcery): env=os.environ / .copy() mirasi +
    PATH/LD_*/PYTHONPATH kontrolü = kod-calistirma; cozum minimal-sabit
    env + allowlist + shell=False.
  - TOCTOU (CWE-367, filelock 3.20.3, 2026 agent-raporu): realpath-kontrol
    + string-ile-ac eszamansizdir; cozum O_NOFOLLOW + fd-dogrulama
    (fstat) + tek-syscall atomikligi (O_CREAT|O_EXCL).

Kapsam (kardeslerle cakisma yok):
  - anti_tamper KOD butunlugunu, anti_import IMPORT-anini, anti_hook
    ENV-hook'larini tutar; BU modul CONFIG DOSYALARI + os.environ
    ANLIK-GORUNTU/pin/verify + subprocess-env hijyenini tutar.
  - anti_error_leakage HATA metnini tutar; bu modul AYAR
    manipülasyonunu tutar. anti_side_channel ZAMANLAMA seklini tutar.

Sinyal kurallari (FP-guvenli):
  - dangerous_env_target (STRONG): kritik listeye environ-yazma
    (os.environ[...] = , del os.environ[...], environ.update,
    putenv, unsetenv). Kritik: PATH, PATHEXT (T1574.008), LD_PRELOAD,
    LD_LIBRARY_PATH, LD_AUDIT, DYLD_INSERT_LIBRARIES,
    DYLD_LIBRARY_PATH, PYTHONPATH, PYTHONHOME, PYTHONPYCACHEPREFIX,
    PYTHONDONTWRITEBYTECODE, PYTHONSTARTUP, PYTHONEXECUTABLE.
    Bilinmeyen anahtara yazma sayilmaz (mesru kullanim cok).
  - dotenv_symlink_write (STRONG): set_key/unset_key + follow_symlinks
    True, ayni cagri-penceresinde (CVE-2026-28684 deseni).
  - environ_cache_desync (STRONG): os.putenv/unsetenv cagrisi
    (onbellegi bypass eder, gizli cift-durum).
  - dotenv_override (WEAK): load_dotenv(override=True), ayni
    cagri-penceresinde (mevcut env'yi ezer).
  - tainted_env_inherit (WEAK): ayni co'da subprocess-cagrisi +
    os.environ.copy() mirasi (tainted miras).
  - Trip >=1 STRONG veya >=2 WEAK. Tek WEAK trip uretmez.

Sinirlar (bilincli tercihler):
  - Baseline process-icidir: ayni-process saldirgan snapshot'i da
    yeniden kurabilir (hashguard dersi); tehdit modeli GEC-yuklenen
    kodun sessiz degisikligidir (dokumante rezidu).
  - HMAC-muhur YOK: anahtar process-icinde olunca muhur supur
    (dürüst sinir); dogruluk SHA-256 + symlink-reddi ile saglanir.
  - Rollback (gecerli-ESKI config) hash ile yakalanamaz
    (dotenv-encrypt siniri); pin-zamani + surum-alan kontrolu cagiranin
    isidir (dokumante).
  - check_all() yalnizca watch()+pin() kayitlarini tarar.

Sessiz, stdlib-only, fail-closed. True=risk, False=temiz.
"""

import functools as _functools
import hashlib as _hashlib
import os as _os
import re as _re
import sys as _sys_config
import threading as _threading
import time as _time
from types import MappingProxyType as _MappingProxy


def _get_dis_insns(fn, cap: int):
    """dis'i lazy yukle + tahliye et (self-FP onler, kardes konvansiyon)."""
    try:
        added = "dis" not in _sys_config.modules
        import dis as _d
        try:
            out = []
            for i, ins in enumerate(_d.get_instructions(fn)):
                if i >= cap:
                    break
                out.append(ins)
            return out
        finally:
            try:
                if added and "dis" in _sys_config.modules:
                    del _sys_config.modules["dis"]
            except Exception:
                pass
    except Exception:
        return []


class ConfigTamperDetected(RuntimeError):
    pass


class ConfigTamperError(RuntimeError):
    """Tek tip runtime hata: hangi ayar bozuldu - belli degil."""

    pass


def _raise():
    raise ConfigTamperDetected("protected")


_LOCK = _threading.RLock()
_WATCHED = {}

WEIGHTS = {
    "dangerous_env_target": 100,
    "dotenv_symlink_write": 100,
    "environ_cache_desync": 100,
    "pin_mismatch": 100,
    "sensor_health": 100,
    "dotenv_override": 30,
    "tainted_env_inherit": 30,
}
STRONG = frozenset({"dangerous_env_target", "dotenv_symlink_write",
                    "environ_cache_desync", "pin_mismatch",
                    "sensor_health"})
_THRESHOLD_TRIP = 100
_INSN_CAP = 20000
_MAX_CFG_BYTES = 8 << 20

_CRITICAL_ENV = frozenset({
    "PATH", "PATHEXT", "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT",
    "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH",
    "PYTHONPATH", "PYTHONHOME", "PYTHONPYCACHEPREFIX",
    "PYTHONDONTWRITEBYTECODE", "PYTHONSTARTUP", "PYTHONEXECUTABLE",
})

_SAFE_SUBPROCESS_CALLS = frozenset({
    "Popen", "run", "call", "check_output", "check_call",
})

_ENV_KEY_RE = _re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_SAFE_ENV_VAL_RE = _re.compile(r"^[A-Za-z0-9_\-./\\:=+@, ]{0,512}$")
_UNSAFE_VAL_RE = _re.compile(
    r"[;&|`$(){}\n\r]|\.\.|\\x[0-9a-fA-F]{2}|%[0-9a-fA-F]{2}|"
    r"https?://|ftp://")
_MAX_PATH_LEN = 4096

if _os.name == "nt":
    _SAFE_PATH = "C:\\Windows\\System32;C:\\Windows"
else:
    _SAFE_PATH = "/usr/bin:/bin"
# os.defpath KULLANILMAZ: Windows'ta '.;C:\bin' icerir, '.' = CWE-426
# (calisma-dizini arama-yolu) zaafidir. Sabit guvenli deger sart.

try:
    _NOFOLLOW = _os.O_NOFOLLOW
except AttributeError:  # pragma: no cover - Windows
    _NOFOLLOW = 0


# --------------------------------------------------------------------------
# statik tarama (dis)


def _insns(fn):
    try:
        code = getattr(fn, "__code__", None)
        if code is None:
            return []
        return _get_dis_insns(fn, _INSN_CAP)
    except Exception:
        return []


def _names(fn):
    try:
        code = getattr(fn, "__code__", None)
        if code is None:
            return frozenset()
        return frozenset(code.co_names)
    except Exception:
        return frozenset()


def _consts(fn):
    try:
        code = getattr(fn, "__code__", None)
        if code is None:
            return ()
        return tuple(code.co_consts or ())
    except Exception:
        return ()


def _dangerous_env_target(fn):
    """Kritik env anahtarina yazma: environ-store / putenv / unsetenv."""
    try:
        ins = _insns(fn)
        if not ins:
            return False
        names = _names(fn)
        # 1) os.environ[...] = x / del os.environ[...] - konteyner
        # DOGRUDAN environ olmali: [..., LOAD environ, LOAD key,
        # STORE/DELETE_SUBSCR]. Baska sozluge yazarken sagda
        # os.environ.get() okumak FP degildir (anti_tamper dersi).
        for idx, one in enumerate(ins):
            if one.opname != "STORE_SUBSCR" and one.opname != "DELETE_SUBSCR":
                continue
            if idx < 2:
                continue
            container = ins[idx - 2]
            keyins = ins[idx - 1]
            if container.argval != "environ":
                continue
            if keyins.opname == "LOAD_CONST":
                if (isinstance(keyins.argval, str)
                        and keyins.argval in _CRITICAL_ENV):
                    return True
            else:
                # environ'a dinamik-anahtarla yazma: hedef bilinmez,
                # supheli say (fail-closed).
                return True
        # 1b) os.environ.update(...) - update'in nesnesi environ olmali.
        for idx, one in enumerate(ins):
            if one.argval != "environ":
                continue
            for nxt in ins[idx + 1:idx + 3]:
                if nxt.argval == "update":
                    return True
        # 2) os.putenv(kritik, ...) / os.unsetenv(kritik)
        if "putenv" in names or "unsetenv" in names:
            for c in _consts(fn):
                if isinstance(c, str) and c in _CRITICAL_ENV:
                    return True
        return False
    except Exception:
        return False


def _call_true_near(names_wanted, kw_names, fn):
    """Hedef cagri + kw-adi + True sabiti ayni cagri-penceresinde mi?

    Co-seviyesi `c is True` taramasi ilgisiz True ile FP uretir; cagri
    etrafinda +-10 komut penceresi gerekir (CVE-2026-28684 / override).
    """
    try:
        ins = _insns(fn)
        if not ins:
            return False
        # KW_NAMES argval dis'te cozulemez (<unknown>); kw-demeti
        # co_consts'tan dogrulanir (o kwarg gecilmedikce demet uretilmez).
        kw_present = False
        try:
            for c in _consts(fn):
                if isinstance(c, tuple) and (set(c) & kw_names):
                    kw_present = True
                    break
        except Exception:
            pass
        if not kw_present:
            return False
        for idx, one in enumerate(ins):
            if not one.opname.startswith("CALL"):
                continue
            lo = max(0, idx - 14)
            hi = min(len(ins), idx + 4)
            seen_fn = False
            seen_true = False
            for w in ins[lo:hi]:
                if w.argval in names_wanted:
                    seen_fn = True
                if w.opname == "LOAD_CONST" and w.argval is True:
                    seen_true = True
            if seen_fn and seen_true:
                return True
        return False
    except Exception:
        return False


def _dotenv_symlink_write(fn):
    """set_key/unset_key + follow_symlinks=True (CVE-2026-28684)."""
    try:
        names = _names(fn)
        if "set_key" not in names and "unset_key" not in names:
            return False
        return _call_true_near({"set_key", "unset_key"},
                               {"follow_symlinks"}, fn)
    except Exception:
        return False


def _environ_cache_desync(fn):
    """os.putenv/unsetenv cagrisi: os.environ onbellegini bypass eder."""
    try:
        names = _names(fn)
        return "putenv" in names or "unsetenv" in names
    except Exception:
        return False


def _dotenv_override(fn):
    """load_dotenv(override=True): mevcut env'yi ezer."""
    try:
        if "load_dotenv" not in _names(fn):
            return False
        return _call_true_near({"load_dotenv"}, {"override"}, fn)
    except Exception:
        return False


def _tainted_env_inherit(fn):
    """subprocess + os.environ.copy() mirasi ayni fonksiyonda."""
    try:
        names = _names(fn)
        if not (names & _SAFE_SUBPROCESS_CALLS):
            return False
        if "environ" not in names or "copy" not in names:
            return False
        ins = _insns(fn)
        for idx, one in enumerate(ins):
            if one.argval != "environ":
                continue
            for nxt in ins[idx + 1:idx + 5]:
                if nxt.argval == "copy":
                    return True
        return False
    except Exception:
        return False


def scan_function(fn):
    res = {"dangerous_env_target": False,
           "dotenv_symlink_write": False,
           "environ_cache_desync": False,
           "dotenv_override": False,
           "tainted_env_inherit": False}
    try:
        if _dangerous_env_target(fn):
            res["dangerous_env_target"] = True
        if _dotenv_symlink_write(fn):
            res["dotenv_symlink_write"] = True
        if _environ_cache_desync(fn):
            res["environ_cache_desync"] = True
        if _dotenv_override(fn):
            res["dotenv_override"] = True
        if _tainted_env_inherit(fn):
            res["tainted_env_inherit"] = True
    except Exception:
        pass
    return res


def scan_module(mod):
    res = {"dangerous_env_target": False,
           "dotenv_symlink_write": False,
           "environ_cache_desync": False,
           "dotenv_override": False,
           "tainted_env_inherit": False}
    try:
        fns = []
        for name in dir(mod):
            if name.startswith("__"):
                continue
            try:
                obj = getattr(mod, name)
            except Exception:
                continue
            if callable(obj) and hasattr(obj, "__code__"):
                fns.append(obj)
        for f in fns:
            try:
                one = scan_function(f)
            except Exception:
                continue
            for k in res:
                if one.get(k):
                    res[k] = True
    except Exception:
        pass
    return res


# --------------------------------------------------------------------------
# runtime: environ pin/verify


_ENV_PINS = {}
_CFG_WATCH = {}
_FROZEN = {}
_LAST_PIN_BAD = False
_LAST_ALERT = {}
_SENSOR = {"watchdog": False, "last_ok": 0.0}
_ALERT_HOOK = None
_ALERTED = False
_PIN_GENERATION = 0
_TAMPER_LATCH = False
_TAMPER_HISTORY = []
_WATCH_CAP = 1024
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
            fr = _sys_config._getframe(1)
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
        with _LOCK:
            _ADMIN_MODULES[name] = fn
        return True
    except Exception:
        return False


def lock_admin():
    """Yonetim kaydini kilitle (start_watchdog zaten kilitler)."""
    global _ADMIN_LOCKED
    try:
        with _LOCK:
            _ADMIN_LOCKED = True
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
            fr = _sys_config._getframe(2)
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
    """Yonetim reddi: sayaç + fail-closed opak hata."""
    global _ADMIN_DENIED
    try:
        with _LOCK:
            _ADMIN_DENIED += 1
    except Exception:
        pass
    _raise()


def pin_env(keys=None):
    """Kritik env anahtarlarinin anlik-goruntusunu al.

    F15 duzeltmesi: her pin generation sayacini artirir + kanit
    append-only history'e yazilir; re-pin latch'i/kaniti SILMEZ.
    """
    global _PIN_GENERATION
    try:
        if keys is None:
            wanted = set(_CRITICAL_ENV)
        else:
            wanted = set()
            for k in keys:
                if isinstance(k, str) and _ENV_KEY_RE.match(k):
                    wanted.add(k)
        snap = {}
        for k in sorted(wanted):
            try:
                v = _os.environ.get(k)
            except Exception:
                v = None
            snap[k] = v
        with _LOCK:
            _ENV_PINS.clear()
            _ENV_PINS.update(snap)
            _PIN_GENERATION += 1
            try:
                _TAMPER_HISTORY.append({"gen": _PIN_GENERATION,
                                        "keys": sorted(snap.keys()),
                                        "at": _time.monotonic()})
                while len(_TAMPER_HISTORY) > 64:
                    _TAMPER_HISTORY.pop(0)
            except Exception:
                pass
        return True
    except Exception:
        return False


def acknowledge_env_tamper():
    """Sticky latch'i kaldir (YONETIM: kayitli operator sart).

    History append-only'dir, silinmez — kanit korunur.
    """
    if not _check_admin():
        _deny_admin("acknowledge_env_tamper")
    global _TAMPER_LATCH
    try:
        with _LOCK:
            _TAMPER_LATCH = False
        return True
    except Exception:
        return False


def verify_env():
    """Pin'den sapma varsa True (bozuk). Sapma sticky latch kurar (F15)."""
    global _TAMPER_LATCH
    try:
        with _LOCK:
            pins = dict(_ENV_PINS)
        if not pins:
            return False
        for k, old in pins.items():
            try:
                cur = _os.environ.get(k)
            except Exception:
                with _LOCK:
                    _TAMPER_LATCH = True
                return True
            if cur != old:
                with _LOCK:
                    _TAMPER_LATCH = True
                return True
        return False
    except Exception:
        return True


def env_diff():
    """Sapma detayini don (changed/added/removed); deger sizdirmaz."""
    out = {"changed": [], "added": [], "removed": []}
    try:
        with _LOCK:
            pins = dict(_ENV_PINS)
        for k, old in pins.items():
            try:
                cur = _os.environ.get(k)
            except Exception:
                out["changed"].append(k)
                continue
            if old is None and cur is not None:
                out["added"].append(k)
            elif old is not None and cur is None:
                out["removed"].append(k)
            elif cur != old:
                out["changed"].append(k)
    except Exception:
        pass
    return out


# --------------------------------------------------------------------------
# runtime: config-dosya watch/verify (TOCTOU-guvenli okuma)


def _coerce_path(path):
    """str/bytes/PathLike -> str; gecersizse None (PEP 519 os.fspath)."""
    try:
        s = _os.fspath(path)
    except Exception:
        return None
    try:
        if isinstance(s, bytes):
            s = s.decode("utf-8", "strict")
        if not isinstance(s, str) or not s:
            return None
        if len(s) > _MAX_PATH_LEN:
            return None
        if "\x00" in s:
            return None
        return s
    except Exception:
        return None


def _read_nofollow(path):
    """Symlink-reddedici, boyut-sinirli, fd-dogrulamali okuma.

    POSIX: O_NOFOLLOW son-bileseni korur; fstat ile tutulan fd dogrulanir
    (string-tekrar-cozumleme yok). Windows: O_NOFOLLOW no-op'tur; bunun
    yerine lstat st_file_attributes'taki REPARSE_POINT bayragi (junction
    dahil, islink'in kacirdigi) kontrol edilir - reparse-point reddedilir.
    Windows lstat->open arasi degisim penceresi kalir (st_ino guvenilmez:
    WebDAV/FAT'ta 0, ReFS/shadow-copy carpisma; ino-karsilastirma YANILTICI
    olur, bilincli olarak YOK). Ara-dizin yarisi iki platformda da
    dokumante sinirdir (2026 TOCTOU dersi: userspace-kontrol dogruluk
    ozelligidir, gercek sinir sandbox'tir).
    """
    try:
        path = _coerce_path(path)
        if path is None:
            return None
        if _os.name == "nt":
            try:
                lst = _os.lstat(path)
                attrs = getattr(lst, "st_file_attributes", 0) or 0
                if int(attrs) & 0x400:
                    return None
            except Exception:
                return None
        fd = _os.open(path, _os.O_RDONLY | _NOFOLLOW)
    except Exception:
        return None
    try:
        try:
            st = _os.fstat(fd)
        except Exception:
            return None
        if st.st_size < 0 or st.st_size > _MAX_CFG_BYTES:
            return None
        h = _hashlib.sha256()
        left = int(st.st_size)
        while left > 0:
            try:
                chunk = _os.read(fd, 65536 if left > 65536 else left)
            except Exception:
                return None
            if not chunk:
                break
            h.update(chunk)
            left -= len(chunk)
        try:
            # Kuyruk-cop kontrolu (git csum-file deseni): fstat sonrasi
            # BUYUYEN dosya okunan one-ek disinda bayt tasir; hash gecerli
            # gorunur ama icerik degismistir -> fail-closed reddet.
            if _os.read(fd, 1):
                return None
        except Exception:
            return None
        return h.hexdigest()
    except Exception:
        return None
    finally:
        try:
            _os.close(fd)
        except Exception:
            pass


def watch_config_file(path):
    """Config dosyasinin SHA-256 taban-cizgisini kaydet."""
    try:
        path = _coerce_path(path)
        if path is None:
            return False
        digest = _read_nofollow(path)
        if digest is None:
            return False
        with _LOCK:
            _CFG_WATCH[str(path)] = digest
        return True
    except Exception:
        return False


def unwatch_config_file(path):
    try:
        path = _coerce_path(path)
        if path is None:
            return False
        with _LOCK:
            _CFG_WATCH.pop(str(path), None)
        return True
    except Exception:
        return False


def verify_configs():
    """Izlenen dosyada sapma/silinme/symlink-degisimi varsa True."""
    try:
        with _LOCK:
            items = list(_CFG_WATCH.items())
        for path, old in items:
            cur = _read_nofollow(path)
            if cur is None or cur != old:
                return True
        return False
    except Exception:
        return True


def verify_pins():
    try:
        if verify_env():
            return True
    except Exception:
        pass
    try:
        if verify_configs():
            return True
    except Exception:
        pass
    return False


# --------------------------------------------------------------------------
# runtime: dondurulmus config + minimal subprocess env


def _freeze_value(obj, depth=0, seen=None):
    """Ozyinelemeli dondurma: dict->MappingProxy, list/tuple->tuple,
    set->frozenset. Dongu-guvenli (seen id seti)."""
    try:
        if depth > 16:
            return None
        if seen is None:
            seen = set()
        try:
            oid = id(obj)
            if oid in seen:
                return None
            seen.add(oid)
        except Exception:
            pass
        if isinstance(obj, dict):
            try:
                return _MappingProxy({k: _freeze_value(v, depth + 1, seen)
                                      for k, v in obj.items()})
            except Exception:
                return _MappingProxy({})
        if isinstance(obj, (list, tuple)):
            try:
                return tuple(_freeze_value(v, depth + 1, seen) for v in obj)
            except Exception:
                return ()
        if isinstance(obj, (set, frozenset)):
            try:
                return frozenset(_freeze_value(v, depth + 1, seen) for v in obj)
            except Exception:
                return frozenset()
        return obj
    except Exception:
        return None


def _canonical_hash(obj) -> str:
    """Karsilastirilabilir kanonik SHA-256 (sirali-key, dongu-guvenli)."""
    try:
        seen = set()

        def _dump(o, depth=0):
            try:
                if depth > 16:
                    return "d16"
                if isinstance(o, _MappingProxy):
                    try:
                        o = dict(o)
                    except Exception:
                        return "m?"
                if isinstance(o, dict):
                    try:
                        oid = id(o)
                        if oid in seen:
                            return "cyc"
                        seen.add(oid)
                    except Exception:
                        pass
                    try:
                        items = sorted(o.items(), key=lambda kv: repr(kv[0]))
                    except Exception:
                        items = list(o.items())
                    return "m:" + ",".join(repr(k) + "=" + _dump(v, depth + 1)
                                           for k, v in items)
                if isinstance(o, (list, tuple)):
                    return "l:" + ",".join(_dump(v, depth + 1) for v in o)
                if isinstance(o, (set, frozenset)):
                    try:
                        parts = sorted(repr(v) for v in o)
                    except Exception:
                        parts = [repr(v) for v in o]
                    return "s:" + ",".join(parts)
                return "v:" + repr(o)[:1024]
            except Exception:
                return "?"
        blob = _dump(obj)
        return _hashlib.sha256(blob.encode("utf-8", "ignore")).hexdigest()
    except Exception:
        return ""


def _deep_copy_plain(mapping):
    """Izole kopya: stdlib deepcopy, duserse manuel ozyineleme."""
    try:
        import copy as _copy
        return _copy.deepcopy(dict(mapping))
    except Exception:
        pass
    try:
        out = {}
        for k, v in dict(mapping).items():
            try:
                import copy as _copy2
                out[k] = _copy2.deepcopy(v)
            except Exception:
                out[k] = v
        return out
    except Exception:
        return {}


def freeze_config(mapping, name="default"):
    """Salt-okunur config gorunumu don; (proxy, True)/(None, False).

    F13 duzeltmesi: DEEP-freeze — ic-ice mutable degerler ozyinelemeli
    dondurulur (proxy arkasindan `cfg["keys"].append()` artik TypeError).
    Snapshot bagimsiz deep-copy + kanonik hash'tir; verify hash
    karsilastirir (MappingProxy dinamik-gorunum tuzagi kapali).
    """
    try:
        if not isinstance(name, str) or not name:
            return None, False
        plain = _deep_copy_plain(mapping)
        frozen = _freeze_value(plain)
        if not isinstance(frozen, _MappingProxy):
            try:
                frozen = _MappingProxy(dict(plain))
            except Exception:
                return None, False
        digest = _canonical_hash(frozen)
        if not digest:
            return None, False
        with _LOCK:
            _FROZEN[name] = (digest, frozen)
        return frozen, True
    except Exception:
        return None, False


def verify_frozen():
    """Dondurulmus kayitlarin butunlugu: hash sapmasi varsa True."""
    try:
        with _LOCK:
            items = list(_FROZEN.items())
        for _, (digest, frozen) in items:
            try:
                if _canonical_hash(frozen) != digest:
                    return True
            except Exception:
                return True
        return False
    except Exception:
        return True


def minimal_env(extra=None, strict=True):
    """Subprocess icin minimal-sabit env kurucu (Sourcery-compliant).

    PATH sabittir; extra yalnizca kritik-listede OLMAYAN, regex-gecerli
    ciftleri kabul eder. Tainted miras YOK. F17: strict modda (varsayilan)
    yol-ayiracli (/, \\) veya nokta-basi degerler reddedilir; mesru
    PATH-benzeri ihtiyac strict=False ile acilir (bilincli tercih).
    """
    try:
        base = {"PATH": _SAFE_PATH}
        if extra is None:
            return dict(base)
        if not isinstance(extra, dict):
            return dict(base)
        for k, v in extra.items():
            try:
                if not isinstance(k, str) or not isinstance(v, str):
                    continue
                if k in _CRITICAL_ENV:
                    continue
                if not _ENV_KEY_RE.match(k):
                    continue
                if not _SAFE_ENV_VAL_RE.match(v):
                    continue
                if _UNSAFE_VAL_RE.search(v):
                    continue
                if strict and ("/" in v or "\\" in v or v.startswith(".")):
                    continue
                base[k] = v
            except Exception:
                continue
        return dict(base)
    except Exception:
        return {"PATH": _SAFE_PATH}


# --------------------------------------------------------------------------
# skor / guard / watchdog (kardes-uyumlu)


def set_alert_hook(fn):
    try:
        global _ALERT_HOOK
        with _LOCK:
            if fn is None:
                _ALERT_HOOK = None
                return True
            if not callable(fn):
                return False
            _ALERT_HOOK = fn
            return True
    except Exception:
        return False


def _fire_alert(count):
    try:
        with _LOCK:
            hook = _ALERT_HOOK
            global _ALERTED
            if hook is None or _ALERTED:
                return
            _ALERTED = True
        try:
            hook(count)
        except Exception:
            pass
    except Exception:
        pass


def last_alert():
    """Son alert baglami: {sources:[env:K/config/frozen:N], at:ts}.

    Deger sizdirmaz (anahtar/kaynak adi + zaman damgasi). Bos dict =
    henuz alert yok."""
    try:
        with _LOCK:
            return dict(_LAST_ALERT)
    except Exception:
        return {}


def check_all(light_only=False):
    res = {"dangerous_env_target": False,
           "dotenv_symlink_write": False,
           "environ_cache_desync": False,
           "dotenv_override": False,
           "tainted_env_inherit": False,
           "pin_mismatch": False,
           "sensor_health": False}
    try:
        with _LOCK:
            fns = list(_WATCHED.values())
        for f in fns:
            try:
                one = scan_function(f)
                for k in res:
                    if k in one and one[k]:
                        res[k] = True
            except Exception:
                continue
        try:
            if verify_pins():
                res["pin_mismatch"] = True
        except Exception:
            pass
        try:
            if verify_frozen():
                res["pin_mismatch"] = True
        except Exception:
            pass
        try:
            if _check_sensor_health():
                res["sensor_health"] = True
        except Exception:
            pass
        # Kenar-tetikli alert: False->True gecisinde bir kez ateslenir
        # (seviye-surekli spam yapmaz; tripwire edge-trigger deseni).
        # Hook'a bozuk-kaynak SAYISI gider; detay last_alert()'tadir
        # (canary-baglami: hangi-kaynak + ne-zaman, deger sizmaz).
        try:
            global _LAST_PIN_BAD
            bad = bool(res["pin_mismatch"])
            if bad and not _LAST_PIN_BAD:
                sources = []
                try:
                    with _LOCK:
                        pins = dict(_ENV_PINS)
                        cfgs = list(_CFG_WATCH.items())
                        frz = list(_FROZEN.items())
                except Exception:
                    pins, cfgs, frz = {}, [], []
                try:
                    for k, old in pins.items():
                        try:
                            if _os.environ.get(k) != old:
                                sources.append("env:" + str(k))
                                break
                        except Exception:
                            sources.append("env:" + str(k))
                            break
                except Exception:
                    pass
                try:
                    for path, old in cfgs:
                        try:
                            if _read_nofollow(path) != old:
                                sources.append("config")
                                break
                        except Exception:
                            sources.append("config")
                            break
                except Exception:
                    pass
                try:
                    for name, (digest, frozen) in frz:
                        try:
                            if _canonical_hash(frozen) != digest:
                                sources.append("frozen:" + str(name))
                                break
                        except Exception:
                            sources.append("frozen:" + str(name))
                            break
                except Exception:
                    pass
                try:
                    with _LOCK:
                        _LAST_ALERT.clear()
                        _LAST_ALERT.update(
                            {"sources": list(sources),
                             "at": _time.monotonic()})
                except Exception:
                    pass
                _fire_alert(len(sources) if sources else 1)
            _LAST_PIN_BAD = bad
        except Exception:
            pass
    except Exception:
        pass
    return res


def watch(fn):
    """Izlemeye al (F16: id-anahtarli + cap'li; dolunca refuse, fail-closed)."""
    try:
        if not callable(fn):
            return False
        key = id(fn)
        with _LOCK:
            if key not in _WATCHED and len(_WATCHED) >= _WATCH_CAP:
                return False
            _WATCHED[key] = fn
        return True
    except Exception:
        return False


def unwatch(fn):
    """Izlemeden cikar (YONETIM: kayitli operator sart — korlestirme kapali)."""
    if not _check_admin():
        _deny_admin("unwatch")
    try:
        with _LOCK:
            _WATCHED.pop(id(fn), None)
        return True
    except Exception:
        return False


def _score_from(results):
    pts = 0
    strong = 0
    weak = 0
    try:
        for k, v in results.items():
            if not v:
                continue
            w = int(WEIGHTS.get(k, 0))
            pts += w
            if k in STRONG:
                strong += 1
            else:
                weak += 1
    except Exception:
        pass
    return pts, strong, weak


def score(light_only=False):
    try:
        r = check_all(light_only=light_only)
        pts, strong, weak = _score_from(r)
        return pts, strong, weak
    except Exception:
        return _THRESHOLD_TRIP, 1, 0


def is_compromised(light_only=False):
    try:
        pts, strong, weak = score(light_only=light_only)
        if strong >= 1:
            return True
        if weak >= 2:
            return True
        return pts >= _THRESHOLD_TRIP
    except Exception:
        return True


def assert_clean(light_only=False):
    try:
        if is_compromised(light_only=light_only):
            _raise()
    except ConfigTamperDetected:
        raise
    except Exception:
        _raise()


def enforce():
    """Pin'li env + izlenen config + frozen kayitlari bozuksa
    ConfigTamperError yukselt (fail-closed zorlayici; assert_clean
    gozlemci, enforce kapidir)."""
    try:
        bad = False
        try:
            if verify_pins():
                bad = True
        except Exception:
            bad = True
        try:
            if verify_frozen():
                bad = True
        except Exception:
            bad = True
        if bad:
            raise ConfigTamperError("configuration failed")
        return True
    except ConfigTamperError:
        raise
    except Exception:
        raise ConfigTamperError("configuration failed")


def guard(func):
    @_functools.wraps(func)
    def _w(*a, **k):
        assert_clean()
        return func(*a, **k)
    return _w


def status(light_only=False):
    try:
        r = check_all(light_only=light_only)
        pts, strong, weak = _score_from(r)
        with _LOCK:
            gen = _PIN_GENERATION
            latched = _TAMPER_LATCH
            hist_n = len(_TAMPER_HISTORY)
            admin_n = len(_ADMIN_MODULES)
        return {"tripped": bool(is_compromised(light_only=light_only)),
                "strong": strong, "weak": weak, "points": pts,
                "results": r, "env_pinned": bool(_ENV_PINS),
                "configs_watched": len(_CFG_WATCH),
                "pin_generation": gen, "tamper_latched": latched,
                "pin_history": hist_n, "admin_authorized": admin_n,
                "admin_locked": _ADMIN_LOCKED, "admin_denied": _ADMIN_DENIED}
    except Exception:
        return {"tripped": True, "strong": 1, "weak": 0, "points": _THRESHOLD_TRIP,
                "results": {}, "env_pinned": False,
                "configs_watched": 0}


def _check_sensor_health():
    try:
        with _LOCK:
            on = bool(_SENSOR.get("watchdog"))
            last = float(_SENSOR.get("last_ok", 0.0) or 0.0)
        if not on:
            return False
        now = _time.monotonic()
        if last <= 0.0:
            return now > 30.0
        return (now - last) > 30.0
    except Exception:
        return False


def _watchdog_loop(stop_ev, interval):
    try:
        while not stop_ev.wait(interval):
            try:
                bad = bool(is_compromised())
                with _LOCK:
                    _SENSOR["watchdog"] = True
                    if not bad:
                        _SENSOR["last_ok"] = _time.monotonic()
            except Exception:
                continue
    except Exception:
        pass


def start_watchdog(interval=0.05):
    global _ADMIN_LOCKED
    try:
        with _LOCK:
            _ADMIN_LOCKED = True
    except Exception:
        pass
    try:
        iv = float(interval)
        if iv < 0.005:
            iv = 0.005
        if iv > 5.0:
            iv = 5.0
    except Exception:
        iv = 0.05
    try:
        import threading as _t
        stop_ev = _t.Event()
        th = _t.Thread(target=_watchdog_loop, args=(stop_ev, iv),
                       daemon=True)
        th.start()
        with _LOCK:
            _SENSOR["watchdog"] = True
        return stop_ev, th
    except Exception:
        return None, None


def stop_all_watchdogs():
    """Watchdog bayraklarini sifirla (YONETIM: kayitli operator sart)."""
    if not _check_admin():
        _deny_admin("stop_all_watchdogs")
    try:
        with _LOCK:
            _SENSOR["watchdog"] = False
            _SENSOR["last_ok"] = 0.0
            global _ALERTED
            _ALERTED = False
            global _LAST_PIN_BAD
            _LAST_PIN_BAD = False
            with _LOCK:
                _LAST_ALERT.clear()
        return True
    except Exception:
        return False
