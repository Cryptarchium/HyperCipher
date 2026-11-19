# -*- coding: utf-8 -*-
"""
HyperCipherAnti - AntiKeyExtraction (Stage 4)
=============================================
Entegre cok katmanli key/passphrase sizinti tespiti + hijyen API'si.
Stdlib-only, cross-platform, fail-closed, sessiz (oracle vermez).

Arastirma sentezi:
  R1 Saldirgan gorunusu (Halderman cold-boot 2008, Kaplan RAMisKey,
     CryKeX, memphantom): anahtar (a) RAM dump entropi/yapi taramasi,
     (b) key-schedule yakinligi (keyfind), (c) swap/pagefile/hiberfil,
     (d) canli process dump (/proc/pid/mem, MiniDumpWriteDump) ile bulunur.
     Kagitlarin kendi onerisi: anahtari RAM'de kisa tut + shutdown/
     screensaver/hibernation'da wipe + mlock + DONTDUMP. Bu modul (a)-(d)
     icin ERISIM-HIJYENI katmanidir; core/swap/dumper-process anti_dump'un,
     DBI/thread anti_instrumentation'un alanidir.
  R2 Python secure-memory (nomyo SecureMemory, ZeroizePy, cypher_cell,
     zeroize-crate, OWASP Secrets-Mgmt, cryptography.io limits):
     bytearray-only (immutable bytes/str SIFIRLANAMAZ), ctypes from_buffer
     + memset/RtlZeroMemory, mlock/VirtualLock, Windows'ta 128KB ustu icin
     SetProcessWorkingSetSize sart, munlock sayfa-paylasim uyarisi,
     MADV_DONTFORK (fork-cocuga sizma), scoped-view + anti-leak repr,
     from_env/from_file direkt yukleme (heap'e degmeden), volatile+TTL,
     constant-time verify. Hepsi KeyVault'a port edildi (Rust yok, stdlib).
  R4 Windows mitigations (MS Learn processthreadsapi, bordergate ACG,
     ired.team): SetProcessMitigationPolicy(ExtensionPointDisablePolicy,
     DisableExtensionPoints=1) legacy enjeksiyon-DLL'lerini keser;
     ImageLoadPolicy(NoRemoteImages|NoLowMandatoryLabelImages|
     PreferSystem32Images=7) uzak-paylasim DLL sideload'u keser.
     SignaturePolicy/MicrosoftSignedOnly REDDEDILDI: CPython .pyd'leri
     MS-signed degil -> process LoadLibrary'de olur (0xc0000428).
     DynamicCodePolicy REDDEDILDI: risk/fayda orani kotu (ctypes
     kirilma riski). harden() best-effort uygular (policy enum:
     ExtensionPoint=6, ImageLoad=10).
  R5 Linux PR_SET_DUMPABLE (man7 pr_set_dumpable, systemshardening,
     OpenSSH 8.2+ ayni yontem): =0 -> no core + /proc/pid/{mem,maps,
     environ} non-root'a kapanir + PTRACE_ATTACH reddedilir (YAMA'dan
     bagimsiz). Yeni WEAK sinyal dumpable_process + harden() prctl(4,0)
     uygular; PR_GET_DUMPABLE(3) ile okunur. Windows karsiligi yok
     (dokumante rezidu).
  R6 VirtualLock durustlugu (MS Learn memoryapi, Raymond Chen OldNewThing,
     windowssyscalls NtLockVirtualMemory): VirtualLock=MAP_PROCESS =
     working-set kilidi, FIZIKSEL pin DEGIL; hibernation dosyasina yazilmayi
     engellemez; gercek pin (MAP_SYSTEM) SeLockMemoryPrivilege ister
     (LocalSystem). Kod zaten SetProcessWorkingSetSize on-kosulu yapiyordu;
     is_locked semantigi docstring'e islendi (swap-karsiti, hiber-karsiti
     DEGIL). Hiber karsiti DONTDUMP+wipe disiplini (R1) ile kapsanir.
  R7 KONTROL-1 oz-denetime: (a) gc.get_objects() bytes/str/bytearray
     DONDURMEZ (CPython cyclic-GC izlemez) -> v1 immutable_copies OLU
     sinyaldi. Fix: container-traversal + 10MB cap. (b) _sig_image_residue
     olu koddu -> sinyal KALDIRILDI; scan_own_image() audit kaldi.
     (c) status() 3x walk -> tek-pas. (d) from_file no-op finally +
     unused _winreg kaldirildi. (e) cmdline argv[0]'i de kapsar.
  R8 Clipboard history (MITRE T1115, msppentesting, malware.news,
     ClipboardHistoryThief, MS Support): Win10 1809+ pano GECMISI 25 oge
     tutar (cbdhsvc/svchost heap) + bulut-senkronda MS sunucusuna cikar.
     clear_clipboard SADECE aktif panoyu siler, gecmisi SILMEZ -> v1
     eksikti. Fix: clipboard_history_enabled() (HKCU\...\Clipboard\
     EnableClipboardHistory registry, stdlib winreg) + yeni WEAK sinyal
     clipboard_history (retention riski) + harden() history'yi kapatir (0).
  R9 audit_text O(n*m) pencere-sha256 (vecna-labs, docker-agent, Letts:
     AC prefilter o pattern'leri BILDIGINDE ise yarar; digest-only
     registry'de plaintext pattern YOK -> AC kurulamaz). Fix: 1MB->256KB
     cap + len==ln fast-path (kisa mesaj tek-hash). AC reddi dokumante.
  R10 CryptProtectMemory SAME_PROCESS (MS Learn dpapi, slowerzs blog):
     RAM'deki sirri per-boot kernel-anahtariyla sifreler (AES-128-CBC,
     blok=16); swap/pagefile/usermode-dump'a sifreli duser (KeePass/RDP
     ayni yontem; anti_dump [9] SecureBuffer'da vardi). Saldirgan
     karsiligi: SeDebugPrivilege + kernel-livedump ile cozulebilir
     (admin-rezidu, dokumante). Fix: KeyVault(shielded=True) Windows'ta
     beklemede SIFRELI durur, read()/verify() penceresinde cozulup geri
     sifrelenir (finally). Ayni-boot sarti + use-penceresi plaintext
     MS-dokuman notu olarak islendi. Linux karsiligi yok (mlock+DONTDUMP
     mevcut savunma).
  R11 KONTROL-2 oz-denetime: traversal bytearray'leri de "bytes" diye
     sayiyordu -> hyper_cipher'in MESRU canlı bytearray anahtarlari
     false-positive trip verirdi. Fix: traversal SADECE bytes+str
     (gercekten sifirlanamayanlar); bytearray hijyeni KeyVault'un isi.
  R12 Bulut-senkron keyfile (CSA SecretPoint 2025, Entro, PanicVault/
     KeePass keyfile rehberi, serverfault): OneDrive KFM (Desktop/
     Documents otomatik) + SharePoint miras-paylasimi = keyfile sessizce
     buluta cikar; ele gecen M365 hesabi tum "local" dosyalari alir.
     KeePass kurali: keyfile ASLA database ile ayni bulutta olmaz. Fix:
     is_cloud_synced(path) (OneDrive/OneDriveCommercial env + ~/Dropbox,
     ~/Google Drive, ~/iCloudDrive, ~/OneDrive kok karsilastirmasi) +
     yeni WEAK sinyal cloud_synced_keyfile (izlenen dosyalar icin).
  R13 NIST SP 800-88 Rev.2 (Eylul 2025) + securetrash FTL analizi:
     multi-pass overwrite RESMEN deprecated; SSD'de overwrite FTL/wear-
     leveling/over-provisioning yuzunden garanti VERMEZ; gercek cozum
     crypto-shred (anahtari yok et) veya firmware-sanitize. Tek-dosya
     icin: shred_file() best-effort single-pass (random+zero) + flush +
     fsync + rename + unlink + verify; SSD/COW'da garanti YOK -> docstring
     durustluk notu. HyperCipher'da kullanim: emekli keyfile/passphrase-
     file silmede.
  R14 GetProcessMitigationPolicy (MS Learn, AlexAdasCca gist, PROCESS_
     MITIGATION_POLICY enum: ExtensionPoint=6, ImageLoad=10; DWORD flags):
     harden() politikayi kuruyordu ama DOGRULAMIYORDU (sessiz basarisizlik
     = sahte-guven). Fix: _verify_windows_mitigations() GetCurrentProcess
     pseudo-handle ile geri okur (ext&1, img&7==7); harden() "mitigations_
     verified" raporlar. KONTROL-dongusu kapatma: kur + dogrula.
  R15 Fork-cocuk sizintisi (Python docs os.register_at_fork, zeroize-crate
     CoW uyarisi, cypher_cell Anti-Fork): fork() ebeveyn RAM'ini kopyalar;
     cocuk gereksizse bile anahtari miras alir (MADV_DONTFORK sadece
     madvise'li bolgeyi korur). Fix: _live_vaults WeakSet + after_in_child
     _fork_child_wipe (kilit ALMAZ, sadece _secure_zero + dead isareti;
     fork-guvenli minimal). Unix-only; Windows'ta fork yok (dokumante).
  R16 from_env direkt-yukleme (cypher_cell from_env, pouch FD, kleys,
     openclaw memfd tartismasi): ara dosya/kopya olmadan environ'dan
     vault'a. DURUSTLUK: env degeri str (immutable) -> okuma sonrasi
     scrub=True ile ayni uzunlukta dummy ile DEGISTIRILIR (orijinal str
     GC'ye duser; sifirlanamaz ama referansi kopar). from_file'a kardes API.
  R17 Watchdog derin-tarama (CPython GC docs, codingconfessions, close.com:
     gc.get_objects maliyeti heap'le buyur; FULL her tick'te calismaz).
     Fix: start_watchdog(deep_every=N) her N tick'te FULL seti kosar
    (heavy sinyaller gozetimsiz kalmaz, maliyet sinirli). deep_every=0
    kapali (default, davranis degismez).
  R21 audit_text timing-oracle taramasi (NCC Time Trial, Bleichenbacher/
     Meyer, Lucky13/AlFardan-Paterson, phpseclib CVE-2026-32935, Wait-a-
     Cycle): erken-cikis karsilastirma pozisyon sizdirir; sabit-zamanli
     karsilastirma sart. audit_text pencere-eslesmede ilk bulguda
     donuyordu (erken-cikis) -> Fix: tum pencereler HER ZAMAN taranir,
     sonuc bayrakta birikir, tek noktada donulur. Not: audit lokal
     hijyen-API'dir (uzak gozlemci yok); degisiklik savunma-derinligidir.
     verify()/digest karsilastirmalari zaten hmac.compare_digest idi.
  R22 from_buffer aliasing (runebook ctypes, cpython#135894, SO cast):
     (a) gorunum yasarken bytearray resize -> segfault/BufferError;
     (b) ctypes C-cagrilari GIL'i BIRAKIR -> baska thread ayni anda
     buf'u buyuturse realloc + dangling addr = bellek-bozulmasi. Fix:
     _native_lock tum native-op sarar (_lock/_unlock/_secure_zero/
     _shield/_unshield/_madvise); from_buffer gorunumu cagri-sonuna dek
     canli tutulur (yerel referans). after_in_child bilerek kilit ALMAZ
     (R15; ebeveynde tutuluyor olabilir).
  R23 TOCTOU (CWE-367, Dean/Provos, systemshardening openat2): getsize()
     + open() arasi dosya degisebilir (buyurse kuyruk kalir). Fix:
     shred_file + scan_own_image boyutu FD uzerinden os.fstat ile alir
     (fd-bazli, yeniden-cozumleme yok; EAFP deseni). Symlink hedefi
     takip edilir (dokumante); is_cloud_synced best-effort audit'tir.
  R18 Acil-wipe (Python atexit docs, pyterminate, safe-exit, gmpy recipe):
     atexit YAKALANMAYAN sinyalde CALISMAZ (SIGTERM default oldurur);
     dogru desen = atexit + SIGTERM/SIGINT(/SIGBREAK/SIGABRT) zincirleme
     (onceki handler'a saygi, idempotent). SIGKILL/os._exit ASLA
     yakalanamaz (dokumante rezidu). Windows'ta CTRL_CLOSE_EVENT icin
     SetConsoleCtrlHandler gerekir (bu modulde yok — rezidu). Fix:
     arm_exit_wipe() tum canli vault'lari _fork_child_wipe (kilit-siz)
     ile sifirlar, sonra onceki handler'a zincirler; disarm() dondurur.
  R19 NTFS kalinti-durustlugu (usnparser, CyberCX rewind, deaddisk,
     usnjrnl-forensic): $UsnJrnl:$J dosya ADI + varlik-gecmisini gunler/
     haftalar saklar (icerik DEGIL); $LogFile metadata before-image
     (dakika-saat); $MFT girdisi yeniden-kullanilana dek durur; VSS/
     pagefile ayri vektorler. shred_file icerigi siler ama ADI + varligi
     journal'da kalir -> Fix: rename hedefi ".shredded" DEGIL rastgele
     16-hex (ad-kalintisi minimize); docstring'e USN/MFT/VSS/pagefile
     rezidu notu. Tam cozum crypto-shred (R13) + FDE'dir.
  R20 Libsodium bellek-doktrini (doc/memory_management, utils.c):
     sodium_mlock = mlock/VirtualLock + MADV_DONTDUMP (bizim _lock_bytes
     + _madvise ile AYNI — tasarim dogrulandi); sodium_munlock once
     SIFIRLAR (bizim wipe sirasi zaten zero->unlock, dogru). Yeni:
     stack/register kopyalari ENGELLENEMEZ (context-switch'te stack'e
     duser; sodium_stackzero kismi-cozum) -> DURUST SINIR notu eklendi.
     mprotect_noaccess guard-page REDDEDILDI (CPython yorumlayicida
     uygulanamaz/asiri). RLIMIT_MEMLOCK/ENOMEM -> yeni audit lock_limits()
     (POSIX resource, yoksa None). Hibernation tum kilitleri bypass eder
     (R6 ile tutarli); gercek baseline FDE'dir.

  DURUST SINIR (rezidu): SIGKILL/os._exit, stack/register kopyalari,
     hibernation dosyasi, ayni-ayricalik live-dump (SeDebugPrivilege),
     USN-Journal ad/varlik izleri, VSS/pagefile, kernel-seviyesi
     saldirilar saf-Python'da durdurulamaz. Bu modul firsatci-cekimi +
     hijyen-disiplini kapsar; sihirli degnek degildir.

  R3 argv/env sizintisi (smallstep command-line-secrets, wzrd-vault,
     secretsh, MySQL-docs tartismasi): argv ps//proc/cmdline'da
     world-readable; env ayni-uid'de okunur ama child'lara miras + crash
     dump/log'a akar. hcli zaten --passphrase inline KABUL ETMIYOR
     (getpass + 0600 --passphrase-file); bu modul bunu ZORLAR (tripwire)
     + kayitli sirr env/argv/clipboard'da gorunurse trip.

Tasarim:
  - Tripwire registry SADECE SHA256 digest + uzunluk saklar (sirrın
    kendisini ASLA tutmaz; registry dump'i oracle degildir).
  - Sinyaller: 2 STRONG (cmdline_leak, env_leak) + 6 WEAK
    (clipboard_leak, immutable_copies, dumpable_process,
    clipboard_history, watched_file_perms, cloud_synced_keyfile).
    Verdict: >=1 strong VEYA >=2 weak.
  - Agir sinyal (gc container-traversal) FULL sette; watchdog LIGHT
    set kosar (cmdline/env/clipboard). FULL ~100-500ms, LIGHT ~1-5ms.
  - KeyVault: bytearray holder + mlock + DONTDUMP/DONTFORK + TTL/volatile
    + anti-leak repr + constant-time verify + from_file. is_locked =
    working-set kilidi (swap-karsiti; hiber-garantisi YOK, bkz R6).
    SecureBuffer (anti_dump) ile ortusmez: o genel tampon, bu
    anahtar-yasam-dongusu.

Kullanim:
    from HyperCipherAnti import anti_key_extraction as ake
    ake.register_secret("master", master_bytearray)
    ake.assert_no_extraction()
    with ake.KeyVault(key_bytes, ttl_sec=60) as v:
        use(bytes(v))
"""
from __future__ import annotations

import ctypes
import gc
import hashlib
import hmac as _hmac
import math
import os
import signal as _signal
import sys
import threading
import time
import weakref
from typing import Callable, Dict, List, Optional, Tuple

__all__ = [
    "KeyExtractionDetected",
    "register_secret",
    "unregister_secret",
    "watch_file",
    "unwatch_file",
    "is_extracted",
    "check_all",
    "score",
    "assert_no_extraction",
    "audit_text",
    "count_secret_copies",
    "scan_own_image",
    "audit_file_perms",
    "is_cloud_synced",
    "shred_file",
    "arm_exit_wipe",
    "lock_limits",
    "clear_clipboard",
    "clipboard_history_enabled",
    "disable_clipboard_history",
    "harden",
    "start_watchdog",
    "stop_all_watchdogs",
    "status",
    "guard",
    "KeyVault",
    "set_verbose",
    "health",
]

_VERBOSE = os.environ.get("HYPERCIPHER_ANTIKEYEX_VERBOSE", "") == "1"


def set_verbose(on: bool = True) -> None:
    """Sessiz default; sadece opt-in debug yazdirir (sir icermez)."""
    global _VERBOSE
    _VERBOSE = bool(on)


def _log(msg: str) -> None:
    if _VERBOSE:
        try:
            print(f"[anti_key_extraction] {msg}", file=sys.stderr)
        except Exception:
            pass


class KeyExtractionDetected(Exception):
    """Sizinti gostergesi (hangi sinyal OP AKTIR)."""


# --------------------------------------------------------------------------
# Tripwire registry (digest-only)
# --------------------------------------------------------------------------
_registry_lock = threading.Lock()
# name -> {"digest": bytes(32), "len": int}
_registry: Dict[str, Dict[str, object]] = {}
# path set (keyfile/passphrase-file izleme)
_watched_files_lock = threading.Lock()
_watched_files: set = set()
_health = {"sensor_fail": 0}


def _fail() -> None:
    _health["sensor_fail"] += 1


def health() -> Dict[str, int]:
    """Sensor hata sayaci (fail-closed telemetri)."""
    return dict(_health)


def lock_limits() -> Dict[str, object]:
    """R20: bellek-kilitleme limitleri denetimi (RLIMIT_MEMLOCK/ENOMEM).

    sodium_mlock doktrini: limit asiminda mlock ENOMEM ile duser.
    Donus: {"memlock_soft": int|None, "memlock_hard": int|None,
    "platform": str}. Non-POSIX -> None degerler (bilinmiyor).
    """
    out: Dict[str, object] = {"memlock_soft": None, "memlock_hard": None,
                              "platform": sys.platform}
    try:
        import resource as _res
        try:
            soft, hard = _res.getrlimit(_res.RLIMIT_MEMLOCK)
            out["memlock_soft"] = int(soft) if soft >= 0 else soft
            out["memlock_hard"] = int(hard) if hard >= 0 else hard
        except Exception:
            pass
    except Exception:
        pass
    return out


def register_secret(name: str, material: bytes | bytearray | memoryview) -> str:
    """Sirri tripwire'a kaydet. SADECE digest+len saklanir (sir tutulmaz).

    material bytearray ise kopyalanmaz, hash'lenip birakilir (wipe YAPILMAZ;
    sahipligi cagiranda kalir — KeyVault kullaniminda vault siler).
    """
    try:
        mv = bytes(material)
    except Exception:
        raise ValueError("register_secret: material okunamadi")
    if not mv:
        raise ValueError("register_secret: bos material")
    digest = hashlib.sha256(mv).digest()
    with _registry_lock:
        _registry[str(name)] = {"digest": digest, "len": len(mv)}
    # Kaynak kopyayi bilerek SIFIRLAMIYORUZ (cagiranin tamponu olabilir).
    del mv
    _log(f"registered '{name}'")
    return str(name)


def unregister_secret(name: str) -> bool:
    """Kaydi sil (digest bellekten duser)."""
    with _registry_lock:
        if name in _registry:
            del _registry[name]
            return True
    return False


def _snapshot() -> List[Tuple[bytes, int]]:
    with _registry_lock:
        return [(v["digest"], v["len"]) for v in _registry.values() if isinstance(v.get("digest"), bytes)]  # type: ignore[union-attr]


def watch_file(path: str) -> str:
    """keyfile/passphrase-file izin denetimine al."""
    with _watched_files_lock:
        _watched_files.add(os.path.abspath(path))
    return os.path.abspath(path)


def unwatch_file(path: str) -> bool:
    ap = os.path.abspath(path)
    with _watched_files_lock:
        if ap in _watched_files:
            _watched_files.remove(ap)
            return True
    return False


# --------------------------------------------------------------------------
# Yardimcilar: entropi + sabit-zamanli karsilastirma
# --------------------------------------------------------------------------
def _shannon(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    ent = 0.0
    for c in freq:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent


def _looks_secret_shaped(text: str) -> bool:
    """Kayitsiz genel argv taramasi: uzun + yuksek-entropili token."""
    try:
        if len(text) < 24 or len(text) > 4096:
            return False
        if any(ch.isspace() for ch in text):
            return False
        classes = 0
        if any(c.islower() for c in text):
            classes += 1
        if any(c.isupper() for c in text):
            classes += 1
        if any(c.isdigit() for c in text):
            classes += 1
        if any(not c.isalnum() for c in text):
            classes += 1
        if classes < 3:
            return False
        raw = text.encode("utf-8", "ignore")
        return _shannon(raw) >= 4.0
    except Exception:
        return False


def _candidate_raws(text: str):
    """str adayi olasi ham-byte karsiliklari (utf-8 metin + latin1 binary).

    R3-notu: environ/pano str'dir; binary sir latin1 ile tasinmis olabilir.
    utf-8 tek basina digest tutmaz -> iki kodlama da denenir.
    """
    try:
        yield text.encode("utf-8", "ignore")
    except Exception:
        pass
    try:
        yield text.encode("latin1")
    except Exception:
        pass


def _contains_digest(candidate: bytes, digest: bytes, ln: int) -> bool:
    """K1: cap-asimi korluk YOK — buyuk metin pencereli taranir.

    Pencere 256KB, overlap ln-1 (sinir-kesit kacis yok). Pencere >= ln
    olmali (dev sirlar icin buyutulur). Erken-cikis YOK (timing-oracle
    disiplini korunur).
    """
    try:
        if ln <= 0 or len(candidate) < ln:
            return False
        if len(candidate) == ln:
            return bool(_hmac.compare_digest(hashlib.sha256(candidate).digest(), digest))
        win = 256 * 1024
        if win < ln:
            win = ln
        step = win - ln + 1
        if step <= 0:
            step = 1
        found = False
        start = 0
        end = len(candidate)
        while start < end:
            try:
                chunk = candidate[start:start + win]
            except Exception:
                break
            if len(chunk) < ln:
                break
            for i in range(0, len(chunk) - ln + 1):
                try:
                    if _hmac.compare_digest(hashlib.sha256(chunk[i:i + ln]).digest(), digest):
                        found = True
                except Exception:
                    continue
            if start + win >= end:
                break
            start += step
        return found
    except Exception:
        return False


def _digest_matches(candidate: bytes, snaps: List[Tuple[bytes, int]]) -> bool:
    """Digest-eslesme (K1-pencereli: cap-asimi korluk yok)."""
    try:
        if not candidate:
            return False
        for digest, ln in snaps:
            try:
                if _contains_digest(candidate, digest, ln):
                    return True
            except Exception:
                continue
        return False
    except Exception:
        return False


# --------------------------------------------------------------------------
# Sinyaller
# --------------------------------------------------------------------------
def _sig_cmdline_leak() -> bool:
    """STRONG: kayitli sir argv'de VEYA secret-shapeli token argv'de.

    smallstep/wzrd-vault: /proc/pid/cmdline world-readable. hcli inline
    passphrase kabul etmez; bu sinyal onu zorlar + -c literal yakalar.
    """
    try:
        snaps = _snapshot()
        for idx, arg in enumerate(sys.argv):  # argv[0] dahil (R7d)
            try:
                raw = arg.encode("utf-8", "ignore") if isinstance(arg, str) else bytes(arg)
            except Exception:
                continue
            if snaps and _digest_matches(raw, snaps):
                return True
            # Sekil-taramasi argv[1:]+ : argv[0] script-YOLudur; uzun
            # venv/derin-yol FP uretirdi. Kayitli-sir digest ile argv[0]'da
            # da yakalanir (yukaridaki dal), sekil sarti gerekmez.
            if idx == 0:
                continue
            if isinstance(arg, str) and _looks_secret_shaped(arg):
                return True
        return False
    except Exception:
        _fail()
        return False


def _sig_env_leak() -> bool:
    """STRONG: kayitli sir process environ'da (child-miras/log/dump riski)."""
    try:
        snaps = _snapshot()
        if not snaps:
            return False
        for _k, val in os.environ.items():
            try:
                raws = list(_candidate_raws(val)) if isinstance(val, str) else [bytes(val)]
            except Exception:
                continue
            if any(_digest_matches(raw, snaps) for raw in raws):
                return True
        return False
    except Exception:
        _fail()
        return False


def _read_clipboard_text() -> Optional[str]:
    """Best-effort pano okuma (Windows CF_UNICODETEXT). Yoksa None."""
    try:
        if os.name != "nt":
            return None
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        CF_UNICODETEXT = 13
        if not user32.OpenClipboard(None):
            return None
        try:
            h = user32.GetClipboardData(CF_UNICODETEXT)
            if not h:
                return None
            ptr = kernel32.GlobalLock(h)
            if not ptr:
                return None
            try:
                return ctypes.wstring_at(ptr)
            finally:
                kernel32.GlobalUnlock(h)
        finally:
            user32.CloseClipboard()
    except Exception:
        return None


def _sig_clipboard_leak() -> bool:
    """WEAK: kayitli sir panoda (kopyala-yapistir kalintisi)."""
    try:
        snaps = _snapshot()
        if not snaps:
            return False
        text = _read_clipboard_text()
        if not text:
            return False
        return any(_digest_matches(raw, snaps) for raw in _candidate_raws(text))
    except Exception:
        _fail()
        return False


_LIVE_BUF_IDS: set = set()
_LIVE_BUF_LOCK = threading.Lock()


def _iter_candidate_buffers():
    """K2: gc container-traversal — nested/obje-ozniteligi/bytearray DAHIL.

    Derinlik<=4 ozyinelemeli yuruyus (dongu-korumali id-set + 100K obje
    butcesi + 10MB/obje cap). R11-FP cozumu: canli KeyVault tamponlari
    (_LIVE_BUF_IDS) ATLANIR — mesru vault'lar trip uretmez, sahipsiz
    bytearray kopyalar yakalanir. bytearray'den digest icin gecici bytes
    kopyasi kacinilmazdir (karsilastirma sonrasi referans duser).
    """
    seen: set = set()
    try:
        objs = gc.get_objects()
    except Exception:
        return
    budget = [100000]

    def _walk(o, depth: int):
        try:
            if budget[0] <= 0:
                return
            budget[0] -= 1
            try:
                oid = id(o)
            except Exception:
                return
            if oid in seen:
                return
            seen.add(oid)
            if isinstance(o, bytes) and not isinstance(o, bytearray):
                if 0 < len(o) <= 10 * 1024 * 1024:
                    yield ("bytes", o)
                return
            if isinstance(o, bytearray):
                try:
                    if oid in _LIVE_BUF_IDS:
                        return
                except Exception:
                    pass
                if 0 < len(o) <= 10 * 1024 * 1024:
                    try:
                        yield ("bytearray", bytes(o))
                    except Exception:
                        pass
                return
            if isinstance(o, str):
                try:
                    enc = o.encode("utf-8", "ignore")
                except Exception:
                    return
                if 0 < len(enc) <= 10 * 1024 * 1024:
                    yield ("str", enc)
                try:
                    enc1 = o.encode("latin1")
                    if enc1 != enc and 0 < len(enc1) <= 10 * 1024 * 1024:
                        yield ("str", enc1)
                except Exception:
                    pass
                return
            if depth <= 0:
                return
            if isinstance(o, dict):
                try:
                    kids = list(o.values())
                except Exception:
                    return
            elif isinstance(o, (list, tuple, set, frozenset)):
                try:
                    kids = list(o)
                except Exception:
                    return
            else:
                kids = None
                try:
                    import types as _t
                    if isinstance(o, _t.FrameType):
                        try:
                            kids = list(o.f_locals.values())
                        except Exception:
                            return
                    else:
                        try:
                            d = object.__getattribute__(o, "__dict__")
                            kids = list(d.values()) if isinstance(d, dict) else None
                        except Exception:
                            kids = None
                        if kids is None:
                            try:
                                slots = getattr(type(o), "__slots__", None)
                                if isinstance(slots, str):
                                    slots = (slots,)
                                if slots:
                                    sk = []
                                    for _s in list(slots):
                                        try:
                                            sk.append(object.__getattribute__(o, _s))
                                        except Exception:
                                            continue
                                    kids = sk if sk else None
                            except Exception:
                                kids = None
                except Exception:
                    return
            if not kids:
                return
            for _k in kids:
                try:
                    for _r in _walk(_k, depth - 1):
                        yield _r
                except Exception:
                    continue
        except Exception:
            return

    for obj in objs:
        try:
            if isinstance(obj, dict):
                vals = list(obj.values())
            elif isinstance(obj, (list, tuple, set, frozenset)):
                vals = list(obj)
            else:
                try:
                    import types as _t2
                    if isinstance(obj, _t2.FrameType):
                        try:
                            vals = list(obj.f_locals.values())
                        except Exception:
                            continue
                    else:
                        continue
                except Exception:
                    continue
            for v in vals:
                try:
                    for _r in _walk(v, 4):
                        yield _r
                except Exception:
                    continue
        except Exception:
            continue


def _sig_immutable_copies() -> bool:
    """WEAK: kayitli sirrin immutable (bytes/str) kopyasi gc'de yasiyor.

    bytes/str SIFIRLANAMAZ (cryptography.io limits) -> varligi hijyen
    ihlalidir. Agir (container-traversal) -> FULL sette, watchdog'da YOK.
    """
    try:
        snaps = _snapshot()
        if not snaps:
            return False
        lens = {ln for _, ln in snaps}
        for _kind, raw in _iter_candidate_buffers():
            try:
                if len(raw) in lens and _digest_matches(raw, snaps):
                    return True
            except Exception:
                continue
        return False
    except Exception:
        _fail()
        return False


def _iter_own_image_paths() -> List[str]:
    """K8: calisan goruntu-kumesi — exe + script + frozen-bundle + yuklu ext-moduller.

    scan_own_image artik SADECE sys.executable degil: __main__ script'i,
    PyInstaller/zipapp bundle dizini (.py/.pyd/.dll/.so, cap'li) ve yuklu
    native eklentiler de taranir.
    """
    paths: List[str] = []
    try:
        exe = sys.executable
        if exe and os.path.isfile(exe):
            paths.append(exe)
    except Exception:
        pass
    try:
        main_mod = sys.modules.get("__main__")
        mf = getattr(main_mod, "__file__", None) if main_mod is not None else None
        if mf and os.path.isfile(mf):
            paths.append(mf)
    except Exception:
        pass
    try:
        argv0 = sys.argv[0] if sys.argv else ""
        if argv0 and os.path.isfile(argv0):
            ap = os.path.abspath(argv0)
            if ap not in paths:
                paths.append(ap)
    except Exception:
        pass
    try:
        bundle = getattr(sys, "_MEIPASS", None) or getattr(sys, "_MEIPATH", None)
        if bundle and os.path.isdir(bundle):
            try:
                names = os.listdir(bundle)[:256]
            except Exception:
                names = []
            for n in names:
                try:
                    if n.lower().endswith((".py", ".pyd", ".dll", ".so", ".dylib")):
                        p = os.path.join(bundle, n)
                        if os.path.isfile(p):
                            paths.append(p)
                except Exception:
                    continue
    except Exception:
        pass
    try:
        mods = list(sys.modules.items())[:4096]
        for _n, _m in mods:
            try:
                if len(paths) >= 512:
                    break
                f = getattr(_m, "__file__", None)
                if f and isinstance(f, str) and f.lower().endswith((".pyd", ".dll", ".so", ".dylib")):
                    if os.path.isfile(f) and f not in paths:
                        paths.append(f)
            except Exception:
                continue
    except Exception:
        pass
    return paths


def _libc_prctl():
    """prctl icin libc tutamaci (glibc yoksa musl/dylib fallback)."""
    try:
        return ctypes.CDLL("libc.so.6", use_errno=True)
    except Exception:
        pass
    try:
        return ctypes.CDLL(None, use_errno=True)
    except Exception:
        return None


def _prctl_get_dumpable() -> Optional[int]:
    """PR_GET_DUMPABLE(3): 1=dumpable(ptrace-acik), 0=korumali, None=bilinmiyor."""
    try:
        if not (os.name == "posix" and sys.platform.startswith("linux")):
            return None
        libc = _libc_prctl()
        if libc is None:
            return None
        libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong,
                               ctypes.c_ulong, ctypes.c_ulong]
        libc.prctl.restype = ctypes.c_int
        rc = libc.prctl(3, 0, 0, 0, 0)
        if rc < 0:
            return None
        return int(rc)
    except Exception:
        return None


def _prctl_set_undumpable() -> bool:
    """prctl(PR_SET_DUMPABLE=4, 0): core+ptrace+proc-mem'i same-UID'e kapat."""
    try:
        if not (os.name == "posix" and sys.platform.startswith("linux")):
            return False
        libc = _libc_prctl()
        if libc is None:
            return False
        libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong,
                               ctypes.c_ulong, ctypes.c_ulong]
        libc.prctl.restype = ctypes.c_int
        return libc.prctl(4, 0, 0, 0, 0) == 0
    except Exception:
        return False


def _sig_dumpable_process() -> bool:
    """WEAK (R5): Linux'ta process dumpable=1 -> same-UID ptrace +
    /proc/pid/mem + core'a acik = canli-extraction vektoru."""
    try:
        d = _prctl_get_dumpable()
        if d is None:
            return False  # non-Linux veya okunamadi: bilinmiyor
        return d == 1
    except Exception:
        _fail()
        return False


def _apply_windows_mitigations() -> Dict[str, bool]:
    """R4: ExtensionPoint + ImageLoad politikalari (best-effort, tek-yonlu).

    SignaturePolicy BILEREK YOK (CPython .pyd'leri MS-signed degil).
    Politikalar kalici sIkIlastirma only (gevsetilemez) -> harden'da
    bir kez uygulanir; basarisizlik sessiz False'dur.
    """
    out = {"extension_point": False, "image_load": False}
    try:
        if os.name != "nt":
            return out
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.SetProcessMitigationPolicy.argtypes = [ctypes.c_int, ctypes.c_void_p,
                                                        ctypes.c_size_t]
        kernel32.SetProcessMitigationPolicy.restype = ctypes.c_bool
        ext = ctypes.c_uint32(1)  # DisableExtensionPoints (policy 6)
        try:
            out["extension_point"] = bool(kernel32.SetProcessMitigationPolicy(
                6, ctypes.byref(ext), ctypes.sizeof(ext)))
        except Exception:
            pass
        img = ctypes.c_uint32(1 | 2 | 4)  # NoRemote|NoLowLabel|PreferSys32 (policy 10)
        try:
            out["image_load"] = bool(kernel32.SetProcessMitigationPolicy(
                10, ctypes.byref(img), ctypes.sizeof(img)))
        except Exception:
            pass
    except Exception:
        pass
    return out


def _verify_windows_mitigations() -> Dict[str, Optional[bool]]:
    """R14: kurulan politikalari GERI OKU (kur + dogrula).

    GetProcessMitigationPolicy(GetCurrentProcess(), policy, &DWORD, 4).
    ext&1 (DisableExtensionPoints), img&7==7 (NoRemote|NoLowLabel|
    PreferSys32). Non-Windows -> None (bilinmiyor).
    """
    out: Dict[str, Optional[bool]] = {"extension_point": None, "image_load": None}
    try:
        if os.name != "nt":
            return out
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        try:
            hproc = kernel32.GetCurrentProcess()
        except Exception:
            return out
        kernel32.GetProcessMitigationPolicy.argtypes = [ctypes.c_void_p, ctypes.c_int,
                                                        ctypes.c_void_p, ctypes.c_size_t]
        kernel32.GetProcessMitigationPolicy.restype = ctypes.c_bool
        try:
            ext = ctypes.c_uint32(0)
            if kernel32.GetProcessMitigationPolicy(hproc, 6,
                                                   ctypes.byref(ext), ctypes.sizeof(ext)):
                out["extension_point"] = bool(ext.value & 1)
        except Exception:
            pass
        try:
            img = ctypes.c_uint32(0)
            if kernel32.GetProcessMitigationPolicy(hproc, 10,
                                                   ctypes.byref(img), ctypes.sizeof(img)):
                out["image_load"] = bool((img.value & 7) == 7)
        except Exception:
            pass
    except Exception:
        pass
    return out
    """KALDIRILDI (R7b): digest-only registry ile imaj-taramasi matematiksel
    imkansizdi (olupass kodu temizlendi). Gercek denetim scan_own_image()
    audit'indedir. Sinyal tablosundan cikarildi; stub import-uyumlulugu
    icin False dondurur."""
    return False


def _file_world_readable(path: str) -> Optional[bool]:
    """True/False/None(bilinmiyor). POSIX mode-bit; Windows ACL (K6).

    K6: Windows'ta Everyone SID'e GRANT edilmis okuma biti aranir
    (GetNamedSecurityInfoW + ACE yuruyusu + EqualSid). Acik DENY ->
    False; GRANT(read) -> True; karar verilemezse None (suphe DEGIL,
    bilinmiyor). Best-effort, sessiz.
    """
    try:
        st = os.stat(path)
        if os.name == "posix":
            return bool(st.st_mode & 0o077)
        if os.name != "nt":
            return None
        return _win_everyone_can_read(path)
    except Exception:
        return None


def _win_everyone_can_read(path: str) -> Optional[bool]:
    """K6: Everyone SID okuma-hakki (ctypes Advapi32, pywin32'suz)."""
    try:
        adv = ctypes.WinDLL("advapi32", use_last_error=True)
        krn = ctypes.WinDLL("kernel32", use_last_error=True)
    except Exception:
        return None
    psd = ctypes.c_void_p()
    try:
        try:
            adv.GetNamedSecurityInfoW.restype = ctypes.c_ulong
            adv.GetNamedSecurityInfoW.argtypes = (ctypes.c_wchar_p, ctypes.c_int,
                                                 ctypes.c_ulong,
                                                 ctypes.POINTER(ctypes.c_void_p),
                                                 ctypes.POINTER(ctypes.c_void_p),
                                                 ctypes.POINTER(ctypes.c_void_p),
                                                 ctypes.POINTER(ctypes.c_void_p),
                                                 ctypes.POINTER(ctypes.c_void_p))
            adv.GetAce.restype = ctypes.c_bool
            adv.GetAce.argtypes = (ctypes.c_void_p, ctypes.c_ulong,
                                   ctypes.POINTER(ctypes.c_void_p))
            adv.EqualSid.restype = ctypes.c_bool
            adv.EqualSid.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
            adv.CreateWellKnownSid.restype = ctypes.c_bool
            adv.CreateWellKnownSid.argtypes = (ctypes.c_int, ctypes.c_void_p,
                                               ctypes.c_void_p,
                                               ctypes.POINTER(ctypes.c_ulong))
        except Exception:
            return None
        owner = ctypes.c_void_p()
        group = ctypes.c_void_p()
        dacl = ctypes.c_void_p()
        sacl = ctypes.c_void_p()
        try:
            rc = adv.GetNamedSecurityInfoW(path, 1, 4, ctypes.byref(owner),
                                           ctypes.byref(group), ctypes.byref(dacl),
                                           ctypes.byref(sacl), ctypes.byref(psd))
        except Exception:
            return None
        if rc != 0 or not psd.value or not dacl.value:
            return None
        try:
            sids = []
            for _wt in (1, 27, 11):
                try:
                    _s = ctypes.create_string_buffer(68)
                    _z = ctypes.c_ulong(68)
                    if adv.CreateWellKnownSid(_wt, None, _s, ctypes.byref(_z)):
                        sids.append(bytes(_s.raw[:_z.value]))
                except Exception:
                    continue
            if not sids:
                return None
            try:
                ace_count = ctypes.c_ushort.from_address(dacl.value + 4).value
            except Exception:
                return None
            grant = False
            for i in range(min(ace_count, 256)):
                try:
                    pace = ctypes.c_void_p()
                    if not adv.GetAce(dacl, i, ctypes.byref(pace)):
                        continue
                    base = pace.value
                    if not base:
                        continue
                    try:
                        atype = ctypes.c_ubyte.from_address(base).value
                    except Exception:
                        continue
                    try:
                        mask = ctypes.c_ulong.from_address(base + 4).value
                    except Exception:
                        continue
                    try:
                        psid = base + 8
                        try:
                            is_world = False
                            for _s in sids:
                                try:
                                    if adv.EqualSid(ctypes.c_void_p(psid),
                                                    ctypes.c_char_p(_s)):
                                        is_world = True
                                        break
                                except Exception:
                                    continue
                        except Exception:
                            continue
                    except Exception:
                        continue
                    if not is_world:
                        continue
                    read_bits = mask & 0x80000001
                    if atype == 1 and read_bits:
                        return False
                    if atype == 0 and read_bits:
                        grant = True
                except Exception:
                    continue
            return True if grant else None
        finally:
            try:
                krn.LocalFree(psd)
            except Exception:
                pass
    except Exception:
        return None


def _sig_watched_file_perms() -> bool:
    """WEAK: izlenen keyfile/passphrase-file world-readable."""
    try:
        with _watched_files_lock:
            paths = list(_watched_files)
        for p in paths:
            r = _file_world_readable(p)
            if r is True:
                return True
        return False
    except Exception:
        _fail()
        return False


def _cloud_roots() -> List[str]:
    """Bulut-senkron kokleri: OneDrive env + yaygin istemci klasorleri."""
    roots: List[str] = []
    try:
        for var in ("OneDrive", "OneDriveCommercial", "OneDriveConsumer"):
            v = os.environ.get(var, "")
            if v:
                roots.append(v)
        home = os.path.expanduser("~")
        for sub in ("OneDrive", "Dropbox", os.path.join("Google Drive"),
                    os.path.join("Google Drive", "My Drive"),
                    os.path.join("Library", "Mobile Documents"),
                    "iCloudDrive", "Nextcloud", "pCloud Drive"):
            roots.append(os.path.join(home, sub))
    except Exception:
        pass
    return roots


def _canonical_path(path: str) -> str:
    """K8: symlink/junction/subst-cozumulmus kanonik yol.

    realpath + Windows'ta GetFinalPathNameByHandleW (subst/junction
    realpath'ten kacar). Hata -> normcase(abspath) fallback.
    """
    try:
        ap = os.path.normcase(os.path.abspath(path))
    except Exception:
        return str(path)
    try:
        rp = os.path.normcase(os.path.realpath(path))
        if rp:
            ap = rp
    except Exception:
        pass
    try:
        if os.name == "nt":
            fin = _win_final_path(path)
            if fin:
                ap = fin
    except Exception:
        pass
    return ap


def _win_final_path(path: str) -> str:
    """GetFinalPathNameByHandleW ile nihai yol (\\?\ oneki temizlenir)."""
    try:
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    except Exception:
        return ""
    h = None
    try:
        try:
            k32.CreateFileW.restype = ctypes.c_void_p
            k32.CreateFileW.argtypes = (ctypes.c_wchar_p, ctypes.c_ulong,
                                        ctypes.c_ulong, ctypes.c_void_p,
                                        ctypes.c_ulong, ctypes.c_ulong,
                                        ctypes.c_void_p)
            k32.GetFinalPathNameByHandleW.restype = ctypes.c_ulong
            k32.GetFinalPathNameByHandleW.argtypes = (ctypes.c_void_p,
                                                      ctypes.c_wchar_p,
                                                      ctypes.c_ulong,
                                                      ctypes.c_ulong)
        except Exception:
            return ""
        try:
            h = k32.CreateFileW(path, 0, 7, None, 3, 0x02000000, None)
        except Exception:
            return ""
        if h in (None, 0, -1, ctypes.c_void_p(-1).value):
            return ""
        try:
            buf = ctypes.create_unicode_buffer(1024)
            n = k32.GetFinalPathNameByHandleW(h, buf, 1024, 0)
            if not n:
                return ""
            s = str(buf.value)
            low = s.lower()
            if low.startswith("\\\\?\\"):
                s = s[4:]
                if s.lower().startswith("unc\\"):
                    s = "\\\\" + s[4:]
            return os.path.normcase(s)
        finally:
            try:
                k32.CloseHandle(h)
            except Exception:
                pass
    except Exception:
        return ""


def is_cloud_synced(path: str) -> Optional[bool]:
    """Dosya bulut-senkron kok altinda mi? True/False/None(hata).

    R12 + K8: OneDrive KFM + SharePoint mirasi = keyfile sessizce buluta
    cikar. Karsilastirma KANONIK yollarla (symlink/junction/subst-cozumlu);
    prefix-aynisim (OneDriveX vs OneDrive) sep-sinirli eslesir.
    """
    try:
        ap = _canonical_path(path)
        for root in _cloud_roots():
            try:
                r = _canonical_path(root)
                if ap == r or ap.startswith(r + os.sep):
                    return True
            except Exception:
                continue
        return False
    except Exception:
        _fail()
        return None


def _sig_cloud_synced_keyfile() -> bool:
    """WEAK (R12): izlenen keyfile/passphrase-file bulut-senkron altinda."""
    try:
        with _watched_files_lock:
            paths = list(_watched_files)
        for p in paths:
            if is_cloud_synced(p) is True:
                return True
        return False
    except Exception:
        _fail()
        return False


def _raw_results(light_only: bool = False) -> Dict[str, bool]:
    table = _SIGNALS_LIGHT if light_only else _SIGNALS_FULL
    out: Dict[str, bool] = {}
    for name, fn, _w in table:
        try:
            out[name] = bool(fn())
        except Exception:
            _fail()
            out[name] = True
    return out


def _score_from_raw(raw: Dict[str, bool], light_only: bool = False) -> Tuple[int, int, int]:
    weights = dict((n, w) for n, _f, w in (_SIGNALS_LIGHT if light_only else _SIGNALS_FULL))
    s = sum(1 for n, v in raw.items() if v and weights.get(n) == "STRONG")
    w = sum(1 for n, v in raw.items() if v and weights.get(n) == "WEAK")
    return (s, w, s * 100 + w * 30)


def score(light_only: bool = False) -> Tuple[int, int, int]:
    """(strong_n, weak_n, toplam_puan). STRONG=100, WEAK=30."""
    return _score_from_raw(_raw_results(light_only=light_only), light_only)


def is_extracted(light_only: bool = False) -> bool:
    """Trip iff >=1 strong VEYA >=2 weak."""
    s, w, _t = score(light_only=light_only)
    return (s >= 1) or (w >= 2)


def check_all(light_only: bool = False) -> Dict[str, bool]:
    """Kardes-kontrat: ham sinyal sozlugu (is_extracted karari icin)."""
    return _raw_results(light_only=light_only)


def assert_no_extraction(light_only: bool = False) -> None:
    """Sizinti gostergesi varsa KeyExtractionDetected (sebep OP AKTIR)."""
    if is_extracted(light_only=light_only):
        raise KeyExtractionDetected("protected")


def status(light_only: bool = False) -> Dict[str, object]:
    """Sessiz durum raporu (sinyal isimleri + skor, sir YOK). Tek-pas (R7c)."""
    raw = _raw_results(light_only=light_only)
    s, w, t = _score_from_raw(raw, light_only)
    verdict = (s >= 1) or (w >= 2)
    return {"signals": raw, "strong": s, "weak": w, "total": t,
            "verdict": verdict, "health": health()}


# --------------------------------------------------------------------------
# Audit yardimcilari (dogru-kullanim denetimi, sir DIŞA AKMAZ)
# --------------------------------------------------------------------------
def audit_text(text: str | bytes) -> bool:
    """Verilen metin kayitli sir iceriyor mu? (log/error-message denetimi).

    anti_error_leakage ile birlikte kullanilir: hata mesaji uretmeden
    once audit_text(msg) False olmali.
    """
    try:
        snaps = _snapshot()
        if not snaps:
            return False
        raw = text.encode("utf-8", "ignore") if isinstance(text, str) else bytes(text)
        raws = [raw]
        if isinstance(text, str):
            try:
                enc1 = text.encode("latin1")
                if enc1 != raw:
                    raws.append(enc1)
            except Exception:
                pass
        # Alt-string eslesmesi (K1: cap YOK — buyuk metin pencereli taranir,
        # digest-only registry'de AC kurulamaz; R21 erken-cikis YOK).
        found = False
        for candidate in raws:
            for digest, ln in snaps:
                if ln <= 0 or len(candidate) < ln:
                    continue
                try:
                    if _contains_digest(candidate, digest, ln):
                        found = True
                except Exception:
                    continue
        return found
    except Exception:
        _fail()
        return False


def count_secret_copies() -> Dict[str, int]:
    """gc container'larinda yasayan kopya sayimi (hijyen olcumu)."""
    out = {"bytes": 0, "str": 0, "bytearray": 0}
    try:
        snaps = _snapshot()
        if not snaps:
            return out
        lens = {ln for _, ln in snaps}
        for kind, raw in _iter_candidate_buffers():
            try:
                if len(raw) in lens and _digest_matches(raw, snaps):
                    try:
                        out[kind] += 1
                    except KeyError:
                        out[kind] = 1
            except Exception:
                continue
    except Exception:
        _fail()
    return out


def scan_own_image(material: bytes | bytearray) -> bool:
    """Own-binary'de material gecer mi? True=sizinti (frozen-exe strings).

    material cagri-disinda tutulmaz (hash'lenip birakilir).
    """
    try:
        secret = bytes(material)
        if not secret:
            return False
        for path in _iter_own_image_paths():
            try:
                try:
                    f = open(path, "rb")
                except Exception:
                    continue
                try:
                    # R23: boyut FD uzerinden (TOCTOU'suz).
                    size = os.fstat(f.fileno()).st_size
                except Exception:
                    try:
                        f.close()
                    except Exception:
                        pass
                    continue
                if size <= 0 or size > 256 * 1024 * 1024:
                    try:
                        f.close()
                    except Exception:
                        pass
                    continue
                overlap = b""
                ln = len(secret)
                with f:
                    while True:
                        chunk = f.read(4 * 1024 * 1024)
                        if not chunk:
                            break
                        buf = overlap + chunk
                        if buf.find(secret) >= 0:
                            return True
                        overlap = buf[-(ln - 1):] if ln > 1 else b""
            except Exception:
                continue
        return False
    except Exception:
        _fail()
        return False
    finally:
        try:
            del secret
        except Exception:
            pass


def audit_file_perms(path: str) -> Optional[bool]:
    """Dosya world-readable mi? True/False/None(bilinmiyor-Windows)."""
    try:
        return _file_world_readable(path)
    except Exception:
        _fail()
        return None


def shred_file(path: str) -> bool:
    """Emekli keyfile/passphrase-file'i guvenli sil (best-effort).

    R13 (NIST SP 800-88 Rev.2): multi-pass DEPRECATED -> single-pass
    (random + zero) + flush + fsync + rename + unlink + yokluk-dogrulama.
    DURUSTLUK NOTU: SSD/COW/journaling'de garanti YOK (FTL/wear-leveling/
    over-provisioning erisilemez kopya birakir). R19: dosya ADI +
    varlik-gecmisi NTFS $UsnJrnl:$J'de gunlerce kalir -> rename hedefi
    rastgele 16-hex (anlamli-ad kalintisi minimize); $MFT/$LogFile/VSS/
    pagefile ayri kalir. Gercek cozum: sirri bastan plaintext yazmamak
    (KeyVault) veya crypto-shred + FDE. Basari True, her basarisizlik
    sessiz False (fail-closed degil, hijyen API'sidir).
    """
    try:
        ap = os.path.abspath(path)
        try:
            f = open(ap, "r+b")
        except Exception:
            return False
        try:
            # R23: boyut FD uzerinden (getsize+open TOCTOU'suz; EAFP).
            try:
                size = os.fstat(f.fileno()).st_size
            except Exception:
                size = -1
            if size < 0 or size > 256 * 1024 * 1024:
                try:
                    f.close()
                except Exception:
                    pass
                return False
            with f:
                chunk = 1024 * 1024
                left = size
                while left > 0:
                    n = chunk if left > chunk else left
                    f.write(os.urandom(n))
                    left -= n
                f.flush()
                try:
                    os.fsync(f.fileno())
                except Exception:
                    pass
                f.seek(0)
                left = size
                zeros = b"\x00" * chunk
                while left > 0:
                    n = chunk if left > chunk else left
                    f.write(zeros[:n])
                    left -= n
                f.flush()
                try:
                    os.fsync(f.fileno())
                except Exception:
                    pass
        except Exception:
            return False
        try:
            d = os.path.dirname(ap) or "."
            try:
                rnd = os.urandom(8).hex()
            except Exception:
                rnd = "deadbeefdeadbeef"
            tmp = os.path.join(d, ".shred-" + rnd)
            try:
                os.rename(ap, tmp)
            except Exception:
                tmp = ap
            os.remove(tmp)
        except Exception:
            return False
        return not os.path.exists(ap)
    except Exception:
        _fail()
        return False


def clear_clipboard() -> bool:
    """Panoyu bosalt (kopyalanmis passphrase kalintisi). Best-effort."""
    try:
        if os.name != "nt":
            return False
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        if not user32.OpenClipboard(None):
            return False
        try:
            return bool(user32.EmptyClipboard())
        finally:
            user32.CloseClipboard()
    except Exception:
        _fail()
        return False


_CLIP_HIST_KEY = r"Software\Microsoft\Clipboard"


def clipboard_history_enabled() -> Optional[bool]:
    """Win+V pano GECMISI acik mi? True/False/None(non-Windows&hata).

    R8: gecmis 25 oge + bulut-senkron = clear_clipboard sonrasi bile
    retention. Okuma HKCU + winreg (stdlib), sessiz.
    """
    try:
        if os.name != "nt":
            return None
        import winreg as _wr
        try:
            with _wr.OpenKey(_wr.HKEY_CURRENT_USER, _CLIP_HIST_KEY) as k:
                val, _typ = _wr.QueryValueEx(k, "EnableClipboardHistory")
                return bool(val)
        except FileNotFoundError:
            return False  # anahtar yok = ozellik hic acilmamis
    except Exception:
        return None


def disable_clipboard_history() -> bool:
    """Pano gecmisini kapat (HKCU yazma, admin gerekmez, best-effort)."""
    try:
        if os.name != "nt":
            return False
        import winreg as _wr
        try:
            with _wr.CreateKey(_wr.HKEY_CURRENT_USER, _CLIP_HIST_KEY) as k:
                _wr.SetValueEx(k, "EnableClipboardHistory", 0, _wr.REG_DWORD, 0)
                return True
        except Exception:
            return False
    except Exception:
        _fail()
        return False


def _sig_clipboard_history() -> bool:
    """WEAK (R8): pano gecmisi ETKIN -> kopyalanan sir 25 ogelik
    retention + bulut-senkron riski altinda (T1115)."""
    try:
        r = clipboard_history_enabled()
        if r is None:
            return False
        return bool(r)
    except Exception:
        _fail()
        return False


_SIGNALS_LIGHT: List[Tuple[str, Callable[[], bool], str]] = [
    ("cmdline_leak", _sig_cmdline_leak, "STRONG"),
    ("env_leak", _sig_env_leak, "STRONG"),
    ("clipboard_leak", _sig_clipboard_leak, "WEAK"),
    ("clipboard_history", _sig_clipboard_history, "WEAK"),
    ("watched_file_perms", _sig_watched_file_perms, "WEAK"),
    ("cloud_synced_keyfile", _sig_cloud_synced_keyfile, "WEAK"),
]

_SIGNALS_HEAVY: List[Tuple[str, Callable[[], bool], str]] = [
    ("immutable_copies", _sig_immutable_copies, "WEAK"),
    ("dumpable_process", _sig_dumpable_process, "WEAK"),
]

_SIGNALS_FULL = _SIGNALS_LIGHT + _SIGNALS_HEAVY


def harden() -> Dict[str, object]:
    """Best-effort guclendirme: pano + dumpable-kapatma (Linux) + Win
    mitigasyonlari; degismeyen ortami (env) DEGISTIRMEZ. Rapor dondurur.
    """
    out: Dict[str, object] = {}
    try:
        out["clipboard_cleared"] = clear_clipboard()
    except Exception:
        out["clipboard_cleared"] = False
    try:
        out["clipboard_history_disabled"] = disable_clipboard_history()
    except Exception:
        out["clipboard_history_disabled"] = False
    try:
        out["undumpable"] = _prctl_set_undumpable()
    except Exception:
        out["undumpable"] = False
    try:
        out["mitigations"] = _apply_windows_mitigations()
    except Exception:
        out["mitigations"] = {}
    try:
        out["mitigations_verified"] = _verify_windows_mitigations()
    except Exception:
        out["mitigations_verified"] = {}
    try:
        out["status"] = status(light_only=True)
    except Exception:
        _fail()
        out["status"] = {}
    return out


# --------------------------------------------------------------------------
# Watchdog (LIGHT set + K5 default FULL devriye) + guard + yonetim
# --------------------------------------------------------------------------
_watchdog_stops: List[threading.Event] = []
_ADMIN_MODULES: Dict[str, str] = {}
_ADMIN_LOCKED = False
_ADMIN_DENIED = 0


def authorize_admin():
    """Operator modulunu kaydet (SADECE kilit-oncesi; boot sirasinda cagrilir).

    Ilk start_watchdog() kaydi kilitler. Donus: True=kaydedildi.
    """
    global _ADMIN_DENIED
    try:
        if _ADMIN_LOCKED:
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
        _ADMIN_MODULES[name] = fn
        return True
    except Exception:
        return False


def _check_admin() -> bool:
    """Dogrudan cagiran cerceve kayitli operator modulu mu? (dosya-dogrulamali)."""
    try:
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
        _ADMIN_DENIED += 1
    except Exception:
        pass
    raise KeyExtractionDetected("protected")


def start_watchdog(interval: float = 1.0,
                   on_trip: Optional[Callable[[Dict[str, bool]], None]] = None,
                   deep_every: int = 10):
    """Arka plan izleme (LIGHT sinyaller + K5: default FULL devriye).

    R17: deep_every=N>0 ise her N tick'te FULL set kosar (agir sinyaller
    gozetimsiz kalmaz, maliyet sinirli). K5: default 10 — heavy sinyaller
    (immutable_copies + dumpable_process) artik default'ta da calisir.
    interval 0.2-3600 araligina kelepcelenir (0/negatif busy-loop olmaz).
    """
    try:
        iv = float(interval)
    except Exception:
        iv = 1.0
    if not (0.2 <= iv <= 3600.0):
        iv = 1.0
    global _ADMIN_LOCKED
    try:
        _ADMIN_LOCKED = True
    except Exception:
        pass
    stop_ev = threading.Event()
    try:
        deep_n = int(deep_every)
    except Exception:
        deep_n = 0

    def _loop() -> None:
        tick = 0
        while not stop_ev.wait(iv):
            tick += 1
            try:
                full = deep_n > 0 and (tick % deep_n == 0)
                raw = _raw_results(light_only=not full)
                s = sum(1 for n, v in raw.items() if v and n in ("cmdline_leak", "env_leak"))
                w = sum(1 for n, v in raw.items() if v and n not in ("cmdline_leak", "env_leak"))
                if s >= 1 or w >= 2:
                    if on_trip is not None:
                        try:
                            on_trip(raw)
                        except Exception:
                            pass
            except Exception:
                continue

    t = threading.Thread(target=_loop, name="ake-watchdog", daemon=True)
    t.start()
    _watchdog_stops.append(stop_ev)

    def _stop() -> None:
        if not _check_admin():
            _deny_admin("_stop")
        stop_ev.set()

    return _stop


def stop_all_watchdogs() -> int:
    """Tum watchdog'lari durdur (YONETIM: kayitli operator sart). Donus: sayi."""
    if not _check_admin():
        _deny_admin("stop_all_watchdogs")
    n = 0
    try:
        stops = list(_watchdog_stops)
        _watchdog_stops.clear()
    except Exception:
        return 0
    for stop in stops:
        try:
            stop.set()
            n += 1
        except Exception:
            continue
    return n


class guard:
    """with-blogu: giriste + cikista kontrol (hafif)."""

    def __init__(self, light_only: bool = True):
        self._light = light_only

    def __enter__(self) -> "guard":
        assert_no_extraction(light_only=self._light)
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        try:
            assert_no_extraction(light_only=self._light)
        except KeyExtractionDetected:
            if exc_type is None:
                raise
        return False


# --------------------------------------------------------------------------
# Fork-guard (R15): cocuk process anahtar miras almasin
# --------------------------------------------------------------------------
_live_vaults: "weakref.WeakSet" = weakref.WeakSet()
_fork_guard_on = False


def _fork_child_wipe() -> None:
    """after_in_child: tum canli vault'lari sifirla (kilit YOK, minimal).

    Fork-safety: lock acquire YOK (ebeveynde tutuluyor olabilir ->
    deadlock), I/O YOK, sadece bellek sifirlama + bayrak. Best-effort.
    """
    try:
        for vault in list(_live_vaults):
            try:
                buf = object.__getattribute__(vault, "_buf")
                if isinstance(buf, bytearray) and buf:
                    # R22: bilerek INLINE sifirlama (_secure_zero cagrilmaz;
                    # o _native_lock alir, ebeveynde tutuluyorsa deadlock).
                    try:
                        for i in range(len(buf)):
                            buf[i] = 0
                    except Exception:
                        pass
                object.__setattr__(vault, "_dead", True)
                object.__setattr__(vault, "_shielded", False)
                object.__setattr__(vault, "_locked", False)
            except Exception:
                continue
    except Exception:
        pass


def _ensure_fork_guard() -> bool:
    """os.register_at_fork(after_in_child) bir kez kur (Unix-only)."""
    global _fork_guard_on
    try:
        if _fork_guard_on:
            return True
        reg = getattr(os, "register_at_fork", None)
        if reg is None:
            return False
        reg(after_in_child=_fork_child_wipe)
        _fork_guard_on = True
        return True
    except Exception:
        return False


_exit_wipe_armed = False
_exit_prev_handlers: Dict[str, object] = {}


def _exit_wipe_now() -> None:
    """Idempotent acil-sifirlama: vault'lar + registry digest'leri."""
    try:
        _fork_child_wipe()
    except Exception:
        pass
    try:
        with _registry_lock:
            _registry.clear()
    except Exception:
        pass


def arm_exit_wipe():
    """R18: cikis/sinyalde tum sirlari sifirla (atexit + sinyal zinciri).

    atexit (temiz cikis) + SIGTERM/SIGINT(/SIGBREAK/SIGABRT varsa) yakalar;
    onceki handler'a SAYGI gosterir (once wipe, sonra zincir). Idempotent;
    donus: disarm() callable. SIGKILL/os._exit yakalanamaz (R18 rezidu).
    """
    global _exit_wipe_armed
    try:
        import atexit as _atexit
        try:
            _atexit.register(_exit_wipe_now)
        except Exception:
            pass
        for signame in ("SIGTERM", "SIGINT", "SIGBREAK", "SIGHUP", "SIGABRT"):
            try:
                signum = getattr(_signal, signame, None)
                if signum is None:
                    continue
                try:
                    prev = _signal.getsignal(signum)
                except Exception:
                    continue
                try:
                    _exit_prev_handlers[signame] = prev
                except Exception:
                    pass

                def _handler(_num, _frm, _prev=prev):
                    try:
                        _exit_wipe_now()
                    except Exception:
                        pass
                    try:
                        if callable(_prev):
                            _prev(_num, _frm)
                            return
                    except Exception:
                        pass
                    try:
                        if _num == getattr(_signal, "SIGINT", None):
                            raise KeyboardInterrupt
                    except KeyboardInterrupt:
                        raise
                    except Exception:
                        pass
                    try:
                        sys.exit(128 + int(_num))
                    except SystemExit:
                        raise
                    except Exception:
                        pass

                try:
                    _signal.signal(signum, _handler)
                except Exception:
                    continue
            except Exception:
                continue
        _exit_wipe_armed = True
    except Exception:
        pass

    def _disarm() -> None:
        try:
            import atexit as _atexit2
            try:
                _atexit2.unregister(_exit_wipe_now)
            except Exception:
                pass
        except Exception:
            pass
        # Sinyal handler'larini onceki degerlerine dondur (kurulum
        # kalintisi birakma).
        try:
            for signame, prev in list(_exit_prev_handlers.items()):
                try:
                    signum = getattr(_signal, signame, None)
                    if signum is None:
                        continue
                    _signal.signal(signum, prev)
                except Exception:
                    continue
        except Exception:
            pass
        try:
            _exit_prev_handlers.clear()
        except Exception:
            pass

    return _disarm


# --------------------------------------------------------------------------
# KeyVault: anahtar yasam-dongusu kasasi
# --------------------------------------------------------------------------
_PAGE = 4096
_MADV_DONTDUMP = 16
_MADV_DONTFORK = 10


_native_lock = threading.Lock()


def _with_native_lock(fn):
    """R22: ctypes GIL'i birakir -> ayni buf'a eszamanli resize/realloc
    dangling-addr verir. Tum native-op'lar bu kilitle serilesir."""
    def _w(*args, **kwargs):
        with _native_lock:
            return fn(*args, **kwargs)
    try:
        _w.__name__ = getattr(fn, "__name__", "native_op")
        _w.__doc__ = getattr(fn, "__doc__", None)
    except Exception:
        pass
    return _w


@_with_native_lock
def _lock_bytes(buf: bytearray) -> bool:
    """mlock/VirtualLock best-effort. Windows >128KB: working-set genislet."""
    try:
        if not buf:
            return False
        n = len(buf)
        cbuf = (ctypes.c_char * n).from_buffer(buf)
        addr = ctypes.addressof(cbuf)
        if os.name == "nt":
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            if n > 128 * 1024:
                try:
                    kernel32.SetProcessWorkingSetSize.argtypes = [
                        ctypes.c_void_p, ctypes.c_size_t, ctypes.c_size_t]
                    kernel32.SetProcessWorkingSetSize.restype = ctypes.c_bool
                    kernel32.SetProcessWorkingSetSize(
                        ctypes.c_void_p(-1),
                        ctypes.c_size_t(n + 4 * 1024 * 1024),
                        ctypes.c_size_t(n + 16 * 1024 * 1024),
                    )
                except Exception:
                    pass
            kernel32.VirtualLock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            kernel32.VirtualLock.restype = ctypes.c_bool
            ok = kernel32.VirtualLock(ctypes.c_void_p(addr), ctypes.c_size_t(n))
            if not ok and n > _PAGE:
                # Sayfa-hizali retry (VirtualLock sayfa-granuler calisir)
                start = addr - (addr % _PAGE)
                span = n + (addr - start)
                ok = kernel32.VirtualLock(ctypes.c_void_p(start), ctypes.c_size_t(span))
            return bool(ok)
        else:
            try:
                libc = ctypes.CDLL("libc.so.6", use_errno=True)
            except Exception:
                try:
                    libc = ctypes.CDLL("libc.dylib", use_errno=True)
                except Exception:
                    return False
            libc.mlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            libc.mlock.restype = ctypes.c_int
            return libc.mlock(ctypes.c_void_p(addr), ctypes.c_size_t(n)) == 0
    except Exception:
        return False


@_with_native_lock
def _unlock_bytes(buf: bytearray) -> bool:
    try:
        if not buf:
            return False
        n = len(buf)
        cbuf = (ctypes.c_char * n).from_buffer(buf)
        addr = ctypes.addressof(cbuf)
        if os.name == "nt":
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.VirtualUnlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            kernel32.VirtualUnlock.restype = ctypes.c_bool
            return bool(kernel32.VirtualUnlock(ctypes.c_void_p(addr), ctypes.c_size_t(n)))
        else:
            try:
                libc = ctypes.CDLL("libc.so.6", use_errno=True)
            except Exception:
                try:
                    libc = ctypes.CDLL("libc.dylib", use_errno=True)
                except Exception:
                    return False
            libc.munlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            libc.munlock.restype = ctypes.c_int
            return libc.munlock(ctypes.c_void_p(addr), ctypes.c_size_t(n)) == 0
    except Exception:
        return False


@_with_native_lock
def _madvise_no_dump_fork(buf: bytearray) -> None:
    """Linux: DONTDUMP (core) + DONTFORK (clone). Best-effort, sessiz."""
    try:
        if os.name == "posix" and sys.platform.startswith("linux"):
            n = len(buf)
            if not n:
                return
            cbuf = (ctypes.c_char * n).from_buffer(buf)
            addr = ctypes.addressof(cbuf)
            libc = ctypes.CDLL("libc.so.6", use_errno=True)
            libc.madvise.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
            libc.madvise.restype = ctypes.c_int
            try:
                libc.madvise(ctypes.c_void_p(addr), ctypes.c_size_t(n), _MADV_DONTDUMP)
            except Exception:
                pass
            try:
                libc.madvise(ctypes.c_void_p(addr), ctypes.c_size_t(n), _MADV_DONTFORK)
            except Exception:
                pass
    except Exception:
        pass


_CPMEM_BLOCK = 16
_CPMEM_SAME_PROCESS = 0


@_with_native_lock
def _shield_bytes(buf: bytearray) -> bool:
    """R10: CryptProtectMemory SAME_PROCESS ile beklemede-sifrele.

    Blok=16'ya pad'lenir (uzunluk _shield_len'de tutulur; bu fonksiyon
    sadece bool dondurur, pad yonetimi KeyVault'tadir). Non-Windows False.
    """
    try:
        if os.name != "nt" or not buf:
            return False
        n = len(buf)
        if n % _CPMEM_BLOCK:
            return False
        cbuf = (ctypes.c_char * n).from_buffer(buf)
        addr = ctypes.addressof(cbuf)
        crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
        crypt32.CryptProtectMemory.argtypes = [ctypes.c_void_p, ctypes.c_ulong,
                                               ctypes.c_ulong]
        crypt32.CryptProtectMemory.restype = ctypes.c_bool
        return bool(crypt32.CryptProtectMemory(ctypes.c_void_p(addr),
                                               ctypes.c_ulong(n),
                                               ctypes.c_ulong(_CPMEM_SAME_PROCESS)))
    except Exception:
        return False


@_with_native_lock
def _unshield_bytes(buf: bytearray) -> bool:
    try:
        if os.name != "nt" or not buf:
            return False
        n = len(buf)
        if n % _CPMEM_BLOCK:
            return False
        cbuf = (ctypes.c_char * n).from_buffer(buf)
        addr = ctypes.addressof(cbuf)
        crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
        crypt32.CryptUnprotectMemory.argtypes = [ctypes.c_void_p, ctypes.c_ulong,
                                                 ctypes.c_ulong]
        crypt32.CryptUnprotectMemory.restype = ctypes.c_bool
        return bool(crypt32.CryptUnprotectMemory(ctypes.c_void_p(addr),
                                                 ctypes.c_ulong(n),
                                                 ctypes.c_ulong(_CPMEM_SAME_PROCESS)))
    except Exception:
        return False


@_with_native_lock
def _secure_zero(buf: bytearray) -> None:
    """ctypes memset/RtlZeroMemory + Python-level sifirlama (derinlik)."""
    try:
        n = len(buf)
        if not n:
            return
        try:
            cbuf = (ctypes.c_char * n).from_buffer(buf)
            addr = ctypes.addressof(cbuf)
            if os.name == "nt":
                try:
                    ctypes.windll.ntdll.RtlZeroMemory(ctypes.c_void_p(addr), ctypes.c_size_t(n))
                except Exception:
                    ctypes.memset(ctypes.c_void_p(addr), 0, n)
            else:
                ctypes.memset(ctypes.c_void_p(addr), 0, n)
        except Exception:
            pass
        for i in range(n):
            buf[i] = 0
    except Exception:
        pass


_VERIFY_TIMES: list = []
_VERIFY_LOCK = threading.Lock()
_VERIFY_WINDOW = 60.0
_VERIFY_MAX = 20


def _verify_allow() -> bool:
    """K7: online-guessing hiz-siniri — 60sn'de 20+ verify False dondurur."""
    try:
        now = time.monotonic()
    except Exception:
        return True
    try:
        with _VERIFY_LOCK:
            cutoff = now - _VERIFY_WINDOW
            while _VERIFY_TIMES and _VERIFY_TIMES[0] < cutoff:
                _VERIFY_TIMES.pop(0)
            if len(_VERIFY_TIMES) >= _VERIFY_MAX:
                return False
            _VERIFY_TIMES.append(now)
        return True
    except Exception:
        return True


def _internal_caller() -> bool:
    """K3: dogrudan cagiran bu modul-ici mi? (muhur-gecidi).

    Dis okuma/yazma AttributeError alir; modul-ici metodlar serbesttir.
    """
    try:
        fr = sys._getframe(2)
    except Exception:
        return False
    try:
        fn = str(getattr(fr.f_code, "co_filename", "") or "")
        return bool(fn) and fn == __file__
    except Exception:
        return False


class KeyVault:
    """Anahtar kasasi: bytearray-only + kilit + wipe + TTL/volatile.

    - repr/str/print HER ZAMAN [REDACTED] (log sizintisi yok).
    - bytes(view) disinda erisim YOK (kopyayi cagiran yonetir + siler).
    - volatile=True: ilk basarili okumada wipe; ttl_sec: sure-asimi wipe.
    - from_file: dosyadan direkt yukleme (0600 onerilir; watch_file ile izle).
    - shielded=True (R10, Windows-only): beklemede CryptProtectMemory
      SAME_PROCESS ile SIFRELI durur; read()/verify() penceresinde
      cozulup finally ile geri sifrelenir. Ayni-boot sarti + use-penceresi
      plaintext (MS-dokuman siniri). Destek yoksa sessiz False'a duser.
    - K3 MUHUR: __slots__ (orselenemez flag'ler icin __dict__ YOK) +
      __getattribute__/__setattr__ gecidi: _buf/_dead/_shielded/_locked
      SADECE bu modul-ici cagirana acilir; dis okuma/yazma
      AttributeError alir (dogrudan bytes(v._buf) + __dict__['_dead']
      diriltme saldirilari kapanir). DURUST rezidu: object.__getattribute__
      ile bilerek-bypass mumkundur (tum Python-seviyesi erisim-kontrollerin
      ortak siniri — strictaccess dokumante); bariyer firsatci degil
      kararli saldirgan Varsayimiyla calisir, anti_hook/anti_tamper
      katmanlariyla birlikte savunur.
    """

    __slots__ = ("_buf", "_ttl", "_born", "_volatile", "_dead", "_reads",
                 "_locked", "_shielded", "_pad", "__weakref__")

    _SENSITIVE = frozenset({"_buf", "_dead", "_shielded", "_locked"})

    def __getattribute__(self, name):
        try:
            if name in KeyVault._SENSITIVE and not _internal_caller():
                raise AttributeError("KeyVault: protected")
        except AttributeError:
            raise
        except Exception:
            raise AttributeError("KeyVault: protected")
        return object.__getattribute__(self, name)

    def __setattr__(self, name, value):
        try:
            if name in KeyVault._SENSITIVE and not _internal_caller():
                raise AttributeError("KeyVault: protected")
        except AttributeError:
            raise
        except Exception:
            raise AttributeError("KeyVault: protected")
        object.__setattr__(self, name, value)

    def __init__(self, material: bytes | bytearray | memoryview,
                 *, ttl_sec: Optional[float] = None, volatile: bool = False,
                 lock: bool = True, shielded: bool = False):
        # K4: ara-bytes KOPYASIZ kurulum — bytearray/memoryview direkt
        # tek-kopya ile canli tampona alinir (bytes girdide tek gecici
        # kopya kacinilmazdir, hemen birakilir).
        if isinstance(material, (bytearray, memoryview)):
            try:
                self._buf = bytearray(material)
            except Exception:
                raise ValueError("KeyVault: material okunamadi")
        else:
            raw = bytes(material)
            if not raw:
                raise ValueError("KeyVault: bos material")
            self._buf = bytearray(raw)
            try:
                del raw
            except Exception:
                pass
        if not self._buf:
            raise ValueError("KeyVault: bos material")
        self._ttl = float(ttl_sec) if ttl_sec is not None else None
        self._born = time.monotonic()
        self._volatile = bool(volatile)
        self._dead = False
        self._reads = 0
        self._locked = False
        self._shielded = False
        self._pad = 0
        if lock:
            _madvise_no_dump_fork(self._buf)
            self._locked = _lock_bytes(self._buf)
        if shielded:
            pad = (-len(self._buf)) % _CPMEM_BLOCK
            if pad:
                self._buf.extend(b"\x00" * pad)
                self._pad = pad
            if _shield_bytes(self._buf):
                self._shielded = True
            elif pad:
                del self._buf[len(self._buf) - pad:]
                self._pad = 0
        try:
            _live_vaults.add(self)
        except Exception:
            pass
        try:
            with _LIVE_BUF_LOCK:
                _LIVE_BUF_IDS.add(id(self._buf))
        except Exception:
            pass
        try:
            _ensure_fork_guard()
        except Exception:
            pass

    @classmethod
    def from_file(cls, path: str, **kw) -> "KeyVault":
        """keyfile/passphrase-file'dan direkt yukleme (heap'e degmeden).

        Cap 1MB: anahtar-materyali kucuktur; dev dosya bellek-sisirmesi
        (DoS) olur. Buyukse ValueError (fail-loud).
        """
        with open(path, "rb") as f:
            data = f.read(1024 * 1024 + 1)
        if len(data) > 1024 * 1024:
            raise ValueError("KeyVault.from_file: dosya cok buyuk (cap 1MB)")
        return cls(data, **kw)

    @classmethod
    def from_env(cls, var: str, *, scrub: bool = True, **kw) -> "KeyVault":
        """Environ degiskeninden direkt yukleme (R16, cypher_cell from_env).

        scrub=True: okuma sonrasi environ[var] ayni-uzunlukta dummy ile
        degistirilir (orijinal str GC'ye duser; immutable oldugu icin
        sifirlanamaz — referans koparma best-effort'tur).
        """
        try:
            val = os.environ.get(var, "")
        except Exception:
            raise ValueError("KeyVault.from_env: environ okunamadi")
        if not val:
            raise ValueError("KeyVault.from_env: bos/kayip degisken")
        try:
            raw = val.encode("utf-8")
        except Exception:
            raise ValueError("KeyVault.from_env: kodlama hatasi")
        try:
            return cls(raw, **kw)
        finally:
            try:
                del raw
            except Exception:
                pass
            if scrub:
                try:
                    os.environ[var] = "\x00" * len(val)
                except Exception:
                    pass
            try:
                del val
            except Exception:
                pass

    def _check_live(self) -> None:
        if self._dead:
            raise ValueError("KeyVault: expired")
        if self._ttl is not None and (time.monotonic() - self._born) > self._ttl:
            self.wipe()
            raise ValueError("KeyVault: expired")

    def _unshield_for_use(self) -> bool:
        """Kullanim penceresi: coz (shielded degilse True)."""
        if not self._shielded:
            return True
        return _unshield_bytes(self._buf)

    def _reshield_after_use(self) -> None:
        if self._shielded:
            try:
                ok = _shield_bytes(self._buf)
            except Exception:
                ok = False
            if not ok:
                try:
                    self.wipe()
                except Exception:
                    pass

    def _plain(self) -> bytes:
        out = bytes(self._buf)
        if self._pad:
            out = out[:len(out) - self._pad]
        return out

    def read(self) -> bytes:
        """Kopya dondurur (cagiran SIFIRLAMAKLA yukumlu). Volatile ise wipe."""
        self._check_live()
        if not self._unshield_for_use():
            raise ValueError("KeyVault: unshield basarisiz")
        try:
            out = self._plain()
        finally:
            self._reshield_after_use()
        self._reads += 1
        if self._volatile:
            self.wipe()
        return out

    def __bytes__(self) -> bytes:
        return self.read()

    def readinto(self, target: bytearray) -> int:
        """K4: sifir-kopya okuma — sir cagiranin tamponuna yazilir, bytes uretilmez.

        Donus: yazilan bayt. Volatile/TTL kurallari read() ile aynidir.
        """
        self._check_live()
        if not self._unshield_for_use():
            raise ValueError("KeyVault: unshield basarisiz")
        try:
            n = len(self._buf) - self._pad
            if n < 0:
                n = 0
            if len(target) < n:
                raise ValueError("KeyVault.readinto: hedef kucuk")
            try:
                target[:n] = self._buf[:n] if self._pad else self._buf
            except Exception:
                raise ValueError("KeyVault.readinto: yazma basarisiz")
        finally:
            self._reshield_after_use()
        self._reads += 1
        if self._volatile:
            self.wipe()
        return n

    def verify(self, candidate: bytes | bytearray) -> bool:
        """Sabit-zamanli karsilastirma (timing-oracle yok) + K7 hiz-sinirli.

        K4: karsilastirma memoryview uzerinden — plaintext bytes kopyasi
        uretilmez. K7: 60sn penceresinde 20+ deneme -> throttling (0.25sn
        bekleme + False); online guessing oracle kurutulur. Hiz sarti
        herkese aciktir (oracle degil, DoS-karsiti).
        """
        try:
            if not _verify_allow():
                try:
                    time.sleep(0.25)
                except Exception:
                    pass
                return False
            self._check_live()
            if not self._unshield_for_use():
                return False
            try:
                n = len(self._buf) - self._pad
                if n < 0:
                    n = 0
                try:
                    mv_self = memoryview(self._buf)[:n] if self._pad else memoryview(self._buf)
                    mv_cand = memoryview(candidate)
                except Exception:
                    return False
                return bool(_hmac.compare_digest(mv_self, mv_cand))
            finally:
                self._reshield_after_use()
        except Exception:
            return False

    @property
    def reads(self) -> int:
        return self._reads

    @property
    def is_locked(self) -> bool:
        return self._locked

    def wipe(self) -> None:
        """Sifirla + unlock + olu isaretle (idempotent)."""
        try:
            try:
                with _LIVE_BUF_LOCK:
                    _LIVE_BUF_IDS.discard(id(object.__getattribute__(self, "_buf")))
            except Exception:
                pass
            if not self._dead:
                if self._shielded:
                    # Sifreli tamponu once coz, sonra sifirla (plaintext
                    # kalintisi birakma); cozum basarisizsa yine sifirla.
                    try:
                        _unshield_bytes(self._buf)
                    except Exception:
                        pass
                    self._shielded = False
                _secure_zero(self._buf)
                try:
                    _unlock_bytes(self._buf)
                except Exception:
                    pass
                self._locked = False
        except Exception:
            pass
        finally:
            self._dead = True
            try:
                _live_vaults.discard(self)
            except Exception:
                pass

    close = wipe

    def __enter__(self) -> "KeyVault":
        self._check_live()
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        # with-cikisi OTOMATIK wipe (scoped-view disiplini)
        try:
            self.wipe()
        except Exception:
            pass
        return False

    def __del__(self):  # noqa: D105 (best-effort son-supurge)
        try:
            self.wipe()
        except Exception:
            pass

    def __repr__(self) -> str:
        return "KeyVault([REDACTED])"

    def __str__(self) -> str:
        return "[REDACTED]"

    def __len__(self) -> int:
        if self._dead:
            return 0
        try:
            # K7: exact-uzunluk sizintisi YOK — 64B kova (tahmin-oracle kurur).
            n = len(self._buf)
            return ((n + 63) // 64) * 64
        except Exception:
            return 0

    @property
    def is_shielded(self) -> bool:
        return self._shielded
