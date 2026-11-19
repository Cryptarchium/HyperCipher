# -*- coding: utf-8 -*-
"""
HYPERCIPHER v5 - 2048-bit hardware-bound rotating stream cipher
===============================================================

MIMARI (4 katman)
-----------------
[L1] MASTER KEY  - 2048 bit (256 byte)
     master = Argon2id(passphrase || 0x00 || hardware_fingerprint,
                       salt, time=3, lanes=1, memory_cost=kdf_n KiB)
     - KDF: Argon2id (RFC 9106, PHC kazanani) - GPU/ASIC/trade-off direnci
       en yuksek parola KDF'si (v4'ten itibaren; once scrypt).
     - v5 keyfile (ikinci faktor): passphrase onceli HKDF-SHA512(salt=keyfile,
       info="HYPR/keyfile/v1") dogrudan KDF'e degil, KDF'e ORTUKLU girer
       (age/sympa modeli) - keyfile yoksa acilamaz.
     - Anahtar ASLA koda gomulmez, ASLA diske yazilmaz.
     - Her calistirmada canli sistem kimliginden (MachineGuid, MAC,
       volume serial, CPU, hostname) + kullanicinin passphrase'inden
       sifirdan turetilir. Iki faktorlu: makine + insan (ve v5'te keyfile).

[L2] ROTASYON - her ROTATION_BYTES (varsayilan 1024) byte veride
     TAZE bir 2048-bit subkey uretilir ve ZINCIRLENIR:
       subkey_i = HKDF-SHA512(master, salt=nonce,
                              info="HYPR/subkey/" || LE64(rot_no) || prev_sub)
       (subkey_{-1} = master; zincirleme = bir subkey kirilirsa geri sarmak
       imkansiz, her subkey tum oncelere bagli)
     ~1 GiB/s throughput'ta bu tam olarak ~0.001 ms'de bir key degisimi
     demektir. Data-driven rotasyon: wall-clock senkronizasyon sorunu yok.

[L3] KEYSTREAM - DUAL-FAMILY (iki bagimsiz hash ailesi, defense in depth):
       blok = KeyedBLAKE2b-512(key=subkey[:64], msg=subkey[64:] || LE64(blok_no) || b"HYPR1")
              XOR
              HMAC-SHA512(key=subkey, msg=LE64(blok_no) || b"HYPR2")
     Bir ailenin gelecekte (bilinmeyen) bir zayifligi cikarsa diger aile
     keystreami sifir geri getirir. ciphertext = plaintext XOR blok

[L4] BUTUNLUK - Encrypt-then-MAC:
       tag = HMAC-SHA512(auth_key, header || ciphertext)
       auth_key = HKDF-SHA512(master, salt=nonce, info="HYPR/auth")

PAKET FORMATI (104 byte header + ciphertext + 64 byte tag):
  version(1) | flags(1) | rotation_bytes(2) | kdf_n(4) | salt(32) |
  nonce(24) | SHA-256(salt||fp)(32) | data_len(8)
  KASITLI OLARAK MAGIC YOK - paket random veri gibi gorunur.
  flags: bit0=donanim bagli, bit1=ISO 7816-4 padding, bit2=keyfile(kullanildi)
  Rezevre flag bitleri fail-closed reddedilir (zafiyet raporu [16]).
  v4 paketler v5 ile uyumlu acilir (VERSION 4 korundu); v3/v2 degil (KDF degisti).

DURUST LIMITLER (tamami README.md'de):
- Key rotasyonu, master key entropisinin UZERINE guvenlik EKLEMEZ.
- 2048-bit uzayi brute-force: ~2^2048 ~= 3.2e616 deneme.
  Saniyede 1e30 deneme (fiziksel olarak imkansiz) ile bile ~1e579 yil.
  Bir googol sadece 1e100 yildir.
- Bu bir ogrenme/muhendislik projesidir. Gercek sirlar icin AES-256-GCM kullan.
"""

from __future__ import annotations

import hashlib
import hmac
import math
import os
import platform
import re
import secrets
import stat
import struct
import tempfile
import unicodedata
import uuid
import warnings
from collections import Counter, namedtuple
from typing import Any, Dict, Optional

# v4: Argon2id KDF (RFC 9106, PHC kazanani). cryptography zorunlu bagimlilik;
# scrypt'in aksine GPU/ASIC/trade-off direnci en ust seviyededir.
try:
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
except ImportError as _ie:  # pragma: no cover - bagimlilik denetimi
    raise SystemExit(
        "v4 Argon2id KDF icin 'cryptography' paketi gerekli: "
        "pip install cryptography"
    ) from _ie

# ---------------------------------------------------------------------------
# Sabitler
# ---------------------------------------------------------------------------
VERSION = 4                      # 1 byte (v4: Argon2id KDF + HKDF + HMAC keystream + nonce 24)
                                 # v5 OZELLIKLERI (keyfile + gunclu-perde) AYNI VERSION'da:
                                 # yeni FLAG_KEYFILE biti ile geriye-uyumlu eklendi - eski
                                 # v4 paketler (flag yok) aynen acilir, yeni keyfile paketleri
                                 # flag bitiyle ayrisir. VERSION yukseltmek eski paketleri
                                 # KIRARDI; flag yaklasimi %100 geriye uyumlu.
KEY_BYTES = 256                  # 2048 bit master key
ROTATION_BYTES = 1024            # subkey basina veri byte'i (~0.001 ms @ 1 GiB/s)
SALT_BYTES = 32
NONCE_BYTES = 24                 # XChaCha tarzi random-nonce guvenligi (zafiyet [12])
FP_HASH_BYTES = 32               # SHA-256(makine parmak izi)
TAG_BYTES = 64                   # HMAC-SHA512
DEFAULT_KDF_N = 1 << 17          # Argon2id memory_cost KiB: OWASP onerilen uzeri
                                 # (128 MiB, ~0.87s olculdu; RFC 9106 second
                                 # recommendation 64 MiB t=3 uzerinde)
MIN_KDF_N = 1 << 14              # alt sinir: API esnekligi (16 MiB; uretimde 2^17 onerilir)
MAX_KDF_N = 1 << 18              # ust sinir: 256 MiB bellek / ~1s CPU -> siseirilmis
                                 # header KDF DoS karsi (RFC 7914 Sec.14 ZORUNLU
                                 # kiler; libsodium SENSITIVE=2^20/1GiB yalnizca
                                 # KENDI sectigin veri icin, saldirgan header'i
                                 # icin degil. age: encrypt 2^18, decrypt cap 22
                                 # ama acik SetMaxWorkFactor uyarisi. DENETIM 5
                                 # bulgu [7]: 512 MiB -> 256 MiB daraltildi;
                                 # HYPERCIPHER_MAX_KDF_N env ile servis
                                 # operatoru kendi butcesine gore daha da
                                 # daraltabilir (rscrypto Argon2VerifyPolicy).)
KDF_MAX_ENV_CAP = 1 << 19        # ESKI env cap (512 MiB). DENETIM 5 bulgu [9]:
                                 # env artik MAX_KDF_N (256 MiB) ile sinirli -
                                 # bu sabit yalnizca geriye uyum/sozlesme icin
                                 # tutulur, _effective_max_kdf_n onu KULLANMAZ.


def _effective_max_kdf_n() -> int:
    """HYPERCIPHER_MAX_KDF_N env: KDF DoS cap'ini servis butcesine gore daralt.

    DENETIM 5 bulgu [7] fix'i: sabit 512 MiB cap servis operatorunun ortamina
    gore fazla genis olabilir (tek saldirgan paket ~2s CPU + 512 MiB bellek).
    rscrypto Argon2VerifyPolicy deseni: operator max_memory_cost_kib secer,
    KDF CALISTIRMADAN once reddedilir. Ayni ilke burada:
      - env yoksa    -> MAX_KDF_N (256 MiB, C++ tarafi set edemez)
      - env gecersiz -> ValueError (fail-closed: sessizce genisletilmez)
      - env 2'nin kuvveti degilse -> ValueError (API sozlesmesi)

    DENETIM 5 bulgu [9] fix'i: env YALNIZCA daraltabilir - ust sinir MAX_KDF_N
    (256 MiB). Eski KDF_MAX_ENV_CAP (512 MiB) genisletme yolu saldirgan
    header ile birlikte 2x bellek/CPU amplifikasyonu uretebiliyordu
    (dos doc/code uyusmazligi: kod 512'ye izin veriyordu, doc 'sadece
    daraltabilir' diyordu). Artik env degerleri asla varsayilani ASAMAZ.

    V5.3 zafiyet raporu [4] notu (BILGI): env her KDF cagrisinda yeniden
    okunur (parse basina degil). Bu BILINCLIDIR - isletme butce degisikligi
    bir sonraki islemde aninda uygulanir; env okuma maliyeti Argon2id'in
    (~0.87s) yaninda ihmal edilir. Kaldi ki fail-closed zaten: gecersiz env
    sessizce genisletme degil, ValueError uretir.
    """
    raw = os.environ.get("HYPERCIPHER_MAX_KDF_N")
    if raw is None:
        return MAX_KDF_N
    try:
        value = int(raw, 10)
    except ValueError:
        raise ValueError(
            "HYPERCIPHER_MAX_KDF_N tamsayi olmali (Argon2id memory_cost KiB, "
            "2'nin kuvveti)") from None
    if value < MIN_KDF_N or value > MAX_KDF_N:
        raise ValueError(
            f"HYPERCIPHER_MAX_KDF_N {value} sinir disi "
            f"[{MIN_KDF_N}..{MAX_KDF_N}] (env yalnizca daraltabilir)")
    if value & (value - 1):
        raise ValueError(
            "HYPERCIPHER_MAX_KDF_N 2'nin kuvveti olmali "
            "(Argon2id memory_cost KiB)")
    return value
ARGON2_TIME = 3                  # Argon2id time_cost (RFC 9106 ikinci onerisi t=3)
ARGON2_LANES = 1                 # Argon2id parallelism (OWASP: minimum p=1)
CHUNK = 1 << 20                  # 1 MiB dosya okuma parcasi
FLAG_HARDWARE = 0b0000_0001      # flag biti: bit0 = donanim bagli
FLAG_PADDED = 0b0000_0010        # flag biti: bit1 = ISO 7816-4 padding uygulandi
FLAG_KEYFILE = 0b0000_0100       # flag biti: bit2 = v5 keyfile (ikinci faktor) kullanildi.
                                 # age/sympa modeli: passphrase + keyfile(>=32 byte)
                                  # HKDF-SHA512 ile birlestirilir (age/sympa HKDF-SHA256
                                  # kullanir, biz SHA512 - master 2048-bit ailesiyle tutarli);
                                  # keyfile tek basina
                                 # ise yaramaz, passphrase de. Saldirgan ikisini de
                                 # ele gecirmek zorunda - zayif perde artik sorun degil.
KEYFILE_MIN_BYTES = 32           # keyfile alt siniri (sympa: >=32 byte onerisi)
KEYFILE_RECOMMENDED_BYTES = 64   # generate_keyfile() varsayilan boyutu
KEYFILE_MAX_BYTES = 1 << 20      # ust sinir: 1 MiB makul kullanim capi (fazlasi DoS)
KEYFILE_INFO = b"HYPR/keyfile/v1"  # HKDF domain separator (SP 800-108 label)

# V5.3 zafiyet raporu [1] (DUSUK) fix'i: deterministic test API'si FAIL-CLOSED.
# _encrypt_deterministic / _encrypt_file_deterministic salt/nonce SABITLER;
# public API'den salt/nonce kaldirildigi (IC[10]) icin kalan tek nonce-reuse
# yolu bu ic API'nin import edilip cagrilmasiydi. Tink felsefesi: nonce
# misuse'a duyarsiz olmayan bir modu KULLANICIYA ACIK birakma - bu fonksiyonlar
# artik varsayilan olarak RuntimeError firlatir; yalnizca acik opt-in
# (conftest.py veya test dosyasi basi: hc._DETERMINISTIC_MODE = True) ile
# calisir. Uretim kodu bu bayraga DOKUNMAMALIDIR.
_DETERMINISTIC_MODE = False
PASSPHRASE_MIN_GUESSES_LOG10 = 14.0  # v5: zxcvbn esigi - 10^14 tahmin ~= 1e4/sn'de
                                     # 781 yil (Argon2id ile gercek hiz 1e4'ten cok
                                     # dusuk oldugundan fiilen milyonlarca yil).
                                     # => alti kalan perde CLI'da REDDEDILIR
                                     # (--allow-weak ile acik riske razi olunur).
_ZXCVBN_AVAILABLE = False       # import denemesi asagida yapilir (bagimlilik opsiyonel)

# Header duzeni (104 byte, little-endian). KASITLI OLARAK MAGIC YOK:
# paket random veri gibi gorunur. Dogrulama tamamen keyed HMAC-SHA512
# tag ile yapilir. v3: nonce 16->24 ([12]), iterations -> kdf_n = scrypt N
# ([13]), header 96 -> 104 byte. v4: kdf_n = Argon2id memory_cost KiB
# (RFC 9106), scrypt parametresi yerine. Boyut degismedi (104 byte).
#   0:1   version (1)
#   1:2   flags (1)
#   2:4   rotation_bytes (2, uint16) - 0 = varsayilan (ROTATION_BYTES)
#   4:8   kdf_n (4, uint32) - Argon2id memory_cost KiB (2'nin kuvveti, [13][14])
#   8:40  salt (32)
#   40:64 nonce (24)
#   64:96 fp_hash (32)
#   96:104 data_len (8)
HEADER_BYTES = 1 + 1 + 2 + 4 + SALT_BYTES + NONCE_BYTES + FP_HASH_BYTES + 8

Header = namedtuple(
    "Header",
    "version flags rotation_bytes kdf_n salt nonce fp_hash data_len payload",
)


class CipherError(Exception):
    """Dogrulama hatasi, kurcalama tespiti veya format hatasi."""


# ---------------------------------------------------------------------------
# L0: Donanim derinligi - makine parmak izi (koda/yere gomulu DEGIL)
# ---------------------------------------------------------------------------
def collect_hardware_fingerprint() -> bytes:
    """Makine kimligi: ikinci key faktoru. Asla saklanmaz, her calistirmada
    canli sistemden toplanir.

    V4 zafiyet raporu [2] (ENTROPI DEGILDIR - SAHIPLIK FAKTORUDUR): bu
    bilesenler yari-kamusal metaveridir - MachineGuid registry'de okunabilir,
    MAC/serial/hostname ag uzerinden sizabilir. Kriptografik guc KAYNAGI
    DEGILDIR; guc passphrase + keyfile'dan gelir. fp yalnizca (a) master
    turetimine makineye-bagli girdi (farkli makinede acilamaz) ve
    (b) hash gorunusuyle gorsel kimlik saglar. Bu yuzden fp hicbir zaman
    "ekstra entropi" olarak sayilmaz - guclu perde/keyfile zorunlulugu
    bu rolden BAGIMSIZDUR.
    """
    parts: list[str] = []

    # 1) MachineGuid - Windows kurulumu basina sabit, en guclu capa
    try:
        import winreg
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography"
        ) as k:
            mg, _ = winreg.QueryValueEx(k, "MachineGuid")
            parts.append(f"mguid:{mg}")
    except Exception:  # nosec B110
        pass  # kasitli: fp kaynagi okunamazsa digerleriyle devam

    # 2) MAC adresleri (sirali - NIC sirasi onemsiz)
    try:
        macs = sorted({uuid.getnode()})
        parts.append(f"mac:{','.join(hex(m) for m in macs)}")
    except Exception:  # nosec B110
        pass  # kasitli: fp kaynagi okunamazsa digerleriyle devam

    # 3) Sistem surucusu volume serial
    # V5.3 zafiyet raporu [3] fix'i: ctypes.windll (bellekten derlenen,
    # argtypes'siz) yerine acik WinDLL + tam imza. Yanlis cagri imzasi
    # sessizce veri bozabilir ya da (x64'te) yigin dengesizligi yaratabilir;
    # argtypes/restype hatali cagrilari calisma aninda reddeder.
    try:
        import ctypes
        _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        _GetVolumeInformationW = _k32.GetVolumeInformationW
        _GetVolumeInformationW.restype = ctypes.c_int          # BOOL
        _GetVolumeInformationW.argtypes = (
            ctypes.c_wchar_p,            # lpRootPathName
            ctypes.c_wchar_p,            # lpVolumeNameBuffer
            ctypes.c_uint32,             # nVolumeNameSize
            ctypes.POINTER(ctypes.c_uint32),   # lpVolumeSerialNumber
            ctypes.POINTER(ctypes.c_uint32),   # lpMaximumComponentLength
            ctypes.POINTER(ctypes.c_uint32),   # lpFileSystemFlags
            ctypes.c_wchar_p,            # lpFileSystemNameBuffer
            ctypes.c_uint32,             # nFileSystemNameSize
        )
        vol_name = ctypes.create_unicode_buffer(256)
        fs_name = ctypes.create_unicode_buffer(256)
        serial = ctypes.c_uint32()
        ok = _GetVolumeInformationW(
            "C:\\", vol_name, 256, ctypes.byref(serial),
            None, None, fs_name, 256,
        )
        if ok:
            parts.append(f"vol:{serial.value:x}")
    except Exception:  # nosec B110
        pass  # kasitli: fp kaynagi okunamazsa digerleriyle devam

    # 4) CPU + hostname (son care entropisi)
    parts.append(f"proc:{platform.processor() or 'unknown'}")
    parts.append(f"node:{platform.node()}")

    return "|".join(parts).encode("utf-8", errors="replace")


def fingerprint_summary() -> str:
    """`hash` komutu icin insan okunur ozet."""
    return collect_hardware_fingerprint().decode("utf-8", errors="replace")


def fingerprint_digest(fp_blob: bytes | None = None,
                       salt: bytes = b"") -> bytes:
    """Donanim parmak izi ozetinin TEK KAYNAGI (V4 zafiyet raporu [4]).

    Eskiden _build_header ICINDE inline `sha256(salt + fp_blob)` yazilirken
    bu fonksiyon ayri bir formulle (tuzsuz) cakisiyordu - iki dogruluk
    kaynagi, ileride sapma riski. Artik tek formul burada:
        digest = SHA-256(salt + fp_blob)
    - fp_blob=None (parametresiz cagri): canli makine parmak izi toplanir
      (demo.py, test stabilite karsilastirmasi - geriye uyumlu).
    - salt=b"" : tuzsuz ozet (eski davranis, yalnizca gorsel/hash amacli).
    _build_header de ayni fonksiyonu cagirir; formuller BIRBIRINDEN
    SAPAMAZ.
    """
    if fp_blob is None:
        fp_blob = collect_hardware_fingerprint()
    return hashlib.sha256(salt + fp_blob).digest()


# ---------------------------------------------------------------------------
# L1: Master key turetimi
# ---------------------------------------------------------------------------
def _derive_master(passphrase: str, fp_blob: bytes, salt: bytes,
                   kdf_n: int, keyfile: bytes | None = None) -> bytearray:
    """passphrase [+ keyfile] + donanim parmak izi -> 2048-bit master key.

    KDF (v4): scrypt -> Argon2id (RFC 9106, PHC kazanani). Argon2id, scrypt'in
    aksine GPU/ASIC/trade-off direnci en yuksek PHC algoritmasidir ve OWASP
    2024+ onerisidir. Parametreler:
      - memory_cost = kdf_n KiB (OWASP min 19 MiB; default 2^17 = 128 MiB)
      - time_cost   = ARGON2_TIME (3; RFC 9106 ikinci onerisi t=3)
      - parallelism = ARGON2_LANES (1; OWASP minimum)
    Salt zaten encrypt tarafinda random uretilir ve header'da saklanir.

    v5 KEYFILE KATMANI (age/sympa modeli): keyfile verildiyse passphrase TEK
    BASINA anahtar materyali olmaktan cikar:
        pre = HKDF-SHA512(ikm=passphrase_bytes, salt=keyfile, info=KEYFILE_INFO)
        material = pre || 0x00 || fp_blob  -> Argon2id
    Boylece saldirgan zayif perdeyi bilse bile keyfile olmadan HICBIR sey
    yapamaz; zayif perde sorunu insan hafizasindan keyfile'a TASINIR.
    keyfile=None ise eski davranis (passphrase || fp) AYNEN korunur ->
    mevcut v4 paketler geriye uyumlu acilir.

    RAM hijyeni (zafiyet raporu [5] + DENETIM 5 bulgu [8]): KDF girdi
    materyali (passphrase + fp) MUTABLE bytearray olarak insa edilir ve KDF
    cagrisindan SONRA sifirlanir. DENETIM 5: pw_bytes ARTIK bytearray
    (immutable bytes degil) - boylece passphrase'in UTF-8 kopyasi da wipe
    edilir; keyfile=None dalinda bytearray(pw_bytes) kopyasi yerine ayni
    buffer kullanilir (ekstra kopya uretilmez). Python'da immutable bytes
    silinemez (pyca/cryptography doc: immutable silinemez, mutable buffer
    gec); yapilabilecek en guclu sey tum gecici kopyalari mutable tutup wipe
    etmektir - boylece heap dump'inda passphrase materyali kalmaz.

    Passphrase guvenligi (zafiyet raporu [26][20]):
      - Bos/whitespace passphrase REDDEDILIR (kutuphane seviyesi - CLI zaten
        reddediyor, API acigi kapatildi) -> ValueError.
      - Unicode NFC normalizasyonu (NIST SP 800-63B): ayni gorunen ama farkli
        kodlanmis (NFC/NFD) passphrase'ler AYNI key'i uretmeli, yoksa
        kullanici kilitli kalir.
    """
    if not passphrase.strip():
        raise ValueError("passphrase bos olamaz")
    # V5.3 zafiyet raporu [2] fix'i: fp_blob NUL byte iceremez. material
    # encoding'i pw_bytes || 0x00 || fp_blob'dur; ayrac (0x00) yalnizca tek
    # bir konumda aranabilir oldugunda encoding INJECTIVE'dir (NIST SP
    # 800-108r1 context encoding ilkesi - belirsizlik yaratan serbest
    # icerik reddedilir). Canli parmak izi (mguid:/mac:/vol:/proc:/node:)
    # ASCII metin oldugu icin NUL asla uretilmez; kontrol davranisi
    # DEGISTIRMEZ, yalnizca KDF girdisinin ayrismasi guvence altina alinir.
    if b"\x00" in fp_blob:
        raise ValueError(
            "fp_blob NUL byte (0x00) iceremez: ayrac tekliligini bozar")
    normalized = unicodedata.normalize("NFC", passphrase)
    # DENETIM 5 bulgu [8]: pw_bytes MUTABLE bytearray - immutable bytes
    # (encode ciktisi) silinemezdi; simdi wipe(material) passphrase
    # kopyasini da temizler (immutable normalized/str CPython'in kopyalari,
    # hepsini temizlemek mumkun degil - en guclu pratik: mutable buffer).
    pw_bytes = bytearray(normalized.encode("utf-8"))
    if keyfile is not None:
        # v5: passphrase'i keyfile'a ORTUKLE (age/sympa). HKDF ciktisi
        # mutable kopyaya tasinir; passphrase'in kendisi KDF'e girmemis olur.
        # (pre immutable bytes -> pyca/cryptography siniri, silinemez;
        # kopyasi material wipe edilir. asil gizlilik HKDF + Argon2id
        # katmanlarinda, passphrase kopyasi pw_bytes ise wipe edilir.)
        pre = _hkdf(pw_bytes, salt=keyfile, info=KEYFILE_INFO,
                    length=KEYFILE_MIN_BYTES)
        material = bytearray(pre)
        # DENETIM 5 bulgu [10]: keyfile branch'inde pw_bytes ayri bir
        # mutable buffer olarak kalir ve material wipe edilse bile PASSphrase
        # kopyasi RAM'de kalir. material != pw_bytes oldugunda ikisi de wipe
        # edilmelidir (else branch'te material is pw_bytes - cift wipe zararsiz).
        wipe_pw = True
    else:
        material = pw_bytes         # kopyasiz: ayni buffer, wipe ile temizlenir
        wipe_pw = False
    material.append(0)              # ayrac
    material.extend(fp_blob)
    try:
        # Argon2id(salt, length, iterations, lanes, memory_cost KiB).
        # Argon2id blok boyu 1024 byte -> memory_cost KiB cinsindendir.
        # type: ignore[call-arg,arg-type] - rust-backed sinifin py.typed
        # stub'i yok; imza calisma aninda dogrulandi (Argon2id(salt, len,
        # iterations, lanes, memory_cost) + bytearray kabul ediyor).
        kdf = Argon2id(salt, KEY_BYTES, ARGON2_TIME, ARGON2_LANES, kdf_n)  # type: ignore[call-arg]
        return bytearray(kdf.derive(material))  # type: ignore[arg-type]
    finally:
        wipe(material)
        if wipe_pw:
            wipe(pw_bytes)


# ---------------------------------------------------------------------------
# HKDF-SHA512 (RFC 5869) - anahtar ayrimi (zafiyet raporu [15])
# ---------------------------------------------------------------------------
def _hkdf(ikm: bytes | bytearray, salt: bytes, info: bytes,
          length: int) -> bytes:
    """HKDF-SHA512: Extract (PRK = HMAC(salt, IKM)) + Expand.

    Raw concatenation yerine SP 800-108 uyumlu label tabanli ayrim:
    info'ya baglam etiketi girer, counter ile genisletilir.

    V4 zafiyet raporu [7]: RFC 5869 counter TEK OKTET'tir (0x01..0xff,
    255 blok). SHA-512 blok boyu 64 -> azami cikti 255 * 64 = 16320 byte.
    Sessiz truncation/ValueError yerine acik sinir kontrolu: bu capin
    uzerinde uzatma ISTENEMEZ (counter 256+ tasardi, iki farkli blok
    ayni T(i) ile cakisirdi).
    """
    max_len = 255 * hashlib.sha512().digest_size   # RFC 5869 tekil oktet
    if length < 0 or length > max_len:
        raise ValueError(
            f"HKDF cikti uzunlugu {length} sinir disi [0..{max_len}] "
            f"(RFC 5869 tek oktet counter siniri)")
    prk = hmac.new(salt, ikm, hashlib.sha512).digest()
    out = bytearray()
    t = b""
    counter = 1
    while len(out) < length:
        # T(i) = HMAC(PRK, T(i-1) || info || i)
        t = hmac.new(prk, t + info + bytes([counter]),
                     hashlib.sha512).digest()
        out += t
        counter += 1
    return bytes(out[:length])


# ---------------------------------------------------------------------------
# L2: Subkey rotasyonu - SHA-512 counter DRBG + ZINCIRLEME
# ---------------------------------------------------------------------------
def _derive_subkey(prev_sub: bytes | bytearray, master: bytes | bytearray,
                   nonce: bytes, rotation_index: int) -> bytes:
    """2048-bit subkey = HKDF-SHA512(master, salt=nonce, info=...).

    Zafiyet raporu [15]: raw concatenation (SHA-512(prev||master||...))
    SP 800-108 uyumsuzdu. Simdi RFC 5869 HKDF: Extract PRK = HMAC(nonce,
    master), Expand ile info label "HYPR/subkey/<rot>" + ZINCIRLEME:
    prev_sub info'ya girer, boylece subkey_{i-1} ele gecirilse bile geri
    sarmak (rewind) imkansizdir ve her subkey tum onceki rotasyonlara
    baglidir.
    """
    info = b"HYPR/subkey/" + struct.pack("<Q", rotation_index) + prev_sub
    return _hkdf(master, nonce, info, KEY_BYTES)


def _derive_auth_key(master: bytes | bytearray, nonce: bytes) -> bytearray:
    """HMAC-SHA512 auth key = HKDF(master, salt=nonce, info="HYPR/auth").

    Zafiyet raporu [15]: SHA-512(master || b"AUTH") yerine SP 800-108
    label tabanli ayrim - auth ve subkey ayni master'dan ama farkli
    baglamlarda turetilir, cakisamaz.
    """
    return bytearray(_hkdf(master, nonce, b"HYPR/auth", 64))


def _keystream_block(subkey: bytes | bytearray, block_idx: int) -> bytes:
    """64 byte dual-family keystream blogu.

    Iki bagimsiz kanitli PRF ayni girisle calisip XOR'lanir:
      a) keyed BLAKE2b-512 (key = subkey[:64])
      b) HMAC-SHA512 (zafiyet raporu [11]: secret-prefix SHA-512 kanitli
         PRF DEGILDIR - length extension teorisi; HMAC ile degistirildi)
    Bir aile zayif cikarsa digeri keystreami korur.
    """
    ctr = struct.pack("<Q", block_idx)
    a = hashlib.blake2b(subkey[64:] + ctr + b"HYPR1",
                        key=subkey[:64], digest_size=64).digest()
    b = hmac.new(subkey, ctr + b"HYPR2", hashlib.sha512).digest()
    return bytes(x ^ y for x, y in zip(a, b))


# ---------------------------------------------------------------------------
# L3: Keystream uretici (XOR simetrik oldugu icin encrypt/decrypt ortak)
# ---------------------------------------------------------------------------
class _CipherState:
    """Chunk'lara bolunmus veri icin rotasyon + blok sayaci durumu."""

    __slots__ = ("master", "nonce", "rotation_bytes",
                 "offset", "cur_rot", "cur_sub", "block_idx")

    def __init__(self, master: bytes | bytearray, nonce: bytes,
             rotation_bytes: int):
        self.master = master
        self.nonce = nonce
        self.rotation_bytes = rotation_bytes
        self.offset = 0          # islenen toplam veri byte'i
        self.cur_rot = -1        # aktif rotasyon indeksi
        self.cur_sub = master    # aktif 2048-bit subkey (zincirin basi: master)
        self.block_idx = 0       # global 64-byte keystream blok sayaci

    def process(self, data: bytes) -> bytes:
        out = bytearray()
        pos = 0
        n = len(data)
        while pos < n:
            rot = self.offset // self.rotation_bytes
            if rot != self.cur_rot:                       # ROTASYON
                self.cur_rot = rot
                self.cur_sub = _derive_subkey(
                    self.cur_sub, self.master, self.nonce, rot)
            ks = _keystream_block(self.cur_sub, self.block_idx)
            take = min(64, n - pos)
            for i in range(take):
                out.append(data[pos + i] ^ ks[i])
            pos += take
            self.offset += take
            self.block_idx += 1
        return bytes(out)


# ---------------------------------------------------------------------------
# Header isleme
# ---------------------------------------------------------------------------
def _build_header(use_hardware: bool, kdf_n: int, salt: bytes,
                  nonce: bytes, fp_blob: bytes, data_len: int,
                  rotation_bytes: int = ROTATION_BYTES,
                  padded: bool = False, keyfile: bool = False) -> bytes:
    flags = FLAG_HARDWARE if use_hardware else 0
    if padded:
        flags |= FLAG_PADDED
    if keyfile:
        # v5: keyfile kullanildi -> decrypt keyfile'siz acilmamali.
        flags |= FLAG_KEYFILE
    if use_hardware:
        # Zafiyet raporu [19]: fp_hash dogrudan SHA-256(makine kimligi)
        # OLSAYDI her pakette AYNI ozet gorunurdu -> calinan dosyalar
        # arasi korelasyon + makine atfetme. Simdi dosyaya ozel salt ile
        # tuzlanir: her pakette FARKLI gorunur, gizlilik/izleme kapisi
        # kapanir. (Kriptografik amac: master turetimine fp zaten giriyor;
        # bu alan yalnizca dogrulama-oripli meta-veri idi.)
        # V4 zafiyet raporu [4]: fp_hash hesabi fingerprint_digest()'in
        # ALTINA GOCERILDI - formullerde sapma imkansiz (tek kaynak).
        fp_hash = fingerprint_digest(fp_blob, salt)
    else:
        fp_hash = b"\x00" * FP_HASH_BYTES
    # rotation_bytes header'a gomulur (decrypt'te dogru degerin kullanilmasi
    # IÇIN - aksi halde yanlis rotation sessizce bozuk plaintext uretir).
    # 0 degeri yalnizca ESKI paketlerde gorunur -> varsayilan.
    stored_rot = rotation_bytes
    return (
        bytes([VERSION, flags]) + struct.pack("<H", stored_rot)
        + struct.pack("<I", kdf_n)
        + salt + nonce + fp_hash
        + struct.pack("<Q", data_len)
    )


def _validate_params(kdf_n: int, rotation_bytes: int,
                     salt: bytes, nonce: bytes) -> None:
    """Encrypt ic API'si icin parametre dogrulamasi (IC[10] sonrasi).

    Sessiz bozuk format / crash / uint16 tasmasi ureten degerler sifreleme
    ONCESI reddedilir:
      - kdf_n sinir disi veya 2'nin kuvveti degil : Argon2id memory_cost
        KiB (2^n sozlesmesi) + siseirilmis header KDF DoS karsi ([13][14]).
      - rotation_bytes < 64 : rotasyon 64-byte keystream bloklarinda uygulanir,
        daha kucuk degerler asla dogru sekilde kullanilamaz -> reddet.
      - rotation_bytes > 65535 : uint16 header tasar -> reddet.
      - salt/nonce yanlis uzunluk : sessizce bozuk format -> reddet.

    NOT: salt/nonce artik PUBLIC API'den gelmez (encrypt()/encrypt_file() her
    cagri icin CSPRNG uretir - IC[10]); bu dogrulama yalnizca ic
    _encrypt_deterministic()/_encrypt_file_deterministic() test yolunu
    korur. Imza zorunlu bytes'tir (None kabul edilmez).
    """
    if not MIN_KDF_N <= kdf_n <= _effective_max_kdf_n():
        raise ValueError(
            f"kdf_n {kdf_n} sinir disi "
            f"[{MIN_KDF_N}..{_effective_max_kdf_n()}] (2'nin kuvveti olmali)")
    if kdf_n & (kdf_n - 1):
        raise ValueError(
            f"kdf_n {kdf_n} 2'nin kuvveti olmali (Argon2id memory_cost KiB)")
    if not 64 <= rotation_bytes <= 65535:
        raise ValueError(
            f"rotation_bytes {rotation_bytes} sinir disi [64..65535]")
    if rotation_bytes % 64 != 0:
        # Zafiyet raporu [17]: keystream 64-byte bloklar halinde uretilir;
        # rotation 64'un kati degilse subkey degisimi blok sinirina denk
        # gelmez ve dokumante edilen "her X byte'da taze subkey" garantisi
        # sessizce ihlal edilir. 64'un kati zorunlu (64, 128, 1024, 65472).
        raise ValueError(
            f"rotation_bytes {rotation_bytes} 64'un kati olmali "
            "(keystream blok siniri ile hizalama)")
    if len(salt) != SALT_BYTES:
        raise ValueError(f"salt {len(salt)} bayt olmali ({SALT_BYTES})")
    if len(nonce) != NONCE_BYTES:
        raise ValueError(f"nonce {len(nonce)} bayt olmali ({NONCE_BYTES})")


def _validate_keyfile(keyfile: bytes | bytearray) -> None:
    """v5 keyfile dogrulamasi: >=32 byte (sympa onerisi), ust cap 1 MiB.

    Keyfile, HKDF-SHA512'ya salt olarak girer; <32 byte entropi icerigi
    ikinci faktorun guvenligini gereksiz yere dusurur (age/sympa ayni
    siniri koyar). Ust sinir: cok buyuk keyfile'lar bellek/performans
    amplifikasyonu yapmasin (bunlar saldirgan kontrolunde degildir ama
    makul kullanim capi yine de sinirli).

    V4 zafiyet raporu [6] (ENTROPI SANITY): boyut siniri tek basina
    yetersizdir - kullanici keyfile olarak tahmin edilebilir bir dosya
    (tumu ayni bayt, kisa donen desen) secerse ikinci faktor ENTROPISIZ
    kalir ve "keyfile korumali" izlenimi yanlis olur. Fail-closed:
      - <8 farkli bayt  -> tahmin edilebilir (tum-ayni / 1-7 bayt donen)
      - Shannon entropisi < 3.0 bit/bayt -> duzenli/desenli dosya
    Gercek rastgele (generate-keyfile) ve gercek dunya metin dosyalari
    (TR/EN, ~4+ bit/bayt) bu esikleri rahat gecer. 'generate-keyfile'
    kullanilmasi ONERILIR - elle secilen dosya ikinci faktoru zayiflatir.
    """
    if not isinstance(keyfile, (bytes, bytearray)):
        raise ValueError("keyfile bytes olmali")
    if len(keyfile) < KEYFILE_MIN_BYTES:
        raise ValueError(
            f"keyfile en az {KEYFILE_MIN_BYTES} byte olmali "
            f"(simdi {len(keyfile)}) - yeterli entropi icin "
            f"'generate-keyfile' komutunu kullanin")
    if len(keyfile) > KEYFILE_MAX_BYTES:
        raise ValueError(
            f"keyfile en fazla {KEYFILE_MAX_BYTES} byte olmali "
            f"(simdi {len(keyfile)})")
    # V4 [6]: entropi sanity (fail-closed - tahmin edilebilir keyfile reddi)
    counts = Counter(keyfile)
    if len(counts) < 8:
        raise ValueError(
            f"keyfile tahmin edilebilir ({len(counts)} farkli bayt < 8) - "
            f"ikinci faktor islevsiz. 'generate-keyfile' ile uretin")
    n = len(keyfile)
    entropy = -sum((c / n) * math.log2(c / n) for c in counts.values())
    if entropy < 3.0:
        raise ValueError(
            f"keyfile dusuk entropi ({entropy:.1f} bit/bayt < 3.0) - "
            f"duzenli/desenli dosya ikinci faktor olarak yetersiz. "
            f"'generate-keyfile' ile uretin")


def parse_header(header: bytes) -> Header:
    if len(header) != HEADER_BYTES:
        raise CipherError("bozuk header uzunlugu")
    version = header[0]
    if version != VERSION:
        raise CipherError(f"desteklenmeyen format surumu: {version}")
    flags = header[1]
    if flags & ~(FLAG_HARDWARE | FLAG_PADDED | FLAG_KEYFILE):
        # Zafiyet raporu [16]: tanimsiz/rezevre flag bitleri fail-open
        # olmasin - ileride guvenlikle ilgili bir bit tanimlanirsa eski
        # surum yabanci paketi sessizce kabul etmemeli.
        raise CipherError("desteklenmeyen flag bitleri (kurcalanmis veya "
                          "yeni format)")
    stored_rot = struct.unpack_from("<H", header, 2)[0]
    if stored_rot != 0 and stored_rot < 64:
        # 0 = eski varsayilan (legacy); 1..63 = encrypt asla uretmez
        # (64 alti rotasyon 64-byte keystream bloklarinda uygulanamaz) ->
        # kurcalanmis veya yabanci format.
        raise CipherError("supheli rotation_bytes (kurcalanmis veya dogru "
                          "dosya degil)")
    if stored_rot != 0 and stored_rot % 64 != 0:
        # Zafiyet raporu [17]: 64'un kati olmayan rotation encrypt ile
        # uretilemez (validate zorunlu kirar) -> boyle header kurcalanmis
        # veya yabanci formattir, fail-open yerine reddet.
        raise CipherError("supheli rotation_bytes (64'un kati degil - "
                          "kurcalanmis veya dogru dosya degil)")
    rotation_bytes = stored_rot if stored_rot != 0 else ROTATION_BYTES
    kdf_n = struct.unpack_from("<I", header, 4)[0]
    # Zafiyet raporu [14]: kdf_n sinir disi/gecersiz -> KDF CALISTIRMADAN
    # reddet (saldirgan 256 MiB bellek / ~1s CPU amplifikasyonu yapamasin).
    # DENETIM 5 bulgu [7]: env daraltilmis cap'a da uyulur (servis
    # operatorunun HYPERCIPHER_MAX_KDF_N'i header'daki kdf_n'den buyukse
    # reddedilir - KDF calismaz).
    # Argon2id memory_cost 8'in kati olmali; 2'nin kuvveti kisi gereksizdir
    # ancak API sozlesmesi 2^n KiB tutar (test/golden uyumlulugu).
    if kdf_n < MIN_KDF_N or kdf_n > _effective_max_kdf_n() or kdf_n & (kdf_n - 1):
        raise CipherError("supheli KDF parametresi (kurcalanmis veya dogru "
                          "dosya degil)")
    salt = header[8:8 + SALT_BYTES]
    nonce = header[40:40 + NONCE_BYTES]
    fp_hash = header[64:64 + FP_HASH_BYTES]
    data_len = struct.unpack_from("<Q", header, 96)[0]
    return Header(version, flags, rotation_bytes, kdf_n, salt, nonce,
                  fp_hash, data_len, header[:HEADER_BYTES])


# ---------------------------------------------------------------------------
# RAM hijyeni
# ---------------------------------------------------------------------------
def wipe(buf: bytearray | None) -> None:
    """Anahtar materyali kullanim sonrasi sifirla.

    None-safe: _derive_auth_key() gibi bir turetim HATA verirse
    `finally: wipe(auth_key)` NameError yerine sorunsuz doner (asil
    hata maskelenmez - Pyright reportPossiblyUnboundVariable fix).

    V5.3 zafiyet raporu [5] notu (BILGI): Python'da immutable bytes
    (ve str) SIFIRLANAMAZ - CPython nesneleri paylasilabilir; pyca/
    cryptography resmi dokumantasyonu da "mutable buffer gec" der.
    Bu nedenle tum KDF girdileri bytearray'dir ve wipe() ile temizlenir;
    immutable kopyalari temizlemek mumkun degildir (tum gecici kopyalari
    mutable tutmak en guclu pratik yaklasimdir - _derive_master'da yapilir).
    Guc kopyalari ise interpreter siniridir, kod duzeltmesi yoktur.
    """
    if buf is None:
        return
    for i in range(len(buf)):
        buf[i] = 0


# ---------------------------------------------------------------------------
# ISO 7816-4 padding (opsiyonel plaintext boyut gizleme - zafiyet raporu [18])
# ---------------------------------------------------------------------------
def _pad_iso7816(data: bytes, block_size: int) -> bytes:
    """data || 0x80 || 0x00...  ->  uzunluk block_size'in kati.

    Her zaman en az 1 byte ekler (0x80): plaintext zaten blok sinirinda
    olsa bile TAM bir 0x80 + 0x00* blogu eklenir. Boylece unpad'de
    "sondaki ilk 0x80" her zaman padding'e aittir - plaintext'in kendi
    icindeki 0x80'lerle karisma imkani yoktur.
    """
    pad_len = block_size - (len(data) % block_size)
    return data + b"\x80" + b"\x00" * (pad_len - 1)


def _pad_len_for(data_len: int, block_size: int) -> int:
    """data_len boyutlu veriye ISO 7816-4 padding ile eklenecek byte sayisi."""
    return block_size - (data_len % block_size)


def _unpad_iso7816(data: bytes) -> bytes:
    """_pad_iso7816'nin tersi. Bozuk/eksik padding -> ValueError.

    Blok boyutundan bagimsiz calisir: ISO 7816-4 pad her zaman 0x80 ile
    biter ve 0x80'den once yalnizca plaintext vardir; sondaki 0x00'lar
    atlanip ilk 0x80 kesilir. Kurcalanmis paket zaten HMAC'te reddedilir;
    bu fonksiyon yalnizca dogrulanmis plaintext uzerinde calisir, ama
    yine de fail-closed. Pad blok boyutu max 65536 oldugundan bundan
    fazla 0x00 siyirmak asla gecerli degildir.
    """
    if not data:
        raise ValueError("bos veri - padding bekleniyor")
    i = len(data) - 1
    n_zeros = 0
    while i >= 0 and data[i] == 0x00:
        i -= 1
        n_zeros += 1
        if n_zeros > 65536:      # [18]: pad_to ust siniri 65536
            raise ValueError("asiri uzun padding (bozuk)")
    if i < 0 or data[i] != 0x80:
        raise ValueError("bozuk padding (0x80 bulunamadi)")
    return data[:i]


# ---------------------------------------------------------------------------
# Tek parca API (kucuk veri)
# ---------------------------------------------------------------------------
def encrypt(plaintext: bytes, passphrase: str, *,
            use_hardware: bool = True, kdf_n: int = DEFAULT_KDF_N,
            rotation_bytes: int = ROTATION_BYTES,
            pad_to: int | None = None,
            keyfile: bytes | None = None) -> bytes:
    """Duz metni sifreler; header + ciphertext + tag paketi dondurur.

    keyfile (v5): ikinci faktor. Verilirse passphrase + keyfile HKDF-SHA512
    ile birlestirilir (sympa/age HKDF-SHA256 kullanir, SHA512 master ailesiyle
    tutarli) ve paket FLAG_KEYFILE tasir; decrypt ayni keyfile olmadan
    acilamaz. zayif perde tek basina artik ise yaramaz.

    pad_to (zafiyet raporu [18]): plaintext boyutunu gizlemek icin opsiyonel
    ISO 7816-4 padding - ciphertext uzunlugu pad_to'nun kati olur. data_len
    header'da PADDING DAHIL uzlunugu tasir; decrypt otomatik kaldirir.

    GUVENLIK (IC[10]): salt ve nonce KULLANICIDAN GIZLENIR - her cagri icin
    CSPRNG (os.urandom) ile uretilir, API sabit nonce kabul ETMEZ. Nonce
    reuse (ayni key+nonce -> ayni keystream -> plaintext XOR sizintisi)
    boylece kullanici hatasiyla imkansiz (libsodium secretstream / Tink
    misuse-resistant modeli). Deterministik testler ic ic
    _encrypt_deterministic() kullanir - PUBLIC API'DE DEGIL.
    """
    return _encrypt_core(
        plaintext, passphrase, use_hardware=use_hardware,
        salt=os.urandom(SALT_BYTES), nonce=os.urandom(NONCE_BYTES),
        kdf_n=kdf_n, rotation_bytes=rotation_bytes, pad_to=pad_to,
        keyfile=keyfile)


def _encrypt_core(plaintext: bytes, passphrase: str, *,
                  use_hardware: bool, salt: bytes, nonce: bytes,
                  kdf_n: int = DEFAULT_KDF_N,
                  rotation_bytes: int = ROTATION_BYTES,
                  pad_to: int | None = None,
                  keyfile: bytes | None = None) -> bytes:
    """IC UYGULAMA CORE - yalnizca encrypt() ve _encrypt_deterministic() cagirir.

    DOGRUDAN CAGIRMAYIN: salt/nonce buraya DISARIDAN gelir. encrypt() her
    cagri icin CSPRNG ile taze uretir; _encrypt_deterministic (test-only)
    V5.3'ten itibaren _DETERMINISTIC_MODE opt-in'i ile korunur. Bu core
    guard tasimaz (public API ayni koddan gecer), ama her iki tek giris
    noktasi da nonce-reuse'u engeller: public=uretilmis taze, deterministic=
    fail-closed kapali.
    """
    _validate_params(kdf_n, rotation_bytes, salt, nonce)
    if keyfile is not None:
        _validate_keyfile(keyfile)
    if pad_to is not None:
        if not 16 <= pad_to <= 65536:
            raise ValueError(f"pad_to {pad_to} sinir disi [16..65536]")
        plaintext = _pad_iso7816(plaintext, pad_to)
    fp = collect_hardware_fingerprint() if use_hardware else b""
    master = _derive_master(passphrase, fp, salt, kdf_n, keyfile)
    auth_key = None    # _derive_auth_key hata verirse wipe(None) -> guvenli
    try:
        auth_key = _derive_auth_key(master, nonce)
        state = _CipherState(master, nonce, rotation_bytes)
        ciphertext = state.process(plaintext)
        header = _build_header(use_hardware, kdf_n, salt, nonce, fp,
                               len(plaintext), rotation_bytes,
                               padded=pad_to is not None,
                               keyfile=keyfile is not None)
        tag = hmac.new(auth_key, header + ciphertext, hashlib.sha512).digest()
        return header + ciphertext + tag
    finally:
        wipe(master)
        wipe(auth_key)


def _encrypt_deterministic(plaintext: bytes, passphrase: str, *,
                           use_hardware: bool, salt: bytes, nonce: bytes,
                           kdf_n: int = DEFAULT_KDF_N,
                           rotation_bytes: int = ROTATION_BYTES,
                           pad_to: int | None = None,
                           keyfile: bytes | None = None) -> bytes:
    """SADECE ic/test API: encrypt() ile ayni ama salt/nonce SABITTIR.

    PUBLIC API'DE KULLANMAYIN. Ayni (salt, nonce) iki farkli mesaj icin
    tekrar kullanilirsa keystream ayni olur ve plaintext XOR ile sizabilir
    (IC[10] / zafiyet raporu [12]). encrypt() her cagri icin CSPRNG ile
    yeni salt/nonce uretir; bu fonksiyon yalnizca deterministik testler
    (keystream determinizmi, STS, avalanche, golden vektor, boyut/uzunluk
    dogrulamasi) icindir.
    V5.3: _DETERMINISTIC_MODE=False iken RuntimeError (fail-closed).
    """
    if not _DETERMINISTIC_MODE:
        raise RuntimeError(
            "_encrypt_deterministic test-only API kapali: "
            "_DETERMINISTIC_MODE=False. Public API icin encrypt() kullan "
            "(CSPRNG salt/nonce); test ortaminda conftest.py opt-in yapar.")
    return _encrypt_core(
        plaintext, passphrase, use_hardware=use_hardware,
        salt=salt, nonce=nonce, kdf_n=kdf_n,
        rotation_bytes=rotation_bytes, pad_to=pad_to, keyfile=keyfile)


def decrypt(packet: bytes, passphrase: str, *,
            keyfile: bytes | None = None) -> bytes:
    """Paketi cozer. Yanlis key / kurcalama / farkli makine -> CipherError.

    keyfile (v5): paket FLAG_KEYFILE tasiyorsa keyfile ZORUNLU - verilmezse
    ayni hata sinifi (CipherError) ile reddedilir (oracle olusturmaz).

    Zafiyet raporu [6]: donanim parmak izi erken ayri olarak KONTROL
    EDILMEZ. fp zaten master key turetimine giriyor; farkli makinede
    master farkli cikar ve HMAC zaten basarisiz olur. Erken fp kiyasi
    yalnizca bir timing/hata-mesaji ORACLE'i uretirdi (PBKDF2 atlanirdi).
    Tek tarafsiz hata mesaji: hangi dogrulama basarisiz oldu belli olmaz.

    rotation_bytes header'dan okunur - encrypt ile birebir ayni deger
    garantilenir (yanlis rotation sessizce bozuk plaintext uretemez).
    """
    if len(packet) < HEADER_BYTES + TAG_BYTES:
        raise CipherError("paket cok kisa")
    h = parse_header(packet[:HEADER_BYTES])
    use_hw = bool(h.flags & FLAG_HARDWARE)
    use_kf = bool(h.flags & FLAG_KEYFILE)
    if use_kf and keyfile is None:
        # v5: keyfile'li paket keyfile'siz acilamaz. "keyfile gerekli" ipucu
        # bir oracle degildir - flag zaten plaintext header'da gorunur.
        raise CipherError("bu paket keyfile (ikinci faktor) ile sifrelenmis - "
                          "aynı keyfile verilmeden acilamaz")
    if keyfile is not None and not use_kf:
        # V4 zafiyet raporu [3]: paket keyfile korumali DEGILSE keyfile
        # SESSIZCE YOK SAYILMAZ - kullanici "keyfile korumali" sanmasin.
        # KDF amplifikasyonu ONCESI net hata (fail-closed). Flag plaintext
        # header'da gorundugu icin bu hata oracle degildir.
        raise CipherError("bu paket keyfile korumali DEGIL - keyfile "
                          "verilmesi gerekmez (paket yalnizca passphrase "
                          "ile sifrelenmis)")
    if keyfile is not None:
        _validate_keyfile(keyfile)
    total = HEADER_BYTES + h.data_len + TAG_BYTES
    if len(packet) != total:
        raise CipherError("paket uzunlugu hatali (kurcalanmis olabilir)")

    fp = collect_hardware_fingerprint() if use_hw else b""

    master = _derive_master(passphrase, fp, h.salt, h.kdf_n,
                            keyfile if use_kf else None)
    auth_key = None    # _derive_auth_key hata verirse wipe(None) -> guvenli
    try:
        auth_key = _derive_auth_key(master, h.nonce)
        ciphertext = packet[HEADER_BYTES:HEADER_BYTES + h.data_len]
        tag = packet[HEADER_BYTES + h.data_len:]
        expected = hmac.new(auth_key, h.payload + ciphertext,
                            hashlib.sha512).digest()
        if not hmac.compare_digest(expected, tag):
            raise CipherError("dogrulama basarisiz - yanlis passphrase, "
                              "farkli makine veya kurcalanmis veri")
        state = _CipherState(master, h.nonce, h.rotation_bytes)
        plaintext = state.process(ciphertext)
        if h.flags & FLAG_PADDED:
            # Zafiyet raporu [18]: header'da data_len PADDING DAHIL uzunluktur;
            # HMAC dogrulandiktan SONRA ISO 7816-4 padding kaldirilir.
            try:
                plaintext = _unpad_iso7816(plaintext)
            except ValueError:
                raise CipherError("dogrulama basarisiz - yanlis passphrase, "
                                  "farkli makine veya kurcalanmis veri")
        return plaintext
    finally:
        wipe(master)
        wipe(auth_key)


# ---------------------------------------------------------------------------
# Dosya stream API (buyuk veri, chunk tabanli)
# ---------------------------------------------------------------------------
def encrypt_file(in_path: str, out_path: str, passphrase: str, *,
                 use_hardware: bool = True, kdf_n: int = DEFAULT_KDF_N,
                 rotation_bytes: int = ROTATION_BYTES,
                 pad_to: int | None = None,
                 keyfile: bytes | None = None,
                 progress=None) -> str:
    """Dosyayi chunk chunk sifreler. progress(done, total) cagrisi opsiyonel.

    keyfile (v5): encrypt() ile ayni - ikinci faktor. FLAG_KEYFILE set edilir.

    GUVENLIK (IC[10]): encrypt() ile ayni politika - salt/nonce kullanicidan
    gizlenir, her cagri icin CSPRNG ile uretilir. API sabit nonce kabul
    etmez (nonce reuse -> keystream XOR sizintisi). Deterministik
    karsilastirmalar icin ic _encrypt_file_deterministic() vardir.

    GUVENLIK (zafiyet raporu [1][2][3][9][10]):
      - Gecici dosya mkstemp(O_EXCL, 0600, random isim) ile acilir:
        symlink/junction saldirisi ve onceden yerlesim imkansiz ([1][2]).
      - TOCTOU: boyut open() SONRASI fstat() ile alinir; islem sirasinda
        dosya degisirse done != data_len kontrolu paketi reddeder ([3]).
      - Girdi normal DOSYA olmali (FIFO/device/dir -> CipherError) ([10]).
      - ATOMIC: fsync + os.replace; hata durumunda gecici dosya silinir,
        asla yarim/bozuk cikti birakilmaz ([9]).
    """
    return _encrypt_file_core(
        in_path, out_path, passphrase, use_hardware=use_hardware,
        salt=os.urandom(SALT_BYTES), nonce=os.urandom(NONCE_BYTES),
        kdf_n=kdf_n, rotation_bytes=rotation_bytes, pad_to=pad_to,
        keyfile=keyfile, progress=progress)


def _encrypt_file_core(in_path: str, out_path: str,
                       passphrase: str, *, use_hardware: bool,
                       salt: bytes, nonce: bytes,
                       kdf_n: int = DEFAULT_KDF_N,
                       rotation_bytes: int = ROTATION_BYTES,
                       pad_to: int | None = None,
                       keyfile: bytes | None = None,
                       progress=None) -> str:
    """IC UYGULAMA CORE - yalnizca encrypt_file() ve
    _encrypt_file_deterministic() cagirir.

    DOGRUDAN CAGIRMAYIN: salt/nonce disaridan gelir; encrypt_file() CSPRNG
    ile taze uretir, _encrypt_file_deterministic (test-only) V5.3'ten
    itibaren _DETERMINISTIC_MODE opt-in'i ile korunur. Iki giris noktasi
    da nonce-reuse'u engeller (bkz. _encrypt_core docstring).
    """
    _validate_params(kdf_n, rotation_bytes, salt, nonce)
    if keyfile is not None:
        _validate_keyfile(keyfile)
    if pad_to is not None and not 16 <= pad_to <= 65536:
        raise ValueError(f"pad_to {pad_to} sinir disi [16..65536]")
    fp = collect_hardware_fingerprint() if use_hardware else b""
    # BULGU 17 fix (arastirma: "create secrets late, destroy early" + RAII
    # wipe-on-all-paths + "zeroize before returning error"): onceki siralamada
    # master derive EDILDIKTEN sonra _make_tmp_near try DISINDA cagrilirdi;
    # tmp olusturma hata verirse (orn. hedef dizin yok) finally hic calismaz
    # ve 256B master wipe edilmeden GC'ye kalirdi (ampirik: ProcessLookupError
    # ile kanitlandi). En guclu cozum: once kaynak (tmp) tahsis edilir, master
    # ise try ICINDE turetilir - boylece tum hata yollari finally/wipe kapsamina
    # girer ve secret mumkun olan EN GEK anda olusturulur (yasam suresi minimum).
    fd, tmp_path = _make_tmp_near(out_path)
    fout = None
    master = None      # finally: wipe(None) guvenli (_derive_master hata yolu)
    auth_key = None    # _derive_auth_key hata verirse wipe(None) -> guvenli
    try:
        master = _derive_master(passphrase, fp, salt, kdf_n, keyfile)
        auth_key = _derive_auth_key(master, nonce)
        state = _CipherState(master, nonce, rotation_bytes)
        with open(in_path, "rb") as fin:
            # TOCTOU [3]: boyut acilmis fd UZERINDEN fstat ile alinir;
            # getsize+open arasinda dosyanin degismesi artik onemsiz.
            finfo = os.fstat(fin.fileno())
            if not stat.S_ISREG(finfo.st_mode):      # [10]
                raise CipherError("girdi normal bir dosya degil (FIFO/"
                                  "cihaz/klasor desteklenmez)")
            orig_len = finfo.st_size
            # [18]: pad_to verildiyse data_len PADDING DAHIL uzunluktur -
            # dosya boyutu plaintext boyutunu birebir ifsa etmez.
            if pad_to is not None:
                pad_len = _pad_len_for(orig_len, pad_to)
                data_len = orig_len + pad_len
            else:
                pad_len = 0
                data_len = orig_len
            header = _build_header(use_hardware, kdf_n, salt, nonce, fp,
                                   data_len, rotation_bytes,
                                   padded=pad_to is not None,
                                   keyfile=keyfile is not None)
            tag = hmac.new(auth_key, header, hashlib.sha512)
            done = 0
            fout = os.fdopen(fd, "wb")          # fd sahipligi -> fout
            fd = -1                             # artik biz kapatmiyoruz
            fout.write(header)
            while True:
                chunk = fin.read(CHUNK)
                if not chunk:
                    if pad_to is not None and pad_len:
                        # Bos dosya (orig_len == 0): dongu HIC donmez -
                        # padding'i yine de ekle, yoksa done != data_len
                        # hatasi ve tag eksikligi olur.
                        chunk = b"\x80" + b"\x00" * (pad_len - 1)
                        pad_len = 0
                    else:
                        break
                if pad_to is not None and pad_len and \
                        done + len(chunk) == orig_len:
                    # Son chunk: ISO 7816-4 padding'i yalnizca dosya sonuna
                    # eklenir (chunk sinirlarindan bagimsiz).
                    chunk = chunk + b"\x80" + b"\x00" * (pad_len - 1)
                    pad_len = 0   # sadece bir kez
                enc = state.process(chunk)
                fout.write(enc)
                tag.update(enc)
                done += len(chunk)
                if progress:
                    progress(done, data_len)
            if done != data_len:                # islem sirasinda degisti [3]
                raise CipherError("girdi dosyasi islem sirasinda degisti "
                                  "(boyut uyusmazligi)")
            fout.write(tag.digest())
            if progress and done == 0:
                progress(0, 0)    # [29] bos dosya: loop donmedi, yine de cagir
        fout.flush()
        os.fsync(fout.fileno())                 # durability [9]
        fout.close()
        fout = None
        os.replace(tmp_path, out_path)          # ATOMIC commit
        return out_path
    except BaseException:
        if fd != -1:                            # fout acilmadan hata
            try:
                os.close(fd)
            except OSError:
                pass
        if fout is not None:
            try:
                fout.close()
            except OSError:
                pass
        _safe_unlink(tmp_path)
        raise
    finally:
        wipe(master)
        wipe(auth_key)


def _encrypt_file_deterministic(in_path: str, out_path: str,
                                passphrase: str, *, use_hardware: bool,
                                salt: bytes, nonce: bytes,
                                kdf_n: int = DEFAULT_KDF_N,
                                rotation_bytes: int = ROTATION_BYTES,
                                pad_to: int | None = None,
                                keyfile: bytes | None = None,
                                progress=None) -> str:
    """SADECE ic/test API: encrypt_file() ile ayni ama salt/nonce SABITTIR.

    PUBLIC API'DE KULLANMAYIN (IC[10]): ayni (salt, nonce) tekrari ->
    keystream tekrari -> plaintext XOR sizintisi. encrypt_file() CSPRNG ile
    uretir; bu fonksiyon deterministik dosya karsilastirmaları (encrypt()
    ile birebir ayni cikti) icindir.
    V5.3: _DETERMINISTIC_MODE=False iken RuntimeError (fail-closed).
    """
    if not _DETERMINISTIC_MODE:
        raise RuntimeError(
            "_encrypt_file_deterministic test-only API kapali: "
            "_DETERMINISTIC_MODE=False. Public API icin encrypt_file() "
            "kullan (CSPRNG salt/nonce); test ortaminda conftest.py opt-in "
            "yapar.")
    return _encrypt_file_core(
        in_path, out_path, passphrase, use_hardware=use_hardware,
        salt=salt, nonce=nonce, kdf_n=kdf_n,
        rotation_bytes=rotation_bytes, pad_to=pad_to,
        keyfile=keyfile, progress=progress)


def decrypt_file(in_path: str, out_path: str, passphrase: str, *,
                 keyfile: bytes | None = None,
                 progress=None) -> str:
    """Dosyayi chunk chunk cozer.

    keyfile (v5): paket FLAG_KEYFILE tasiyorsa zorunlu (decrypt() ile ayni).

    GUCLU GUVENLIK (zafiyet raporu [1][2][3][4][9][10]):
      - IKI GECISLI verify-then-decrypt (zafiyet raporu [2] fix'i):
        GECIS 1 tum ciphertext uzerinde HMAC-SHA512 isletir ve tag'i
        dogrular - bu sirada HICBIR dosya acilmaz, tek byte plaintext
        uretilmez. GECIS 2 (tag OK ise) seek + decrypt + gecici dosyaya
        yazar. Kurcalanmis paketin kismi plaintext'i asla diske dusmez;
        dogrulama basarisizsa hicbir tmp dosyasi yoktur ([1][2]).
      - Plaintext, dogrulama GECENE kadar hedef dosya adi altinda
        GORUNMEZ; Windows'ta CreateFileW + protected DACL (SDDL D:P) /
        POSIX'te mkstemp 0600 ile gecici plaintext'i diger kullanicilar
        okuyamaz ([4] fix'i).
      - TOCTOU [3]: boyut fstat ile open SONRASI alinir; kesik paket
        erken tespit edilir.
      - ATOMIC: fsync + os.replace sadece basarili dogrulamadan sonra ([9]).
      - Girdi normal DOSYA olmalidir ([10]).

    rotation_bytes header'dan okunur (decrypt_file'a parametre GECMEZ -
    yanlis deger verme imkani yok, format bunu garantiler).
    """
    fout = None
    verified = False
    fd = -1
    tmp_path = None
    try:
        with open(in_path, "rb") as fin:
            finfo = os.fstat(fin.fileno())     # TOCTOU [3]: open sonrasi
            if not stat.S_ISREG(finfo.st_mode):  # [10]
                raise CipherError("girdi normal bir dosya degil (FIFO/"
                                  "cihaz/klasor desteklenmez)")
            size = finfo.st_size
            if size < HEADER_BYTES + TAG_BYTES:
                raise CipherError("paket cok kisa")
            header = fin.read(HEADER_BYTES)
            h = parse_header(header)
            use_hw = bool(h.flags & FLAG_HARDWARE)
            use_kf = bool(h.flags & FLAG_KEYFILE)
            if use_kf and keyfile is None:
                raise CipherError("bu paket keyfile (ikinci faktor) ile "
                                  "sifrelenmis - ayni keyfile verilmeden "
                                  "acilamaz")
            if keyfile is not None and not use_kf:
                # V4 zafiyet raporu [3]: keyfile korumali OLMAYAN pakete
                # keyfile verilirse SESSIZCE YOK SAYILMAZ - kullanici
                # "keyfile korumali" sanmasin (fail-closed, oracle degil).
                raise CipherError("bu paket keyfile korumali DEGIL - keyfile "
                                  "verilmesi gerekmez (paket yalnizca "
                                  "passphrase ile sifrelenmis)")
            if keyfile is not None:
                _validate_keyfile(keyfile)
            fp = collect_hardware_fingerprint() if use_hw else b""
            # Zafiyet raporu [6]: fp ERKEN KONTROL EDILMEZ (oracle).
            # fp zaten master turetimine girer -> farkli makinede master farkli
            # cikar ve HMAC basarisiz olur. Tek tarafsiz hata mesaji yeter.
            # Cross-check: header'da yazan data_len ile dosyanin gercek boyutu
            # uyumlu olmali - kurcalanmis/kesik paket MAC oncesi erken tespit.
            if size != HEADER_BYTES + h.data_len + TAG_BYTES:
                raise CipherError("paket uzunlugu hatali (kurcalanmis olabilir)")
            master = _derive_master(passphrase, fp, h.salt, h.kdf_n,
                                    keyfile if use_kf else None)
            auth_key = None  # _derive_auth_key hata verirse wipe(None) guvenli
            try:
                auth_key = _derive_auth_key(master, h.nonce)

                # ===== PASS 1: ciphertext uzerinde HMAC akisi (YAZMA YOK) =====
                # Zafiyet raporu [2] fix'i: onceki surum plaintext'i HMAC
                # dogrulanmadan ONCE tmp dosyaya yaziyordu (kurcalanmis
                # paketin kismi plaintext'i diske dusuyordu). Simdi:
                #   - PASS 1: header + tum ciphertext akar, sadece HMAC
                #     islenir. HICBIR dosya acilmaz, tek byte plaintext
                #     uretilmez, diskte iz YOK.
                #   - PASS 2: tag dogrulandiktan SONRA fin.seek(HEADER_BYTES)
                #     ile basa donulur, tmp dosya ANCAK simdi acilir ve
                #     dogrulanmis ciphertext cozulur. Dogrulanmis ciphertext
                #     -> dogrulanmis plaintext (verify-then-decrypt).
                # Desen: libsodium secretstream / age STREAM (tag oncelikli
                # dogrulama) - GPG'nin .part + MDC-sonrasi hata sinifi bu
                # iki gecisle tamamen kapatilir.
                tag = hmac.new(auth_key, header, hashlib.sha512)
                remaining = h.data_len
                while remaining > 0:
                    take = min(CHUNK, remaining)
                    chunk = fin.read(take)
                    if not chunk:
                        raise CipherError("paket kesik (truncated)")
                    tag.update(chunk)
                    remaining -= len(chunk)
                stored_tag = fin.read(TAG_BYTES)
                if not hmac.compare_digest(tag.digest(), stored_tag):
                    raise CipherError("dogrulama basarisiz - yanlis passphrase, "
                                      "farkli makine veya kurcalanmis veri")

                # ===== PASS 2: dogrulanmis ciphertext -> plaintext tmp'e =====
                # tmp dosya SADECE dogrulama gectikten sonra acilir; hata
                # durumunda tmp_path None kalir, _safe_unlink gerekmez.
                fd, tmp_path = _make_tmp_near(out_path)
                fout = os.fdopen(fd, "wb")     # fd sahipligi -> fout
                fd = -1
                fin.seek(HEADER_BYTES)         # ciphertext basina don
                # DENETIM 5 bulgu [2] (TOCTOU): PASS 1 ile PASS 2 arasinda
                # dosya degisirse PASS 1'in dogruladigi HMAC ESKI baytlari
                # kapsar, PASS 2'nin cozdugu YENI baytlar olur. En guclu
                # cozum (Soatok/Halite deseni): PASS 2'de decrypt ile AYNI
                # akista HMAC'i YENIDEN hesapla ve loop sonunda tekrar
                # dogrula -> dogrulanan baytlar == cozulen baytlar garantisi.
                # Ek maliyet: bir ekstra HMAC-SHA512 akisi (decrypt'ten ucuz).
                tag2 = hmac.new(auth_key, header, hashlib.sha512)
                state = _CipherState(master, h.nonce, h.rotation_bytes)
                remaining = h.data_len
                done = 0
                pending = b""          # [18]: son chunk unpad icin bekletilir
                while remaining > 0:
                    take = min(CHUNK, remaining)
                    chunk = fin.read(take)
                    if not chunk:
                        raise CipherError("paket kesik (truncated)")
                    tag2.update(chunk)         # TOCTOU fix: ayni baytlar dogrulanir
                    dec = state.process(chunk)
                    if pending:
                        fout.write(pending)    # onceki chunk yaz (son degil)
                    pending = dec
                    remaining -= len(chunk)
                    done += len(chunk)
                    if progress:
                        progress(done, h.data_len)
                if not hmac.compare_digest(tag2.digest(), stored_tag):
                    # PASS 2 okudugu baytlar PASS 1'den farkli -> tmp silinir
                    raise CipherError("dogrulama basarisiz - yanlis passphrase, "
                                      "farkli makine veya kurcalanmis veri")
                if progress and done == 0:
                    progress(0, 0)  # [29] bos paket: loop donmedi, yine de cagir
                if h.flags & FLAG_PADDED:
                    try:
                        pending = _unpad_iso7816(pending)
                    except ValueError:
                        raise CipherError("dogrulama basarisiz - yanlis "
                                          "passphrase, farkli makine veya "
                                          "kurcalanmis veri")
                fout.write(pending)
                fout.flush()
                os.fsync(fout.fileno())        # durability [9]
                fout.close()
                fout = None
                verified = True
            finally:
                wipe(master)
                wipe(auth_key)
        # fin burada KAPALI: out_path == in_path (self-overwrite) Windows'ta
        # artik PermissionError uretmez.
    except BaseException:
        if fd != -1:                           # fout acilmadan hata
            try:
                os.close(fd)
            except OSError:
                pass
        if fout is not None:
            try:
                fout.close()
            except OSError:
                pass
        if tmp_path is not None:
            _safe_unlink(tmp_path)
        raise
    # Replace sadece dogrulanmis plaintext icin ATOMIC commit.
    if verified:
        # BULGU 18 fix (OpenSSF pyscg-0037 + Bandit B101 + PyNaCl ensure()
        # deseni): assert -O/PYTHONOPTIMIZE ile bytecode'dan SILINIR; kritik
        # invariant'lar icin explicit fail-closed raise kullanilir. verified
        # =True yalnizca PASS 2 sonunda tmp_path atanmisken kurulabilir; bu
        # internal invariant ihlali yine de KALICI olarak denetlenir (-O'da
        # bile calisir, sessizce None ile os.replace'e girilmez).
        if tmp_path is None:
            raise RuntimeError(
                "internal invariant bozuldu: verified=True ama tmp_path yok "
                "(PASS 2 yazim yolu hatasi)")
        try:
            os.replace(tmp_path, out_path)
        except BaseException:
            _safe_unlink(tmp_path)
            raise
    return out_path


def _make_tmp_near(out_path: str) -> tuple[int, str]:
    """Hedef dizinde GUVENLI gecici dosya: O_EXCL + random isim + 0600.

    Zafiyet raporu [1]: deterministik ".tmp" adi symlink/junction
    saldirisina acikti (saldirgan once "cikti.hyp.tmp" adinda symlink
    yerlestirir, encrypt/decrypt o yolu TAKIP eder). Cikti dosyasinin
    yaninda, SADECE bu surecin urettigi, O_EXCL ile acilmis (var olan
    hicbir yolu takip etmez), random isimli gecici dosya uretilir. Ayni
    dizinde oldugu icin os.replace() EXDEV hata vermez.

    DENETIM 2 bulgu [1] fix'i: POSIX'te mkstemp mode=0o600 GERCEKTEN
    uygulanir (baska kullanici okuyamaz). WINDOWS'ta ise mode parametresi
    YOK SAYILIR - dosya, dizinden ACL KALITIR (SYSTEM/Administrators +
    Authenticated Users + sandbox SID'leri -> plaintext'i iceren gecici
    dosyayi baska kullanicilar okuyabilir). Fix: Windows'ta ctypes ile
    CreateFileW + SECURITY_ATTRIBUTES + SDDL "D:P(A;;FA;;;{user_sid})":
      - D:P = PROTECTED DACL: dizinden gelen kalitimsal ACE'ler UYGULANMAZ
      - (A;;FA;;;{user_sid}) = yalnizca mevcut kullaniciya tam erisim
      - dwShareMode=0 = handle acikken HICBIR surec dosyayi yeniden
        acamaz (okuma/yazma/silme paylasimi yok) - en guclu kilit
      - CREATE_NEW = O_EXCL semantigi; isim secrets.token_hex ile
      Handle -> msvcrt.open_osfhandle -> fd (os.fdopen ile uyumlu).
    os.replace ACL'yi KORUR (MS: varsayilan SD yalnizca olusturmada
    atanir, rename'de degil) -> hedef dosya da kullaniciya ozel kalir.
    """
    directory = os.path.dirname(os.path.abspath(out_path)) or "."
    if os.name == "nt":
        return _make_tmp_near_windows(directory)
    fd, tmp_path = tempfile.mkstemp(prefix=".hyp-", suffix=".tmp",
                                    dir=directory)
    return fd, tmp_path


_WIN_TOKEN_API: Optional[Dict[str, Any]] = None


def _win_token_api() -> Dict[str, Any]:
    """BULGU 16 fix: SID cozumleme ctypes prototiplerinin lazy singleton'i.

    Ampirik kanit (30.000 cagri -> WorkingSet +260 MB, ~8.7 KB/call):
    1. Eski kod HER cagrida yeni WinDLL ornekleri + argtypes/restype atamalari
       ve yeni SID_AND_ATTRIBUTES/TOKEN_USER Structure siniflari uretiyordu.
    2. Her cagrida olusturulan YENI Structure sinifi icin ctypes.POINTER()
       cagrildiginda sinif ctypes._pointer_type_cache'e kaydediliyordu.
       Bu cache SINIRSIZDIR (CPython gh-100926) -> her cagri kalici ~8 KB
       birakti; uzun yasayan sureclerde (servis/GUI/batch) OOM riski.

    En guclu fix (arastirma: mkropat gist + CPython gh-100926 + SO 17125978):
    tum prototipleri TEK KEZ kur (lazy singleton). Boylece pointer-cache'e
    yalnizca bir girilir, cagri-basi maliyet ~0'a iner. Windows-disi
    platformlar bu fonksiyonu hic cagirmaz (import'ta DLL yuklenmez).
    """
    global _WIN_TOKEN_API
    if _WIN_TOKEN_API is not None:
        return _WIN_TOKEN_API
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    # BULGU 16: ConvertSidToStringSidW'nin LocalAlloc ile ayirdigi stringi
    # iade etmek icin LocalFree prototipi (MSDN/pinvoke; LocalFree(NULL)
    # guvenli no-op'tir).
    kernel32.LocalFree.argtypes = [wintypes.HANDLE]
    kernel32.LocalFree.restype = wintypes.HANDLE
    advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD,
                                          ctypes.POINTER(wintypes.HANDLE)]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int,
                                             ctypes.c_void_p, wintypes.DWORD,
                                             ctypes.POINTER(wintypes.DWORD)]
    advapi32.GetTokenInformation.restype = wintypes.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p,
                                                ctypes.POINTER(ctypes.c_wchar_p)]
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL

    # Structure siniflari TEK KEZ tanimlanir -> POINTER(TOKEN_USER) cache'e
    # yalnizca bir kez girer (sinirsiz buyume kapanir).
    class SID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("Sid", ctypes.c_void_p),
                    ("Attributes", wintypes.DWORD)]

    class TOKEN_USER(ctypes.Structure):
        _fields_ = [("User", SID_AND_ATTRIBUTES)]

    _WIN_TOKEN_API = {
        "ctypes": ctypes,
        "wintypes": wintypes,
        "kernel32": kernel32,
        "advapi32": advapi32,
        "TOKEN_USER": TOKEN_USER,
        # POINTER() her cagrida yeniden kurulmasin diye onceden uretilir.
        "P_TOKEN_USER": ctypes.POINTER(TOKEN_USER),
    }
    return _WIN_TOKEN_API


def _current_user_sid_string() -> str:
    """Windows: aktif prosesin kullanici SID'ini string olarak dondurur.

    DENETIM 5 bulgu [1]: keyfile uretimi de ACL korumasi gerektirir;
    SID cozumleme kodu _make_tmp_near_windows ile PAYLASILIR (tek kaynak).

    BULGU 16 fix: ctypes prototipleri _win_token_api() singleton'indan gelir
    (cagri-basi sinif/DLL uretimi yok -> pointer-cache sizintisi kapanir) ve
    ConvertSidToStringSidW'nin ayirdigi string LocalFree ile her zaman iade
    edilir (MSDN/pinvoke: zorunlu; onceki kod hic free etmiyordu).
    """
    api = _win_token_api()
    ctypes = api["ctypes"]
    wintypes = api["wintypes"]
    kernel32 = api["kernel32"]
    advapi32 = api["advapi32"]
    p_token_user = api["P_TOKEN_USER"]

    TOKEN_QUERY = 0x0008
    TokenUser = 1                      # TokenInformationClass::TokenUser

    h_token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(
            kernel32.GetCurrentProcess(), TOKEN_QUERY,
            ctypes.byref(h_token)):
        raise OSError(ctypes.get_last_error()
                      if ctypes.get_last_error()
                      else ctypes.WinError(), "OpenProcessToken basarisiz")
    p_str = ctypes.c_wchar_p()
    try:
        buf_len = wintypes.DWORD()
        advapi32.GetTokenInformation(h_token, TokenUser, None, 0,
                                     ctypes.byref(buf_len))
        buf = ctypes.create_string_buffer(buf_len.value)
        if not advapi32.GetTokenInformation(h_token, TokenUser, buf,
                                            buf_len.value,
                                            ctypes.byref(buf_len)):
            raise OSError(ctypes.WinError(), "GetTokenInformation basarisiz")

        user = ctypes.cast(buf, p_token_user).contents
        psid = ctypes.c_void_p(user.User.Sid)
        if not advapi32.ConvertSidToStringSidW(
                psid, ctypes.byref(p_str)):
            raise OSError(ctypes.WinError(), "ConvertSidToStringSidW basarisiz")
        if p_str.value is None:
            raise OSError("ConvertSidToStringSidW bos sonuc dondu")
        return p_str.value
    finally:
        # BULGU 16: LocalAlloc ile ayrilan string her zaman serbest birakilir.
        # p_str.value Python str olarak KOPYALANDIKTAN sonra free guvenlidir;
        # LocalFree(NULL) MSDN'e gore guvenli no-op'tir (erken raise yolu).
        kernel32.LocalFree(ctypes.cast(p_str, ctypes.c_void_p))
        if h_token.value:
            kernel32.CloseHandle(h_token)


def _create_private_file_windows(path: str) -> int:
    """Windows: hedef path'te CreateFileW + protected DACL + CREATE_NEW.

    DENETIM 5 bulgu [1]: generate_keyfile sinirsiz/sahipsiz ACL ile dosya
    olusturuyordu (os.open 0o600 Windows'ta yok sayilir). En guclu cozum:
    dosyayi ACL'si disinda kimse erisemeyecek sekilde ATOMIK olusturmak
    (CreateFileW + SDDL D:P(A;;FA;;;user_sid) + CREATE_NEW = O_EXCL).
    Once olusturup sonra ACL degistirmek TOCTOU penceresi birakir.

    Hedef zaten varsa FileExistsError yukseltir (ustune YAZILMAZ).
    """
    import ctypes
    from ctypes import wintypes
    import msvcrt

    GENERIC_RW = 0xC0000000            # GENERIC_READ | GENERIC_WRITE
    CREATE_NEW = 1
    FILE_ATTRIBUTE_NORMAL = 0x80
    # DENETIM 5 bulgu [15]: CreateFileW varsayilan olarak reparse point'leri
    # (symlink/junction) TAKIP EDER -> saldirgan hedef yol yerine symlink
    # koyarsa keyfile baska dosyaya yazilir (hedef dosya ustune yazma riski).
    # FILE_FLAG_OPEN_REPARSE_POINT ile reparse point COZULMEZ; CREATE_NEW ile
    # zaten var oldugu icin FileExistsError alinir (fail-closed).
    FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
    INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value
    ERROR_FILE_EXISTS = 80
    ERROR_ALREADY_EXISTS = 183
    SDDL_REVISION_1 = 1

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD,
                                     wintypes.DWORD, ctypes.c_void_p,
                                     wintypes.DWORD, wintypes.DWORD,
                                     wintypes.HANDLE]
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.GetLastError.restype = wintypes.DWORD
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_void_p]
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = (
        wintypes.BOOL)

    class SECURITY_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("nLength", wintypes.DWORD),
                    ("lpSecurityDescriptor", ctypes.c_void_p),
                    ("bInheritHandle", wintypes.BOOL)]

    sa = SECURITY_ATTRIBUTES()
    sa.nLength = ctypes.sizeof(SECURITY_ATTRIBUTES)
    sa.bInheritHandle = False
    psd = ctypes.c_void_p()
    sddl = f"D:P(A;;FA;;;{_current_user_sid_string()})"
    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, SDDL_REVISION_1, ctypes.byref(psd), None):
        raise OSError(ctypes.WinError(), "SDDL donusumu basarisiz")
    sa.lpSecurityDescriptor = psd
    try:
        h = kernel32.CreateFileW(
            path, GENERIC_RW, 0,            # dwShareMode=0: paylasim YOK
            ctypes.byref(sa), CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, None)
        if h == INVALID_HANDLE_VALUE:
            err = kernel32.GetLastError()
            if err in (ERROR_FILE_EXISTS, ERROR_ALREADY_EXISTS):
                raise FileExistsError(f"keyfile zaten var (ustune yazilmadi): {path}")
            raise OSError(err, f"CreateFileW basarisiz: {path}")
        fd = msvcrt.open_osfhandle(h, os.O_RDWR)
        if fd == -1:
            kernel32.CloseHandle(h)
            raise OSError("open_osfhandle basarisiz")
        return fd
    finally:
        if psd.value:
            kernel32.LocalFree(psd)


def _make_tmp_near_windows(directory: str) -> tuple[int, str]:
    """Windows: CreateFileW + protected DACL (yalnizca mevcut kullanici).

    DENETIM 2 bulgu [1] - mkstemp 0600 iddiasi Windows'ta gecersizdi.
    En guclu cozum: dosyayi ACL'si disinda kimse erisemeyecek sekilde
    ATOMik olusturmak (once olusturup sonra ACL degistirmek TOCTOU
    penceresi birakir - dosya kisa da olsa kalitimsal ACL ile gorunur).
    """
    import ctypes
    from ctypes import wintypes
    import secrets

    GENERIC_RW = 0xC0000000            # GENERIC_READ | GENERIC_WRITE
    CREATE_NEW = 1
    FILE_ATTRIBUTE_NORMAL = 0x80
    # BULGU A fix (MSDN CreateFileW + CERT POS01-C O_NOFOLLOW Windows parity):
    # CreateFileW varsayilan olarak reparse point'leri (symlink/junction) TAKIP
    # EDER. tmp dosyasi olusturulurken hedef yol bilesenlerinden biri reparse
    # point ise plaintext icerigi baska konuma yazilabilir. FILE_FLAG_OPEN_
    # REPARSE_POINT reparse point'i COZMEZ; CREATE_NEW ile birlesince reparse
    # point zaten "var" sayilir ve olusturma fail-closed reddedilir. Dosya
    # reparse point degilse flag yok sayilir (normal davranis birebir ayni).
    # Bu, POSIX yolundaki O_NOFOLLOW (BULGU 15) ve _create_private_file_windows
    # ile ayni korumayi saglar (rapor satir 201 iddiasiyla da tutarli).
    FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
    INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value
    ERROR_FILE_EXISTS = 80
    ERROR_ALREADY_EXISTS = 183
    SDDL_REVISION_1 = 1

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    import msvcrt  # yerlesik modul: open_osfhandle C runtime'ini dogru bulur

    # --- WinAPI imzalari (64-bit HANDLE truncation'ini ONLER) ---
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD,
                                     wintypes.DWORD, ctypes.c_void_p,
                                     wintypes.DWORD, wintypes.DWORD,
                                     wintypes.HANDLE]
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.GetLastError.restype = wintypes.DWORD
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_void_p]
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = (
        wintypes.BOOL)

    # --- 1) Mevcut kullanicinin SID'i (paylasilan helper) ---
    sid_str = _current_user_sid_string()

    # --- 2) SECURITY_ATTRIBUTES: protected DACL + yalnizca kullanici ---
    class SECURITY_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("nLength", wintypes.DWORD),
                    ("lpSecurityDescriptor", ctypes.c_void_p),
                    ("bInheritHandle", wintypes.BOOL)]

    sa = SECURITY_ATTRIBUTES()
    sa.nLength = ctypes.sizeof(SECURITY_ATTRIBUTES)
    sa.bInheritHandle = False
    psd = ctypes.c_void_p()
    # D:P -> protected (kalitimsal ACE yok); (A;;FA;;;SID) -> tam erisim
    sddl = f"D:P(A;;FA;;;{sid_str})"
    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, SDDL_REVISION_1, ctypes.byref(psd), None):
        raise OSError(ctypes.WinError(), "SDDL donusumu basarisiz")
    sa.lpSecurityDescriptor = psd
    try:
        # --- 3) CREATE_NEW ile atomik olustur (O_EXCL), 100 deneme ---
        for _ in range(100):
            name = ".hyp-" + secrets.token_hex(8) + ".tmp"
            tmp_path = os.path.join(directory, name)
            h = kernel32.CreateFileW(
                tmp_path, GENERIC_RW, 0,            # dwShareMode=0: paylasim YOK
                ctypes.byref(sa), CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, None)
            if h != INVALID_HANDLE_VALUE:
                fd = msvcrt.open_osfhandle(h, os.O_RDWR)
                if fd == -1:
                    kernel32.CloseHandle(h)
                    raise OSError("open_osfhandle basarisiz")
                return fd, tmp_path
            err = kernel32.GetLastError()
            if err not in (ERROR_FILE_EXISTS, ERROR_ALREADY_EXISTS):
                raise OSError(err, f"CreateFileW basarisiz: {name}")
        raise OSError("gecici dosya isim uretimi 100 denemede basarisiz")
    finally:
        if psd.value:
            kernel32.LocalFree(psd)


def _safe_unlink(path: str) -> None:
    """Var olan dosyayi siler; basarisizsa guvenli sekilde UYARIR.

    Zafiyet raporu [4]: basarisiz _safe_unlink sessizce yutuluyordu;
    kilitli/kalinti bir plaintext dosyasi fark edilmeden kalabiliyordu.
    Artik warnings.warn ile en azindan bildirilir.
    """
    try:
        os.unlink(path)
    except OSError as e:
        warnings.warn(f"gecici dosya temizlenemedi: {path} ({e})",
                      RuntimeWarning, stacklevel=2)


# ---------------------------------------------------------------------------
# v5: Keyfile islemleri (ikinci faktor - age/sympa modeli)
# ---------------------------------------------------------------------------
def generate_keyfile(path: str, length: int = KEYFILE_RECOMMENDED_BYTES) -> str:
    """Yeni keyfile uretir ve dosyaya yazar (0600, O_EXCL - var olan uzerine
    YAZILMAZ).

    Keyfile = os.urandom(length) -> 256-bit entropi (64 byte). Insan
    hafizasi yerine rastgelelik: saldirgan perdeyi bilse bile keyfile
    olmadan HICBIR sey yapamaz.

    Guvenlik (rapor [1] deseni): dosya O_EXCL ile acilir (saldirganin
    onceden symlink yerlestirmesi imkansiz), POSIX'te 0600 ile. Windows'ta
    os.open(0o600) modu YOK SAYILIR (denetim 5 bulgu [1]) -> bunun yerine
    CreateFileW + protected DACL (D:P(A;;FA;;;user_sid)) + CREATE_NEW ile
    dogrudan hedef path'te atomik olusturulur (_create_private_file_windows).
    """
    if not KEYFILE_MIN_BYTES <= length <= KEYFILE_MAX_BYTES:
        raise ValueError(f"keyfile boyutu {length} sinir disi "
                         f"[{KEYFILE_MIN_BYTES}..{KEYFILE_MAX_BYTES}]")
    directory = os.path.dirname(os.path.abspath(path)) or "."
    # BULGU 13 fix: makedirs varsayilan mode 0o777 & ~umask (genelde 0o755)
    # ile ebeveyn dizin olusturuyordu -> dizin-okunur (metadata sizintisi)
    # ve dunya-yazilabilir dizinde keyfile UNLINK edilebilirdi (DoS).
    # Python 3.7+ (bpo-19930): mode yalnizca LEAF (buradaki directory =
    # keyfile'in dogrudan ust dizini) icin gecerlidir - tam istedigimiz.
    # Windows'ta mode yok sayilir; koruma zaten protected DACL'dedir.
    os.makedirs(directory, mode=0o700, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if os.name == "nt":
        # DENETIM 5 bulgu [1]: os.open 0o600 Windows'ta YOK SAYILIR ve dosya
        # dizinden ACL kalitir -> keyfile (ikinci faktor) herkese okunur.
        # En guclu cozum: CreateFileW + protected DACL + CREATE_NEW ile
        # dogrudan hedef path'te ATOMIK olustur (paylasilan helper).
        try:
            fd = _create_private_file_windows(path)
        except FileExistsError:
            raise ValueError(f"keyfile zaten var (ustune yazilmadi): {path}")
    else:
        try:
            fd = os.open(path, flags, 0o600)
        except FileExistsError:
            raise ValueError(f"keyfile zaten var (ustune yazilmadi): {path}")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(os.urandom(length))
    except BaseException:
        _safe_unlink(path)      # yarim keyfile birakma
        raise
    return path


_ACL_STRUCTS = None


def _acl_structs():
    """ACL Structure siniflarinin TEK ORNEGI (BULGU-16 sinifi sizinti fix'i).

    _check_private_file_windows her cagrida YENI Structure siniflari
    tanimliyordu; ctypes.POINTER(YeniSinif) her seferinde
    ctypes._pointer_type_cache'e (SINIRSIZ, gh-100926) yeni giris ekliyordu
    (olculdu: 300 cagri -> +319 giris). Siniflar modul-seviyesinde TEK KEZ
    kurulur; POINTER() cache'e yalnizca bir kez girer (_win_token_api
    singleton deseniyle ayni).
    """
    global _ACL_STRUCTS
    if _ACL_STRUCTS is None:
        import ctypes
        from ctypes import wintypes

        class ACL_SIZE_INFORMATION(ctypes.Structure):
            _fields_ = [("AceCount", wintypes.DWORD),
                        ("AclBytesInUse", wintypes.DWORD),
                        ("AclBytesFree", wintypes.DWORD)]

        class ACE_HEADER(ctypes.Structure):
            _fields_ = [("AceType", ctypes.c_ubyte),
                        ("AceFlags", ctypes.c_ubyte),
                        ("AceSize", wintypes.WORD)]

        class ACCESS_ALLOWED_ACE(ctypes.Structure):
            _fields_ = [("Header", ACE_HEADER),
                        ("Mask", wintypes.DWORD),
                        ("SidStart", wintypes.DWORD)]

        _ACL_STRUCTS = {
            "ACL_SIZE_INFORMATION": ACL_SIZE_INFORMATION,
            "ACE_HEADER": ACE_HEADER,
            "ACCESS_ALLOWED_ACE": ACCESS_ALLOWED_ACE,
        }
    return _ACL_STRUCTS


def _check_private_file_windows(path: str, label: str = "dosya",
                                 fd: int | None = None) -> None:
    """Windows: dosyanin sahibini ve dünya-okunur ACL'ini dogrular.

    DENETIM 5 bulgu [11]: read_keyfile ACL/sahip dogrulamasi yapmiyordu
    (sahip-dogrulama yalnizca hcli'deki passphrase dosyasi icin vardi).
    Keyfile = ikinci faktor = passphrase ile AYNI hassasiyette -> ayni
    koruma uygulanir (OpenSSH-Windows `check_acl` deseni):

      1. SAHIP: dosya aktif kullaniciya ait olmali (GetNamedSecurityInfoW
         OWNER + ConvertSidToStringSidW). Sahibi baska kimlikse fail-closed.
      2. DÜNYA-OKUNUR: DACL'de Everyone (S-1-1-0), Authenticated Users
         (S-1-5-11) veya BUILTIN\\Users (S-1-5-32-545) OKUMA hakkina sahipse
         fail-closed (POSIX 0o077 karsiligi).
      3. SYSTEM ve BUILTIN\\Administrators TOLERE edilir: Windows'ta
         normaldir (POSIX 0o600 bile root'u engellemez).

    DENETIM 5 bulgu [16] (TOCTOU): fd verilirse dosya ONCE acilmis demektir
    ve ACL acik fd'nin HANDLE'i uzerinden GetSecurityInfo ile okunur -
    path uzerinden yeniden cozumleme YAPILMAZ. Boylece stat+ACL kontrolu
    ile open arasina saldirganin baska dosya yerlestirmesi (symlink swap)
    imkansizdir (acilmis fd degismez; path ne olursa olsun kontrol edilen
    dosya = okunacak dosya).
    """
    import ctypes
    from ctypes import wintypes

    SE_FILE_OBJECT = 1
    OWNER_SECURITY_INFORMATION = 0x00000001
    DACL_SECURITY_INFORMATION = 0x00000004
    ACCESS_ALLOWED_ACE_TYPE = 0
    # Dosyaya ERISIM hakkini temsil eden bitler (GENERIC_READ | GENERIC_WRITE
    # | GENERIC_ALL | FILE_ALL_ACCESS). FILE_ALL_ACCESS tum dosya haklarini
    # (read/write/delete/DAC) kapsar -> write-only ACE de yakalanir.
    # BULGU 11 fix: READ_BITS ismi yanilticiydi (yalnizca okuma saniyordu) -
    # gercek kapsam "dosyaya herhangi bir erisim" oldugu icin ACCESS_BITS.
    ACCESS_BITS = 0x80000000 | 0x00120089 | 0x10000000 | 0x001F01FF
    ERROR_SUCCESS = 0

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi32.GetNamedSecurityInfoW.argtypes = [
        wintypes.LPCWSTR, ctypes.c_int, wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p)]
    # [16] handle tabanli varyant: GetSecurityInfo(handle, ...) - ilk
    # parametre path degil HANDLE; kalan imza GetNamedSecurityInfoW ile ayni.
    advapi32.GetSecurityInfo.restype = wintypes.DWORD
    advapi32.GetSecurityInfo.argtypes = [
        wintypes.HANDLE, ctypes.c_int, wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p)]
    advapi32.GetAclInformation.restype = wintypes.BOOL
    advapi32.GetAclInformation.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD]
    advapi32.GetAce.restype = wintypes.BOOL
    advapi32.GetAce.argtypes = [
        ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(ctypes.c_wchar_p)]
    kernel32.LocalFree.restype = ctypes.c_void_p
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]

    psd = ctypes.c_void_p()
    p_owner = ctypes.c_void_p()
    p_dacl = ctypes.c_void_p()
    if fd is not None:
        import msvcrt
        h = msvcrt.get_osfhandle(fd)
        ret = advapi32.GetSecurityInfo(
            h, SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            ctypes.byref(p_owner), None, ctypes.byref(p_dacl), None,
            ctypes.byref(psd))
    else:
        ret = advapi32.GetNamedSecurityInfoW(
            path, SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            ctypes.byref(p_owner), None, ctypes.byref(p_dacl), None,
            ctypes.byref(psd))
    try:
        if ret != ERROR_SUCCESS:
            raise ValueError(f"{label} ACL okunamadi (WinError {ret}): {path}")
        # 1) Sahip kontrolu (fail-closed: sahip cozulemezse REDDET).
        if not p_owner.value:
            raise ValueError(f"{label} sahibi cozulemedi (fail-closed): {path}")
        owner = ctypes.c_wchar_p()
        if advapi32.ConvertSidToStringSidW(
                p_owner, ctypes.byref(owner)) and owner.value:
            try:
                if owner.value != _current_user_sid_string():
                    raise ValueError(
                        f"{label} sahibi SIZ DEGILSINIZ ({owner.value}): "
                        f"{path} - yalnizca size ait bir dosya olmali.")
            finally:
                kernel32.LocalFree(owner)
        else:
            raise ValueError(f"{label} sahibi cozulemedi (fail-closed): {path}")
        if not p_dacl.value:
            # DACL yok = herkes tam erisim.
            raise ValueError(
                f"{label} korumasiz (DACL yok, herkes erisebilir): {path}")
        # 2) DACL taramasi - ALLOWLIST deseni (BULGU 11 fix).
        # Eski blacklist (WORLD_SIDS) yalnizca 3 toplu SID'i reddediyordu:
        #   (a) SPESIFIK baska bir kullaniciya READ veren ACE
        #       (S-1-5-21-...-kullanici) kontrolu GECIYORDU;
        #   (b) yalnizca READ_BITS taranmasina ragmen write-only ACE
        #       FILE_ALL_ACCESS icinde kaldigi icin kismen yakalaniyordu ama
        #       blacklist SID seti dar oldugundan spesifik kullanici kaciyordu.
        # En guclu cozum OpenSSH Windows deseni (check_acl, OpenSSHUtils):
        # dosyaya ERISIM veren her ALLOWED ACE, yalnizca {sahip, SYSTEM,
        # Administrators, OWNER RIGHTS} SID'lerine ait olabilir; baska her
        # SID reddedilir. Sahip kontrolu ustte yapildigi icin OWNER RIGHTS
        # (S-1-3-4) guvenlidir (Win32-OpenSSH issue #2317: OpenSSH bunu
        # reddediyor ama biz sahibi zaten dogruluyoruz).
        ALLOWED_SIDS = {
            _current_user_sid_string(),   # dosya sahibi (ustte dogrulandi)
            "S-1-5-18",                   # SYSTEM
            "S-1-5-32-544",               # BUILTIN\Administrators
            "S-1-3-4",                    # OWNER RIGHTS (sahip haklari)
        }
        acl_info = _acl_structs()["ACL_SIZE_INFORMATION"]()
        if not advapi32.GetAclInformation(
                p_dacl, ctypes.byref(acl_info),
                ctypes.sizeof(acl_info), 2):       # AclSizeInformation
            raise ValueError(f"{label} ACL boyutu okunamadi: {path}")
        # BULGU 20+21 fix (MSDN "fail securely and not allow access" +
        # MS-DTYP 2.4.4): ACE taramasi FAIL-CLOSED ve tum ALLOW ACE tiplerini
        # kapsar. Onceki kod (a) GetAce basarisizsa ACE'yi sessizce atliyordu
        # (fail-open), (b) yalnizca ACCESS_ALLOWED_ACE_TYPE(0) goruyordu;
        # object/callback allow ACE'leri denetlenmiyordu.
        ACCESS_ALLOWED_OBJECT_ACE_TYPE = 0x05
        ACCESS_ALLOWED_CALLBACK_ACE_TYPE = 0x09
        ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE = 0x0B
        # Object ACE Flags (MS-DTYP 2.4.4.3): GUID alanlarinin varligi.
        ACE_OBJECT_TYPE_PRESENT = 0x1
        ACE_INHERITED_OBJECT_TYPE_PRESENT = 0x2
        for i in range(acl_info.AceCount):
            p_ace = ctypes.c_void_p()
            if not advapi32.GetAce(p_dacl, i, ctypes.byref(p_ace)):
                # BULGU 20 fix (fail-closed; MSDN GetAce): AceCount sinirlari
                # icinde GetAce basarisizsa bu ANOMALIDIR; ACE'yi sessizce
                # atlamak FAIL-OPEN olur (okunamayan bir ALLOW ACE denetlenmez).
                raise ValueError(
                    f"{label} ACL'deki ACE #{i} okunamadi (fail-closed): "
                    f"{path}")
            # GetAce basariliysa adres doludur; tip denetimi (pyright) icin
            # adresi yerel degiskene al ve None olursa fail-closed reddet.
            ace_addr = p_ace.value
            if ace_addr is None:
                raise ValueError(
                    f"{label} ACL'deki ACE #{i} adresi bos (fail-closed): "
                    f"{path}")
            hdr = ctypes.cast(
                p_ace,
                ctypes.POINTER(_acl_structs()["ACE_HEADER"])).contents
            if hdr.AceType in (ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
                               ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE):
                # BULGU 21 fix: callback allow ACE'leri kosullu (dynamic)
                # erisim verir ve guvenilir sekilde statik parse edilemez;
                # bir keyfile'da varliklari zaten suphelidir -> fail-closed.
                raise ValueError(
                    f"{label} ACL'de desteklenmeyen callback allow ACE "
                    f"(tip 0x{hdr.AceType:02X}) bulundu (fail-closed): {path}")
            if hdr.AceType != ACCESS_ALLOWED_ACE_TYPE and \
                    hdr.AceType != ACCESS_ALLOWED_OBJECT_ACE_TYPE:
                continue                       # deny/audit ACE erisim VERMEZ
            if hdr.AceFlags & 0x08:            # INHERIT_ONLY_ACE: dosyada
                continue                       # etkisiz, cocuklara uygulanir
            # Mask her erisim ACE'sinde header(4B) sonrasindadir.
            mask = ctypes.cast(ctypes.c_void_p(ace_addr + 4),
                               ctypes.POINTER(wintypes.DWORD)).contents.value
            if not (mask & ACCESS_BITS):
                continue                       # bu dosyaya erisim hakki yok
            # BULGU 21 fix: SID ofseti ACE tipine gore degisir (MS-DTYP).
            if hdr.AceType == ACCESS_ALLOWED_ACE_TYPE:
                sid_offset = 8                 # header(4) + mask(4)
            else:  # ACCESS_ALLOWED_OBJECT_ACE_TYPE
                # header(4)+mask(4)+flags(4)[+ObjectType 16][+InhObjType 16]
                obj_flags = ctypes.cast(
                    ctypes.c_void_p(ace_addr + 8),
                    ctypes.POINTER(wintypes.DWORD)).contents.value
                sid_offset = 12
                if obj_flags & ACE_OBJECT_TYPE_PRESENT:
                    sid_offset += 16
                if obj_flags & ACE_INHERITED_OBJECT_TYPE_PRESENT:
                    sid_offset += 16
            p_sid = ctypes.c_void_p(ace_addr + sid_offset)
            sid = ctypes.c_wchar_p()
            if not advapi32.ConvertSidToStringSidW(
                    p_sid, ctypes.byref(sid)):
                # BULGU 20 fix: SID'i cozulemeyen ALLOW ACE fail-closed reddet.
                raise ValueError(
                    f"{label} ACL'deki ACE #{i} SID'i cozulemedi "
                    f"(fail-closed): {path}")
            try:
                if not sid.value:
                    raise ValueError(
                        f"{label} ACL'deki ACE #{i} SID'i bos dondu "
                        f"(fail-closed): {path}")
                if sid.value not in ALLOWED_SIDS:
                    raise ValueError(
                        f"{label} baska kullanicilar tarafindan "
                        f"erisilebilir ({sid.value}): {path} - "
                        f"yalnizca size acik olmali.")
            finally:
                kernel32.LocalFree(sid)
    finally:
        if psd.value:
            kernel32.LocalFree(psd)


def _open_private_file_read(path: str, label: str) -> int:
    """Guvenli gizli-dosya okuma: ac, SONRA acilan fd uzerinden dogrula.

    DENETIM 5 bulgu [16] (TOCTOU): eski desen `os.stat` + ACL kontrolu
    yapip SONRA open cagiriyordu. stat ile open arasinda saldirgan dosyayi
    degistirebilir (symlink swap) - dogrulama eski dosyaya, okuma yeni
    dosyaya giderdi. En guclu cozum (O_NOFOLLOW + fd tabanli dogrulama):
      - POSIX: os.open(O_NOFOLLOW) -> os.fstat(fd) ile mode & 0o077 + uid.
      - NT:    CreateFileW arkasindaki wskapi da reparse point'i acar ama
               dogrulama ACILMIS handle uzerinden (GetSecurityInfo) yapilir;
               acilan fd degismez -> path ne olursa olsun kontrol edilen ve
               okunan dosya AYNI dosyadir.
    Donen fd, cagiranin kapatmasina tabidir.
    """
    flags = os.O_RDONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    # POSIX: symlink suicide - son bilesen symlink ise ELOOP. Pyright
    # Windows tipinde O_NOFOLLOW bilmez -> getattr ile tip-guvenli erisim.
    _no_follow = getattr(os, "O_NOFOLLOW", 0)
    if _no_follow:
        flags |= _no_follow
    # BULGU 15 fix: O_NONBLOCK olmadan FIFO path'inde os.open(O_RDONLY)
    # writer gelene kadar BLOKLAR (hang) ve fstat kontrolune asla
    # ulasilamaz. O_NONBLOCK ile open aninda doner, asagidaki S_ISREG
    # kontrolu FIFO/device'i reddeder (SEI CERT FIO32-C + now-playing
    # _io_safe.py deseni; regular dosyada etkisiz - Linux open(2)).
    _nonblock = getattr(os, "O_NONBLOCK", 0)
    if _nonblock:
        flags |= _nonblock
    try:
        fd = os.open(path, flags)
    except OSError as e:
        raise ValueError(f"{label} okunamadi: {path} ({e})") from e
    try:
        if os.name == "nt":
            # Windows: ACL/sahip dogrulamasi ACILMIS fd'nin handle'i
            # uzerinden (GetSecurityInfo) - path yeniden cozulmez ([16]).
            _check_private_file_windows(path, label, fd=fd)
        else:
            st = os.fstat(fd)
            # BULGU 15 fix: dosya tipi kontrolu MODE'DAN ONCE gelmeli -
            # FIFO/device/dizin/soket 0600 gibi gorunse bile reddedilir.
            # O_NONBLOCK olmadan bu satira FIFO'da asla ulasilamazdi.
            if not stat.S_ISREG(st.st_mode):
                raise ValueError(
                    f"{label} duzenli dosya degil (FIFO/device/dizin "
                    f"olabilir): {path}")
            if st.st_mode & 0o077:
                raise ValueError(
                    f"{label} diger kullanicilar tarafindan okunabilir "
                    f"(mode {oct(st.st_mode & 0o777)}) - 0600 olmali: {path}")
            if hasattr(os, "geteuid") and st.st_uid != os.geteuid():
                raise ValueError(
                    f"{label} sahibi SIZ DEGILSINIZ "
                    f"(uid {st.st_uid} != {os.geteuid()}): {path}")
            # SEI CERT FIO32-C: O_NONBLOCK'un read() uzerindeki davranisi
            # belirsiz -> regular dosya dogrulandiktan sonra bayragi dusur
            # (yalnizca POSIX; Windows'ta O_NONBLOCK yok, bu dal hic calismaz).
            if _nonblock:
                import fcntl
                fcntl.fcntl(fd, fcntl.F_SETFL,
                            fcntl.fcntl(fd, fcntl.F_GETFL) & ~_nonblock)
    except BaseException:
        os.close(fd)
        raise
    return fd


def read_keyfile(path: str) -> bytes:
    """Keyfile'i diskten okur ve dogrular (boyut sinirlari).

    Keyfile'lar binary olabilir -> text modunda okunmaz. Bos/13 byte'lık
    gibi yetersiz keyfile'lar _validate_keyfile ile REDDEDILIR (ikinci
    faktorun entropisi korunur). DENETIM 5 bulgu [6]: okuma aninda
    KEYFILE_MAX_BYTES + 1 bayt tavani uygulanir (age'nin io.LimitReader
    deseni) - dev bir dosya once TAMAMEN belleğe cekilip OOM
    uretilemez, tavan sonrasi dogrudan ValueError.

    DENETIM 5 bulgu [11]: keyfile ikinci faktor -> passphrase dosyasi ile
    ayni erisim korumasini ister. Windows'ta _check_private_file_windows
    (sahip + dünya-okunur DACL, OpenSSH check_acl deseni), POSIX'te
    mode & 0o077 + sahip (uid) kontrolu uygulanir (fail-closed).

    DENETIM 5 bulgu [16] (TOCTOU): okuma _open_private_file_read ile
    yapilir - dosya ONCE acilir, mode/uid/ACL dogrulamasi ACILMIS fd
    uzerinden yapilir. Doğrulama ile okuma arasinda baska dosya
    yerlestirilemez (stat+open TOCTOU penceresi kapatildi).
    """
    fd = _open_private_file_read(path, "keyfile")
    try:
        with os.fdopen(fd, "rb") as f:
            data = f.read(KEYFILE_MAX_BYTES + 1)
    except OSError as e:
        raise ValueError(f"keyfile okunamadi: {path} ({e})") from e
    _validate_keyfile(data)
    return data


# ---------------------------------------------------------------------------
# v5: Passphrase gucluk kontrolu (zxcvbn + builtin fallback)
# ---------------------------------------------------------------------------
# V5.7 BULGU-1 fix (5x research: dwolfhub/zxcvbn-python f54add5 + README
# "strongly advise against setting max_length greater than 72" DoS uyarisi;
# dropbox/zxcvbn#194 resmi onerisi "truncate user input before passing to
# zxcvbn()"; NIST SP 800-63B 5.1.1.2 "SHOULD permit >=64 characters" +
# "Truncation of the secret SHALL NOT be performed" - KDF girdisi icin;
# zulip/zulip#34146 ayni hatanin uretim vakasi): zxcvbn'un degerlendirme
# girisi 72 codepoint ile sinirlandirilir. Gizli anahtar uretimi (Argon2id)
# TAM UZUNLUK passphrase kullanmaya DEVAM EDER (NIST: truncation YASAK);
# yalnizca DEGERLENDIRME pencereleri kesilir -> zxcvbn maliyeti girdi
# uzunlugundan bagimsiz (1 MiB pw dosyasi bile DoS olamaz).
# CIFT PENCERE: ilk 72 + son 72. >72'ye tasan desenler (tekrar/ardisik)
# her iki pencerede de gorunur -> zayif uzun desenler dogru reddedilir;
# guclu-suffix (zayif-prefix + rastgele 60+) ilk pencerede guclu cikar.
ZXCVBN_MAX_INPUT_CHARS = 72

try:
    from zxcvbn import zxcvbn as _zxcvbn  # type: ignore[import-not-found]
    _ZXCVBN_AVAILABLE = True
except ImportError:  # pragma: no cover - bagimlilik yoksa fallback kullanilir
    _zxcvbn = None
    _ZXCVBN_AVAILABLE = False


def _zxcvbn_windows(passphrase: str) -> tuple[float, str]:
    """zxcvbn degerlendirmesini cift-pencere (ilk+son 72) ile yapar.

    zxcvbn-python __init__: len(password) > 72 -> ValueError. Uzun perde
    NIST 800-63B geregi tam uzunluk KDF'e gider; gucluk TAHMINI icin
    dropbox'un resmi onerisi (zxcvbn#194) olan kesme uygulanir. Pencereler
    birlesik degil ayri degerlendirilir; zayif pencere sonucu belirler.
    """
    n = len(passphrase)
    if _zxcvbn is None:
        raise RuntimeError("zxcvbn kurulu degil - _zxcvbn_windows cagrilamaz")
    if n <= ZXCVBN_MAX_INPUT_CHARS:
        r = _zxcvbn(passphrase)
        return float(r["guesses_log10"]), _zxcvbn_feedback(r)
    first = _zxcvbn(passphrase[:ZXCVBN_MAX_INPUT_CHARS])
    last = _zxcvbn(passphrase[-ZXCVBN_MAX_INPUT_CHARS:])
    g1 = float(first["guesses_log10"])
    g2 = float(last["guesses_log10"])
    fb = _zxcvbn_feedback(first) if g1 <= g2 else _zxcvbn_feedback(last)
    # IKI pencere de guclu degilse zayif demektir (min); ikisi de guclu ise
    # guclu-suffix saldirisina karsi temkinli: iyimser degil, zayif pencere
    # esigi belirler (fail-conservative).
    return min(g1, g2), fb


def _zxcvbn_feedback(r) -> str:
    fb = r.get("feedback") or {}
    warning = fb.get("warning") or ""
    suggestions = fb.get("suggestions") or []
    parts = [s for s in ([warning] if warning else []) + list(suggestions) if s]
    return " | ".join(parts) if parts else "pattern-aware zxcvbn tahmini"

# Basit desenler: zxcvbn yoksa kaba gucluk tahmini icin (fallback). Tam liste
# zxcvbn'in 30k+ kelime veritabaninda; bu yalnizca hicbir sey kurulmamissa.
_WEAK_PATTERNS = (
    "123456", "password", "qwerty", "abc123", "letmein", "admin",
    "welcome", "monkey", "dragon", "master", "login", "passw0rd",
    "111111", "123123", "12345678", "000000", "sifre", "parola",
    "ankara", "istanbul", "qazwsx", "football", "baseball",
)

# DENETIM 5 bulgu [5]: fallback Shannon tahmini SADECE karakter siniflarina
# bakar (uzunluk x charset) - sozluk kelimelerini GORMEZ. "myDogIsBlue"
# fallback'te 18.88 (GECER) ama zxcvbn'de 10.02 (RED): fallback 10^8 kat
# iyimserdi. Bu set: yaygin sozluk kelimeleri (TR+EN karisik). Bir kelime
# passphrase icinde gecerse fallback tahmini agresif sekilde dusurulur.
_DICTIONARY_WORDS = frozenset(
    _WEAK_PATTERNS + (
        # EN yaygin 200 kelime (sozluk tabanli saldiri onceligi)
        "the", "be", "to", "of", "and", "a", "in", "that", "have",
        "i", "it", "for", "not", "on", "with", "he", "as", "you", "do",
        "at", "this", "but", "his", "by", "from", "they", "we", "say",
        "her", "she", "or", "an", "will", "my", "one", "all", "would",
        "there", "their", "what", "so", "up", "out", "if", "about",
        "who", "get", "which", "go", "me", "when", "make", "can",
        "like", "time", "no", "just", "him", "know", "take", "people",
        "into", "year", "your", "good", "some", "could", "them", "see",
        "other", "than", "then", "now", "look", "only", "come", "its",
        "over", "think", "also", "back", "after", "use", "two", "how",
        "our", "work", "first", "well", "way", "even", "new", "want",
        "because", "any", "these", "give", "day", "most", "us",
        "house", "world", "life", "love", "child", "money", "friend",
        "family", "school", "water", "right", "book", "story", "night",
        "week", "car", "room", "city", "state", "country", "name",
        "place", "case", "point", "number", "group", "problem", "fact",
        "dog", "cat", "bird", "fish", "horse", "king", "queen", "star",
        "sun", "moon", "fire", "sky", "earth", "wind", "rain", "snow",
        "summer", "winter", "spring", "beach", "mountain", "river",
        "blue", "red", "green", "black", "white", "yellow", "orange",
        "purple", "pink", "brown", "gold", "silver", "iron", "steel",
        "apple", "orange", "banana", "cherry", "grape", "lemon",
        "secret", "hidden", "magic", "shadow", "dragon", "tiger",
        "eagle", "wolf", "bear", "lion", "angel", "devil", "heaven",
        "hell", "dream", "wish", "hope", "faith", "power", "strong",
        "super", "hero", "champion", "victory", "winner", "master",
        "shadow", "knight", "sword", "shield", "royal", "prince",
        "princess", "cookie", "monster", "garden", "forest", "flower",
        "happy", "lucky", "rich", "smart", "cool", "awesome",
        # TR yaygin kelimeler + sehirler
        "sifre", "parola", "sifrem", "benim", "bizim", "senin", "ask",
        "sevgi", "hayat", "dunya", "yildiz", "deniz", "dag", "gunes",
        "ay", "gece", "gunduz", "kalp", "can", "anne", "baba", "kardes",
        "arkadas", "cocuk", "bebek", "mama", "kedi", "kopek", "kus",
        "balik", "at", "aslan", "kartal", "kurt", "tavsan", "fare",
        "ekmek", "peynir", "sut", "su", "cay", "kahve", "seker", "tuz",
        "karadeniz", "akdeniz", "ege", "marmara", "istanbul", "ankara",
        "izmir", "bursa", "antalya", "adana", "konya", "gaziantep",
        "mersin", "eskişehir", "trabzon", "samsun", "kayseri", "van",
        "erzurum", "diyarbakir", "malatya", "urfa", "maras",
        "fenerbahce", "galatasaray", "besiktas", "trabzonspor",
        "turk", "turkiye", "futbol", "gol", "saha", "oyun", "bilgisayar",
        "telefon", "ekran", "klavye", "isik", "ses", "video",
        "resim", "muzik", "sarki", "dans", "film", "sinema", "kitap",
        "hikaye", "yazi", "kelime", "harf", "rakam", "sayi", "zaman",
        "dakika", "saat", "gun", "hafta", "mevsim", "bahar",
        "yaz", "sonbahar", "kis", "sabah", "aksam", "ogle", "geceyarisi",
    )
)

# Yil deseni (1900-2099): "myDogIsBlue2026" gibi passphrase'lerde tarih
# bolumu sozluk saldirisinda cok ucuzdur (zxcvbn year matcher karsiligi).
_YEAR_RE = re.compile(r"(?:19|20)\d{2}")

# V4 zafiyet raporu [1]: fallback desen tespiti. zxcvbn'siz ortamda Shannon
# tahmini "abcabc123", "qwerty123", "aaaaaaaa" gibi desenleri karakter
# sinifi sayisindan dolayi YUKSEK entropili sanabilir (iyimser tahmin).
# Bu setler tahmin tavanini 10^8'e (veya 10^6'ya) sabitler. TR+EN klavye
# satirlari: donanim tipik, kullanici egilimi (qazwsx, asdf) - en yaygin.
_KEYBOARD_ROWS = (
    "qwertyuiop", "asdfghjkl", "zxcvbnm",          # EN
    "qwertyuıopğü", "asdfghjklşi", "zxcvbnmöç",    # TR
)


def _fallback_pattern_cap(lower: str) -> float | None:
    """Desenli passphrase tahmin tavanini dondurur (yoksa None).

    V4 zafiyet raporu [1] fixi: builtin fallback artık Shannon'a ek olarak
    yapisal desenleri de tarar. Bu desenlerden BIRI gecerse tahmin asla
    10^8'in (tekrar icin 10^6) uzerine cikmaz - builtin tahmin fail-conservative
    kalir. Rastgele gorunumlu perde (M7#v9Kx2!pQ5@zL4) hicbir desene girmez,
    tahmin dokunulmaz.

    Tespit edilen desenler:
      - ardisik harf/rakam dizisi >=4  ("abcd", "1234", "wxyz")  -> 10^8
      - ayni karakter tekrari >=3      ("aaa", "111")             -> 10^6
      - klavye satiri >=4              ("qwer", "asdf", "zxcv")   -> 10^8
      - iki karakter donusumu >=6      ("ababab", "121212")       -> 10^8
    """
    # 1) ardisik dizi: alt-alta siralanmis karakterler (harf/rakam ayri)
    for i in range(len(lower) - 3):
        window = lower[i:i + 4]
        if window.isalpha() and all(
                ord(window[j + 1]) == ord(window[j]) + 1
                for j in range(3)):
            return 8.0
        if window.isdigit() and all(
                int(window[j + 1]) == int(window[j]) + 1
                for j in range(3)):
            return 8.0
    # 2) ayni karakter tekrari (>=3)
    for i in range(len(lower) - 2):
        if lower[i] == lower[i + 1] == lower[i + 2]:
            return 6.0
    # 3) klavye satirlari (>=4 bitisik tus) - TR+EN
    for row in _KEYBOARD_ROWS:
        for i in range(len(row) - 3):
            if row[i:i + 4] in lower:
                return 8.0
    # 4) iki karakter donusumu (>=6): "ababab", "123123"
    for i in range(len(lower) - 5):
        if (lower[i] == lower[i + 2] == lower[i + 4]
                and lower[i + 1] == lower[i + 3] == lower[i + 5]):
            return 8.0
    return None


def check_passphrase_strength(passphrase: str) -> tuple[float, str]:
    """Passphrase guclugunu degerlendirir.

    Donus: (guesses_log10, feedback). zxcvbn kuruluysa pattern-aware
    tahmin (Dropbox zxcvbn - 30k yaygin parola, tarih, klavye dizisi,
    l33t, isimler); degilse builtin kaba tahmin (uzunluk + karakter
    siniflari + basit desen cezasi).

    DENETIM 5 bulgu [5]: builtin fallback karakter sinifi Shannon
    tahmini sozluk kelimelerini gormuyordu (myDogIsBlue 18.88 PASS vs
    zxcvbn 10.02 RED = 10^8 kat iyimserlik). Fallback artik _DICTIONARY_WORDS
    alt-dize taramasi yapar: sozluk kelimesi gecerse tahmin 10^6'ya,
    yil gecerse 10^8'e sabitlenir (fail-conservative).

    guesses_log10 = tahmini deneme sayisinin 10 tabanli logaritmasi:
      - 14.0+  -> Argon2id (1e4/sn bile) ~= 781 yil+  (GUCLU)
      - 10-14  -> saatler/yillar arasi (ZAYIF-ORTA)
      - <10    -> saniyeler/saatler (COK ZAYIF - reddedilir)
    """
    if not passphrase:
        return 0.0, "bos passphrase"
    lower = passphrase.lower()
    if _zxcvbn is not None:
        try:
            # V5.7 BULGU-1: cift-pencere zxcvbn (72+ karakterli NIST-uyumlu
            # uzun perde artik ValueError atmaz; degerlendirme penceresi
            # kesilir, KDF girdisi tam uzunluk kalir).
            guesses_log10, fb_str = _zxcvbn_windows(passphrase)
            return guesses_log10, fb_str
        except Exception as exc:
            # BULGU 19 fix (fail-closed; django_zxcvbn_password_validator +
            # NIST SP 800-63B + "security guards fail closed" ilkesi): zxcvbn
            # KURULU ama bu girdide hata verdi. Onceki kod sessizce `pass` ile
            # ZAYIF builtin fallback'e dusuyordu; bu FAIL-OPEN'dir: zxcvbn'in
            # reddedecegi bir passphrase kaba Shannon tahminiyle "guclu"
            # sanilip kabul edilebilir. Guvenlik denetimi sirasinda guclu
            # motor devre disi kalmali, zayifina sessizce gecilmemeli.
            # Builtin fallback artik YALINZCA zxcvbn HIC kurulu degilse
            # (_zxcvbn is None) kullanilir; o yolu da
            # assert_strong_passphrase fail-closed reddeder.
            raise ValueError(
                "passphrase guclugu DOGRULANAMIYOR: zxcvbn kurulu ama bu "
                "girdide hata verdi (fail-closed; zayif fallback'e sessizce "
                "dusulmez). Passphrase'yi degistirin.") from exc
    # ---- builtin fallback: Shannon benzeri kaba entropi ----
    length = len(passphrase)
    classes = 0
    if any(c.islower() for c in lower):
        classes += 26
    if any(c.isupper() for c in passphrase):
        classes += 26
    if any(c.isdigit() for c in passphrase):
        classes += 10
    if any(not c.isalnum() for c in passphrase):
        classes += 32
    if classes == 0:
        classes = 1
    bits = length * math.log2(classes) if classes > 1 else 0.0
    guesses_log10 = bits * 0.30103  # log10(2^bits)
    # DENETIM 5 bulgu [5]: sozluk kelimesi gecerse iyimser Shannon tahminini
    # agresif sekilde dusur (sozluk tabanli saldiri 10^6 denemede basarir).
    # Yalnizca >=3 harf kelimeler taranir: 2 harflikler ("in", "do", "to")
    # her yerde gecer (elma-...incir icindeki "in") -> yanlis pozitif uretir;
    # zxcvbn de 2 harf kelimelere dusuk agirlik verir.
    for word in _DICTIONARY_WORDS:
        if len(word) >= 3 and word in lower:
            # DENETIM 5 bulgu [13]: feedback'te eslesen kelimeyi YANKILAMA
            # (hcli bulgusu) - sozluk kelimesi ifsa edilmez, yalnizca desen
            # bildirilir; kullanicinin perdesinin parcalari ekrana donmez.
            return min(guesses_log10, 6.0), \
                "sozluk kelimesi iceriyor (zayif desen)"
    # Yil deseni: tarih-ekli parolalar sozluk+yil birlestirmesiyle kolay krilir.
    if _YEAR_RE.search(passphrase):
        return min(guesses_log10, 8.0), "tarih/yil iceriyor"
    # V4 zafiyet raporu [1]: yapisal desen taramasi (ardisik, tekrar, klavye,
    # donusum). Desen tespit edilirse tahmin tavanini 8.0/6.0'ya sabitle.
    cap = _fallback_pattern_cap(lower)
    if cap is not None:
        return min(guesses_log10, cap), "desenli passphrase (zayif desen)"
    return guesses_log10, "builtin tahmin (zxcvbn kurulu degil)"


def assert_strong_passphrase(passphrase: str,
                             min_guesses_log10: float = PASSPHRASE_MIN_GUESSES_LOG10) -> None:
    """Zayif passphrase'i REDDEDER (ValueError).

    CLI ve kutuphane kullanicilari icin v5 zorunlulugu: zxcvbn esigini
    gecmeyen perde ile sifreleme YAPILMAZ. Esik 10^14 tahmin (~= 1e4/sn
    Argon2id'de 781 yil). Kullanici daha guclu perde girmek zorunda kalir
    veya keyfile kullanir (keyfile varliginda perde entropisi ikincildir).

    V4 zafiyet raporu [1] - FAIL-CLOSED: zxcvbn (pattern-aware motor) KURULU
    DEGILSE hicbir perdeyi "guclu" kabul etme. Builtin Shannon+desen tahmini
    izlenebilirlik/goruntuleme icindir, AMA gercek zxcvbn'in 30k+ kelime,
    l33t, tarih, klavye dizisi analizinin yerini TUTAMAZ - "yeterli guclu"
    garantisi veremez. Bu yuzden tahmin motoru yokken assert_strong HER ZAMAN
    reddeder; guclu perde uretmek icin 'generate-passphrase' (Diceware)
    veya zxcvbn kurulumu gerekir. (--allow-weak bilincli risk kabuludur,
    encrypt yolunu acar - bu fonksiyon onu atlayarak cagrilmaz.)
    """
    if _zxcvbn is None:
        raise ValueError(
            "passphrase guclugu DOGRULANAMIYOR: zxcvbn (pattern-aware tahmin "
            "motoru) kurulu degil. Builtin tahmin, zxcvbn'in 30k+ kelime/l33t/"
            "tarih/klavye analizinin yerini tutamaz (fail-closed).\n"
            "  'pip install zxcvbn' ile motoru kurun, 'generate-passphrase' "
            "ile Diceware perde uretin, veya riski bilincli kabul edip "
            "'--allow-weak' kullanin.")
    guesses_log10, feedback = check_passphrase_strength(passphrase)
    if guesses_log10 < min_guesses_log10:
        raise ValueError(
            f"passphrase cok zayif (tahmini 10^{guesses_log10:.1f} deneme; "
            f"esik 10^{min_guesses_log10:.0f}). {feedback}\n"
            f"  Daha guclu bir passphrase girin veya 'generate-passphrase' "
            f"ile Diceware perde uretin.")


# ---------------------------------------------------------------------------
# v5: Diceware passphrase ureteci (EFF large wordlist - 7776 kelime)
# ---------------------------------------------------------------------------
_DICEWARE_WORDS: list[str] | None = None


def _load_diceware_words() -> list[str]:
    """EFF large wordlist'i (diceware_words.txt) yukler (bir kez).

    Format: '11111<TAB>abacus' - her satir 5 zar atisi + kelime. Kelime
    listesinin gizliligine ihtiyac YOK (Diceware: entropi kombinasyondan
    gelir, kelimeler herkese aciktir).

    DENETIM 5 bulgu [4]: builtin 100 kelimelik yedek liste KALDIRILDI.
    Yedek liste herkese acik oldugundan log2(100)~=6.64 bit/kelime ile
    6 kelime ~=39.8 bit'e SESSIZCE dusuyordu (beklenen 77.5 bit).
    Yanlis guvenlik hissi en tehlikeli durumdur -> fail-closed: wordlist
    dosyasi yoksa veya bozuksa ValueError (zayif uretim YOK).
    """
    global _DICEWARE_WORDS
    if _DICEWARE_WORDS is not None:
        return _DICEWARE_WORDS
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "diceware_words.txt")
    words: list[str] = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split("\t")
                if len(parts) == 2 and parts[1]:
                    words.append(parts[1])
                elif " " in line:   # tab yerine bosluk kullanan varyant
                    words.append(line.split(" ", 1)[1])
    except OSError as e:
        raise ValueError(
            f"diceware wordlist yuklenemedi: {path} ({e}) - "
            f"guvenli passphrase uretimi icin dosya zorunludur "
            f"(zayif yedek liste KULLANILMAZ).") from e
    if len(words) < 7776:
        raise ValueError(
            f"diceware wordlist eksik/bozuk: {path} - {len(words)} kelime "
            f"bulundu, EFF 7776 kelime gereklidir (zayif yedek liste "
            f"KULLANILMAZ).")
    # BULGU 12 fix: sayi kontrolu tek basina yetmez - 7776 satir iceren ama
    # TEKRARLAYAN kelimeler barindiran bir liste (orn. 100 benzersiz kelime
    # x 78 kopya) sayi kontrolunden gecer ve gercek entropi log2(100)~=6.64
    # bit/kelimeye duserdi. Reinhold (diceware.txt): "there should be no
    # duplicates. As long as all the words are different, the list will
    # provide full security." -> fail-closed: tekrar varsa ValueError.
    if len(words) != len(set(words)):
        raise ValueError(
            f"diceware wordlist tekrarlayan kelime iceriyor: {path} - "
            f"her kelime benzersiz olmali (entropi korunur, zayif yedek "
            f"liste KULLANILMAZ).")
    _DICEWARE_WORDS = words
    return words


def generate_passphrase(num_words: int = 6, *, sep: str = "-") -> str:
    """Diceware passphrase uretir: 6 kelime ~= 77.5 bit entropi.

    EFF large wordlist (7776 kelime, her kelime ~12.9 bit) uzerinden
    secrets.choice (CSPRNG) ile secim. 6 kelime = log2(7776^6) ~= 77.5 bit -
    Brute-force icin evrenin yasindan uzun sure; akilda tutmasi 16 rastgele
    karakterden cok daha kolay.

    Daha yuksek guvenlik icin num_words artirilabilir:
      5 kelime = 64.6 bit, 7 kelime = 90.4 bit (EFF onerisi).
    """
    if not 3 <= num_words <= 20:
        raise ValueError(f"kelime sayisi {num_words} sinir disi [3..20]")
    words = _load_diceware_words()
    return sep.join(secrets.choice(words) for _ in range(num_words))

