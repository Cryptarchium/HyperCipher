# -*- coding: utf-8 -*-
"""HASSAS YAPILANDIRMA - degistirilemez (immutable) Python yapilari.

Bu dosya: gizli anahtar materyali, veritabani kimlik bilgileri, odeme
API anahtari ve yetki listeleri icerir. Tum degerler IMMUTABLE
(bytes/str/tuple/frozenset/NamedTuple): calisma aninda DEGISTIRILEMEZ
(TypeError/AttributeError firlatir). Ancak kaynak dosya duz metin
oldugu surece herkes okuyabilir - koruma yalnizca SIFRELEME ile gelir.
Tum degerler DEMO'dur (gercek kimlik bilgisi DEGIL).
"""

from typing import NamedTuple

# --- 1) Gizli anahtar materyali (bytes: immutable) ---
MASTER_KEY: bytes = b"\x8f\xc2\x5b\x9a\x11\xe4\x77\x03\xaa\x5d\xf0\x1c\x8b\x66\x2e\xd9"

# --- 2) Veritabani kimlik bilgileri (str: immutable) ---
DB_USER: str = "hyper_admin"
DB_PASS: str = "Zx9$kLm2!qR7#vW4!"
DB_HOST: str = "10.0.3.21"
DB_PORT: int = 5432

# --- 3) Odeme API anahtari + JWT gizli (str: immutable) ---
PAYMENT_API_KEY: str = "sk_live_demo_7f3a9c2e5b81d4f6"
JWT_SECRET: str = "jwt-demo-9kL2#vW4$qR7!xZ8"

# --- 4) Yetkili IP listesi (tuple: immutable) ---
ALLOWED_IPS: tuple = ("192.168.1.10", "192.168.1.11", "10.0.0.5")

# --- 5) Yetki rolleri (frozenset: immutable) ---
ADMIN_ROLES: frozenset = frozenset({"root", "superadmin", "audit"})

# --- 6) Kilitli kripto yapilandirmasi (NamedTuple: immutable) ---
class _CryptoConfig(NamedTuple):
    algorithm: str
    key_derivation: str
    memory_mib: int


CRYPTO_CONFIG = _CryptoConfig("xchacha20poly1305", "argon2id", 128)


if __name__ == "__main__":
    print("[kanit 1] MASTER_KEY immutable mi?", end=" ")
    try:
        MASTER_KEY[0] = 0x01            # bytes'a yazma -> TypeError
        print("HAYIR (degisti!)")
    except TypeError:
        print("EVET - TypeError: bytes elemani degistirilemez")

    print("[kanit 2] ALLOWED_IPS immutable mi?", end=" ")
    try:
        ALLOWED_IPS[0] = "10.0.0.99"    # tuple'a yazma -> TypeError
        print("HAYIR (degisti!)")
    except TypeError:
        print("EVET - TypeError: tuple elemani degistirilemez")

    print("[kanit 3] ADMIN_ROLES immutable mi?", end=" ")
    try:
        ADMIN_ROLES.add("root2")        # frozenset'e ekleme -> AttributeError
        print("HAYIR (degisti!)")
    except AttributeError:
        print("EVET - AttributeError: frozenset'e eleman eklenemez")

    print("[mesaj] Bu degerler kaynak dosyada DÜZ METIN duruyor; "
          "sifreleme algoritmasi bunlara DOKUNAMAZ - dosyayi opak byte "
          "dizisi olarak sifreler ve cozumde birebir geri verir. "
          "Koruma = dosyanin kendisini sifrelemek.")