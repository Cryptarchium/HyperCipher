# -*- coding: utf-8 -*-
"""GIZLI CUZDAN - kaybedilmesi imkansiz sirlar (immutable yapilar).

Bu dosya: kripto cuzdan kurtarma ifadesi, ozel anahtarlar, API
token'lari, oturum sirlari ve tek kullanimlik kurtarma kodlari icerir.
Tum degerler IMMUTABLE (str/bytes/tuple/frozenset/NamedTuple):
calisma aninda DEGISTIRILEMEZ. Kaynak duz metin oldugu surece herkes
okuyabilir - koruma yalnizca SIFRELEME ile gelir.
Tum degerler DEMO'dur (gercek kimlik bilgisi DEGIL).
"""

from typing import NamedTuple

# --- 1) Kripto cuzdan kurtarma ifadesi (str: immutable) ---
MNEMONIC: str = ("avalanche bridge castle dragon echo forest galaxy "
                 "harbor island jungle knight lagoon")

# --- 2) Ozel anahtar + adresler (bytes: immutable) ---
BTC_ADDRESS: str = "bc1qdemo9xw2y3z4a5b6c7d8e9f0g1h2i3j4k5l6m7n8"
ETH_PRIVATE_KEY: bytes = b"\x3a\xb9\x77\x1e\xc4\x08\x5d\xf2\x9b\x66\x30\xa1\xe7\x44\x8c\x2b"

# --- 3) API token'lari (str: immutable) ---
GITHUB_TOKEN: str = "ghp_demo_7f3a9c2e5b81d4f6a0b3c8d1e4f7a2b5"
AWS_SECRET_KEY: str = "AKIAdemoFX7pL9xQ3wR2tY6uN8vB4cM1zK5jH0gS"
STRIPE_SECRET: str = "sk_live_demo_51Nz8VpX4qW2rT7yU6iK9oL0mJ3nB5c"

# --- 4) Oturum sirlari (bytes: immutable) ---
SESSION_SIGNING_KEY: bytes = b"\x9d\x12\xf8\x43\xa6\x70\x1b\xe9\x55\x88\x24\xc3\x6f\x0a\xd7\x31"

# --- 5) Kurtarma kodlari (tuple: immutable) ---
RECOVERY_CODES: tuple = ("K7P2-X9QM", "L4WD-8RTP", "M2XZ-6QVA",
                         "N9BS-3JWE", "R5CT-7YHF", "P8GD-2KZX")

# --- 6) Guvenilen cihaz parmak izleri (frozenset: immutable) ---
TRUSTED_DEVICE_FINGERPRINTS: frozenset = frozenset({
    "sha256:ae7e11b9...", "sha256:4d8f20c3...", "sha256:b1c90d57..."
})


# --- 7) Kilitli cuzdan ayarlari (NamedTuple: immutable) ---
class _WalletConfig(NamedTuple):
    cipher: str
    rounds: int
    require_hardware: bool


WALLET_CONFIG = _WalletConfig("xchacha20poly1305", 3, True)


if __name__ == "__main__":
    print("[kanit 1] ETH_PRIVATE_KEY immutable mi?", end=" ")
    try:
        ETH_PRIVATE_KEY[0] = 0x01       # bytes'a yazma -> TypeError
        print("HAYIR (degisti!)")
    except TypeError:
        print("EVET - TypeError: bytes elemani degistirilemez")

    print("[kanit 2] RECOVERY_CODES immutable mi?", end=" ")
    try:
        RECOVERY_CODES[0] = "XXXX-XXXX"  # tuple'a yazma -> TypeError
        print("HAYIR (degisti!)")
    except TypeError:
        print("EVET - TypeError: tuple elemani degistirilemez")

    print("[kanit 3] TRUSTED_DEVICE_FINGERPRINTS immutable mi?", end=" ")
    try:
        TRUSTED_DEVICE_FINGERPRINTS.add("sha256:ffff...")  # frozenset -> AttributeError
        print("HAYIR (degisti!)")
    except AttributeError:
        print("EVET - AttributeError: frozenset'e eleman eklenemez")

    print("[mesaj] Cuzdan sirlari kaynak dosyada DÜZ METIN; koruma = "
          "dosyanin kendisini sifrelemek. HyperCipher max security ile "
          "sifrelendiginde: donanim kilidi + keyfile + 128 MiB Argon2id.")