# -*- coding: utf-8 -*-
"""Standart kutuphaneden AES-256-CBC ile sifreleme: hello.py -> AES256CBC_şifreledi.

En yaygin endustri standardi: AES-256-CBC + PKCS7 padding.
Anahtar/IV rastgele uretilir ve yalnizca EKRANA basilir (DEMO).
"""

import os
import sys

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

DIR = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(DIR, "hassas_ayarlar.py")
OUT = os.path.join(DIR, "AES256CBC_şifreledi")

key = os.urandom(32)  # 256-bit anahtar
iv = os.urandom(16)   # 128-bit IV (CBC'de rastgele olmali)
print(f"[AES-256-CBC] anahtar (DEMO-ONLY): {key.hex()}")
print(f"[AES-256-CBC] IV     (DEMO-ONLY): {iv.hex()}")

with open(SRC, "rb") as f:
    data = f.read()

# CBC blok tabanli -> PKCS7 padding sart
padder = padding.PKCS7(128).padder()
padded = padder.update(data) + padder.finalize()

enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
ct = enc.update(padded) + enc.finalize()

if os.path.exists(OUT):
    os.remove(OUT)  # onceki kosunun ciktisini temizle
with open(OUT, "wb") as f:
    f.write(ct)
print(f"[AES-256-CBC] sifrelendi: {OUT} ({os.path.getsize(OUT)} byte)")

# --- Dogrulama: geri coz ve birebir karsilastir ---
dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
pt = dec.update(ct) + dec.finalize()
unpadder = padding.PKCS7(128).unpadder()
pt = unpadder.update(pt) + unpadder.finalize()
print(f"[AES-256-CBC] dogrulama: geri cozuldu, esit mi? -> {pt == data}")
