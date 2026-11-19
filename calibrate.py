# -*- coding: utf-8 -*-
"""Kalibrasyon: STS motorunun dogru calistigini kanitla.
AES-256-CTR (bilinen iyi) GECMELI; sifir-byte veri KALMALI."""

import os

from Crypto.Cipher import AES

import ststests as s

print("=== STS KALIBRASYON ===")

# 1) AES-256-CTR keystream - bilinen guclu cipher, GECMELI
key = os.urandom(32)
nonce = os.urandom(8)
aes = AES.new(key, AES.MODE_CTR, nonce=nonce)
keystream = aes.encrypt(b"\x00" * 65536)

r = s.run_all(keystream)
ok = True
for k, v in r.items():
    passed = v >= 0.01
    ok &= passed
    print(f"  {k:20s} p={v:.6f}  {'PASS' if passed else 'FAIL'}")
print(f"  -> AES-256-CTR GENEL: {'PASS' if ok else 'FAIL'}")
assert ok, "AES bile STS'den gecmedi - test motoru bozuk!"

# 2) Sifir byte - rastgele DEGIL, KALMALI
r2 = s.run_all(b"\x00" * 65536)
ok2 = not s.all_pass(r2)
print(f"  Zero-bytes GENEL: {'PASS (dogru sekilde reddedildi)' if ok2 else 'FAIL (sifir gecti!)'}")
for k, v in r2.items():
    if v < 0.01:
        print(f"    {k}: p={v:.2e} -> reddedildi (dogru)")
assert ok2, "Sifir-byte veri STS'den gecti - test motoru ciddi sekilde bozuk!"

# 3) Tekrarlayan pattern (0xAA) - KALMALI
r3 = s.run_all(b"\xAA" * 65536)
ok3 = not s.all_pass(r3)
print(f"  0xAA pattern GENEL: {'PASS (dogru sekilde reddedildi)' if ok3 else 'FAIL'}")
assert ok3

print("\n[OK] KALIBRASYON BASARILI - STS motoru dogru calisiyor.")
print("     AES-256 gecti, bilinen-kotu veriler reddedildi.")
