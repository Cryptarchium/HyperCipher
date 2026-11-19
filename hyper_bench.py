#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
hyper_bench.py - HyperCipher v5 performans + bellek olcum araci
================================================================
Tek dosya. hyper_cipher.py ile ayni dizinde calistirin:

    python hyper_bench.py           # tam olcum (~1-2 dk)
    python hyper_bench.py --quick   # kucuk boyutlarla hizli tur

Olcum plani:
  [1] Argon2id KDF - tek seferlik maliyet (farkli kdf_n degerleri)
  [2] Sicak dongu mikro-analizi: BLAKE2b / HMAC / saf-Python XOR ayrisimi (%)
  [3] Bellek ici API: gorunen MB/s (KDF dahil) vs KDF-haric "gercek" MB/s
  [4] Rotasyon frekansinin etkisi (rotation_bytes 64 -> 65472)
  [5] Dosya API: encrypt_file/decrypt_file hizi + roundtrip dogrulama
  [6] RAM: in-memory API (dosyayla BUYUR) vs dosya API (SABIT ~MiB)
  [7] Referans: AES-256-GCM, ChaCha20-Poly1305, ham BLAKE2b (ayni surecte)
  [8] Ozet: docstring iddiasi vs olculen + KDF/cipher baskinlik esigi
"""

from __future__ import annotations

import argparse
import gc
import hashlib
import hmac as hmac_mod
import os
import platform
import shutil
import struct
import sys
import tempfile
import time
import tracemalloc

import hyper_cipher as hc

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    HAVE_AES = True
except Exception:
    HAVE_AES = False

try:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    HAVE_CHACHA = True
except Exception:
    HAVE_CHACHA = False

try:
    import psutil
    HAVE_PSUTIL = True
except Exception:
    HAVE_PSUTIL = False

PW = "benchmark-passphrase-2026"
KDF_BENCH = 1 << 14            # olcumlerde kullanilan hizli KDF (16 MiB)
MIB = 1 << 20


# ---------------------------------------------------------------------------
# Yardimcilar
# ---------------------------------------------------------------------------
def hr(title: str) -> None:
    print("\n" + "=" * 68, flush=True)
    print(title, flush=True)
    print("=" * 68, flush=True)


def t_min(fn, repeats: int) -> float:
    """fn'yi repeats kez calistir, EN IYI (min) sureyi dondur."""
    best = float("inf")
    for _ in range(repeats):
        t0 = time.perf_counter()
        fn()
        best = min(best, time.perf_counter() - t0)
    return best


def _reset_peak() -> None:
    try:
        tracemalloc.reset_peak()
    except AttributeError:          # Python < 3.9
        tracemalloc.stop()
        tracemalloc.start()


# ---------------------------------------------------------------------------
# [1] KDF
# ---------------------------------------------------------------------------
def bench_kdf() -> dict:
    hr("[1] ARGON2ID KDF - TEK SEFERLIK MALIYET (her sifrelemede 1 kez)")
    print(f"  {'kdf_n':>10} {'RAM(teorik)':>12} {'sure':>10}")
    out = {}
    for kdf_n in (1 << 14, 1 << 15, 1 << 16, 1 << 17):
        salt = os.urandom(32)
        fp = b"bench-fp"
        t = t_min(lambda k=kdf_n: hc._derive_master(PW, fp, salt, k), 3)
        out[kdf_n] = t
        print(f"  {kdf_n:>10} {kdf_n / 1024:>9.0f} MiB {t:>8.3f} s")
    print("\n  NOT: Bu sure dosya boyutundan BAGIMSIZDIR - 1 byte icin de")
    print("       10 GB icin de ayni kadar ode.nir (bir kez yapilir).")
    return out


# ---------------------------------------------------------------------------
# [2] Sicak dongu mikro-analizi
# ---------------------------------------------------------------------------
def bench_micro() -> dict:
    hr("[2] SICAK DONGU MIKRO-ANALIZI - her 64 byte'lik keystream blogu")
    sub = os.urandom(256)
    N = 3000

    # Tam blok (BLAKE2b + HMAC + XOR + pack + cagri overhead)
    t_block = t_min(lambda: [hc._keystream_block(sub, i) for i in range(N)], 3) / N

    # Sadece BLAKE2b kismi (ayni girdilerle)
    def f_blake():
        for i in range(N):
            ctr = struct.pack("<Q", i)
            hashlib.blake2b(sub[64:] + ctr + b"HYPR1",
                            key=sub[:64], digest_size=64).digest()
    t_blake = t_min(f_blake, 3) / N

    # Sadece HMAC-SHA512 kismi (256 byte key -> SHA-512 key pre-hash pahali)
    def f_hmac():
        for i in range(N):
            ctr = struct.pack("<Q", i)
            hmac_mod.new(sub, ctr + b"HYPR2", hashlib.sha512).digest()
    t_hmac = t_min(f_hmac, 3) / N

    # Sadece saf-Python XOR (64 iterasyon bytecode)
    a = hc._keystream_block(sub, 0)
    b = hc._keystream_block(sub, 1)
    t_xor = t_min(lambda: [bytes(x ^ y for x, y in zip(a, b))
                           for _ in range(N)], 3) / N

    # struct.pack (blok sayaci)
    t_pack = t_min(lambda: [struct.pack("<Q", i) for i in range(N)], 3) / N

    # _CipherState.process icindeki IKINCI xor dongusu (veri ^ ks + append)
    buf = bytearray(64)
    def f_dataxor():
        for _ in range(N):
            for i in range(64):
                buf[i] = a[i] ^ b[i]
    t_dataxor = t_min(f_dataxor, 3) / N

    # Subkey turetimi (rotasyon basina 1 kez)
    t_sub = t_min(lambda: [hc._derive_subkey(sub, sub, b"\x00" * 24, i)
                           for i in range(300)], 3) / 300

    parts = t_blake + t_hmac + t_xor - t_pack     # pack iki kez sayildi -> duzelt
    overhead = t_block - parts

    print(f"  {'bilesen':<38}{'us/blok':>10}{'pay':>8}")
    print(f"  {'-' * 56}")
    print(f"  {'BLAKE2b-512 (keyed)':<38}{t_blake * 1e6:>9.2f}{100 * t_blake / t_block:>7.1f}%")
    print(f"  {'HMAC-SHA512 (256B key -> pre-hash)':<38}{t_hmac * 1e6:>9.2f}{100 * t_hmac / t_block:>7.1f}%")
    print(f"  {'saf-Python XOR (zip generator)':<38}{t_xor * 1e6:>9.2f}{100 * t_xor / t_block:>7.1f}%")
    print(f"  {'fonksiyon cagrisi + struct.pack vs.':<38}{overhead * 1e6:>9.2f}{100 * overhead / t_block:>7.1f}%")
    print(f"  {'TOPLAM _keystream_block':<38}{t_block * 1e6:>9.2f}{100.0:>7.1f}%")
    print(f"  {'(ayrica) veri^ks xor+append [process]':<38}{t_dataxor * 1e6:>9.2f}")
    print(f"  {'(ayrica) _derive_subkey / rotasyon':<38}{t_sub * 1e6:>9.2f}")

    # Alternatif XOR yontemi (karsilastirma icin, 4096 byte buffer)
    A, B = os.urandom(4096), os.urandom(4096)
    t_loop_big = t_min(lambda: [bytes(x ^ y for x, y in zip(A, B))
                                for _ in range(500)], 3) / 500
    t_int_big = t_min(lambda: [(int.from_bytes(A, "little") ^
                                int.from_bytes(B, "little")).to_bytes(4096, "little")
                               for _ in range(500)], 3) / 500
    print(f"\n  4096-byte XOR karsilastirmasi:")
    print(f"    generator-loop : {t_loop_big * 1e6:8.1f} us")
    print(f"    int.from_bytes : {t_int_big * 1e6:8.1f} us  "
          f"({t_loop_big / max(t_int_big, 1e-12):.0f}x hizli - potansiyel)")

    # Model: 1 MiB sifrelemenin tahmini cipher suresi (varsayilan rotasyon 1024)
    blocks_per_mib = MIB // 64
    rots_per_mib = MIB // hc.ROTATION_BYTES
    t_cipher_mib = (t_block + t_dataxor) * blocks_per_mib + t_sub * rots_per_mib
    pred = 1.0 / t_cipher_mib
    print(f"\n  MODEL (mikro-olcumlerden tahmin): {pred:.2f} MB/s")
    print(f"  (asagida [3]'teki marjinal olcumle karsilastirilacak)")
    return {"t_block": t_block, "t_sub": t_sub, "pred": pred}


# ---------------------------------------------------------------------------
# [3] Bellek ici API throughput
# ---------------------------------------------------------------------------
def bench_memory_api(kdf_time: float, quick: bool):
    hr("[3] BELLEK-ICI API - hc.encrypt / hc.decrypt")
    sizes = [1, 4, 16] if not quick else [1, 4]
    reps = {1: 3, 4: 2, 16: 2}
    times, cache = {}, {}
    for s in sizes:
        data = os.urandom(s * MIB)
        cache[s] = data
        t = t_min(lambda d=data: hc.encrypt(d, PW, use_hardware=False,
                                            kdf_n=KDF_BENCH), reps.get(s, 2))
        times[s] = t
        app = s / t
        net = s / max(t - kdf_time, 1e-9)
        print(f"  encrypt {s:>3} MiB: toplam {t:7.3f} s | gorunen "
              f"{app:7.2f} MB/s | KDF-haric ~{net:7.2f} MB/s")

    marginal = None
    if len(sizes) >= 2:
        s1, s2 = sizes[-2], sizes[-1]
        marginal = (s2 - s1) / (times[s2] - times[s1])
        print(f"\n  >> MARJINAL (saf cipher, KDF tamamen elenmis): "
              f"{marginal:.2f} MB/s")

    s2 = sizes[-1]
    enc = hc.encrypt(cache[s2], PW, use_hardware=False, kdf_n=KDF_BENCH)
    t = t_min(lambda: hc.decrypt(enc, PW), 2)
    net = s2 / max(t - kdf_time, 1e-9)
    print(f"  decrypt {s2:>3} MiB: toplam {t:7.3f} s | KDF-haric ~{net:7.2f} MB/s")
    return marginal


# ---------------------------------------------------------------------------
# [4] Rotasyon frekansi
# ---------------------------------------------------------------------------
def bench_rotation(kdf_time: float, quick: bool) -> None:
    hr("[4] ROTASYON FREKANSININ ETKISI (KDF-haric net MB/s)")
    size = 1 if quick else 2
    data = os.urandom(size * MIB)
    print(f"  {'rotation_bytes':>15} {'net MB/s':>12}   not")
    for rot in (64, 512, 1024, 4096, 65472):
        t = t_min(lambda r=rot: hc.encrypt(data, PW, use_hardware=False,
                                           kdf_n=KDF_BENCH, rotation_bytes=r), 1)
        net = size / max(t - kdf_time, 1e-9)
        note = "  <- varsayilan" if rot == 1024 else ""
        print(f"  {rot:>15} {net:>10.2f}{note}")
    print("\n  NOT: rotasyon kuculdukce _derive_subkey (HKDF x5) cagrisi siklasir.")


# ---------------------------------------------------------------------------
# [5] Dosya API
# ---------------------------------------------------------------------------
def bench_file_api(tmpdir: str, kdf_time: float, quick: bool) -> None:
    hr("[5] DOSYA API - encrypt_file / decrypt_file (fsync dahil)")
    size = 4 if quick else 12
    inp = os.path.join(tmpdir, "bench.bin")
    hyp = os.path.join(tmpdir, "bench.hyp")
    out = os.path.join(tmpdir, "bench.out")
    with open(inp, "wb") as f:
        f.write(os.urandom(size * MIB))
    with open(inp, "rb") as f:
        src_hash = hashlib.sha256(f.read()).hexdigest()

    t = t_min(lambda: hc.encrypt_file(inp, hyp, PW, use_hardware=False,
                                      kdf_n=KDF_BENCH), 1)
    print(f"  encrypt_file {size:>3} MiB: {t:7.3f} s | KDF-haric ~"
          f"{size / max(t - kdf_time, 1e-9):7.2f} MB/s")
    t = t_min(lambda: hc.decrypt_file(hyp, out, PW), 1)
    print(f"  decrypt_file {size:>3} MiB: {t:7.3f} s | KDF-haric ~"
          f"{size / max(t - kdf_time, 1e-9):7.2f} MB/s")
    with open(out, "rb") as f:
        ok = hashlib.sha256(f.read()).hexdigest() == src_hash
    print(f"  roundtrip SHA-256 dogrulama: {'TAMAM' if ok else 'HATA!'}")


# ---------------------------------------------------------------------------
# [6] RAM kullanimi
# ---------------------------------------------------------------------------
def bench_memory(tmpdir: str, quick: bool) -> None:
    hr("[6] RAM KULLANIMI - in-memory API (dosyayla buyur) vs dosya API (sabit)")
    sizes = (2, 6) if quick else (4, 12)
    tracemalloc.start()
    try:
        for s in sizes:
            data = os.urandom(s * MIB)
            _reset_peak()
            enc = hc.encrypt(data, PW, use_hardware=False, kdf_n=KDF_BENCH)
            _, peak = tracemalloc.get_traced_memory()
            print(f"  hc.encrypt      {s:>3} MiB veri  -> RAM tepesi: "
                  f"{peak / MIB:7.2f} MiB  (~{peak / (s * MIB):.1f}x veri)")
            del data, enc
            gc.collect()

        for s in sizes:
            inp = os.path.join(tmpdir, f"m{s}.bin")
            hyp = os.path.join(tmpdir, f"m{s}.hyp")
            with open(inp, "wb") as f:
                f.write(os.urandom(s * MIB))
            _reset_peak()
            hc.encrypt_file(inp, hyp, PW, use_hardware=False, kdf_n=KDF_BENCH)
            _, peak = tracemalloc.get_traced_memory()
            print(f"  hc.encrypt_file {s:>3} MiB dosya -> RAM tepesi: "
                  f"{peak / MIB:7.2f} MiB  (dosya boyutundan BAGIMSIZ)")
    finally:
        tracemalloc.stop()

    if HAVE_PSUTIL:
        p = psutil.Process()
        gc.collect()
        before = p.memory_info().rss
        hc._derive_master(PW, b"fp", os.urandom(32), 1 << 17)
        gc.collect()
        after = p.memory_info().rss
        print(f"\n  Argon2id kdf_n=2^17 islem RSS artisi: ~{(after - before) / MIB:.0f} MiB "
              f"(teorik 128 MiB)")
    else:
        print("\n  (psutil yok - Argon2id RSS olcumu atlandi)")
    print("\n  SONUC: dosya API RAM'i dosya boyutundan bagimsiz tutar;")
    print("  4 GB makine ile 64 GB makine ayni THROUGHPUT gorur.")


# ---------------------------------------------------------------------------
# [7] Referans olcumler
# ---------------------------------------------------------------------------
def bench_reference(quick: bool) -> None:
    hr("[7] REFERANS - ayni makine, ayni Python sureci")
    size = (4 if quick else 12) * MIB
    data = os.urandom(size)
    mib = size / MIB

    if HAVE_AES:
        aes = AESGCM(os.urandom(32))
        nonce = os.urandom(12)
        t = t_min(lambda: aes.encrypt(nonce, data, None), 3)
        print(f"  AES-256-GCM (cryptography, AES-NI) : {mib / t:9.1f} MB/s")
    else:
        print("  AES-256-GCM : N/A")

    if HAVE_CHACHA:
        cc = ChaCha20Poly1305(os.urandom(32))
        nonce = os.urandom(12)
        t = t_min(lambda: cc.encrypt(nonce, data, None), 3)
        print(f"  ChaCha20-Poly1305 (cryptography)   : {mib / t:9.1f} MB/s")
    else:
        print("  ChaCha20-Poly1305 : N/A")

    t = t_min(lambda: hashlib.blake2b(data, digest_size=64).digest(), 3)
    print(f"  ham BLAKE2b-512 hash (C hizi)      : {mib / t:9.1f} MB/s")
    print("\n  -> Primitiflerin kendisi GB/s seviyesinde. Aradaki fark =")
    print("     Python yapistirici kodu (obje insasi + bytecode XOR).")


# ---------------------------------------------------------------------------
# [8] Ozet
# ---------------------------------------------------------------------------
def summary(kdf_times: dict, micro: dict, marginal) -> None:
    hr("[8] OZET")
    print(f"  Docstring iddiasi ('~1 GiB/s')     : 1024 MB/s")
    if marginal:
        print(f"  Olculen marjinal cipher throughput : {marginal:7.2f} MB/s "
              f"-> iddianin ~{1024 / marginal:.0f}x altinda")
    if micro.get("pred"):
        print(f"  Mikro-olcum modelinin tahmini      : {micro['pred']:7.2f} MB/s "
              f"(model vs olcum uyumu dogrulamasi)")

    kdf_default = kdf_times.get(1 << 17)
    if kdf_default and marginal:
        print(f"\n  KDF payi tablosu (varsayilan Argon2id 2^17 = ~{kdf_default:.2f}s):")
        print(f"  {'dosya':>10} {'toplam sure':>12} {'KDF payi':>10}")
        for s in (1, 10, 100, 1000):
            total = kdf_default + s / marginal
            print(f"  {s:>7} MiB {total:>10.1f} s {100 * kdf_default / total:>9.1f}%")
        cross = kdf_default * marginal
        print(f"\n  Esik: ~{cross:.1f} MiB altindaki dosyalarda surenin cogu Argon2id;")
        print(f"        uzerinde Python cipher dongusu baskin.")


# ---------------------------------------------------------------------------
def main() -> None:
    ap = argparse.ArgumentParser(description="HyperCipher benchmark")
    ap.add_argument("--quick", action="store_true", help="kucuk boyutlar, hizli tur")
    args = ap.parse_args()

    print("HyperCipher BENCHMARK", flush=True)
    print(f"  Python : {sys.version.split()[0]}  |  {platform.system()} "
          f"{platform.release()}  |  CPU cekirdek: {os.cpu_count()}")
    print(f"  cipher : hyper_cipher v{hc.VERSION} | ROTATION_BYTES="
          f"{hc.ROTATION_BYTES} | DEFAULT_KDF_N=2^{hc.DEFAULT_KDF_N.bit_length() - 1}")
    if args.quick:
        print("  MOD    : --quick (olcumsel dogrulik dusuk, sadece fikir verir)")

    tmpdir = tempfile.mkdtemp(prefix="hypbench_")
    try:
        kdf_times = bench_kdf()
        micro = bench_micro()
        kdf_time = kdf_times[KDF_BENCH]
        marginal = bench_memory_api(kdf_time, args.quick)
        bench_rotation(kdf_time, args.quick)
        bench_file_api(tmpdir, kdf_time, args.quick)
        bench_memory(tmpdir, args.quick)
        bench_reference(args.quick)
        summary(kdf_times, micro, marginal)
        print("\n[BITTI] Tum gecici dosyalar temizlendi.")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    main()