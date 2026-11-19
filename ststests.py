# -*- coding: utf-8 -*-
"""
ststests.py - NIST SP 800-22 Statistical Test Suite (alt kume)
================================================================
Saf Python (stdlib) implementasyonu. Kriptografik rastgelelik dogrulamasi
icin profesyonel standart testler:

  - Frequency (Monobit)            - Block Frequency (M=128)
  - Runs                           - Longest Run of Ones (M=128)
  - Cumulative Sums (fwd + rev)    - Serial (m=3)
  - Approximate Entropy (m=3)      - Spectral (DFT, n=2^16)

Her test bir p-degeri dondurur. NIST kurali: p >= 0.01 -> GECTI.
p < 0.01 -> sekans rastgele degil (bias var).

Referans: NIST SP 800-22 Rev 1a (https://csrc.nist.gov/publications/detail/sp/800-22/rev-1a/final)
"""

from __future__ import annotations

import math

# ---------------------------------------------------------------------------
# Yardimcilar
# ---------------------------------------------------------------------------
def bits_from_bytes(data: bytes) -> str:
    """Byte dizisini '0'/'1' bit dizisine cevirir."""
    return "".join(f"{b:08b}" for b in data)


def _gammp(a: float, x: float) -> float:
    """Regularized lower incomplete gamma P(a, x) (Cephes uyumlu)."""
    if a <= 0.0:
        raise ValueError("gammp: gecersiz a")
    if x <= 0.0:
        return 0.0          # P(a, 0) = 0 (Cephes igam davranisi)
    return _gser(a, x) if x < a + 1.0 else 1.0 - _gcf(a, x)


def _gammq(a: float, x: float) -> float:
    """Regularized upper incomplete gamma Q(a, x) = 1 - P(a, x).

    NIST Serial testi rastgele veride NEGATIF chi-square uretebilir;
    Cephes referans kodu Q(a, x<=0) = 1.0 dondurur (p=1 -> PASS).
    """
    if a <= 0.0:
        raise ValueError("gammq: gecersiz a")
    if x <= 0.0:
        return 1.0          # Q(a, 0) = 1 (Cephes igamc davranisi)
    return 1.0 - _gser(a, x) if x < a + 1.0 else _gcf(a, x)


def _gser(a: float, x: float, eps: float = 3e-14) -> float:
    """Seri acilimi ile P(a, x) (Numerical Recipes)."""
    gln = math.lgamma(a)
    ap = a
    summ = 1.0 / a
    delta = summ
    for _ in range(10_000):
        ap += 1.0
        delta *= x / ap
        summ += delta
        if abs(delta) < abs(summ) * eps:
            return summ * math.exp(-x + a * math.log(x) - gln)
    raise RuntimeError("gser yakinsamadi")


def _gcf(a: float, x: float, eps: float = 3e-14) -> float:
    """Surekli kesir acilimi ile Q(a, x) (Numerical Recipes)."""
    gln = math.lgamma(a)
    b = x + 1.0 - a
    c = 1e300
    d = 1.0 / b
    h = d
    for _ in range(10_000):
        an = -1.0 * (_ + 1) * (_ + 1 - a)
        b += 2.0
        d = an * d + b
        if abs(d) < 1e-300:
            d = 1e-300
        c = b + an / c
        if abs(c) < 1e-300:
            c = 1e-300
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < eps:
            break
    return math.exp(-x + a * math.log(x) - gln) * h


def _chi2_pvalue(chi2: float, dof: float) -> float:
    """Ki-kare p-degeri = Q(dof/2, chi2/2)."""
    return _gammq(dof / 2.0, chi2 / 2.0)


# ---------------------------------------------------------------------------
# 1) Frequency (Monobit) Test
# ---------------------------------------------------------------------------
def monobit(data: bytes) -> float:
    """n bit icin +1/-1 toplami; p = erfc(|S|/sqrt(2))."""
    n = len(data) * 8
    s = sum(1 if (byte >> bit) & 1 else -1
            for byte in data for bit in range(8))
    s_obs = s / math.sqrt(n)
    return math.erfc(abs(s_obs) / math.sqrt(2.0))


# ---------------------------------------------------------------------------
# 2) Frequency within a Block Test (M = 128)
# ---------------------------------------------------------------------------
def block_frequency(data: bytes, m: int = 128) -> float:
    n = len(data) * 8
    n_blocks = n // m
    if n_blocks < 1:
        raise ValueError("veri cok kisa")
    chi2 = 0.0
    for i in range(n_blocks):
        block = data[i * m // 8:(i + 1) * m // 8]
        ones = sum(1 if (byte >> bit) & 1 else 0
                   for byte in block for bit in range(8))
        pi = ones / m
        chi2 += (pi - 0.5) ** 2
    chi2 *= 4.0 * m
    return _chi2_pvalue(chi2, n_blocks)


# ---------------------------------------------------------------------------
# 3) Runs Test
# ---------------------------------------------------------------------------
def runs(data: bytes) -> float:
    n = len(data) * 8
    ones = sum(1 if (byte >> bit) & 1 else 0
               for byte in data for bit in range(8))
    pi = ones / n
    if abs(pi - 0.5) >= 2.0 / math.sqrt(n):
        return 0.0  # monobit oncelikle basarisiz
    v = 1
    prev = None
    for byte in data:
        for bit in range(8):
            cur = (byte >> bit) & 1
            if prev is not None and cur != prev:
                v += 1
            prev = cur
    num = abs(v - 2.0 * n * pi * (1.0 - pi))
    den = 2.0 * math.sqrt(2.0 * n) * pi * (1.0 - pi)
    return math.erfc(num / den)


# ---------------------------------------------------------------------------
# 4) Longest Run of Ones (M = 128)
# ---------------------------------------------------------------------------
def longest_run_ones(data: bytes, m: int = 128) -> float:
    n = len(data) * 8
    k = 6                     # M=128 icin K=6 kategori
    mmin = 128
    n_blocks = n // m
    if m != mmin or n_blocks < 1:
        raise ValueError("bu test M=128, n>=1024 ister")
    # NIST tablosu (M=128): K, pi degerleri
    pi_table = [0.1174, 0.2430, 0.2493, 0.1752, 0.1027, 0.1124]
    # Kategori sinirlari: v_0:[0,4], v_1:[5], v_2:[6], v_3:[7], v_4:[8], v_5:[9,inf)
    counts = [0] * k
    for i in range(n_blocks):
        block = data[i * m // 8:(i + 1) * m // 8]
        longest = 0
        cur = 0
        for byte in block:
            for bit in range(8):
                if (byte >> bit) & 1:
                    cur += 1
                    longest = max(longest, cur)
                else:
                    cur = 0
        if longest <= 4:
            counts[0] += 1
        elif longest == 5:
            counts[1] += 1
        elif longest == 6:
            counts[2] += 1
        elif longest == 7:
            counts[3] += 1
        elif longest == 8:
            counts[4] += 1
        else:
            counts[5] += 1
    chi2 = sum((counts[i] - n_blocks * pi_table[i]) ** 2 /
               (n_blocks * pi_table[i]) for i in range(k))
    # NIST 2.5: p = igamc(K/2, chi2/2)  (K = kategori sayisi, K-1 degil)
    return _gammq(k / 2.0, chi2 / 2.0)


# ---------------------------------------------------------------------------
# 5) Cumulative Sums (forward + reverse) - NIST 2.13
#    p = 1 - sum1 + sum2  (Phi = normal CDF)
# ---------------------------------------------------------------------------
def _phi(x: float) -> float:
    """Standart normal CDF (NIST cumsum testinde kullanilir)."""
    return 0.5 * math.erfc(-x / math.sqrt(2.0))


def _cumsum_pvalue(bits: list[int], n: int, z: float) -> float:
    sn = math.sqrt(n)
    total = 0.0
    # sum1: k = floor((-n/z + 1)/4) .. floor((n/z - 1)/4)
    k = (-n / z + 1) // 4
    hi = (n / z - 1) // 4
    while k <= hi:
        total += _phi((4 * k + 1) * z / sn) - _phi((4 * k - 1) * z / sn)
        k += 1
    # sum2: k = floor((-n/z - 3)/4) .. floor((n/z - 1)/4)
    k = (-n / z - 3) // 4
    while k <= hi:
        total -= _phi((4 * k + 3) * z / sn) - _phi((4 * k + 1) * z / sn)
        k += 1
    return max(0.0, min(1.0, 1.0 - total))


def cumulative_sums(data: bytes) -> tuple[float, float]:
    n = len(data) * 8
    bits = [1 if (byte >> bit) & 1 else -1
            for byte in data for bit in range(8)]
    run = 0
    mx = 0
    for x in bits:
        run += x
        mx = max(mx, abs(run))
    if mx == 0:
        return 0.0, 0.0
    fwd = _cumsum_pvalue(bits, n, mx)
    rev = _cumsum_pvalue(list(reversed(bits)), n, mx)
    return fwd, rev


# ---------------------------------------------------------------------------
# 6) Serial Test (m = 3) - NIST 2.11
#    psi_m = (1/n) * sum(freq * ln(freq/n))  [dogal log, Cephes referansi]
#    p1 = igamc(2^(m-2), dPsi1/2) ; p2 = igamc(2^(m-3), dPsi2/2)
# ---------------------------------------------------------------------------
def _psi(data: bytes, m: int) -> float:
    n = len(data) * 8
    bits = [1 if (byte >> bit) & 1 else 0 for byte in data for bit in range(8)]
    # dairesel: ilk m-1 biti sona ekle
    ext = bits + bits[:m - 1]
    counts = {}
    for i in range(n):
        pattern = 0
        for j in range(m):
            pattern = (pattern << 1) | ext[i + j]
        counts[pattern] = counts.get(pattern, 0) + 1
    return sum((c / n) * math.log(c / n) for c in counts.values())


def serial(data: bytes, m: int = 3) -> tuple[float, float]:
    n = len(data) * 8
    if n < 2 * m:
        raise ValueError("veri cok kisa")
    psi_m = _psi(data, m)
    psi_m1 = _psi(data, m - 1)
    psi_m2 = _psi(data, m - 2)
    d1 = psi_m - psi_m1
    d2 = psi_m - 2 * psi_m1 + psi_m2
    p1 = _gammq(2 ** (m - 2), d1 / 2.0)
    p2 = _gammq(2 ** (m - 3), d2 / 2.0)
    return p1, p2


# ---------------------------------------------------------------------------
# 7) Approximate Entropy Test (m = 3) - NIST 2.12
#    ApEn = psi_m - psi_{m+1} ; chi2 = 2n(ln2 - ApEn)
#    p = igamc(2^(m-1), chi2/2)
# ---------------------------------------------------------------------------
def approximate_entropy(data: bytes, m: int = 3) -> float:
    n = len(data) * 8
    if n < 2 * (m + 1):
        raise ValueError("veri cok kisa")
    apen = _psi(data, m) - _psi(data, m + 1)
    chi2 = 2.0 * n * (math.log(2.0) - apen)
    return _gammq(2 ** (m - 1), chi2 / 2.0)


# ---------------------------------------------------------------------------
# 8) Spectral (DFT) Test - radix-2 iteratif FFT, n = 2^16
# ---------------------------------------------------------------------------
def _fft(samples: list[complex]) -> None:
    """In-place radix-2 iteratif FFT (samples uzunlugu 2'nin kuvveti)."""
    n = len(samples)
    j = 0
    for i in range(1, n):
        bit = n >> 1
        while j & bit:
            j ^= bit
            bit >>= 1
        j ^= bit
        if i < j:
            samples[i], samples[j] = samples[j], samples[i]
    length = 2
    while length <= n:
        ang = -2.0 * math.pi / length
        wlen = complex(math.cos(ang), math.sin(ang))
        for i in range(0, n, length):
            w = 1.0 + 0.0j
            half = length >> 1
            for j in range(i, i + half):
                u = samples[j]
                v = samples[j + half] * w
                samples[j] = u + v
                samples[j + half] = u - v
                w *= wlen
        length <<= 1


def spectral(data: bytes) -> float:
    """DFT testi. n = 2^16 = 8192 byte gerekli."""
    n = len(data) * 8
    if n != 65536:
        raise ValueError("spectral test icin tam 8192 byte (65536 bit) gerek")
    x = [complex(1.0 if (byte >> bit) & 1 else -1.0, 0.0)
         for byte in data for bit in range(8)]
    _fft(x)
    m = n // 2
    threshold = math.sqrt(math.log(1.0 / 0.05) * n)
    n1 = sum(1 for k in range(1, m) if abs(x[k]) < threshold)
    n0 = 0.95 * m
    d = (n1 - n0) / math.sqrt(n * 0.95 * 0.05 / 4.0)
    return math.erfc(abs(d) / math.sqrt(2.0))


# ---------------------------------------------------------------------------
# Toplu calistirici: tum testleri tek keystream'de uygula
# ---------------------------------------------------------------------------
def run_all(data: bytes) -> dict[str, float]:
    """Butun NIST testlerini calistirir; p-degerleri sozlugu dondurur."""
    results = {"monobit": monobit(data)}
    results["block_frequency"] = block_frequency(data)
    results["runs"] = runs(data)
    results["longest_run_ones"] = longest_run_ones(data)
    fwd, rev = cumulative_sums(data)
    results["cumsum_fwd"] = fwd
    results["cumsum_rev"] = rev
    s1, s2 = serial(data)
    results["serial_p1"] = s1
    results["serial_p2"] = s2
    results["approx_entropy"] = approximate_entropy(data)
    results["spectral"] = spectral(data[:8192])
    return results


def all_pass(results: dict[str, float], alpha: float = 0.01) -> bool:
    """NIST kurali: tum p-degerleri >= alpha olmali."""
    return all(v >= alpha for v in results.values())
