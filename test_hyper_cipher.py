# -*- coding: utf-8 -*-
"""HyperCipher v1 birim testleri. Calistirma: python -m unittest -v"""

import os
import shutil
import struct
import subprocess
import tempfile
import time
import unittest
import inspect
import hashlib
from unittest import mock

import hyper_cipher as hc

# V5.3 zafiyet raporu [1] fix'i opt-in: deterministic test API (sabit
# salt/nonce) yalnizca test ortaminda calisir. `python -m unittest` altinda
# conftest.py yuklenmez -> burada acilir. (pytest altinda conftest ayni
# seyi yapar; cift opt-in zararsiz.)
hc._DETERMINISTIC_MODE = True

PW = "test-passphrase-42"
PW2 = "yanlis-passphrase-99"


class TestRoundtrip(unittest.TestCase):
    def test_kucuk_veri(self):
        data = b"Gizli mesaj: HyperCipher calisiyor!"
        enc = hc.encrypt(data, PW, use_hardware=False, kdf_n=1 << 14)
        self.assertEqual(hc.decrypt(enc, PW), data)

    def test_bos_veri(self):
        enc = hc.encrypt(b"", PW, use_hardware=False, kdf_n=1 << 14)
        self.assertEqual(hc.decrypt(enc, PW), b"")

    def test_1mb_veri(self):
        data = os.urandom(1 << 20)
        enc = hc.encrypt(data, PW, use_hardware=False, kdf_n=1 << 14)
        self.assertEqual(hc.decrypt(enc, PW), data)

    def test_rotasyon_sinirlari(self):
        for n in (1023, 1024, 1025, 1088, 2048, 4096 + 63):
            data = os.urandom(n)
            enc = hc.encrypt(data, PW, use_hardware=False, kdf_n=1 << 14)
            self.assertEqual(hc.decrypt(enc, PW), data, f"boyut {n}")

    def test_turkce_utf8(self):
        data = "Merhaba dunya! TLEuro-half".encode("utf-8")
        enc = hc.encrypt(data, PW, use_hardware=False, kdf_n=1 << 14)
        self.assertEqual(hc.decrypt(enc, PW), data)


class TestSecurity(unittest.TestCase):
    def test_yanlis_passphrase_reddedilir(self):
        enc = hc.encrypt(b"top secret", PW, use_hardware=False,
                         kdf_n=1 << 14)
        with self.assertRaises(hc.CipherError):
            hc.decrypt(enc, PW2)

    def test_kurcalama_tespit_edilir(self):
        enc = bytearray(hc.encrypt(b"kurcalanma beni", PW,
                                   use_hardware=False, kdf_n=1 << 14))
        enc[len(enc) // 2] ^= 0xFF
        with self.assertRaises(hc.CipherError):
            hc.decrypt(bytes(enc), PW)

    def test_tag_kurcalamasi_tespit_edilir(self):
        enc = bytearray(hc.encrypt(b"tag korunmali", PW,
                                   use_hardware=False, kdf_n=1 << 14))
        enc[-1] ^= 0x01
        with self.assertRaises(hc.CipherError):
            hc.decrypt(bytes(enc), PW)

    def test_kesik_paket_reddedilir(self):
        enc = hc.encrypt(b"kesik paket", PW, use_hardware=False,
                         kdf_n=1 << 14)
        with self.assertRaises(hc.CipherError):
            hc.decrypt(enc[:-10], PW)

    def test_gecersiz_magic_reddedilir(self):
        enc = bytearray(hc.encrypt(b"x", PW, use_hardware=False,
                                   kdf_n=1 << 14))
        enc[0] ^= 0xFF
        with self.assertRaises(hc.CipherError):
            hc.decrypt(bytes(enc), PW)

    def test_bos_passphrase_reddedilir(self):
        # Zafiyet raporu [26]: kutuphane seviyesinde bos/whitespace -> ValueError
        for bad in ("", "   ", "\t\n", " \u00a0 "):
            with self.assertRaises(ValueError):
                hc.encrypt(b"x", bad, use_hardware=False, kdf_n=1 << 14)
            with self.assertRaises(ValueError):
                hc.decrypt(hc.encrypt(b"x", PW, use_hardware=False,
                                      kdf_n=1 << 14), bad)

    def test_nfc_normalizasyon_ayni_key(self):
        # Zafiyet raporu [20]: NFC/NFD ayni key'i uretmeli (NIST SP 800-63B).
        import unicodedata
        nfc = "cafe\u0301"          # e + birlestiren aksan (NFD)
        nfd = unicodedata.normalize("NFC", nfc)   # tek karakterli e-acute
        self.assertNotEqual(nfc, nfd)              # bayt olarak farkli...
        enc = hc.encrypt(b"unicode test", nfc, use_hardware=False,
                         kdf_n=1 << 14)
        self.assertEqual(hc.decrypt(enc, nfd), b"unicode test")  # ...ama ayni key


class TestDeterminism(unittest.TestCase):
    def test_ayni_nonce_salt_ayni_cikti(self):
        salt = b"\x11" * 32
        nonce = b"\x22" * 24
        a = hc._encrypt_deterministic(b"deterministik", PW,
                                      use_hardware=False, salt=salt,
                                      nonce=nonce, kdf_n=1 << 14)
        b = hc._encrypt_deterministic(b"deterministik", PW,
                                      use_hardware=False, salt=salt,
                                      nonce=nonce, kdf_n=1 << 14)
        self.assertEqual(a, b)

    def test_farkli_nonce_farkli_cikti(self):
        salt = b"\x11" * 32
        a = hc._encrypt_deterministic(b"nonce farkli", PW,
                                      use_hardware=False, salt=salt,
                                      nonce=b"\x22" * 24, kdf_n=1 << 14)
        b = hc._encrypt_deterministic(b"nonce farkli", PW,
                                      use_hardware=False, salt=salt,
                                      nonce=b"\x33" * 24, kdf_n=1 << 14)
        self.assertNotEqual(a, b)

    def test_public_encrypt_nonce_kabul_etmez(self):
        # IC[10]: salt/nonce PUBLIC API'den kaldirildi - sabit nonce ile
        # keystream reuse (XOR sizintisi) kullanici hatasiyla imkansiz.
        # Imza dogrulamasi: parametreler artik mevcut DEGIL...
        sig_e = inspect.signature(hc.encrypt)
        self.assertNotIn("salt", sig_e.parameters)
        self.assertNotIn("nonce", sig_e.parameters)
        sig_f = inspect.signature(hc.encrypt_file)
        self.assertNotIn("salt", sig_f.parameters)
        self.assertNotIn("nonce", sig_f.parameters)
        # ...ve eski imza ile baglama TypeError uretir (runtime dogrulama).
        with self.assertRaises(TypeError):
            inspect.signature(hc.encrypt).bind(b"x", PW, use_hardware=False,
                                               salt=b"\x00" * 32)
        with self.assertRaises(TypeError):
            inspect.signature(hc.encrypt).bind(b"x", PW, use_hardware=False,
                                               nonce=b"\x00" * 24)
        with self.assertRaises(TypeError):
            inspect.signature(hc.encrypt_file).bind("_a", "_b", PW,
                                                    nonce=b"\x00" * 24)

    def test_public_encrypt_her_cagri_farkli_nonce(self):
        # IC[10]: public encrypt() her cagri icin CSPRNG nonce uretir -
        # iki sifreleme asla ayni ciktiyi vermez.
        a = hc.encrypt(b"aynisi", PW, use_hardware=False, kdf_n=1 << 14)
        b = hc.encrypt(b"aynisi", PW, use_hardware=False, kdf_n=1 << 14)
        self.assertNotEqual(a, b)


class TestRotation(unittest.TestCase):
    def test_subkeyler_farkli(self):
        master = bytes(range(256))
        nonce = b"\x00" * 24
        s0 = hc._derive_subkey(master, master, nonce, 0)     # ilk: prev=master
        s1 = hc._derive_subkey(s0, master, nonce, 1)          # zincirli
        s2 = hc._derive_subkey(s1, master, nonce, 2)
        self.assertEqual(len(s0), 256)
        self.assertEqual(len(s1), 256)
        self.assertEqual(len(s2), 256)
        self.assertNotEqual(s0, s1)
        self.assertNotEqual(s1, s2)

    def test_rotasyon_keystreami_degistirir(self):
        # 2048 byte sifir: ciphertext = keystream. Rotasyon 1024'te
        # keystream degismeli -> ilk blok ile 17. blok farkli olmali.
        zeros = b"\x00" * 2048
        enc = hc.encrypt(zeros, PW, use_hardware=False, kdf_n=1 << 14)
        body = enc[hc.HEADER_BYTES:-hc.TAG_BYTES]
        self.assertEqual(len(body), 2048)
        self.assertNotEqual(body[0:64], body[1024:1088])

    def test_rotasyon_icinde_bloklar_farkli(self):
        zeros = b"\x00" * 2048
        enc = hc.encrypt(zeros, PW, use_hardware=False, kdf_n=1 << 14)
        body = enc[hc.HEADER_BYTES:-hc.TAG_BYTES]
        self.assertNotEqual(body[0:64], body[64:128])


class TestHardware(unittest.TestCase):
    def test_parmak_izi_stabil(self):
        self.assertEqual(hc.collect_hardware_fingerprint(),
                         hc.collect_hardware_fingerprint())
        self.assertEqual(hc.fingerprint_digest(), hc.fingerprint_digest())

    def test_donanim_bagli_roundtrip(self):
        data = b"bu makineye bagli gizli veri"
        enc = hc.encrypt(data, PW, use_hardware=True, kdf_n=1 << 14)
        self.assertEqual(hc.decrypt(enc, PW), data)

    def test_portable_flag_headerda(self):
        enc = hc.encrypt(b"x", PW, use_hardware=False, kdf_n=1 << 14)
        h = hc.parse_header(enc[:hc.HEADER_BYTES])
        self.assertFalse(h.flags & hc.FLAG_HARDWARE)
        enc2 = hc.encrypt(b"x", PW, use_hardware=True, kdf_n=1 << 14)
        h2 = hc.parse_header(enc2[:hc.HEADER_BYTES])
        self.assertTrue(h2.flags & hc.FLAG_HARDWARE)

    def test_header_yapisi(self):
        enc = hc.encrypt(b"header test", PW, use_hardware=False,
                         kdf_n=1 << 14)
        header = enc[:hc.HEADER_BYTES]
        self.assertEqual(len(header), hc.HEADER_BYTES)  # 104 (magic yok)
        self.assertEqual(header[0], 4)  # version v4
        # KASITLI: dosya basinda tanimlayici magic string OLMAMALI -
        # paket random veri gibi gorunur, cipher hakkinda ipucu vermez.
        self.assertNotIn(b"HYPRC1", header)
        self.assertNotIn(b"HYPER", header)
        # ilk 2 byte random degil (version+flags) ama 6+ byte sabit degil:
        # version/flags/rotation disindaki alanlar (salt) random uretilir
        enc2 = hc.encrypt(b"header test", PW, use_hardware=False,
                          kdf_n=1 << 14)
        self.assertNotEqual(enc[:16], enc2[:16])  # salt farkli -> basi farkli


class TestStreamAPI(unittest.TestCase):
    """Dosya API testleri.

    [30] Test izolasyonu: tum gecici dosyalar tempfile.mkdtemp dizininde
    uretilir (CWD-goreli sabit adlar yok) - paralel/pes pese kosan test
    surecleri birbirini ezemez; proses kill edilse bile sistem temp
    dizinini temizler.
    """

    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="hc_test_")

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def test_dosya_roundtrip(self):
        tmp_in = os.path.join(self.d, "_test_in.bin")
        tmp_hyp = os.path.join(self.d, "_test_in.hyp")
        tmp_out = os.path.join(self.d, "_test_out.bin")
        try:
            data = os.urandom(300_000)  # rotasyon sinirini asar
            with open(tmp_in, "wb") as f:
                f.write(data)
            hc.encrypt_file(tmp_in, tmp_hyp, PW, use_hardware=False,
                            kdf_n=1 << 14)
            hc.decrypt_file(tmp_hyp, tmp_out, PW)
            with open(tmp_out, "rb") as f:
                self.assertEqual(f.read(), data)
        finally:
            for p in (tmp_in, tmp_hyp, tmp_out):
                if os.path.exists(p):
                    os.remove(p)

    def test_dosya_kurcalama(self):
        tmp_in = os.path.join(self.d, "_test_in2.bin")
        tmp_hyp = os.path.join(self.d, "_test_in2.hyp")
        tmp_out = os.path.join(self.d, "_test_out2.bin")
        try:
            with open(tmp_in, "wb") as f:
                f.write(os.urandom(100_000))
            hc.encrypt_file(tmp_in, tmp_hyp, PW, use_hardware=False,
                            kdf_n=1 << 14)
            with open(tmp_hyp, "r+b") as f:
                f.seek(hc.HEADER_BYTES + 5000)
                b = f.read(1)
                f.seek(hc.HEADER_BYTES + 5000)
                f.write(bytes([b[0] ^ 0xFF]))
            with self.assertRaises(hc.CipherError):
                hc.decrypt_file(tmp_hyp, tmp_out, PW)
        finally:
            for p in (tmp_in, tmp_hyp, tmp_out):
                if os.path.exists(p):
                    os.remove(p)

    def test_bos_dosya_roundtrip(self):
        tmp_in = os.path.join(self.d, "_ef_in.bin")
        tmp_hyp = os.path.join(self.d, "_ef_in.hyp")
        tmp_out = os.path.join(self.d, "_ef_out.bin")
        try:
            open(tmp_in, "wb").close()
            hc.encrypt_file(tmp_in, tmp_hyp, PW, use_hardware=False,
                            kdf_n=1 << 14)
            hc.decrypt_file(tmp_hyp, tmp_out, PW)
            self.assertEqual(os.path.getsize(tmp_out), 0)
        finally:
            for p in (tmp_in, tmp_hyp, tmp_out):
                if os.path.exists(p):
                    os.remove(p)

    def test_multi_chunk_dosya_roundtrip(self):
        tmp_in = os.path.join(self.d, "_mc_in.bin")
        tmp_hyp = os.path.join(self.d, "_mc_in.hyp")
        tmp_out = os.path.join(self.d, "_mc_out.bin")
        try:
            data = os.urandom(3 * hc.CHUNK + 1234)   # 3 MiB'yi asar
            with open(tmp_in, "wb") as f:
                f.write(data)
            hc.encrypt_file(tmp_in, tmp_hyp, PW, use_hardware=False,
                            kdf_n=1 << 14)
            hc.decrypt_file(tmp_hyp, tmp_out, PW)
            with open(tmp_out, "rb") as f:
                self.assertEqual(f.read(), data)
        finally:
            for p in (tmp_in, tmp_hyp, tmp_out):
                if os.path.exists(p):
                    os.remove(p)

    def test_dosya_truncation_reddedilir(self):
        tmp_in = os.path.join(self.d, "_tr_in.bin")
        tmp_hyp = os.path.join(self.d, "_tr_in.hyp")
        tmp_out = os.path.join(self.d, "_tr_out.bin")
        try:
            with open(tmp_in, "wb") as f:
                f.write(os.urandom(200_000))
            hc.encrypt_file(tmp_in, tmp_hyp, PW, use_hardware=False,
                            kdf_n=1 << 14)
            with open(tmp_hyp, "r+b") as f:
                f.truncate(hc.HEADER_BYTES + 50_000)   # ortasindan kes
            with self.assertRaises(hc.CipherError):
                hc.decrypt_file(tmp_hyp, tmp_out, PW)
            self.assertFalse(os.path.exists(tmp_out))
            leftovers = [n for n in os.listdir(self.d) if ".hyp-" in n]
            self.assertFalse(leftovers, f"tmp kalintisi kaldi: {leftovers}")
        finally:
            for p in (tmp_in, tmp_hyp, tmp_out):
                if os.path.exists(p):
                    os.remove(p)

    def test_progress_callback_cagrilir(self):
        tmp_in = os.path.join(self.d, "_pg_in.bin")
        tmp_hyp = os.path.join(self.d, "_pg_in.hyp")
        calls = []
        try:
            with open(tmp_in, "wb") as f:
                f.write(os.urandom(300_000))
            hc.encrypt_file(tmp_in, tmp_hyp, PW, use_hardware=False,
                            kdf_n=1 << 14,
                            progress=lambda d, t: calls.append((d, t)))
            self.assertTrue(calls, "progress hic cagrilmadi")
            self.assertEqual(calls[-1][0], calls[-1][1],
                             "son cagri done == total olmali")
        finally:
            for p in (tmp_in, tmp_hyp):
                if os.path.exists(p):
                    os.remove(p)

    def test_decrypt_file_progress_callback(self):
        """[33] decrypt_file progress callback'i de cagrilmali."""
        tmp_in = os.path.join(self.d, "_dpg_in.bin")
        tmp_hyp = os.path.join(self.d, "_dpg_in.hyp")
        tmp_out = os.path.join(self.d, "_dpg_out.bin")
        calls = []
        try:
            with open(tmp_in, "wb") as f:
                f.write(os.urandom(300_000))
            hc.encrypt_file(tmp_in, tmp_hyp, PW, use_hardware=False,
                            kdf_n=1 << 14)
            hc.decrypt_file(tmp_hyp, tmp_out, PW,
                            progress=lambda d, t: calls.append((d, t)))
            self.assertTrue(calls, "decrypt progress hic cagrilmadi")
            self.assertEqual(calls[-1][0], calls[-1][1],
                             "son cagri done == total olmali")
            with open(tmp_out, "rb") as f:
                with open(tmp_in, "rb") as g:
                    self.assertEqual(f.read(), g.read())
        finally:
            for p in (tmp_in, tmp_hyp, tmp_out):
                if os.path.exists(p):
                    os.remove(p)

    def test_dosya_donanim_bagli_roundtrip(self):
        """[33] use_hardware=True ile dosya API roundtrip."""
        tmp_in = os.path.join(self.d, "_hdw_in.bin")
        tmp_hyp = os.path.join(self.d, "_hdw_in.hyp")
        tmp_out = os.path.join(self.d, "_hdw_out.bin")
        try:
            with open(tmp_in, "wb") as f:
                f.write(os.urandom(150_000))
            hc.encrypt_file(tmp_in, tmp_hyp, PW, use_hardware=True,
                            kdf_n=1 << 14)
            with open(tmp_hyp, "rb") as f:
                h = hc.parse_header(f.read(hc.HEADER_BYTES))
            self.assertTrue(h.flags & hc.FLAG_HARDWARE)
            hc.decrypt_file(tmp_hyp, tmp_out, PW)
            with open(tmp_out, "rb") as f:
                with open(tmp_in, "rb") as g:
                    self.assertEqual(f.read(), g.read())
        finally:
            for p in (tmp_in, tmp_hyp, tmp_out):
                if os.path.exists(p):
                    os.remove(p)

    def test_sondaki_fazlalik_byte_reddedilir(self):
        """[33] Paketin sonuna eklenen fazlalik byte'lar reddedilmeli."""
        enc = hc.encrypt(b"payload", PW, use_hardware=False, kdf_n=1 << 14)
        with self.assertRaises(hc.CipherError):
            hc.decrypt(enc + b"X", PW)

    def test_dosya_self_overwrite_decrypt(self):
        """out == in (--force): fin kapanmadan replace -> Windows'ta
        PermissionError uretmemeli (audit bulgusu WinError 5)."""
        tmp_hyp = os.path.join(self.d, "_so_in.hyp")
        try:
            data = os.urandom(80_000)
            with open(tmp_hyp, "wb") as f:
                f.write(data)
            hc.encrypt_file(tmp_hyp, tmp_hyp, PW, use_hardware=False,
                            kdf_n=1 << 14)   # kendi uzerine
            hc.decrypt_file(tmp_hyp, tmp_hyp, PW)   # kendi uzerine
            with open(tmp_hyp, "rb") as f:
                self.assertEqual(f.read(), data)
        finally:
            if os.path.exists(tmp_hyp):
                os.remove(tmp_hyp)

    def test_tmp_kalintisi_yok_basari(self):
        """Rapor [1]: gecici dosya mkstemp ile guvenli uretilir ve basarili
        islem sonrasi HICBIR .hyp-*.tmp kalintisi kalmaz (deterministik
        .tmp adi + symlink saldirisi yolu kapatildi)."""
        d = tempfile.mkdtemp(prefix="hc_io_")
        try:
            inp = os.path.join(d, "in.bin")
            hyp = os.path.join(d, "out.hyp")
            with open(inp, "wb") as f:
                f.write(os.urandom(50_000))
            hc.encrypt_file(inp, hyp, PW, use_hardware=False,
                            kdf_n=1 << 14)
            hc.decrypt_file(hyp, os.path.join(d, "out.bin"), PW)
            leftovers = [n for n in os.listdir(d) if ".hyp-" in n]
            self.assertEqual(leftovers, [],
                             f"gecici dosya kalintisi: {leftovers}")
            self.assertFalse(os.path.exists(hyp + ".tmp"),
                             "deterministik .tmp adi kullanilmamali")
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_tmp_kalintisi_yok_hata(self):
        """Rapor [1]: kurcalanmis paket decrypt'inde tmp kalintisi KALMAZ."""
        d = tempfile.mkdtemp(prefix="hc_io2_")
        try:
            inp = os.path.join(d, "in.bin")
            hyp = os.path.join(d, "out.hyp")
            with open(inp, "wb") as f:
                f.write(os.urandom(50_000))
            hc.encrypt_file(inp, hyp, PW, use_hardware=False,
                            kdf_n=1 << 14)
            with open(hyp, "r+b") as f:
                f.seek(hc.HEADER_BYTES + 100)
                b = f.read(1)
                f.seek(hc.HEADER_BYTES + 100)
                f.write(bytes([b[0] ^ 0xFF]))
            with self.assertRaises(hc.CipherError):
                hc.decrypt_file(hyp, os.path.join(d, "out.bin"), PW)
            leftovers = [n for n in os.listdir(d) if ".hyp-" in n]
            self.assertEqual(leftovers, [])
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_fifo_cihaz_girdi_reddedilir(self):
        """Rapor [10]: normal dosya olmayan girdi (burada klasor) reddedilir."""
        d = tempfile.mkdtemp(prefix="hc_fifo_")
        try:
            out = os.path.join(d, "out.hyp")
            # Klasor girdisi: open PermissionError veya S_ISREG CipherError
            with self.assertRaises((hc.CipherError, OSError)):
                hc.encrypt_file(d, out, PW, use_hardware=False,
                                kdf_n=1 << 14)
            self.assertFalse(os.path.exists(out))
            self.assertFalse(any(".hyp-" in n for n in os.listdir(d)))
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_dosya_concurrency(self):
        from concurrent.futures import ThreadPoolExecutor
        paths = [(os.path.join(self.d, f"_cc_{i}.bin"),
                  os.path.join(self.d, f"_cc_{i}.hyp"),
                  os.path.join(self.d, f"_cc_{i}.out"))
                 for i in range(8)]
        payloads = [os.urandom(50_000 + i * 7_000) for i in range(8)]
        try:
            for (inp, _, _), d in zip(paths, payloads):
                with open(inp, "wb") as f:
                    f.write(d)

            def work(i):
                inp, hyp, out = paths[i]
                hc.encrypt_file(inp, hyp, PW, use_hardware=False,
                                kdf_n=1 << 14)
                hc.decrypt_file(hyp, out, PW)
                with open(out, "rb") as f:
                    return f.read() == payloads[i]

            with ThreadPoolExecutor(max_workers=8) as ex:
                self.assertTrue(all(ex.map(work, range(8))),
                                "paralel dosya islemlerinden biri bozuldu")
        finally:
            for inp, hyp, out in paths:
                for p in (inp, hyp, out):
                    if os.path.exists(p):
                        os.remove(p)
            # .hyp-* kalintilarini da temizle (atomik yazma deseni)
            for n in os.listdir(self.d):
                if ".hyp-" in n:
                    try:
                        os.remove(os.path.join(self.d, n))
                    except OSError:
                        pass


class TestAPIGuards(unittest.TestCase):
    """Encrypt API parametre validasyonu (audit bulgusu: sessiz bozuk
    format / ZeroDivisionError / crash onleyici)."""

    def test_encrypt_rejects_low_kdf_n(self):
        # 2^14 alti + 2'nin kuvveti olmayan degerler reddedilmeli.
        for bad in (hc.MIN_KDF_N - 1, 1 << 13, 3 << 14, 1 << 21):
            with self.assertRaises(ValueError):
                hc.encrypt(b"x", PW, use_hardware=False, kdf_n=bad)

    def test_encrypt_rejects_high_kdf_n(self):
        with self.assertRaises(ValueError):
            hc.encrypt(b"x", PW, use_hardware=False,
                       kdf_n=hc.MAX_KDF_N << 1)

    def test_encrypt_rejects_non_power_of_two_kdf_n(self):
        with self.assertRaises(ValueError):
            hc.encrypt(b"x", PW, use_hardware=False, kdf_n=(1 << 17) + 1)

    def test_env_kdf_tavanini_daraltir(self):
        # DENETIM 5 bulgu [7]: HYPERCIPHER_MAX_KDF_N servis operatorunun
        # KDF DoS cap'ini daraltmasi (rscrypto Argon2VerifyPolicy deseni).
        # Env yokken MAX gecerli; env daraltilinca eski MAX artik reddedilir.
        d = tempfile.mkdtemp(prefix="hc_envkdf_")
        try:
            # roundtrip gecerli: env yok -> MAX_KDF_N gecerli
            enc = hc.encrypt(b"x", PW, use_hardware=False,
                             kdf_n=hc.MAX_KDF_N)
            self.assertEqual(hc.decrypt(enc, PW), b"x")
            # env daraltilmis -> MAX_KDF_N artik sinir disi
            os.environ["HYPERCIPHER_MAX_KDF_N"] = str(hc.MAX_KDF_N // 2)
            try:
                with self.assertRaises(ValueError):
                    hc.encrypt(b"x", PW, use_hardware=False,
                               kdf_n=hc.MAX_KDF_N)
                # daraltilmis sinir icerisi hala gecerli
                enc2 = hc.encrypt(b"y", PW, use_hardware=False,
                                  kdf_n=hc.MAX_KDF_N // 2)
                self.assertEqual(hc.decrypt(enc2, PW), b"y")
            finally:
                os.environ.pop("HYPERCIPHER_MAX_KDF_N", None)
            # env yokken tekrar gecerli
            enc3 = hc.encrypt(b"z", PW, use_hardware=False,
                              kdf_n=hc.MAX_KDF_N)
            self.assertEqual(hc.decrypt(enc3, PW), b"z")
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_env_kdf_gecersiz_fail_closed(self):
        # DENETIM 5 bulgu [7]: gecersiz env sessizce yok sayilmaz -
        # fail-closed ValueError (operatore acik hata).
        # DENETIM 5 bulgu [9]: MAX_KDF_N'i ASAN degerler de reddedilir
        # (eski KDF_MAX_ENV_CAP=2^19 genisletme yolu kapatildi - env yalnizca
        # daraltabilir; eski cap degeri artik gecersiz).
        for bad in ("abc", "0", "3",
                    str(hc.MAX_KDF_N << 1),      # MAX_KDF_N uzeri -> red
                    str(hc.KDF_MAX_ENV_CAP)):    # eski 512 MiB cap -> artik red
            os.environ["HYPERCIPHER_MAX_KDF_N"] = bad
            try:
                with self.assertRaises(ValueError):
                    hc._effective_max_kdf_n()
            finally:
                os.environ.pop("HYPERCIPHER_MAX_KDF_N", None)

    def test_encrypt_rejects_zero_rotation(self):
        # Onceden ZeroDivisionError ile coker, simdi temiz ValueError.
        with self.assertRaises(ValueError):
            hc.encrypt(b"x", PW, use_hardware=False, rotation_bytes=0)

    def test_encrypt_rejects_low_rotation(self):
        with self.assertRaises(ValueError):
            hc.encrypt(b"x", PW, use_hardware=False, rotation_bytes=63)

    def test_encrypt_rejects_high_rotation(self):
        with self.assertRaises(ValueError):
            hc.encrypt(b"x", PW, use_hardware=False, rotation_bytes=65536)

    def test_encrypt_rejects_bad_salt_length(self):
        with self.assertRaises(ValueError):
            hc._encrypt_deterministic(b"x", PW, use_hardware=False,
                                      salt=b"\x00" * 31, nonce=b"\x00" * 24)

    def test_encrypt_rejects_bad_nonce_length(self):
        with self.assertRaises(ValueError):
            hc._encrypt_deterministic(b"x", PW, use_hardware=False,
                                      salt=b"\x00" * 32, nonce=b"\x00" * 23)

    def test_encrypt_file_rejects_bad_rotation(self):
        with self.assertRaises(ValueError):
            hc.encrypt_file("_yok.bin", "_yok.hyp", PW, rotation_bytes=0)

    def test_rotation_edges_roundtrip(self):
        # Zafiyet raporu [17]: rotation 64'un kati olmali (keystream 64-byte
        # blok siniri) - 64, 128, 65472 gecerlidir.
        for rot in (64, 128, 65472):
            data = os.urandom(5000)
            enc = hc.encrypt(data, PW, use_hardware=False,
                             rotation_bytes=rot, kdf_n=1 << 14)
            h = hc.parse_header(enc[:hc.HEADER_BYTES])
            self.assertEqual(h.rotation_bytes, rot)
            self.assertEqual(hc.decrypt(enc, PW), data)

    def test_encrypt_rejects_non_multiple_rotation(self):
        # 65, 65535: 64'un kati degil -> sessiz takvim kaymasi yerine red.
        for rot in (65, 100, 65535):
            with self.assertRaises(ValueError):
                hc.encrypt(b"x", PW, use_hardware=False, rotation_bytes=rot)

    def test_parse_header_rejects_non_multiple_rotation(self):
        enc = bytearray(hc.encrypt(b"x", PW, use_hardware=False,
                                   kdf_n=1 << 14))
        enc[2:4] = struct.pack("<H", 65)   # kurcalanmis: 64'un kati degil
        with self.assertRaises(hc.CipherError):
            hc.decrypt(bytes(enc), PW)

    def test_parse_header_rejects_reserved_flags(self):
        # Zafiyet raporu [16]: tanimsiz flag bitleri fail-open olmasin.
        # DENETIM 5 bulgu [12]: eski test 0b0000_0010 (bit1) kullaniyordu -
        # o bit FLAG_PADDED, rezevre DEGIL! Gercek rezevre bitler bit3+
        # (bit0..2: HARDWARE/PADDED/KEYFILE). Hem bit3 hem bit7 test edilir.
        enc = hc.encrypt(b"x", PW, use_hardware=False, kdf_n=1 << 14)
        for reserved in (0b0000_1000, 0b1000_0000):
            t = bytearray(enc)
            t[1] |= reserved
            with self.assertRaises(hc.CipherError):
                hc.decrypt(bytes(t), PW)

    def test_parse_header_rejects_suspicious_kdf_n(self):
        # Zafiyet raporu [14]: sinir disi / 2'nin kuvveti olmayan kdf_n,
        # KDF CALISTIRMADAN reddedilmeli (amplifikasyon DoS karsi).
        enc = hc.encrypt(b"x", PW, use_hardware=False, kdf_n=1 << 14)
        for bad in (1 << 13, (1 << 17) + 1, 1 << 21, 0xFFFFFFFF):
            t = bytearray(enc)
            struct.pack_into("<I", t, 4, bad)
            with self.assertRaises(hc.CipherError):
                hc.decrypt(bytes(t), PW)

    def test_decrypt_rejects_suspicious_rotation(self):
        # 1..63 araliginda rotation header'a gomulemez (encrypt reddeder) -
        # boyle paket kurcalanmis/yabanci olmalidir.
        enc = bytearray(hc.encrypt(b"x", PW, use_hardware=False,
                                   kdf_n=1 << 14))
        enc[2:4] = struct.pack("<H", 32)
        with self.assertRaises(hc.CipherError):
            hc.decrypt(bytes(enc), PW)

    def test_fp_mismatch_rejected(self):
        # Portable paketi donanim-bagli gibi goster (bayrak + bozuk fp_hash)
        enc = bytearray(hc.encrypt(b"x", PW, use_hardware=False,
                                   kdf_n=1 << 14))
        enc[1] |= hc.FLAG_HARDWARE
        enc[64:96] = b"\xAA" * 32   # fp_hash 64:96 ofsetinde
        with self.assertRaises(hc.CipherError):
            hc.decrypt(bytes(enc), PW)


class TestPadding(unittest.TestCase):
    """Zafiyet raporu [18]: opsiyonel ISO 7816-4 padding ile plaintext
    boyutu ciphertext'ten ifsa edilmez."""

    def test_pad_to_roundtrip(self):
        for n in (0, 1, 15, 16, 100, 1023, 1024, 4096):
            data = os.urandom(n)
            for pad in (16, 64, 256):
                enc = hc.encrypt(data, PW, use_hardware=False,
                                 kdf_n=1 << 14, pad_to=pad)
                body = enc[hc.HEADER_BYTES:-hc.TAG_BYTES]
                self.assertEqual(len(body) % pad, 0,
                                 f"n={n} pad={pad}: boyut kati degil")
                self.assertEqual(hc.decrypt(enc, PW), data)

    def test_padding_flag_headerda(self):
        enc = hc.encrypt(b"x", PW, use_hardware=False,
                         kdf_n=1 << 14, pad_to=64)
        h = hc.parse_header(enc[:hc.HEADER_BYTES])
        self.assertTrue(h.flags & hc.FLAG_PADDED)
        # padding'siz pakette bayrak YOK
        enc2 = hc.encrypt(b"x", PW, use_hardware=False, kdf_n=1 << 14)
        h2 = hc.parse_header(enc2[:hc.HEADER_BYTES])
        self.assertFalse(h2.flags & hc.FLAG_PADDED)

    def test_pad_to_sinir_disidir(self):
        for bad in (0, 1, 15, 65537):
            with self.assertRaises(ValueError):
                hc.encrypt(b"x", PW, use_hardware=False, kdf_n=1 << 14,
                           pad_to=bad)

    def test_0x80_ile_biten_veri(self):
        # ISO 7816-4: plaintext 0x80 ile bitse bile padding dogru kaldirilir
        # (padding her zaman en az 1 byte: 0x80 + 0x00*).
        data = b"sonu 0x80 ile biten\x80"
        for pad in (16, 64):
            enc = hc.encrypt(data, PW, use_hardware=False,
                             kdf_n=1 << 14, pad_to=pad)
            self.assertEqual(hc.decrypt(enc, PW), data)

    def test_dosya_pad_to_roundtrip(self):
        d = tempfile.mkdtemp(prefix="hc_pad_")
        try:
            for n, pad in ((0, 64), (100, 16), (300_000, 256)):
                inp, hyp, out = (os.path.join(d, f"i{n}"),
                                 os.path.join(d, f"i{n}.hyp"),
                                 os.path.join(d, f"o{n}"))
                data = os.urandom(n)
                with open(inp, "wb") as f:
                    f.write(data)
                hc.encrypt_file(inp, hyp, PW, use_hardware=False,
                                kdf_n=1 << 14, pad_to=pad)
                # Header(104) + tag(64) sabit; ciphertext GÖVDESI pad'in
                # kati olmali (dosyanin tamami degil).
                body_len = os.path.getsize(hyp) - hc.HEADER_BYTES - hc.TAG_BYTES
                self.assertEqual(body_len % pad, 0,
                                 f"n={n} pad={pad}: gövde boyutu kati degil")
                hc.decrypt_file(hyp, out, PW)
                with open(out, "rb") as f:
                    self.assertEqual(f.read(), data, f"n={n} pad={pad}")
        finally:
            shutil.rmtree(d, ignore_errors=True)


class TestRAMHijyeni(unittest.TestCase):
    def test_wipe_sifirlar(self):
        buf = bytearray(b"gizli-anahtar-materyali-256bit")
        hc.wipe(buf)
        self.assertEqual(buf, bytearray(len(buf)))

    def test_pw_bytes_bytearray_ve_wipe(self):
        # DENETIM 5 bulgu [8]: pw_bytes immutable bytes DEGIL bytearray
        # olmali - boylece wipe(material) passphrase kopyasini da temizler
        # (keyfile=None dalinda material AYNI buffer'dir).
        hc._derive_master("gizli-passphrase-123", b"fp",
                          b"salt-salt-salt-salt", 1 << 14)
        # master uretildi - hata olmadi demektir; wipe semantigi asagida:
        pw_bytes = bytearray("gizli-passphrase-123".encode("utf-8"))
        material = pw_bytes
        material.append(0)
        hc.wipe(material)
        # material == pw_bytes ayni nesne -> ikisi de sifirlanmis olmali
        self.assertEqual(pw_bytes, bytearray(len(pw_bytes)))


class TestKeyfile(unittest.TestCase):
    """v5: ikinci faktor (keyfile) katmani - age/sympa HKDF modeli."""

    KF = bytes(range(64))          # deterministik keyfile (>= 32 byte)

    def test_roundtrip_keyfile_ile(self):
        data = os.urandom(5000)
        enc = hc.encrypt(data, PW, use_hardware=False, kdf_n=1 << 14,
                         keyfile=self.KF)
        self.assertEqual(hc.decrypt(enc, PW, keyfile=self.KF), data)

    def test_flag_headerda_set(self):
        enc = hc.encrypt(b"x", PW, use_hardware=False, kdf_n=1 << 14,
                         keyfile=self.KF)
        h = hc.parse_header(enc[:hc.HEADER_BYTES])
        self.assertTrue(h.flags & hc.FLAG_KEYFILE)

    def test_flag_yoksa_set_degil(self):
        enc = hc.encrypt(b"x", PW, use_hardware=False, kdf_n=1 << 14)
        h = hc.parse_header(enc[:hc.HEADER_BYTES])
        self.assertFalse(h.flags & hc.FLAG_KEYFILE)

    def test_keyfile_siz_acilamaz(self):
        enc = hc.encrypt(b"gizli", PW, use_hardware=False, kdf_n=1 << 14,
                         keyfile=self.KF)
        with self.assertRaises(hc.CipherError):
            hc.decrypt(enc, PW)

    def test_yanlis_keyfile_acilamaz(self):
        enc = hc.encrypt(b"gizli", PW, use_hardware=False, kdf_n=1 << 14,
                         keyfile=self.KF)
        with self.assertRaises(hc.CipherError):
            hc.decrypt(enc, PW, keyfile=bytes(range(64, 128)))

    def test_keyfile_farkli_ise_farkli_cikti(self):
        data = b"ayni veri"
        a = hc._encrypt_deterministic(data, PW, use_hardware=False,
                                      salt=b"\x01" * 32, nonce=b"\x02" * 24,
                                      kdf_n=1 << 14, keyfile=self.KF)
        b = hc._encrypt_deterministic(data, PW, use_hardware=False,
                                      salt=b"\x01" * 32, nonce=b"\x02" * 24,
                                      kdf_n=1 << 14,
                                      keyfile=bytes(range(128, 192)))
        self.assertNotEqual(a, b)

    def test_kisa_keyfile_reddedilir(self):
        for bad in (b"", b"kisa", b"\x00" * 31):
            with self.assertRaises(ValueError):
                hc.encrypt(b"x", PW, use_hardware=False, kdf_n=1 << 14,
                           keyfile=bad)

    def test_generate_ve_read_keyfile(self):
        d = tempfile.mkdtemp(prefix="hc_kf_")
        try:
            path = os.path.join(d, "anahtar.key")
            hc.generate_keyfile(path)
            self.assertEqual(os.path.getsize(path),
                             hc.KEYFILE_RECOMMENDED_BYTES)
            kf = hc.read_keyfile(path)
            self.assertEqual(len(kf), hc.KEYFILE_RECOMMENDED_BYTES)
            # roundtrip okumayla
            enc = hc.encrypt(b"disk keyfile", PW, use_hardware=False,
                             kdf_n=1 << 14, keyfile=kf)
            self.assertEqual(hc.decrypt(enc, PW, keyfile=kf), b"disk keyfile")
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_read_keyfile_cok_buyuk_reddedilir(self):
        # DENETIM 5 bulgu [6]: okuma aninda tavan - dev dosya once
        # TAMAMEN belleğe cekilmeden reddedilmeli.
        d = tempfile.mkdtemp(prefix="hc_kfbig_")
        try:
            path = os.path.join(d, "dev.key")
            with open(path, "wb") as f:
                f.write(b"\x00" * (hc.KEYFILE_MAX_BYTES + 1))
            with self.assertRaises(ValueError):
                hc.read_keyfile(path)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_generate_keyfile_ustune_yazmaz(self):
        d = tempfile.mkdtemp(prefix="hc_kf2_")
        try:
            path = os.path.join(d, "var.key")
            with open(path, "wb") as f:
                f.write(b"mevcut")
            with self.assertRaises(ValueError):
                hc.generate_keyfile(path)
            with open(path, "rb") as f:
                self.assertEqual(f.read(), b"mevcut")  # icerik degismedi
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_read_keyfile_symlink_reddedilir(self):
        # DENETIM 5 bulgu [15]/[16]: O_NOFOLLOW ile son bilesen symlink ise
        # reddedilir (symlink swap -> baska dosya okuma penceresi kapanir).
        # Windows'ta symlink cozumlemek icin ayricalik gerekir -> atla.
        if os.name == "nt" or not hasattr(os, "symlink"):
            self.skipTest("sadece POSIX")
        d = tempfile.mkdtemp(prefix="hc_kfsym_")
        try:
            hedef = os.path.join(d, "hedef.key")
            with open(hedef, "wb") as f:
                f.write(os.urandom(hc.KEYFILE_RECOMMENDED_BYTES))
            os.chmod(hedef, 0o600)
            baglanti = os.path.join(d, "baglanti.key")
            os.symlink(hedef, baglanti)
            with self.assertRaises(ValueError):
                hc.read_keyfile(baglanti)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_read_keyfile_mode_077_reddedilir(self):
        # DENETIM 5 bulgu [16]: mode dogrulamasi ACILMIS fd uzerinden
        # (fstat) - stat+open arasi degistirme senaryosunda bile okunan
        # dosyanin kendisi kontrol edilir.
        if os.name == "nt":
            self.skipTest("POSIX mode - Windows'ta DACL kontrolu gecerli")
        d = tempfile.mkdtemp(prefix="hc_kfmode_")
        try:
            path = os.path.join(d, "herkese.key")
            with open(path, "wb") as f:
                f.write(os.urandom(hc.KEYFILE_RECOMMENDED_BYTES))
            os.chmod(path, 0o644)   # diger kullanicilar okur
            with self.assertRaises(ValueError):
                hc.read_keyfile(path)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_dosya_api_keyfile_roundtrip(self):
        d = tempfile.mkdtemp(prefix="hc_kf3_")
        try:
            inp = os.path.join(d, "in.bin")
            hyp = os.path.join(d, "in.hyp")
            out = os.path.join(d, "out.bin")
            data = os.urandom(100_000)
            with open(inp, "wb") as f:
                f.write(data)
            hc.encrypt_file(inp, hyp, PW, use_hardware=False,
                            kdf_n=1 << 14, keyfile=self.KF)
            with open(hyp, "rb") as f:
                h = hc.parse_header(f.read(hc.HEADER_BYTES))
            self.assertTrue(h.flags & hc.FLAG_KEYFILE)
            with self.assertRaises(hc.CipherError):
                hc.decrypt_file(hyp, out, PW)   # keyfile'siz -> red
            hc.decrypt_file(hyp, out, PW, keyfile=self.KF)
            with open(out, "rb") as f:
                self.assertEqual(f.read(), data)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_keyfile_hardware_birlikte(self):
        # DENETIM 5 kapsam: keyfile + donanim bagli ayni pakette (iki faktor
        # + makine) - flag bitleri OR'lu. Decrypt header'dan use_hw okur ve
        # AYNI makinede fingerprint otomatik eslesir -> keyfile ile acilir,
        # keyfile'siz reddedilir (makine kontrolu zaten ayni makinede dogal
        # olarak gecer; farkli makine senaryosu bu makinede test edilemez).
        data = os.urandom(3000)
        enc = hc.encrypt(data, PW, use_hardware=True, kdf_n=1 << 14,
                         keyfile=self.KF)
        h = hc.parse_header(enc[:hc.HEADER_BYTES])
        self.assertTrue(h.flags & hc.FLAG_KEYFILE)
        self.assertTrue(h.flags & hc.FLAG_HARDWARE)
        # keyfile'siz -> red (keyfile zorunlu)
        with self.assertRaises(hc.CipherError):
            hc.decrypt(enc, PW)
        # keyfile ile -> basari (ayni makine: hardware eslesir)
        self.assertEqual(hc.decrypt(enc, PW, keyfile=self.KF), data)

    def test_keyfile_pad_to_birlikte(self):
        # DENETIM 5 kapsam: keyfile + ISO 7816-4 padding kombinasyonu -
        # paket acilir ve padding dogru kaldirilir.
        data = os.urandom(4096)
        enc = hc.encrypt(data, PW, use_hardware=False, kdf_n=1 << 14,
                         keyfile=self.KF, pad_to=512)
        self.assertEqual(hc.decrypt(enc, PW, keyfile=self.KF), data)

    def test_keyfile_bytes_kabul(self):
        # DENETIM 5 kapsam: keyfile API sozlesmesi bytes'tir (tip imzasi
        # `keyfile: bytes | None`). Bytearray pyright'ta bytes'a zorlanmaz
        # -> test bytes girisinin hem bytes hem callback akisi boyunca
        # degismeden tasidigini dogrular (hesaplama icinde kopya yok).
        kf = bytes(range(64))
        enc = hc.encrypt(b"bytes keyfile", PW, use_hardware=False,
                         kdf_n=1 << 14, keyfile=kf)
        self.assertEqual(hc.decrypt(enc, PW, keyfile=kf), b"bytes keyfile")

    def test_generate_keyfile_uzunluk_sinirlari(self):
        # DENETIM 5 kapsam: generate_keyfile boyut dogrulamasi - [32..MAX]
        # disinda ValueError (dosya YARATILMAMALI).
        d = tempfile.mkdtemp(prefix="hc_kflen_")
        try:
            for bad in (0, 16, 31, hc.KEYFILE_MAX_BYTES + 1, -1):
                p = os.path.join(d, f"len_{bad}.key")
                with self.assertRaises(ValueError, msg=f"len={bad}"):
                    hc.generate_keyfile(p, length=bad)
                self.assertFalse(os.path.exists(p), f"len={bad} dosya olustu!")
            # sinirda: 32 ve MAX gecerli
            lo = os.path.join(d, "lo.key")
            hi = os.path.join(d, "hi.key")
            hc.generate_keyfile(lo, length=32)
            hc.generate_keyfile(hi, length=hc.KEYFILE_MAX_BYTES)
            self.assertEqual(os.path.getsize(lo), 32)
            self.assertEqual(os.path.getsize(hi), hc.KEYFILE_MAX_BYTES)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_read_keyfile_yok_hata(self):
        # DENETIM 5 kapsam: olmayan keyfile -> ValueError (FileNotFoundError
        # perdelemek yerine tutarli hata tipi).
        d = tempfile.mkdtemp(prefix="hc_kfnen_")
        try:
            with self.assertRaises(ValueError):
                hc.read_keyfile(os.path.join(d, "yok.key"))
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_generate_keyfile_dizin_yok_olusturur(self):
        # DENETIM 5 kapsam: ust dizin yoksa generate_keyfile makedirs ile
        # olusturup yine calismali (kullanim rahatligi, guvenlik kaybi yok -
        # dosyanin kendisi O_EXCL + kisiye ozel ACL ile yaratilir).
        d = tempfile.mkdtemp(prefix="hc_kfdir_")
        try:
            yol = os.path.join(d, "alt", "icin", "anahtar.key")
            hc.generate_keyfile(yol)
            self.assertEqual(os.path.getsize(yol),
                             hc.KEYFILE_RECOMMENDED_BYTES)
            kf = hc.read_keyfile(yol)
            self.assertEqual(len(kf), hc.KEYFILE_RECOMMENDED_BYTES)
        finally:
            shutil.rmtree(d, ignore_errors=True)


class TestPassphraseStrength(unittest.TestCase):
    """v5: zxcvbn esikli passphrase gucluk kontrolu."""

    def test_guclu_gecer(self):
        for pw in ("professional-test-passphrase-2048",
                   "golden-passphrase-2026",
                   "cli-subprocess-passphrase-42",
                   "kisrak-mercan-dolap-havlu-cinar-serif"):
            g, _ = hc.check_passphrase_strength(pw)
            self.assertGreaterEqual(g, hc.PASSPHRASE_MIN_GUESSES_LOG10,
                                    f"{pw}: esigin altinda ({g:.1f})")

    def test_zayif_reddedilir(self):
        for pw in ("ankara1234", "abc12345", "123456", "password",
                   "sifre-123"):
            g, _ = hc.check_passphrase_strength(pw)
            self.assertLess(g, hc.PASSPHRASE_MIN_GUESSES_LOG10,
                            f"{pw}: esigin ustunde ({g:.1f})")

    def test_assert_strong_zayifta_hata(self):
        with self.assertRaises(ValueError):
            hc.assert_strong_passphrase("ankara1234")
        hc.assert_strong_passphrase("professional-test-passphrase-2048")

    def test_bos_passphrase_sifir(self):
        g, _ = hc.check_passphrase_strength("")
        self.assertEqual(g, 0.0)

    def test_builtin_fallback_sozluk_cezasi(self):
        # DENETIM 5 bulgu [5]: fallback Shannon tahmini sozluk kelimelerini
        # gormuyordu (myDogIsBlue fallback 18.88 PASS vs zxcvbn 10.02 RED).
        # Fallback zorlanir; sozluk kelimesi gecen passphrase 6.0'a iner.
        real_zxcvbn = hc._zxcvbn
        hc._zxcvbn = None
        try:
            g, fb = hc.check_passphrase_strength("myDogIsBlue")
            self.assertLessEqual(g, 6.0, f"sozluk cezasi yok: {g} ({fb})")
            self.assertIn("sozluk", fb)
        finally:
            hc._zxcvbn = real_zxcvbn

    def test_builtin_fallback_yil_cezasi(self):
        real_zxcvbn = hc._zxcvbn
        hc._zxcvbn = None
        try:
            g, fb = hc.check_passphrase_strength("gizliKelime2026")
            self.assertLessEqual(g, 8.0, f"yil cezasi yok: {g} ({fb})")
        finally:
            hc._zxcvbn = real_zxcvbn

    def test_builtin_fallback_rastgele_guclu_kalir(self):
        # Gercek rastgele uzun passphrase fallback'te de gecmeli (yanlis
        # negatif yok - sozluk kelimesi icermeyen Shannon tahmini korunur).
        real_zxcvbn = hc._zxcvbn
        hc._zxcvbn = None
        try:
            g, _ = hc.check_passphrase_strength("M7#v9Kx2!pQ5@zL4")
            self.assertGreaterEqual(g, hc.PASSPHRASE_MIN_GUESSES_LOG10)
        finally:
            hc._zxcvbn = real_zxcvbn


class TestV57Bulgu1(unittest.TestCase):
    """V5.7 BULGU-1 fix kilidi: cift-pencere zxcvbn.

    Once: 73+ karakterli perde -> zxcvbn ValueError -> CLI decrypt exit 1
    (kutuphane ayni paketi acarken). NIST 800-63B 5.1.1.2 "SHOULD permit
    at least 64 characters": uzun perdeyi reddetmek politika DISI.
    Fix: degerlendirme cift-pencere (ilk+son 72 codepoint); KDF girdisi
    tam uzunluk. Kaynak research: zxcvbn-python f54add5 + README DoS uyarisi,
    dropbox/zxcvbn#194 (resmi truncate onerisi), zulip/zulip#34146.
    """

    def test_uzun_passphrase_degerlendirilebilir(self):
        # 73+ karakter artik ValueError atmaz (NIST >=64 izni).
        for n in (73, 80, 100, 512, 1024):
            pw = ("kisrak-mercan-dolap-havlu-cinar-serif-kayak-mango-"
                  "balon-kule-7K2#aZ" * 40)[:n]
            g, _ = hc.check_passphrase_strength(pw)
            self.assertGreaterEqual(
                g, hc.PASSPHRASE_MIN_GUESSES_LOG10,
                f"uzun guclu perde {n} karakterde zayif sanildi: {g:.1f}")

    def test_uzun_ama_desenli_passphrase_zayif(self):
        # Cift pencerenin amaci: >72'ye tasan TEKRAR desenleri her iki
        # pencerede de gorunur -> zxcvbn'in zayif saydigi uzun desenler
        # red edilir. Not: "abcdefghij"*12 gibi alfabe dizisi repeat'i
        # zxcvbn taban token'i bruteforce (26^10) sayar -> 10^15 guclu
        # cikar; o zxcvbn skorlama ozelligidir, pencereleme kusuru degil.
        for pw in ("a" * 120,                 # tek karakter tekrari
                   "password" * 15,           # sozluk kelimesi tekrari
                   "1234567890" * 12,         # rakam dizisi tekrari
                   "kisrak" * 20):            # kisa kelime tekrari
            g, fb = hc.check_passphrase_strength(pw)
            self.assertLess(
                g, hc.PASSPHRASE_MIN_GUESSES_LOG10,
                f"desenli uzun perde guclu sanildi ({g:.1f}): {fb}")

    def test_kdf_girdisi_tam_uzunluk(self):
        # NIST 800-63B "Truncation of the secret SHALL NOT be performed":
        # 80 karakterli perde ILE sifrelenen paket ayni perde ile acilir
        # (Argon2id tam uzunluk girdiyi kullanir; pencereleme yalnizca
        # degerlendirme icindir).
        pw = ("kisrak-mercan-dolap-havlu-cinar-serif-kayak-mango-"
              "balon-kule-7K2#aZ" * 4)[:80]
        enc = hc.encrypt(b"v5.7 tam uzunluk kaniti", pw,
                         use_hardware=False, kdf_n=1 << 14)
        self.assertEqual(hc.decrypt(enc, pw), b"v5.7 tam uzunluk kaniti")

    def test_zayif_prefix_guclu_suffix(self):
        # Adil degerlendirme: zayif baslangic + rastgele 40+ karakter
        # guclu pencere olusturur (min() yanlis pozitif uretmez).
        pw = "ankara1234-" + "K7#v9mQ2!pZ5@xL4" * 3
        g, _ = hc.check_passphrase_strength(pw)
        self.assertGreaterEqual(g, hc.PASSPHRASE_MIN_GUESSES_LOG10,
                                f"guclu-suffix perde zayif sanildi: {g:.1f}")


class TestDiceware(unittest.TestCase):
    """v5: Diceware perde ureteci (EFF 7776 kelime)."""

    def test_varsayilan_6_kelime(self):
        pw = hc.generate_passphrase()
        parts = pw.split("-")
        self.assertEqual(len(parts), 6)
        words = hc._load_diceware_words()
        for w in parts:
            self.assertIn(w, words, f"wordlist disinda: {w}")

    def test_kelime_sayisi(self):
        self.assertEqual(len(hc.generate_passphrase(5).split("-")), 5)
        self.assertEqual(len(hc.generate_passphrase(7).split("-")), 7)

    def test_gucluluk_esigini_gecer(self):
        for n in (5, 6, 7):
            pw = hc.generate_passphrase(n)
            g, _ = hc.check_passphrase_strength(pw)
            self.assertGreaterEqual(g, hc.PASSPHRASE_MIN_GUESSES_LOG10,
                                    f"{n} kelime zayif: {g:.1f}")

    def test_rastgele_tekrar_etmez(self):
        a = hc.generate_passphrase(6)
        b = hc.generate_passphrase(6)
        self.assertNotEqual(a, b)   # CSPRNG -> pratikte cakisamaz

    def test_sinir_disisi(self):
        for n in (2, 21):
            with self.assertRaises(ValueError):
                hc.generate_passphrase(n)

    def test_wordlist_boyutu(self):
        words = hc._load_diceware_words()
        self.assertGreaterEqual(len(words), 7776,
                                f"EFF wordlist eksik: {len(words)}")

    def test_wordlist_yoksa_fail_closed(self):
        # DENETIM 5 bulgu [4]: builtin zayif yedek liste KALDIRILDI.
        # Wordlist dosyasi yoksa sessizce zayif (39.8 bit) uretilmez -
        # ValueError firlatilir (fail-closed).
        orig = hc._DICEWARE_WORDS
        hc._DICEWARE_WORDS = None
        try:
            with mock.patch("builtins.open",
                            side_effect=FileNotFoundError(
                                "diceware_words.txt yok")):
                with self.assertRaises(ValueError):
                    hc._load_diceware_words()
        finally:
            hc._DICEWARE_WORDS = orig


class TestV4Fixler(unittest.TestCase):
    """V4 zafiyet raporu fix'leri: 1 (desen tespiti + fail-closed),
    3 (keyfile flagsiz hata), 6 (entropi), 7 (HKDF cap), 4 (tek kaynak)."""

    # ---- F1: builtin fallback desen cezalari ----
    def test_fallback_ardisik_dizi_cezasi(self):
        # "abcdefghijklmnop" Shannon'da 10^22 GECER ama aslinda cok zayif
        # (ardisik alfabe). Fallback bunu yakalamali (zxcvbn sequence matcher).
        real = hc._zxcvbn
        hc._zxcvbn = None
        try:
            g, fb = hc.check_passphrase_strength("abcdefghijklmnop")
            self.assertLessEqual(g, 8.0, f"ardisik dizi cezasi yok: {g} ({fb})")
        finally:
            hc._zxcvbn = real

    def test_fallback_tekrar_cezasi(self):
        real = hc._zxcvbn
        hc._zxcvbn = None
        try:
            g1, _ = hc.check_passphrase_strength("aaaaaaaaaaaaaaaa")
            self.assertLessEqual(g1, 6.0, f"tekrar cezasi yok: {g1}")
            g2, _ = hc.check_passphrase_strength("abababababababab")
            self.assertLessEqual(g2, 8.0, f"dongu deseni cezasi yok: {g2}")
        finally:
            hc._zxcvbn = real

    def test_fallback_klavye_cezasi(self):
        real = hc._zxcvbn
        hc._zxcvbn = None
        try:
            g, fb = hc.check_passphrase_strength("asdfghjkl1234")
            self.assertLessEqual(g, 8.0, f"klavye satiri cezasi yok: {g} ({fb})")
        finally:
            hc._zxcvbn = real

    def test_assert_strong_zxcvbn_yoksa_fail_closed(self):
        # EN GÜCLÜ FIX: zxcvbn kurulu degilse builtin tahmine GUVENILMEZ -
        # fallback guclu tahmin etse bile assert_strong REDDEDER. Zayif
        # perdeyle sifreleme yalnizca --allow-weak (bilincli risk kabulu).
        real = hc._zxcvbn
        hc._zxcvbn = None
        try:
            with self.assertRaises(ValueError):
                hc.assert_strong_passphrase("M7#v9Kx2!pQ5@zL4")
        finally:
            hc._zxcvbn = real

    def test_assert_strong_zxcvbn_varsa_guclu_gecer(self):
        # zxcvbn kurulu ortamda guclu perde reddedilmez (normal akis).
        hc.assert_strong_passphrase("professional-test-passphrase-2048")

    # ---- F7: HKDF cikti siniri (RFC 5869 tek oktet counter) ----
    def test_hkdf_cikti_siniri(self):
        out = hc._hkdf(b"ikm", b"salt", b"info", 16320)
        self.assertEqual(len(out), 16320)
        with self.assertRaises(ValueError):
            hc._hkdf(b"ikm", b"salt", b"info", 16321)

    # ---- F6: keyfile entropi sanity ----
    def test_keyfile_entropi_dusuk_reddedilir(self):
        for bad in (b"\x00" * 32, b"A" * 32, (b"abc" * 20)[:64],
                    b"\x01\x02\x03\x04" * 16):
            with self.assertRaises(ValueError, msg=f"entropisiz: {bad[:8]!r}..."):
                hc._validate_keyfile(bad)

    def test_keyfile_entropi_yuksek_gecer(self):
        hc._validate_keyfile(bytes(range(64)))     # deterministik ama cesitli
        hc._validate_keyfile(b"disk keyfile" * 4)  # gercek dunya metin keyfile

    # ---- F3: keyfile verildi ama paket korumasiz -> hata (sessiz yoksayma) ----
    def test_decrypt_keyfile_flagsiz_hata(self):
        enc = hc.encrypt(b"gizli", PW, use_hardware=False, kdf_n=1 << 14)
        with self.assertRaises(hc.CipherError):
            hc.decrypt(enc, PW, keyfile=bytes(range(64)))

    def test_decrypt_file_keyfile_flagsiz_hata(self):
        d = tempfile.mkdtemp(prefix="hc_f3_")
        try:
            src = os.path.join(d, "g.dat")
            with open(src, "wb") as f:
                f.write(b"gizli")
            hyp = os.path.join(d, "g.hyp")
            hc.encrypt_file(src, hyp, PW, use_hardware=False, kdf_n=1 << 14)
            out = os.path.join(d, "out")
            with self.assertRaises(hc.CipherError):
                hc.decrypt_file(hyp, out, PW, keyfile=bytes(range(64)))
            self.assertFalse(os.path.exists(out))
        finally:
            shutil.rmtree(d, ignore_errors=True)

    # ---- F4: fingerprint_digest tek kaynak (header ile tutarli) ----
    def test_fingerprint_digest_tek_kaynak(self):
        enc = hc.encrypt(b"x", PW, use_hardware=True, kdf_n=1 << 14)
        h = hc.parse_header(enc[:hc.HEADER_BYTES])
        fp = hc.collect_hardware_fingerprint()
        self.assertEqual(h.fp_hash, hc.fingerprint_digest(fp, h.salt))
        # parametresiz cagri (test/demo uyumlulugu) hala calisir
        self.assertEqual(hc.fingerprint_digest(),
                         hashlib.sha256(fp).digest())


class TestV5Guards(unittest.TestCase):
    """V5.3 zafiyet fixleri (zafiyet raporu [1] DUSUK + ayrac tekliligi).

    Fix 1: deterministic API fail-closed. _encrypt_deterministic ve
    _encrypt_file_deterministic yalnizca _DETERMINISTIC_MODE=True iken
    calisabilir (test/conftest opt-in). Public API'den salt/nonce kaldirildigi
    icin kullanici nonce reuse'a dusemez; kalan tek nonce-reuse yolu bu ic
    API'nin import edilmesiydi -> artik RuntimeError.
    Fix 2: fp_blob NUL byte iceremez -> material.append(0) ayraci
    kanitlanabilir tekil (pw\\x00fp encoding'i injective).
    """

    def test_deterministic_guard_kapaliyken_runtimeerror(self):
        # Bayragi kaydet/geri yukle: conftest veya dosya basi True yapar,
        # guard'in kendisini izole test ederiz.
        saved = getattr(hc, "_DETERMINISTIC_MODE", False)
        hc._DETERMINISTIC_MODE = False
        try:
            with self.assertRaises(RuntimeError):
                hc._encrypt_deterministic(
                    b"x", PW, use_hardware=False,
                    salt=b"\x11" * 32, nonce=b"\x22" * 24, kdf_n=1 << 14)
        finally:
            hc._DETERMINISTIC_MODE = saved

    def test_deterministic_file_guard_kapaliyken_runtimeerror(self):
        saved = getattr(hc, "_DETERMINISTIC_MODE", False)
        hc._DETERMINISTIC_MODE = False
        d = tempfile.mkdtemp(prefix="hc_g1_")
        try:
            src = os.path.join(d, "s.bin")
            with open(src, "wb") as f:
                f.write(b"x")
            out = os.path.join(d, "o.bin")
            try:
                with self.assertRaises(RuntimeError):
                    hc._encrypt_file_deterministic(
                        src, out, PW, use_hardware=False,
                        salt=b"\x11" * 32, nonce=b"\x22" * 24, kdf_n=1 << 14)
                self.assertFalse(os.path.exists(out))
            finally:
                shutil.rmtree(d, ignore_errors=True)
        finally:
            hc._DETERMINISTIC_MODE = saved

    def test_fp_nul_byte_reddedilir(self):
        # Ayrac (material.append(0)) tekliligi: fp_blob NUL icerirse
        # KDF girdisi belirsizlesir -> ValueError (fail-closed).
        with self.assertRaises(ValueError):
            hc._derive_master(PW, b"mguid:x\x00vol:y", b"\x01" * 32, 1 << 14)


class TestV54Fixler(unittest.TestCase):
    """V5.4 solo denetim fix'leri (BULGU 11-15).

    B11: Windows ACL allowlist (spesifik kullanici READ ACE + write-only
         ACE artik yakalanir; yalnizca {sahip, SYSTEM, Administrators,
         OWNER RIGHTS} tolere edilir).
    B12: diceware wordlist benzersizlik (tekrar -> fail-closed ValueError).
    B13: generate_keyfile ebeveyn dizin mode=0o700 (POSIX).
    B14: _guard_output yas/sahiplik filtresi (test_hcli.py'de).
    B15: _open_private_file_read O_NONBLOCK + S_ISREG (FIFO hang yok).
    """

    # ---- BULGU 12: diceware benzersizlik ----
    def test_wordlist_tekrarlayan_kelime_reddedilir(self):
        orig = hc._DICEWARE_WORDS
        hc._DICEWARE_WORDS = None
        # EFF format: kelime TAB 5-haneli sayi. 7776 satir ama 1 benzersiz
        # kelime -> sayi kontrolu gecer, benzersizlik kontrolu yakalar.
        fake = "ab\t00000\n" * 7776
        try:
            with mock.patch("builtins.open",
                            mock.mock_open(read_data=fake)):
                with self.assertRaises(ValueError):
                    hc._load_diceware_words()
        finally:
            hc._DICEWARE_WORDS = orig

    def test_wordlist_benzersiz_gecer(self):
        # 7776 benzersiz kelime (EFF format) -> sorunsuz yuklenir.
        orig = hc._DICEWARE_WORDS
        hc._DICEWARE_WORDS = None
        fake = "\n".join(f"w{i}\t{i:05d}" for i in range(7776)) + "\n"
        try:
            with mock.patch("builtins.open",
                            mock.mock_open(read_data=fake)):
                words = hc._load_diceware_words()
            self.assertEqual(len(words), 7776)
            self.assertEqual(len(set(words)), 7776)
        finally:
            hc._DICEWARE_WORDS = orig

    # ---- BULGU 13: generate_keyfile ebeveyn dizin mode ----
    @unittest.skipUnless(os.name != "nt", "POSIX-only")
    def test_keyfile_ebeveyn_dizin_0700(self):
        d = tempfile.mkdtemp(prefix="hc_b13_")
        try:
            yol = os.path.join(d, "yeni_alt", "kf.key")
            hc.generate_keyfile(yol, length=64)
            mode = os.stat(os.path.join(d, "yeni_alt")).st_mode & 0o777
            self.assertEqual(mode, 0o700,
                             f"ebeveyn dizin 0o700 olmali, {oct(mode)}")
        finally:
            shutil.rmtree(d, ignore_errors=True)

    # ---- BULGU 15: FIFO/device reddi + hang yok ----
    @unittest.skipUnless(hasattr(os, "mkfifo"), "POSIX-only")
    def test_fifo_reddedilir_hang_yok(self):
        d = tempfile.mkdtemp(prefix="hc_b15_")
        _mkfifo = getattr(os, "mkfifo", None)
        if _mkfifo is None:
            shutil.rmtree(d, ignore_errors=True)
            self.skipTest("mkfifo yok")
        try:
            fifo = os.path.join(d, "kf.key")
            _mkfifo(fifo, 0o600)
            t0 = time.monotonic()
            with self.assertRaises(ValueError):
                hc._open_private_file_read(fifo, "keyfile")
            self.assertLess(time.monotonic() - t0, 2.0,
                            "FIFO open'i hang yapmamali (O_NONBLOCK)")
        finally:
            shutil.rmtree(d, ignore_errors=True)

    # ---- BULGU 11: Windows ACL allowlist (entegrasyon, icacls) ----
    @unittest.skipUnless(os.name == "nt", "Windows-only")
    def test_windows_spesifik_kullanici_ace_reddedilir(self):
        # Guests grubu (S-1-5-32-546) allowlist'te DEGIL: READ verilen
        # dosya reddedilmeli (eski WORLD_SIDS blacklist bunu kacirirdi).
        d = tempfile.mkdtemp(prefix="hc_b11_")
        try:
            yol = os.path.join(d, "kf.key")
            hc.generate_keyfile(yol, length=64)
            # once guvenli dosya kontrolu GECMELI (protected DACL)
            hc._check_private_file_windows(yol, "keyfile")
            r = subprocess.run(
                ["icacls", yol, "/grant", "*S-1-5-32-546:(R)"],
                capture_output=True, text=True)
            if r.returncode != 0:
                self.skipTest(f"icacls basarisiz: {r.stderr.strip()}")
            with self.assertRaises(ValueError):
                hc._check_private_file_windows(yol, "keyfile")
        finally:
            shutil.rmtree(d, ignore_errors=True)

    @unittest.skipUnless(os.name == "nt", "Windows-only")
    def test_windows_write_only_ace_reddedilir(self):
        # write-only ACE (FILE_WRITE_DATA) da allowlist disinda kalan
        # SID icin reddedilmeli (BULGU 11 (b)).
        d = tempfile.mkdtemp(prefix="hc_b11w_")
        try:
            yol = os.path.join(d, "kf.key")
            hc.generate_keyfile(yol, length=64)
            r = subprocess.run(
                ["icacls", yol, "/grant", "*S-1-5-32-546:(W)"],
                capture_output=True, text=True)
            if r.returncode != 0:
                self.skipTest(f"icacls basarisiz: {r.stderr.strip()}")
            with self.assertRaises(ValueError):
                hc._check_private_file_windows(yol, "keyfile")
        finally:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
