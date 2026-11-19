# -*- coding: utf-8 -*-
"""hcli.py CLI testleri - validasyon, guardlar, exit kodlari.

NOT: Windows'ta getpass(pipe stdin) msvcrt.getwch() ile ASILIR, bu yuzden
passphrase istemine ULASAN subprocess testi yazilmaz. Passphrase mantigi
unittest.mock ile dogrudan test edilir; subprocess testleri yalnizca
passphrase ONCESI reddedilen yollari (validasyon/guard/argparse) kapsar.
"""

import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest import mock

import hcli
import hyper_cipher as hc

HCLI = os.path.join(os.path.dirname(os.path.abspath(__file__)), "hcli.py")


def _mkdtemp_secure(prefix="hc_test_"):
    """BULGU 11: bu makinede AppData\\Local\\Temp ACL'si YABANCI SID'lere
    acik (inherited ACE'ler: mask 0x1201bf/0x1301ff). Buraya olusturulan
    dosyalar o ACE'leri devraldigi icin yeni allowlist onlari dogru
    sekilde reddediyor. Test dosyalarinin guvenli gorunmesi icin dizin
    olusturulduktan sonra ACL temizlenir: yalnizca kullanici + SYSTEM +
    Administrators (icacls /inheritance:r + explicit grant).
    POSIX'te ek islem gerekmez (mkdtemp 0o700 uretir)."""
    d = tempfile.mkdtemp(prefix=prefix)
    if os.name == "nt":
        sid = hc._current_user_sid_string()
        r = subprocess.run(
            ["icacls", d, "/inheritance:r",
             "/grant", f"*{sid}:(OI)(CI)F",
             "*S-1-5-18:(OI)(CI)F",
             "*S-1-5-32-544:(OI)(CI)F"],
            capture_output=True, text=True)
        if r.returncode != 0:
            shutil.rmtree(d, ignore_errors=True)
            raise RuntimeError(f"icacls guvenli dizin olusturamadi: {r.stderr}")
    return d


class TestValidateRotation(unittest.TestCase):
    def test_alt_sinir(self):
        self.assertEqual(hcli._validate_rotation(64, "encrypt"), 64)
        with self.assertRaises(hcli.CliError):
            hcli._validate_rotation(63, "encrypt")

    def test_ust_sinir(self):
        # Zafiyet raporu [17]: 64'un kati olmali (65504 = 64*1023.5 degil;
        # 65472 = 64*1023, 65536 siniri asar).
        self.assertEqual(hcli._validate_rotation(65472, "encrypt"), 65472)
        with self.assertRaises(hcli.CliError):
            hcli._validate_rotation(65535, "encrypt")
        with self.assertRaises(hcli.CliError):
            hcli._validate_rotation(65536, "encrypt")

    def test_64_katı_zorunlu(self):
        with self.assertRaises(hcli.CliError):
            hcli._validate_rotation(65, "encrypt")
        with self.assertRaises(hcli.CliError):
            hcli._validate_rotation(1000, "encrypt")


class TestValidateKdfN(unittest.TestCase):
    def test_sinirlar(self):
        self.assertEqual(hcli._validate_kdf_n(hc.MIN_KDF_N), hc.MIN_KDF_N)
        self.assertEqual(hcli._validate_kdf_n(hc.MAX_KDF_N), hc.MAX_KDF_N)
        with self.assertRaises(hcli.CliError):
            hcli._validate_kdf_n(hc.MIN_KDF_N - 1)
        with self.assertRaises(hcli.CliError):
            hcli._validate_kdf_n(hc.MAX_KDF_N << 1)

    def test_iki_kuvveti_zorunlu(self):
        # Argon2id memory_cost KiB 2'nin kuvveti olmali (zafiyet raporu [13][14])
        with self.assertRaises(hcli.CliError):
            hcli._validate_kdf_n((1 << 17) + 1)
        with self.assertRaises(hcli.CliError):
            hcli._validate_kdf_n(3 << 16)


class TestGuardOutput(unittest.TestCase):
    def setUp(self):
        self.tmp = _mkdtemp_secure(prefix="hcli_test_")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_yoksa_gecer(self):
        out = os.path.join(self.tmp, "yeni.hyp")
        hcli._guard_output(out, force=False, label="encrypt")  # gecmeli

    def test_varsa_force_sart(self):
        out = os.path.join(self.tmp, "var.hyp")
        open(out, "wb").close()
        with self.assertRaises(hcli.CliError):
            hcli._guard_output(out, force=False, label="encrypt")
        hcli._guard_output(out, force=True, label="encrypt")  # force -> gecer

    def test_klasor_reddedilir(self):
        d = os.path.join(self.tmp, "klasor")
        os.mkdir(d)
        with self.assertRaises(hcli.CliError):
            hcli._guard_output(d, force=True, label="encrypt")

    def test_kalan_tmp_reddedilir(self):
        # Zafiyet raporu [4] fix'i: kalinti deseni .hyp-*.tmp (mkstemp'in
        # gercek deseni). Eski test "out + '.tmp'" kontrol ediyordu - o kod
        # HICBIR ZAMAN tetiklenmeyen olu kodu test ediyordu.
        # BULGU 14 fix: yalnizca ESKI (stale) tmp kalinti sayilir; taze dosya
        # aktif/paralel islem olabilir. Burada mtime gecmise alinir -> red.
        out = os.path.join(self.tmp, "yarim.hyp")
        p = os.path.join(self.tmp, ".hyp-yarim-kalinti.tmp")
        open(p, "wb").close()
        old = time.time() - 7200          # 2 saat once -> stale
        os.utime(p, (old, old))
        with self.assertRaises(hcli.CliError):
            hcli._guard_output(out, force=True, label="encrypt")

    def test_taze_tmp_gecer(self):
        # BULGU 14 fix: paralel islem yanlis pozitifi - canli tmp dosyasi
        # (taze mtime) kalinti sayilmaz, islem SURER.
        out = os.path.join(self.tmp, "devam.hyp")
        open(os.path.join(self.tmp, ".hyp-canli.tmp"), "wb").close()
        hcli._guard_output(out, force=True, label="encrypt")  # gecmeli

    @unittest.skipUnless(hasattr(os, "geteuid"), "POSIX-only")
    def test_baska_kullanici_tmp_yok_sayilir(self):
        # BULGU 14 fix: saldirganin kendi uid'iyle olusturdugu eski tmp
        # dosyasi kalinti sayilmaz (DoS vektoru kapandi). Farkli uid'li
        # dosya uretmek icin os.chown kullanilir.
        out = os.path.join(self.tmp, "guvenli.hyp")
        p = os.path.join(self.tmp, ".hyp-saldirgan.tmp")
        open(p, "wb").close()
        old = time.time() - 7200
        os.utime(p, (old, old))
        _geteuid = getattr(os, "geteuid", None)
        _chown = getattr(os, "chown", None)
        if _geteuid is None or _chown is None:
            self.skipTest("geteuid/chown yok")
        try:
            _chown(p, _geteuid() ^ 1, -1)   # farkli uid (varsa)
        except (OSError, PermissionError):
            self.skipTest("chown yapilamadi")
        hcli._guard_output(out, force=True, label="encrypt")  # gecmeli


class TestPromptPassphrase(unittest.TestCase):
    def _tty(self):
        # Zafiyet raporu [7]: tty yoksa istem REDDEDILIR - testler tty
        # taklidi yapar, ayrica non-tty reddi ayrica test edilir.
        return mock.patch.object(sys.stdin, "isatty", return_value=True)

    def test_non_tty_reddedilir(self):
        # [7] fail-closed: pipe/yonlendirmede passphrase istemi yok.
        with mock.patch.object(sys.stdin, "isatty", return_value=False):
            with self.assertRaises(hcli.CliError) as cm:
                hcli._prompt_passphrase()
        self.assertIn("--passphrase-file", str(cm.exception))

    def test_bos_reddedilir(self):
        with self._tty(), mock.patch("getpass.getpass", return_value=""):
            with self.assertRaises(hcli.CliError):
                hcli._prompt_passphrase()

    def test_whitespace_reddedilir(self):
        with self._tty(), mock.patch("getpass.getpass", return_value="   "):
            with self.assertRaises(hcli.CliError):
                hcli._prompt_passphrase()

    def test_eslesme_kontrol(self):
        with self._tty(), mock.patch("getpass.getpass",
                                     side_effect=["aaaabbbb", "aaabbbcc"]):
            with self.assertRaises(hcli.CliError):
                hcli._prompt_passphrase(confirm=True)

    def test_eof_reddedilir(self):
        with self._tty(), mock.patch("getpass.getpass", side_effect=EOFError):
            with self.assertRaises(hcli.CliError):
                hcli._prompt_passphrase()

    def test_gecerli_passphrase(self):
        with self._tty(), mock.patch(
                "getpass.getpass",
                side_effect=["uzun-ve-guclu-passphrase",
                             "uzun-ve-guclu-passphrase"]):
            pw = hcli._prompt_passphrase(confirm=True)
        self.assertEqual(pw, "uzun-ve-guclu-passphrase")


class TestPassphraseFile(unittest.TestCase):
    """--passphrase-file (zafiyet raporu [7] fix'inin parcasi)."""

    def setUp(self):
        self.tmp = _mkdtemp_secure(prefix="hcli_pwf_")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_okunur_satir_sonu_kirpilir(self):
        p = os.path.join(self.tmp, "pw.txt")
        with open(p, "w", encoding="utf-8") as f:
            f.write("sifre-123\n")
        self.assertEqual(hcli._read_passphrase_file(p), "sifre-123")

    def test_bos_reddedilir(self):
        p = os.path.join(self.tmp, "bos.txt")
        open(p, "w", encoding="utf-8").close()
        with self.assertRaises(hcli.CliError):
            hcli._read_passphrase_file(p)

    def test_yoksa_reddedilir(self):
        with self.assertRaises(hcli.CliError):
            hcli._read_passphrase_file(os.path.join(self.tmp, "yok.txt"))

    def test_bas_ve_ust_bosluk_korunur(self):
        # passphrase'in anlamli bosluklari kirpilMAZ (sadece satir sonu).
        p = os.path.join(self.tmp, "bosluk.txt")
        with open(p, "w", encoding="utf-8") as f:
            f.write("  gecen bosluk  \n")
        self.assertEqual(hcli._read_passphrase_file(p), "  gecen bosluk  ")

    def test_cok_buyuk_reddedilir(self):
        # DENETIM 5 bulgu [6]: okuma aninda tavan (age io.LimitReader
        # deseni) - dev dosya belleği tuketmeden reddedilmeli.
        p = os.path.join(self.tmp, "dev.txt")
        with open(p, "w", encoding="utf-8") as f:
            f.write("x" * (hcli.PASSPHRASE_FILE_MAX_BYTES + 1))
        with self.assertRaises(hcli.CliError):
            hcli._read_passphrase_file(p)

    @unittest.skipIf(os.name != "nt", "Windows ACL kontrolu")
    def test_windows_herkese_acik_reddedilir(self):
        # DENETIM 5 bulgu [3]: Windows'ta st_mode anlamsiz - gercek DACL
        # kontrolu. Everyone'a okuma verilmis dosya fail-closed reddedilir.
        import subprocess as _sp
        p = os.path.join(self.tmp, "herkese_acik.txt")
        with open(p, "w", encoding="utf-8") as f:
            f.write("sifre-123\n")
        r = _sp.run(["icacls", p, "/grant", "*S-1-1-0:(R)"],
                    capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        with self.assertRaisesRegex(hcli.CliError, "baska kullanicilar"):
            hcli._read_passphrase_file(p)


class TestCliSubprocess(unittest.TestCase):
    """Passphrase istemine ULASMAYAN CLI yollari (getpass hang riski)."""

    def setUp(self):
        # Windows'ta 0600 kontrolu atlanir (os.name != "nt") - passphrase
        # dosyasi gecerli bir otomasyon yolu olarak kullanilabilir.
        self.tmp = _mkdtemp_secure(prefix="hcli_sub_")
        self.pwfile = os.path.join(self.tmp, "pw.txt")
        with open(self.pwfile, "w", encoding="utf-8") as f:
            f.write("cli-subprocess-passphrase-42\n")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_cli(self, *args):
        return subprocess.run(
            [sys.executable, HCLI, *args],
            capture_output=True, text=True, timeout=60,
            cwd=os.path.dirname(HCLI),
        )

    def test_missing_input_file(self):
        # Zafiyet raporu [21]: eksik girdi dosyasi = kullanim hatasi -> 2.
        r = self.run_cli("encrypt", "boyle_dosya_yok.bin")
        self.assertEqual(r.returncode, 2)
        self.assertIn("bulunamadi", r.stderr)

    def test_bad_rotation_exit1(self):
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(b"veri")
            fname = f.name
        try:
            r = self.run_cli("encrypt", fname, "--portable", "--rotation", "10")
            self.assertEqual(r.returncode, 1)
            self.assertIn("gecersiz rotasyon", r.stderr)
        finally:
            os.remove(fname)

    def test_bad_kdf_n_exit1(self):
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(b"veri")
            fname = f.name
        try:
            r = self.run_cli("encrypt", fname, "--portable", "--kdf-n", "5")
            self.assertEqual(r.returncode, 1)
            self.assertIn("KDF memory_cost", r.stderr)
        finally:
            os.remove(fname)

    def test_bad_pad_to_exit1(self):
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(b"veri")
            fname = f.name
        try:
            r = self.run_cli("encrypt", fname, "--portable",
                             "--pad-to", "8")
            self.assertEqual(r.returncode, 1)
            self.assertIn("--pad-to", r.stderr)
        finally:
            os.remove(fname)

    def test_pad_to_roundtrip_exit0(self):
        with tempfile.TemporaryDirectory() as d:
            inp = os.path.join(d, "in.bin")
            hyp = os.path.join(d, "in.hyp")
            out = os.path.join(d, "out.bin")
            with open(inp, "wb") as f:
                f.write(b"padding test verisi")
            r = self.run_cli("encrypt", inp, "--portable", "--pad-to", "64",
                             "--out", hyp, "--passphrase-file", self.pwfile)
            self.assertEqual(r.returncode, 0, r.stderr)
            body_len = os.path.getsize(hyp) - hc.HEADER_BYTES - hc.TAG_BYTES
            self.assertEqual(body_len % 64, 0)
            r2 = self.run_cli("decrypt", hyp, "--out", out,
                              "--passphrase-file", self.pwfile)
            self.assertEqual(r2.returncode, 0, r2.stderr)
            with open(out, "rb") as f:
                self.assertEqual(f.read(), b"padding test verisi")

    def test_existing_target_without_force_exit1(self):
        with tempfile.TemporaryDirectory() as d:
            inp = os.path.join(d, "in.bin")
            out = os.path.join(d, "out.hyp")
            with open(inp, "wb") as f:
                f.write(b"veri")
            open(out, "wb").close()
            r = self.run_cli("encrypt", inp, "--portable", "--out", out)
            self.assertEqual(r.returncode, 1)
            self.assertIn("hedef dosya zaten var", r.stderr)

    def test_argparse_error_exit2(self):
        r = self.run_cli("bilinmeyen_komut")
        self.assertEqual(r.returncode, 2)

    def test_selftest_exit0(self):
        r = self.run_cli("selftest")
        self.assertEqual(r.returncode, 0)
        self.assertIn("SELF-TEST GECTI", r.stdout)

    def test_hash_exit0(self):
        r = self.run_cli("hash")
        self.assertEqual(r.returncode, 0)
        self.assertIn("SHA-256", r.stdout)


class TestV5KeyfileCLI(unittest.TestCase):
    """v5 CLI: generate-keyfile + encrypt/decrypt --key-file."""

    PW_FILE_STRONG = "cli-v5-strong-passphrase-2026"

    def _tmp(self):
        return _mkdtemp_secure(prefix="hcli_v5_")

    def _write_pw(self, d, pw=None):
        p = os.path.join(d, "perde.txt")
        with open(p, "w", encoding="utf-8") as f:
            f.write(pw or self.PW_FILE_STRONG)
        return p

    def test_generate_keyfile_exit0_ve_64byte(self):
        d = self._tmp()
        try:
            kf = os.path.join(d, "anahtar.key")
            r = subprocess.run([sys.executable, hcli.__file__, "generate-keyfile", kf],
                               capture_output=True, text=True, encoding="utf-8",
                               errors="replace")
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(os.path.getsize(kf), hc.KEYFILE_RECOMMENDED_BYTES)
            self.assertIn("[OK]", r.stdout)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_generate_keyfile_var_yok_hata(self):
        d = self._tmp()
        try:
            kf = os.path.join(d, "var.key")
            with open(kf, "wb") as f:
                f.write(b"mevcut")
            r = subprocess.run([sys.executable, hcli.__file__, "generate-keyfile", kf],
                               capture_output=True, text=True, encoding="utf-8",
                               errors="replace")
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("zaten var", r.stderr.lower() + r.stdout.lower())
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_encrypt_decrypt_keyfile_roundtrip(self):
        d = self._tmp()
        try:
            src = os.path.join(d, "gizli.txt")
            with open(src, "w", encoding="utf-8") as f:
                f.write("v5 keyfile roundtrip CLI verisi")
            pwf = self._write_pw(d)
            kf = os.path.join(d, "anahtar.key")
            subprocess.run([sys.executable, hcli.__file__, "generate-keyfile", kf],
                           capture_output=True, text=True)
            hyp = os.path.join(d, "gizli.hyp")
            r = subprocess.run([sys.executable, hcli.__file__, "encrypt", src,
                                "--portable", "--passphrase-file", pwf,
                                "--key-file", kf, "--out", hyp],
                               capture_output=True, text=True, encoding="utf-8",
                               errors="replace")
            self.assertEqual(r.returncode, 0, r.stderr)
            out = os.path.join(d, "coz.txt")
            r = subprocess.run([sys.executable, hcli.__file__, "decrypt", hyp,
                                "--passphrase-file", pwf, "--key-file", kf,
                                "--out", out, "--force"],
                               capture_output=True, text=True, encoding="utf-8",
                               errors="replace")
            self.assertEqual(r.returncode, 0, r.stderr)
            with open(out, "r", encoding="utf-8") as f:
                self.assertEqual(f.read(), "v5 keyfile roundtrip CLI verisi")
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_keyfile_siz_decrypt_reddedilir(self):
        d = self._tmp()
        try:
            src = os.path.join(d, "gizli.txt")
            with open(src, "w", encoding="utf-8") as f:
                f.write("keyfile zorunlu")
            pwf = self._write_pw(d)
            kf = os.path.join(d, "anahtar.key")
            subprocess.run([sys.executable, hcli.__file__, "generate-keyfile", kf],
                           capture_output=True, text=True)
            hyp = os.path.join(d, "gizli.hyp")
            subprocess.run([sys.executable, hcli.__file__, "encrypt", src,
                            "--portable", "--passphrase-file", pwf,
                            "--key-file", kf, "--out", hyp],
                           capture_output=True, text=True, encoding="utf-8")
            out = os.path.join(d, "coz.txt")
            r = subprocess.run([sys.executable, hcli.__file__, "decrypt", hyp,
                                "--passphrase-file", pwf, "--out", out, "--force"],
                               capture_output=True, text=True, encoding="utf-8",
                               errors="replace")
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("keyfile", (r.stderr + r.stdout).lower())
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_keyfile_flagsiz_pakete_keyfile_hata(self):
        """V4 bulgu 3: keyfile KORUMASIZ pakete --key-file verilirse sessizce
        yoksayilmaz - KDF amplifikasyonu ONCESI net hata (fail-closed)."""
        d = self._tmp()
        try:
            src = os.path.join(d, "gizli.txt")
            with open(src, "w", encoding="utf-8") as f:
                f.write("keyfile korumasiz veri")
            pwf = self._write_pw(d)
            kf = os.path.join(d, "gereksiz.key")
            subprocess.run([sys.executable, hcli.__file__, "generate-keyfile", kf],
                           capture_output=True, text=True)
            hyp = os.path.join(d, "gizli.hyp")
            enc = subprocess.run([sys.executable, hcli.__file__, "encrypt", src,
                                  "--portable", "--passphrase-file", pwf,
                                  "--out", hyp],
                                 capture_output=True, text=True, encoding="utf-8",
                                 errors="replace")
            self.assertEqual(enc.returncode, 0, enc.stderr)
            out = os.path.join(d, "coz.txt")
            r = subprocess.run([sys.executable, hcli.__file__, "decrypt", hyp,
                                "--passphrase-file", pwf, "--key-file", kf,
                                "--out", out, "--force"],
                               capture_output=True, text=True, encoding="utf-8",
                               errors="replace")
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("keyfile", (r.stderr + r.stdout).lower())
            self.assertFalse(os.path.exists(out))
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_keyfile_paket_zayif_perde_uyarisi_yok(self):
        """V4 bulgu 3: keyfile korumali pakette zayif perde uyarisi BASILMAZ
        (perde tek basina yetersiz - yanlis alarm yerine keyfile bilgisi)."""
        d = self._tmp()
        try:
            src = os.path.join(d, "gizli.txt")
            with open(src, "w", encoding="utf-8") as f:
                f.write("keyfile korumali veri")
            pwf = os.path.join(d, "zayif.txt")
            with open(pwf, "w", encoding="utf-8") as f:
                f.write("ankara1234")          # zayif perde - ama keyfile var
            kf = os.path.join(d, "anahtar.key")
            subprocess.run([sys.executable, hcli.__file__, "generate-keyfile", kf],
                           capture_output=True, text=True)
            hyp = os.path.join(d, "gizli.hyp")
            enc = subprocess.run([sys.executable, hcli.__file__, "encrypt", src,
                                  "--portable", "--passphrase-file", pwf,
                                  "--allow-weak", "--key-file", kf, "--out", hyp],
                                 capture_output=True, text=True, encoding="utf-8",
                                 errors="replace")
            self.assertEqual(enc.returncode, 0, enc.stderr)
            out = os.path.join(d, "coz.txt")
            dec = subprocess.run([sys.executable, hcli.__file__, "decrypt", hyp,
                                  "--passphrase-file", pwf, "--key-file", kf,
                                  "--out", out, "--force"],
                                 capture_output=True, text=True, encoding="utf-8",
                                 errors="replace")
            self.assertEqual(dec.returncode, 0, dec.stderr)
            self.assertNotIn("zayif passphrase", dec.stderr.lower())
            with open(out, "r", encoding="utf-8") as f:
                self.assertEqual(f.read(), "keyfile korumali veri")
        finally:
            shutil.rmtree(d, ignore_errors=True)


class TestV5PassphraseCLI(unittest.TestCase):
    """v5 CLI: zxcvbn zorlugu + generate-passphrase."""

    def _tmp(self):
        return _mkdtemp_secure(prefix="hcli_v5p_")

    def test_zayif_perde_encrypt_reddedilir(self):
        d = self._tmp()
        try:
            src = os.path.join(d, "gizli.txt")
            with open(src, "w", encoding="utf-8") as f:
                f.write("red testi")
            pwf = os.path.join(d, "zayif.txt")
            with open(pwf, "w", encoding="utf-8") as f:
                f.write("ankara1234")
            hyp = os.path.join(d, "gizli.hyp")
            r = subprocess.run([sys.executable, hcli.__file__, "encrypt", src,
                                "--portable", "--passphrase-file", pwf, "--out", hyp],
                               capture_output=True, text=True, encoding="utf-8",
                               errors="replace")
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("cok zayif", (r.stderr + r.stdout).lower())
            self.assertFalse(os.path.exists(hyp))
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_allow_weak_zayifi_gecirir(self):
        d = self._tmp()
        try:
            src = os.path.join(d, "gizli.txt")
            with open(src, "w", encoding="utf-8") as f:
                f.write("guclu veri zayif perde")
            pwf = os.path.join(d, "zayif.txt")
            with open(pwf, "w", encoding="utf-8") as f:
                f.write("ankara1234")
            hyp = os.path.join(d, "gizli.hyp")
            r = subprocess.run([sys.executable, hcli.__file__, "encrypt", src,
                                "--portable", "--passphrase-file", pwf,
                                "--allow-weak", "--out", hyp],
                               capture_output=True, text=True, encoding="utf-8",
                               errors="replace")
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertTrue(os.path.exists(hyp))
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_zayif_perde_decrypt_uyari_basar(self):
        """DENETIM 5 bulgu [14]: decrypt zayif perdede UYARI basmali
        (reddetmemeli - eski paketler kilitlenmesin) ve yine de acmali."""
        d = self._tmp()
        try:
            src = os.path.join(d, "gizli.txt")
            with open(src, "w", encoding="utf-8") as f:
                f.write("zayif perde ile acilacak veri")
            pwf = os.path.join(d, "zayif.txt")
            with open(pwf, "w", encoding="utf-8") as f:
                f.write("ankara1234")
            hyp = os.path.join(d, "gizli.hyp")
            enc = subprocess.run([sys.executable, hcli.__file__, "encrypt", src,
                                  "--portable", "--passphrase-file", pwf,
                                  "--allow-weak", "--out", hyp],
                                 capture_output=True, text=True, encoding="utf-8",
                                 errors="replace")
            self.assertEqual(enc.returncode, 0, enc.stderr)
            out = os.path.join(d, "coz.txt")
            dec = subprocess.run([sys.executable, hcli.__file__, "decrypt", hyp,
                                  "--passphrase-file", pwf, "--out", out,
                                  "--force"],
                                 capture_output=True, text=True, encoding="utf-8",
                                 errors="replace")
            self.assertEqual(dec.returncode, 0, dec.stderr)
            self.assertIn("UYARI", dec.stderr)
            self.assertIn("zayif passphrase", dec.stderr.lower())
            with open(out, "r", encoding="utf-8") as f:
                self.assertEqual(f.read(), "zayif perde ile acilacak veri")
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_guclu_perde_decrypt_uyarisiz(self):
        """Guclu perdeyle decrypt uyari basmaz (yanlis pozitif yok)."""
        d = self._tmp()
        try:
            src = os.path.join(d, "gizli.txt")
            with open(src, "w", encoding="utf-8") as f:
                f.write("guclu perde verisi")
            pwf = os.path.join(d, "guclu.txt")
            # "correct horse battery staple" sinifinda, zxcvbn esigini gecer
            with open(pwf, "w", encoding="utf-8") as f:
                f.write("dogru-at-batarya-zimba-dolap-gece-2017")
            hyp = os.path.join(d, "gizli.hyp")
            enc = subprocess.run([sys.executable, hcli.__file__, "encrypt", src,
                                  "--portable", "--passphrase-file", pwf,
                                  "--out", hyp],
                                 capture_output=True, text=True, encoding="utf-8",
                                 errors="replace")
            self.assertEqual(enc.returncode, 0, enc.stderr)
            out = os.path.join(d, "coz.txt")
            dec = subprocess.run([sys.executable, hcli.__file__, "decrypt", hyp,
                                  "--passphrase-file", pwf, "--out", out,
                                  "--force"],
                                 capture_output=True, text=True, encoding="utf-8",
                                 errors="replace")
            self.assertEqual(dec.returncode, 0, dec.stderr)
            self.assertNotIn("UYARI", dec.stderr)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_generate_passphrase_exit0(self):
        r = subprocess.run([sys.executable, hcli.__file__, "generate-passphrase"],
                           capture_output=True, text=True, encoding="utf-8",
                           errors="replace")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("Tahmini gucluk", r.stdout)
        self.assertIn("bit entropi", r.stdout)

    def test_generate_passphrase_7_kelime(self):
        r = subprocess.run([sys.executable, hcli.__file__, "generate-passphrase",
                            "--words", "7"],
                           capture_output=True, text=True, encoding="utf-8",
                           errors="replace")
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_generate_passphrase_kotu_words_hata(self):
        r = subprocess.run([sys.executable, hcli.__file__, "generate-passphrase",
                            "--words", "21"],
                           capture_output=True, text=True, encoding="utf-8",
                           errors="replace")
        self.assertNotEqual(r.returncode, 0)

    def test_generate_passphrase_bos_kelime_yok(self):
        r = subprocess.run([sys.executable, hcli.__file__, "generate-passphrase",
                            "--words", "0"],
                           capture_output=True, text=True, encoding="utf-8",
                           errors="replace")
        self.assertNotEqual(r.returncode, 0)


class TestV4FixlerHcli(unittest.TestCase):
    """V4 zafiyet raporu [1] alt bileseni: hcli encrypt, zxcvbn kurulu
    degilken fail-closed --allow-weak zorunlulugu."""

    def _enc_args(self, d: str, allow_weak: bool):
        src = os.path.join(d, "girdi.txt")
        with open(src, "wb") as f:
            f.write(b"gizli veri")
        pw = os.path.join(d, "perde.txt")
        with open(pw, "w", encoding="utf-8") as f:
            f.write("V4-Fix-Guclu-Perde-2026!")   # gorsel olarak guclu
        return SimpleNamespace(
            rotation=4096, kdf_n=hc.MIN_KDF_N, pad_to=None,
            out=os.path.join(d, "cikti.hyp"), force=True,
            passphrase_file=pw, allow_weak=allow_weak, key_file=None,
            file=src, quiet=True, portable=True)

    def test_encrypt_zxcvbn_yokken_allow_weak_zorunlu(self):
        # Fail-closed: zxcvbn yokken assert_strong_passphrase HER ZAMAN
        # reddeder -> --allow-weak'siz encrypt CliError ile durur, cikti
        # dosyasi OLUSMAZ.
        d = _mkdtemp_secure(prefix="hcli_v4f_")
        try:
            args = self._enc_args(d, allow_weak=False)
            with mock.patch.object(hc, "_zxcvbn", None):
                with self.assertRaises(hcli.CliError) as ctx:
                    hcli.cmd_encrypt(args)
            self.assertIn("zxcvbn", str(ctx.exception))
            self.assertFalse(os.path.exists(args.out))
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_encrypt_zxcvbn_yokken_allow_weak_gecer(self):
        # --allow-weak = bilincli risk kabulu: gucluk kontrolu atlanir,
        # sifreleme akisi devam eder (encrypt_file cagrisiyla dogrulanir).
        d = _mkdtemp_secure(prefix="hcli_v4f_")
        try:
            args = self._enc_args(d, allow_weak=True)
            with mock.patch.object(hc, "_zxcvbn", None), \
                 mock.patch.object(hc, "encrypt_file") as ef:
                hcli.cmd_encrypt(args)
            ef.assert_called_once()
        finally:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
