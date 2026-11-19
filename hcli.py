#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HyperCipher CLI - 2048-bit hardware-bound rotating stream cipher arac.

Kullanim:
  python hcli.py hash                      -> makine parmak izini goster
  python hcli.py encrypt DOSYA [secenekler]   (--force ile uzerine yaz)
  python hcli.py decrypt DOSYA.hyp [secenekler]
  python hcli.py selftest                  -> 64 KiB roundtrip kendini test et

Cikti korumasi: hedef dosya zaten varsa --force verilmeden islem REDDEDILIR.
Exit kodlari: 0=basarili, 1=calisma hatasi, 2=kullanim hatasi.
"""

import argparse
import getpass
import glob
import hashlib
import os
import secrets
import sys
import tempfile
import time

import hyper_cipher as hc

# Parametre sinirlari (makul kullanim araligi)
MIN_ROTATION = 64          # 64 byte'tan kucuk rotasyon performans catisi
MAX_ROTATION = 65535       # header'da uint16 olarak saklanir (0=eski varsayilan)
PASSPHRASE_FILE_MAX_BYTES = 1 << 20   # DENETIM 5 bulgu [6]: 1 MiB tavan


class CliError(Exception):
    """Kullaniciya gosterilecek temiz hata."""


def _validate_rotation(value: int, cmd_name: str) -> int:
    if value < MIN_ROTATION or value > MAX_ROTATION:
        raise CliError(
            f"{cmd_name}: gecersiz rotasyon {value} byte - "
            f"[{MIN_ROTATION}, {MAX_ROTATION}] araliginda olmali.")
    if value % 64 != 0:
        # Zafiyet raporu [17]: keystream 64-byte blok sinirli - 64'un
        # kati olmayan rotasyon subkey takvimini dokumandan saptirir.
        raise CliError(
            f"{cmd_name}: gecersiz rotasyon {value} byte - "
            f"64'un kati olmali (64, 128, 1024, ...).")
    return value


def _validate_kdf_n(value: int) -> int:
    # Zafiyet raporu [13][14]: Argon2id memory_cost KiB 2'nin kuvveti
    # sozlesmesine uymalI (API uyumlulugu); sinir disi degerler ya Argon2id'in
    # hata vermesine ya da amplifikasyon siseirmesine yol acar. Encrypt icin
    # CLI'dan gelen her deger dogrulanir. DENETIM 5 bulgu [7]: ust sinir
    # HYPERCIPHER_MAX_KDF_N env'i ile daraltilabilir (servis butcesi).
    max_kdf = hc._effective_max_kdf_n()
    if value < hc.MIN_KDF_N or value > max_kdf:
        raise CliError(
            f"gecersiz KDF memory_cost {value} - "
            f"[{hc.MIN_KDF_N}, {max_kdf}] araliginda olmali "
            f"(2'nin kuvveti).")
    if value & (value - 1):
        raise CliError(
            f"gecersiz KDF memory_cost {value} - 2'nin kuvveti olmali "
            f"(Argon2id memory_cost KiB).")
    return value


def _guard_output(out: str, force: bool, label: str) -> None:
    """Hedef dosya varsa uzerine yazmayi engelle (--force sart).

    V4 zafiyet raporu [5] (BILGI - tasarim dogru, belgelendi): bu kontrol
    ile acilis arasinda teorik bir TOCTOU penceresi vardir (saldirgan
    .exists() sonrasi out'a symlink koyabilir). Ancak atomik yazma araci
    hedefi once gercek uzantiyla acar ve acilis sonrasi os.fstat ile
    S_ISREG dogrular -> symlink hedefi regular dosya ise uzerine yazilir,
    degilse CipherError. Yani silme saldirisi (denial) teorik olarak
    mumkundur ama hedefin CONTENT'ini degistirme/hedefi caldirma yolu
    yoktur. Tam cozum icin OS-seviyesi reflink/rename-discipline gerekirdi;
    mevcut tasarim bilincli bir denge olarak korunuyor.
    """
    if os.path.exists(out):
        if not force:
            raise CliError(
                f"{label}: hedef dosya zaten var: {out}\n"
                f"  Uzerine yazmak icin --force kullanin "
                f"(veri kaybini onlemek icin varsayilan RED).")
        if os.path.isdir(out):
            raise CliError(f"{label}: hedef bir klasor: {out}")
    # Zafiyet raporu [4] fix'i: eski kod "out + '.tmp'" adini kontrol ediyordu
    # ama atomik yazma araci mkstemp(prefix='.hyp-', suffix='.tmp') kullaniyor.
    # Yani o kontrol HICBIR ZAMAN tetiklenmiyordu (olu kod). Gercek desen:
    # hedef dizindeki .hyp-*.tmp kalintilari (yarim kalmis onceki islem).
    #
    # BULGU 14 fix: ham glob yeterli DEGILDI -
    #   (a) iki PARALEL islem birbirinin CANLI tmp'ini "kalinti" sanip
    #       yanlis pozitif uretiyordu;
    #   (b) hedef dizine yazma hakki olan saldirgan bos bir .hyp-x.tmp
    #       olusturarak o dizine yapilacak islemleri KALICI engelleyebiliyordu
    #       (DoS).
    # En guclu cozum (QLockFile/proper-lockfile mtime esigi deseni):
    # yalnizca X saniyeden ESKI (st_mtime) tmp dosyalari kalinti sayilir;
    # taze dosya = suryen/paralel islem olabilir -> gecirilir. POSIX'te ek
    # guvenlik: baska kullaniciya ait dosyalar da yok sayilir (saldirgan
    # kendi uid'iyle olusturdugu dosyayi "kalinti" gibi gosteremez).
    # Windows'ta st_uid her zaman 0'dir; koruma yas esiginden gelir (canli
    # tmp dosyalar dwShareMode=0 ile kilitli oldugundan taze gorunur).
    directory = os.path.dirname(os.path.abspath(out)) or "."
    _stale_after_s = 3600.0          # 1 saat: suruyen islem bundan uzun
    _now = time.time()
    leftovers = []
    for _p in sorted(glob.glob(os.path.join(directory, ".hyp-*.tmp"))):
        try:
            _st = os.stat(_p)
        except OSError:
            continue                 # yarisda silindi -> yok say
        if _st.st_mtime > _now - _stale_after_s:
            continue                 # taze: aktif/paralel islem olabilir
        _geteuid = getattr(os, "geteuid", None)
        if _geteuid is not None and _st.st_uid != _geteuid():
            continue                 # POSIX: baska kullaniciya ait -> DoS dosyasi
        leftovers.append(_p)
    if leftovers:
        raise CliError(
            f"{label}: kalan gecici dosya(lar) bulundu: "
            f"{', '.join(os.path.basename(p) for p in leftovers[:3])}"
            f"{'...' if len(leftovers) > 3 else ''}\n"
            f"  Onceki islem yarim kalmis olabilir - inceleyip silin.")


def _prompt_passphrase(confirm: bool = False, *,
                       require_strong: bool = False) -> str:
    # Zafiyet raporu [7]: non-tty stdin'de getpass Windows fallback'e duser
    # ve passphrase DUZ METIN olarak ekranda gorunur (shell history/log).
    # Fail-closed: tty yoksa istemi REDDET; otomasyon icin
    # --passphrase-file (0600) kullanilir.
    if not sys.stdin.isatty():
        raise CliError(
            "passphrase istemi icin etkilesimli terminal (tty) gerekli.\n"
            "  Otomasyon icin --passphrase-file DOSYA kullanin "
            "(dosya 0600 olmali, sadece sizin okunabilir).")
    try:
        pw = getpass.getpass("Passphrase (gorunmez): ")
    except (EOFError, KeyboardInterrupt):
        raise CliError("passphrase giris iptal edildi.")
    if not pw or not pw.strip():
        raise CliError("passphrase bos olamaz - islem iptal edildi.")
    if confirm:
        try:
            pw2 = getpass.getpass("Tekrar (dogrulama): ")
        except (EOFError, KeyboardInterrupt):
            raise CliError("passphrase giris iptal edildi.")
        if pw != pw2:
            raise CliError("passphrase'ler eslesmiyor.")
    if require_strong:
        # v5: zxcvbn esigi gecmeyen perdeyle sifreleme REDDEDILIR. Kullanici
        # ya daha guclu perde girer ya da --allow-weak ile acikca riske razi
        # olur (script icin --passphrase-file + --allow-weak).
        try:
            hc.assert_strong_passphrase(pw)
        except ValueError as e:
            raise CliError(
                f"{e}\n"
                f"  ISTEMIYORSANIZ --allow-weak ile bu uyaruyi gecin "
                f"(ONERILMEZ - zayif perde brute-force ile kirilabilir).")
    elif len(pw) < 8:
        print("UYARI: kisa passphrase zayif bir key demektir. "
              "Minimum 16 karakter onerilir.")
    return pw


def _read_passphrase_file(path: str) -> str:
    """--passphrase-file destegi: 0600 zorunlu, sadece satir sonu kirpilir.

    Zafiyet raporu [7] fix'inin parcasi: otomasyon guvenli tek yoldur.
    Bas/ust bosluklar passphrase'in parcasi olabilir - kirpilMAZ.
    DENETIM 5 bulgu [3]: Windows'ta st_mode yerine gercek DACL/sahip
    kontrolu yapilir (hc._open_private_file_read -> _check_private_file_windows
    handle uzerinden, OpenSSH check_acl deseni).

    DENETIM 5 bulgu [16] (TOCTOU): okuma hc._open_private_file_read ile
    yapilir - dosya ONCE acilir, mode/uid/ACL dogrulamasi ACILMIS fd
    uzerinden yapilir; dogrulama ile okuma arasinda baska dosya
    yerlestirilemez (stat+open TOCTOU penceresi kapatildi).
    """
    try:
        fd = hc._open_private_file_read(path, "passphrase dosyasi")
    except ValueError as e:
        raise CliError(str(e)) from None
    try:
        with os.fdopen(fd, "r", encoding="utf-8") as f:
            pw = f.read(PASSPHRASE_FILE_MAX_BYTES + 1)
    except OSError as e:
        raise CliError(f"passphrase dosyasi okunamadi: {e}")
    if len(pw) > PASSPHRASE_FILE_MAX_BYTES:
        # DENETIM 5 bulgu [6]: okuma aninda tavan (age io.LimitReader
        # deseni) - dev dosya once belleğe cekilip OOM uretilemez.
        raise CliError(
            f"passphrase dosyasi cok buyuk "
            f"(>{PASSPHRASE_FILE_MAX_BYTES} byte) - dogru dosya mi?")
    pw = pw.rstrip("\r\n")          # sadece satir sonu
    if not pw or not pw.strip():
        raise CliError("passphrase dosyasi bos olamaz.")
    return pw


def _progress(done: int, total: int, label: str) -> None:
    # Zafiyet raporu [22]: progress SADECE tty'de - yonlendirme/log/screencast
    # dosya boyutunu ifsa etmemeli, \r satirlari loglari doldurmamali.
    if not sys.stdout.isatty():
        return
    pct = done * 100 // total if total else 100
    print(f"\r{label} {done / 1048576:.1f} / {total / 1048576:.1f} MiB "
          f"({pct}%)", end="", flush=True)


def cmd_hash(args):
    # Zafiyet raporu [8]: Varsayilan cikti SADECE SHA-256 ozeti + hassas
    # uyarisi. Tam bilesenler (MachineGuid, MAC, serial...) anahtar
    # materyalinin ikinci faktorunu ifsa eder -> --full arkasinda.
    blob = hc.collect_hardware_fingerprint()
    print(f"Makine parmak izi SHA-256: {hashlib.sha256(blob).hexdigest()}")
    print("UYARI: Bu ozet anahtar materyalinin parcasi - kimseyle paylasmayin.")
    if args.full:
        print("Bilesenler (hassas):")
        for part in blob.decode("utf-8", errors="replace").split("|"):
            print(f"   {part}")


def cmd_encrypt(args):
    rotation = _validate_rotation(args.rotation, "encrypt")
    kdf_n = _validate_kdf_n(args.kdf_n)
    if args.pad_to is not None and not 16 <= args.pad_to <= 65536:
        raise CliError(f"encrypt: gecersiz --pad-to {args.pad_to} - "
                       f"[16, 65536] araliginda olmali (ISO 7816-4).")
    out = args.out or args.file + ".hyp"
    _guard_output(out, args.force, "encrypt")
    if args.passphrase_file:
        pw = _read_passphrase_file(args.passphrase_file)
        if not args.allow_weak:
            # v5: --passphrase-file yolu da zorunlu guclu perde kontrolunden
            # gecer (script'ler --allow-weak ile acikca riske razi olur).
            try:
                hc.assert_strong_passphrase(pw)
            except ValueError as e:
                raise CliError(str(e))
    else:
        pw = _prompt_passphrase(confirm=True, require_strong=not args.allow_weak)
    keyfile = None
    if args.key_file:
        keyfile = hc.read_keyfile(args.key_file)
    # Girdi boyutu sifreleme ONCESI alinir: self-overwrite (--force ile
    # out == file) durumunda istatistikler dogru kalir.
    size = os.path.getsize(args.file)
    t0 = time.time()
    last = [0.0]
    warned = [False]   # [28] progress hatasi bir kez loglanir

    def prog(done, total):
        try:   # [28] hatali UI callback'i islemi iptal etmesin
            now = time.time()
            if now - last[0] > 0.2 or done == total:
                _progress(done, total, "Sifreleniyor")
                last[0] = now
        except Exception as e:
            if not warned[0]:
                print(f"UYARI: ilerleme gosterimi hata verdi "
                      f"({e}) - gosterim kapatildi", file=sys.stderr)
                warned[0] = True

    hc.encrypt_file(args.file, out, pw,
                    use_hardware=not args.portable,
                    kdf_n=kdf_n,
                    rotation_bytes=rotation,
                    pad_to=args.pad_to,
                    keyfile=keyfile,
                    progress=prog)
    dt = max(time.time() - t0, 1e-9)   # cok hizli islemde 0'a bolme karsi
    rots = (size + rotation - 1) // rotation
    if not args.quiet:
        print()
        print(f"[OK] {args.file} -> {out}")
        # Zafiyet raporu [22]: boyut/hiz istatistikleri de tty + !quiet.
        if sys.stdout.isatty():
            print(f"     {size:,} byte | {rots:,}x 2048-bit subkey rotasyonu "
                  f"| {dt:.2f}s | {size / dt / 1048576:.1f} MiB/s")
            if keyfile is not None:
                print("     Durum: DONANIMA BAGLI + KEYFILE (ikinci faktor) - "
                      "perde VE keyfile birlikte gerekli")
            elif not args.portable:
                print("     Durum: DONANIMA BAGLI "
                      "(bu makinenin disinda acilamaz)")
    elif not sys.stdout.isatty():
        print(f"[OK] {args.file} -> {out}")


def cmd_decrypt(args):
    # Zafiyet raporu [23]: case-insensitive .hyp kontrolu + len > 4 guard
    # ("x.hyp" -> "" bos cikti adi hatasi). .dec kalintisi kaldirildi:
    # uzantisiz/yarim dosyada cikti her zaman acik ve tahmin edilebilir.
    out = args.out
    if not out:
        name = args.file
        if len(name) > 4 and name[-4:].lower() == ".hyp":
            out = name[:-4]
        else:
            out = name + ".dec"
    _guard_output(out, args.force, "decrypt")
    if args.passphrase_file:
        pw = _read_passphrase_file(args.passphrase_file)
    else:
        pw = _prompt_passphrase(confirm=False)
    # DENETIM 5 bulgu [14]: README "decrypt'te yalnizca uyarı verilir"
    # diyordu ama kodda HICBIR uyari yoktu (doc/code uyusmazligi).
    # En guclu cozum: kodu dokumana hizala - zayif perdeyle acilan dosya
    # brute-force korumasizdir, kullanici BUNU bilmeli (encrypt'te oldugu
    # gibi reddetmek eski paketleri kilitler; uyari dogru denge).
    # V4 zafiyet raporu [3] fixi: uyari YALNIZCA keyfile KORUMASI OLMAYAN
    # paketlerde gosterilir. Keyfile korumali pakette perde entropisi
    # ikincildir (asil koruma ikinci faktor keyfile'dadir) - zayif perde
    # uyarisi orada YANLIS ALARM olur. kf_flag header'dan okunur; header
    # okunamazsa False varsayilir (eskisi gibi uyari cikar, decrypt_file
    # zaten hata verecektir).
    # V5.3 zafiyet raporu [7] notu (BILGI): kf_flag icin dosya BURADA bir
    # kez daha acilir (kucuk bir okuma; encrypt tarafinda zaten bir kez
    # acildi). Bu BILINCLIDIR - yalnizca UYARI gosterme karari icindir;
    # yetkili dogrulama decrypt_file icinde yapilir (kf_flag'i header'dan
    # kendisi yeniden okur). Arada dosya degisirse kf_flag yalnizca uyari
    # metnini etkiler, sifreleme dogrulugu etkilenmez (TOCTOU zararsiz).
    try:
        with open(args.file, "rb") as fin:
            _hdr = fin.read(hc.HEADER_BYTES)
        kf_flag = bool(hc.parse_header(_hdr).flags & hc.FLAG_KEYFILE)
    except Exception:
        kf_flag = False
    guesses = None
    try:
        guesses, _ = hc.check_passphrase_strength(pw)
    except ValueError as exc:
        # V5.7 BULGU-1 (derinlik savunma): gucluk tahmini burada yalnizca
        # UYARI amaclidir; asil dogrulama decrypt_file icindeki HMAC'dir.
        # Tahmin motoru hata verirse uyari atlanir, COZME DEVAM EDER
        # (fail-closed guvenlik kapisi yalnizca encrypt yolundadir).
        print(f"BILGI: passphrase gucluk tahmini atlandi ({exc})",
              file=sys.stderr)
    if (guesses is not None
            and not kf_flag
            and guesses < hc.PASSPHRASE_MIN_GUESSES_LOG10):
        print(f"UYARI: zayif passphrase (tahmini 10^{guesses:.1f} deneme) - "
              f"bu dosya brute-force'a karsi korumasiz olabilir.",
              file=sys.stderr)
    keyfile = None
    if args.key_file:
        keyfile = hc.read_keyfile(args.key_file)
    t0 = time.time()
    last = [0.0]
    warned = [False]   # [28] progress hatasi bir kez loglanir

    def prog(done, total):
        try:   # [28] hatali UI callback'i islemi iptal etmesin
            now = time.time()
            if now - last[0] > 0.2 or done == total:
                _progress(done, total, "Cozuluyor")
                last[0] = now
        except Exception as e:
            if not warned[0]:
                print(f"UYARI: ilerleme gosterimi hata verdi "
                      f"({e}) - gosterim kapatildi", file=sys.stderr)
                warned[0] = True

    hc.decrypt_file(args.file, out, pw, keyfile=keyfile, progress=prog)
    dt = time.time() - t0
    size = os.path.getsize(out)
    if not args.quiet:
        print()
        print(f"[OK] {args.file} -> {out}")
        if sys.stdout.isatty():
            print(f"     {size:,} byte cozuldu | {dt:.2f}s "
                  f"| HMAC dogrulamasi GECTI")
    elif not sys.stdout.isatty():
        print(f"[OK] {args.file} -> {out}")


def cmd_selftest(args):
    # Zafiyet raporu [25]: eski selftest yalnizca portable yolu test ediyordu.
    # Simdi: portable + DONANIM-BAGLI roundtrip + gecici dosya ile
    # encrypt_file/decrypt_file (atomic tmp yolu dahil).
    print("Kendini test: roundtrip (portable + donanim-bagli) + dosya API...")
    pw = "selftest-passphrase"
    data = secrets.token_bytes(65537)  # 64 KiB + 1 byte -> rotasyon siniri asimi

    # 1) portable bellek roundtrip + kurcalama tespiti
    enc = hc.encrypt(data, pw, use_hardware=False, kdf_n=1 << 16)
    dec = hc.decrypt(enc, pw)
    if dec != data:
        raise CliError("portable roundtrip bozuk! cipher durumu sagliksiz.")
    tampered = bytearray(enc)
    tampered[len(tampered) // 2] ^= 0xFF
    try:
        hc.decrypt(bytes(tampered), pw)
    except hc.CipherError:
        pass
    else:
        raise CliError("kurcalanmis veri dogrulandi! HMAC calismiyor.")

    # 2) donanim-bagli roundtrip (fp toplama + fp_hash yolu)
    enc_hw = hc.encrypt(data, pw, use_hardware=True, kdf_n=1 << 16)
    if hc.decrypt(enc_hw, pw) != data:
        raise CliError("donanim-bagli roundtrip bozuk! fp yolu sagliksiz.")

    # 3) gecici dosya ile encrypt_file/decrypt_file (atomic tmp, fsync)
    fd, inp = tempfile.mkstemp(prefix="hyp_self_", suffix=".bin")
    os.close(fd)
    out_hyp = inp + ".hyp"
    out_dec = inp + ".dec"
    try:
        with open(inp, "wb") as f:
            f.write(data)
        hc.encrypt_file(inp, out_hyp, pw, use_hardware=False,
                        kdf_n=1 << 16)
        hc.decrypt_file(out_hyp, out_dec, pw)
        with open(out_dec, "rb") as f:
            if f.read() != data:
                raise CliError("dosya API roundtrip bozuk!")
    finally:
        for p in (inp, out_hyp, out_dec):
            try:
                os.remove(p)
            except OSError:
                pass
    print("[OK] SELF-TEST GECTI: roundtrip + kurcalama tespiti + "
          "donanim-bagli + dosya API calisiyor.")


def cmd_generate_keyfile(args):
    """generate-keyfile: ikinci faktor (keyfile) uretir.

    v5: Bu dosya, passphrase ile birlikte master key'in TAMAMLAYICISIDIR.
    USB/flash'ta ayri saklayin - sifrelenmis dosyalari keyfile olmadan
    hicbir saldirgan (perdeyi bilse bile) acamaz.
    """
    try:
        path = hc.generate_keyfile(args.out, length=args.bytes)
    except (ValueError, OSError) as e:
        raise CliError(f"generate-keyfile: {e}")
    size = os.path.getsize(path)
    bits = size * 8
    print(f"[OK] keyfile uretildi: {path} ({size} byte = {bits} bit entropi)")
    print("     BU DOSYAYI GUVENDE TUTUN ve yedekleyin. Kaybolursa")
    print("     keyfile ile sifrelenmis dosyalar KALICI olarak acilamaz.")
    print("     Ayrica kopyalarini GUVENLİ bir yerde saklayin - perde ile")
    print("     birlikte ele gecirilirse koruma kaybolur.")


def cmd_generate_passphrase(args):
    """generate-passphrase: Diceware (EFF 7776 kelime) perde uretir.

    6 kelime ~= 77.5 bit entropi - brute-force icin evrenin yasindan uzun.
    Akilda tutmasi 16 rastgele karakterden cok daha kolay.
    """
    try:
        pw = hc.generate_passphrase(args.words)
    except ValueError as e:
        raise CliError(f"generate-passphrase: {e}")
    guesses, feedback = hc.check_passphrase_strength(pw)
    bits = guesses * 3.321928  # log2(10^guesses)
    print("Passphrase (asagidaki perdeyi girin):")
    print(f"  {pw}")
    print(f"Tahmini gucluk: 10^{guesses:.1f} deneme "
          f"({bits:.1f} bit entropi) - {feedback}")


def main():
    # Zafiyet raporu [24]: yonlendirilmis stdout'ta konsol kod sayfasi
    # UnicodeEncodeError firlatir (Turkce/emoji dosya adlari) -> traceback
    # ve veri kaybi. UTF-8 + backslashreplace ile pipe'ta da temiz cikti.
    for stream in (sys.stdout, sys.stderr):
        # getattr: TextIO tipinde reconfigure yok (Pyright) - TextIOWrapper
        # alt tipinde var; getattr ile tip-guvenli erisim.
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="backslashreplace")
        except (AttributeError, ValueError):
            pass  # reconfigure desteklemeyen ortam (bazi embed'ler)

    p = argparse.ArgumentParser(
        prog="hcli",
        description="HyperCipher v5 - 2048-bit donanim bagli rotasyonlu "
                    "stream cipher",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    p_hash = sub.add_parser("hash", help="makine parmak izi ozetini goster")
    p_hash.add_argument("--full", action="store_true",
                        help="tam bilesenleri de yazdir (HASSAS - "
                             "anahtar materyalinin parcasi)")
    p_hash.set_defaults(fn=cmd_hash)

    p_enc = sub.add_parser("encrypt", help="dosya sifrele")
    p_enc.add_argument("file")
    p_enc.add_argument("--out", help="cikti dosyasi (varsayilan: FILE.hyp)")
    p_enc.add_argument("--force", action="store_true",
                       help="hedef dosya varsa uzerine yaz (varsayilan: RED)")
    p_enc.add_argument("--portable", action="store_true",
                       help="donanim baglamadan sifrele (tasinabilir paket)")
    p_enc.add_argument("--quiet", action="store_true",
                       help="progress/istatistik ciktisini kapat")
    p_enc.add_argument("--passphrase-file",
                       help="passphrase'i dosyadan oku (0600 zorunlu; "
                            "tty yoksa tek yol)")
    p_enc.add_argument("--rotation", type=int, default=hc.ROTATION_BYTES,
                       help=f"rotasyon araligi byte (varsayilan: "
                            f"{hc.ROTATION_BYTES})")
    p_enc.add_argument("--kdf-n", type=int, default=hc.DEFAULT_KDF_N,
                       help=f"Argon2id memory_cost KiB (2'nin kuvveti; "
                            f"varsayilan: {hc.DEFAULT_KDF_N}, "
                            f"~{hc.DEFAULT_KDF_N//1024} MiB bellek)")
    p_enc.add_argument("--pad-to", type=int, default=None,
                       help="dolgu blogu boyutu - ciphertext uzunlugu bu "
                            "sayinin kati olur, dosya boyutu plaintext "
                            "boyutunu ifsa etmez (ISO 7816-4, [16,65536])")
    p_enc.add_argument("--key-file",
                       help="ikinci faktor keyfile dosyasi (>=32 byte, "
                            "or: generate-keyfile ile uretilir). Verilirse "
                            "perde VE keyfile birlikte gerekli olur - zayif "
                            "perde tek basina artik ise yaramaz (v5)")
    p_enc.add_argument("--allow-weak",
                       action="store_true",
                       help="zayif passphrase ile sifrelemeye izin ver "
                            "(ONERILMEZ - brute-force saldirisina acik; "
                            "keyfile kullanmak cok daha guvenli)")
    p_enc.set_defaults(fn=cmd_encrypt)

    p_dec = sub.add_parser("decrypt", help="dosya coz")
    p_dec.add_argument("file")
    p_dec.add_argument("--out", help="cikti dosyasi")
    p_dec.add_argument("--force", action="store_true",
                       help="hedef dosya varsa uzerine yaz (varsayilan: RED)")
    p_dec.add_argument("--quiet", action="store_true",
                       help="progress/istatistik ciktisini kapat")
    p_dec.add_argument("--passphrase-file",
                       help="passphrase'i dosyadan oku (0600 zorunlu; "
                            "tty yoksa tek yol)")
    p_dec.add_argument("--key-file",
                       help="ikinci faktor keyfile dosyasi (paket keyfile "
                            "ile sifrelenmisse ZORUNLU - v5)")
    p_dec.set_defaults(fn=cmd_decrypt)

    p_self = sub.add_parser("selftest", help="hizli kendini test")
    p_self.set_defaults(fn=cmd_selftest)

    p_kf = sub.add_parser("generate-keyfile", help="v5: ikinci faktor keyfile uret")
    p_kf.add_argument("out", help="keyfile yazilacak dosya yolu")
    p_kf.add_argument("--bytes", type=int, default=hc.KEYFILE_RECOMMENDED_BYTES,
                      help=f"keyfile boyutu (varsayilan: "
                           f"{hc.KEYFILE_RECOMMENDED_BYTES} = "
                           f"{hc.KEYFILE_RECOMMENDED_BYTES * 8} bit)")
    p_kf.set_defaults(fn=cmd_generate_keyfile)

    p_gp = sub.add_parser("generate-passphrase",
                          help="v5: Diceware perde uret (6 kelime ~= 77.5 bit)")
    p_gp.add_argument("--words", type=int, default=6,
                      help="kelime sayisi (varsayilan: 6 ~= 77.5 bit; "
                           "5=64.6, 7=90.4)")
    p_gp.set_defaults(fn=cmd_generate_passphrase)

    args = p.parse_args()
    # Girdi dosyasi kontrolu (cmd_hash/selftest disinda)
    # Zafiyet raporu [21]: eksik girdi dosyasi = KULLANIM hatasi -> 2.
    if args.cmd in ("encrypt", "decrypt") and not os.path.isfile(args.file):
        print(f"HATA: girdi dosyasi bulunamadi: {args.file}", file=sys.stderr)
        sys.exit(2)
    try:
        args.fn(args)
    except CliError as e:
        print(f"HATA: {e}", file=sys.stderr)
        sys.exit(1)
    except hc.CipherError as e:
        print(f"HATA: {e}", file=sys.stderr)
        sys.exit(1)
    except OSError as e:
        print(f"HATA: dosya/disk sorunu: {e}", file=sys.stderr)
        sys.exit(1)
    except (ValueError, UnicodeError) as e:
        # Zafiyet raporu [21]: yakalanmayan ValueError/UnicodeEncodeError
        # traceback yerine temiz mesaj + 1.
        print(f"HATA: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nIptal edildi.", file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    main()
