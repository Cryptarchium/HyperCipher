# -*- coding: utf-8 -*-
"""HyperCipher v1 - PROFESYONEL TEST TAKIMI.

Icerik:
  1. Altin vektor (Known-Answer Test) - sabit girdiler -> sabit hex cikti
  2. NIST SP800-22 STS (ststests.py motoru) - 3 bagimsiz keystream
  3. AES-256-CTR kalibrasyonu (STS motorunun saglamliginin kaniti)
  4. Istatistik: chi-square, min-entropy, sikistirilamazlik, blok tekrari
  5. Avalanche: master-key / nonce / subkey-zinciri / passphrase
  6. Concurrency: 8 thread paralel roundtrip
  7. Cross-API: encrypt() ile encrypt_file() birebir ayni cikti
  8. Atomicity: basarisiz islem asla yarim dosya birakmaz
  9. Format: v1 paketleri reddedilir, tum header bolgeleri kurcalanmali
"""

import math
import os
import shutil
import tempfile
import time
import unittest
import zlib
from concurrent.futures import ThreadPoolExecutor

import hyper_cipher as hc
import ststests as sts

# V5.3 zafiyet raporu [1] fix'i opt-in: deterministic test API (sabit
# salt/nonce) yalnizca test ortaminda calisir. `python -m unittest` altinda
# conftest.py yuklenmez -> burada acilir. (pytest altinda conftest ayni
# seyi yapar; cift opt-in zararsiz.)
hc._DETERMINISTIC_MODE = True

try:
    from Crypto.Cipher import AES as _CryptoAES
    HAVE_CRYPTO = True
except ImportError:
    _CryptoAES = None   # skipUnless(HAVE_CRYPTO) runtime'da atlar (Pyright)
    HAVE_CRYPTO = False

PW = "professional-test-passphrase-2048"
SALT = b"\x55" * 32
NONCE_A = b"\x10" * 24
NONCE_B = b"\x20" * 24
NONCE_C = b"\x30" * 24
KDF_N = 1 << 14   # 16 MiB Argon2id - test hizi (varsayilan 2^17 degil)

# Altin vektor: 4121 byte -> 4+ rotasyon (1024'te) + yuzlerce keystream blogu
# pinlenir; subkey zinciri ve blok sayaci kodunda regresyon yakalanir ([31]).
# encrypt(GOLDEN_DATA, "golden-passphrase-2026", use_hardware=False,
#         salt=b"\x01"*32, nonce=b"\x02"*24, kdf_n=1<<14)
GOLDEN = bytes.fromhex(
    "04000004004000000101010101010101010101010101010101010101010101010101010101010101"
    "02020202020202020202020202020202020202020202020200000000000000000000000000000000"
    "00000000000000000000000000000000191000000000000080522385a28917ee94ce71a4d02b0006"
    "1431ab4c19a0cde17f54ce5a96b9f0f6db4504894a6ad2171077c0857bad4bb7191a658af2840fc6"
    "5bcee5d2b94b8325215ae1ef3bf8f346222ea7473b9b2c03001af874e466036117a8174ec5d416bf"
    "77132005c028d4d9dc937cecdf48169ebcf88e9525b9793572dba57a2e26986947bb6495438d853f"
    "fca92d5aae5817442f04879e0e31e40ecc3a3d5047dd83aa23237d4bdc973a1ccb0d170e6170054d"
    "1e3bfef8a3c3ec36175417a6ddfbbbd3bef96c50c4b5e3e0ccab3ea20e91ff2e19196888f2ff08e7"
    "27edf7c725861443438ab2e6dc944a90ed71c72957c0b1e438fb3048de94952e3ff6952c2d07e74a"
    "e1672b3381c4f58ec444acdc6728af03f87df0da7014d9ea53104e24a85492dd385f78ab580b4492"
    "7f104c49d9a8644979b74a3960e430ac254896d1ee730cace0c71c55e9008c984cee8246604d4b8d"
    "42af0b467be30f0d768ce802eb9e48a42f304ced85dc75cf8160e051f42db2d852d6180c0534f869"
    "539fe10c997274ecea84cceab600faee90a1e82b3bc31baa19e52781e0cbf1ae843a34cdfcc122ae"
    "581758d3c599e0281a050379f63925c4b5188ef1041aac439635fc1f895d27dda6744284be33625e"
    "2e2a336075b661fd19be72989c4e17bca37971295bb48df1dcd40c979b0f60ef57169b6cec513c9c"
    "df693a3c1ac9d7945af7dfc7c5550d242c7ba3f3b823d3cbbec597e7b3523ffae5a3064d1147d944"
    "7fd370cae35c18ca42bfce6ea348f80ffe1d8fba9eba9dc780bd7de08c966e1fb475e2baef1297b1"
    "04a18d09fceb0549345b61850f7098383b633e7382bf6bc663dc52eacad2c1cb0fffc160f692e90e"
    "711e7e51184b4f241cfc4a677ab02138a2bf9e00ce372e3d7dd566496926c8372a9d2163f5cbd639"
    "6dffe3b62f699d0b6bfd00a24d7eac52ef95f3929495166ec014aebb1e000d38bd5175d7331e897e"
    "d8d962cff3b0efbecfa4a6403846388311657cbab7056dc995badd16f3a92f944d41d9b94cbcecaf"
    "348ad9e2544626fcb9691e2d671c3211acbbb8118bc1660ff5e67c56284c6ed9025e015322051fde"
    "976a3c8dcd3a1b304b0d332610a686ccfbceda7dd13aa9d7a4b06f244628d7b38c0b2828bd14850d"
    "f7473e482922b624ecfa9326131e7ac953c044bdb28a19afe1a171c1e044040a5a657ba0d21794ba"
    "df620ea69f0acbadbbbb3cd55a2169366030ad738991bbd151dce6e60e3cff88e1786f8a72b36df7"
    "d31a944e7a795650d2e17f7001fdb582fe87860e91a07c3b6181c5941e3a32d30ec6225ded9b5e3c"
    "5eee786d72f10eb9838e0bc48fc345ae96b2fd9cbb3da9bb2c86b96af4308baa46efe8bc11b654d0"
    "8a073409212c09c06ce1d1f87573f8a6a1fd8194fb628c9606cee44d6ce5af319b51a0fb7f2e4b09"
    "20401d80bbf9fc611442718472b512388b35948227e11788b5110d866bb5c13afa60ef6c39bdc9ec"
    "940c56779f4e7057c3949a74406809af927674c40418d4d15b4a8a410386fae04fcb3d442e96c410"
    "90a2a84363b60c0947128189cc76e81bd36bb96b0d5c3392698e2f18ac6f82b22fc6f5989b3fffe2"
    "06eb53170e28bee5364693724b5ffbe39a3b290a1ed4a6c4e748169dddd6c899c0b9e5cc96f0f68c"
    "5f2f501a66b7d09edad6694ddc65f2ede1198483205fac3b3e4a61ef8b8563aacc564c20312b2ebb"
    "738fcf2103c45a7a85e1aa96d92f7945eeb25052dc2a56bf9a07cddc7707e375d73737af1de27b3c"
    "d9d22b5035b8090b66615ad373cfe2975e66c8de1b74b36457c9f09e3f792029d0e2a787270af9c6"
    "b6b4f926a49a9e90be03de60ff31771b5487b6a343ab485824672d7a9864880ce16a11b9f6331bd1"
    "2bdcac8f695b427c2febf9fcfd70f4bd78ae1eef9da70ed46e23f4f32ea510c8e88599d97657e80f"
    "3f1ea4f4735263dcf49aba2a7030ce264819a36cbe9a8ce5d449dbe9628f57325459974dfc54ba9c"
    "2e61e968391e08e305b19742977708336e59178343b8ff0e49ed9c08194707b8fa709c12d9d5c2d2"
    "a79c6dc9fbe562298d6e736e78bb25f2347b900b422d62d412f8c3883c60bad827ee7c5061bc37ce"
    "d78aae339d6e090948e8492dbd2be88e346b08c2e58dec080da688b23780b4ecf85d07acf3586555"
    "b95cd3e416dc3f9a932245b9cf0b42fbeecb2a4cf60d6429a77d41b24a5eed313ebec93295cc16a7"
    "e73f2e06d7fdb52f84b2b8e7a3d08c9cda1ab8f26f2c5becf6df9f66cb2e589b1dcbe38c5d46a165"
    "4b82529218a4945ed67bd672f4790add1ac69e2eb6b50b0c673686e71277decea2b75e956d2e8f82"
    "e32ef99e133c7d4a047fbea5e190cb27639c180e7aa34e3fe03bed62976bef2f3e0e149c0ed9cdd5"
    "7357300b7258e6172188dd872905655e69f0e9946c0b8cb8ef13c0af39e911141c645f4184299e13"
    "72681adfbce7c9bd6b81e2954357467384f8f4081a90b081bb0bf7dab449363b555fd301de69e299"
    "f33d038aa79a259e7096bfc9b7a8b1f3729e657b165f1bba5401b3989e1787d1608fdeb03fd9f3d6"
    "b7aaea8b42e140adce84998f04397cb92b873aedc50ca53a5767595c71663ee6694f76c2b946ce0d"
    "3b2ff772c308d4c719e5885d36ffa87bfc6f9261c654011df36ddc44ad4baa3a376ef56aa5a30b1a"
    "32a54ed725093d7b9df2b8457fbba7d678fa414a1b32ab0c060b79fc95836df77ed1ae1b2ffbe629"
    "6b0a6ac3b96ccba34480b7164c27902412a2c79b01fe4bf0396e4aa15a10062ea3a88cefd2e9cd0f"
    "95512870e061ef118c1f20017d6715afded8c5c30b8ec14fccc305d9f811c096b8bae6244d9c4959"
    "2c9f5bccbc0b1fd375c91bd23a91bc4c017de77e9f725a50cede9f73cf7bf89be5f832cd11c3b39f"
    "93794eb071adc20395a2e94b727791a77b868a6327bbb1a17c0680d71b2c959f367100571aad6e64"
    "06f6c9412482738dc7d7e1a761fe1954f8c23831d12d30750df4ebf559f1ed30119dabbee284730c"
    "10f2b34379e1774cd6dbcbbe2dece26295e1e91f8447030110515324ebb895ce608cc0ea8a05bc7b"
    "cd19c5e7d67ed632b96e9a48c809ba0b037e457f7d21a54f89c61ca643a3043a638527a8ca5fbafa"
    "aa0472c474afb01f426a972813a8c4e5bfd3078ae70c9a2917cb4cbd3fce52338f8565f04070af65"
    "58297a853ae339e3d77c644cbd2e0763e05463e8f89b793f38db3c076bab2333346e7b09af6c32bb"
    "65dab725e0ed579fc16b7a162987e1ba6e7faaa407ab95536956af2e6e1624371f41d58b957ea2af"
    "68feb528a89d8a0d8b88b8ba88a46441c28d7d5d8e92a8fee2f8f1c51e42e9011986b413fb48386f"
    "20e3899e393d7c6c10467988102dae78a70ae4a02e7694e32b0a8d2d2561d8daf8c202ada3a878d9"
    "0af8b9b2d006ce7f03e629b9774f6bffba06f349ca40a009685e549a965d55f6ff5de80664a91842"
    "c453386ae2cf9360db4910060de7491ab62b7c0764e7d4ea161e753d5aa776c6bddb9e673d237b23"
    "114ec4273bbb63e5c0125bd67389faba3a76c027102eed6d646ebfd48a1e54bd6ed3a6f8312212b0"
    "a85b31e853235999246819c49683a7eeb5ee9c0e56856c162e18061f34780e3d3b32d0e373f1df24"
    "cf629b482594b532f2ad0492ba73975856d5499a07f7bd291cf76cabe3cabc39acc13d802a9e6aa9"
    "468e44d73851c42ff927a3fc2f07d0d173eb153093bba4560824dc153e1b1b7e4983b3b8625f1cf1"
    "9574a333d1ef68d4c40db130d98d9ab73d14a154676bebf19f406948f05191b6148865735957fef4"
    "aea2483a1ebcf1cb62a270d1cd6a85a9b2ae963baa42e8f17efa51eb10b29777fa4f74359d513e68"
    "3c4d5796eadb2b11c9fb3dec935439aac8a91c9d644dcc76bc1eef3c5a32dc25dd172a861c3e619e"
    "2267858247b23d1f1a9fe58d4ea5ec253ad7d1b75866cffbef157364bc1cea392594a0951ea4339c"
    "fed55e3b59ce22519c362514c22bd477630b291704ebfed928c412ac04365c4a378598ce74be452a"
    "396ce69036aed876e7608f5bba2ab661745e575320ea5ab385ee2dedff7744a18bb16d11ee6a2b75"
    "83ef26372aa451fd78cfff2103d9e8aec5fc1b1819aca557df11412610c98986e1c1e48d68941067"
    "f549418a97d928219183bf82efad12b8322afbb974838a6981609e0ad1eed94dc5d6851ce73b32e3"
    "f9106ba4ca71ad7184d325ec6407f252892b2a1c0a3c56c0f622b1fdb88ab353e934d1f7f32e8b4c"
    "5b7b0813f83dcae3f43e21c4425b1f0b07b99f92cba1583f61116285571b2f81c933b7eeb556842c"
    "d74506bfceb4bab4f6551d1f51521546919df11dbb45b0765ccb0b367cb14b0142f3ffe5b5a4d8c7"
    "158a3d54da7b882a4dc3aea05b61e904e672486d474134e74568775045e6d7bee03d4eb88f065743"
    "fe6d6f1c1ef6eaf4b6f5892e0b6ef8be8fc2adc6655e40ace75a194ec93e84fa401cf8f4324280ea"
    "cbd4d7ff9cb8c59e4f635ee6bf533d50f26734f9bd903ad850fcfcf19a1fa49406b44e5d72cefe65"
    "56453a74720b424e694336832ba392ac49acd31a8162f0c8ab20b3bf73d2cc8abb4bcd73c34ba433"
    "728553cb339b0145b1fb872a838d7f81e3fac1a11e974cc6249e1364ce8027a776ccf8424c7ac2ac"
    "752fc0a453fe63de2c9e5719a1607dd4ca1b56d1c3a2777d2ec3052e4a6bd86e750bce59425d4dfb"
    "d8d8fbc46293372ee22735365e2056deacade230cfdc0b4c3c1832b2b2f17d504147d5e50cff0ef0"
    "4116f58c67ce769a45bc1e6e2c4b75890c5256d51739c2d53732afb408d2fe1a35630bc87b877115"
    "07d6d12d29d01567a95c017e3a068a4fcec906664b531ad050ac7a0304278ba920feb65511f79dce"
    "0c5e0c09a7c0b70f8edf5afe931145a5b2266e5d64e4cb6ed76f8390c2afb9239d8cccccbea1f9fc"
    "cb3994c2169d6f678d58b064498dbe55684ced5891f7fa7f5aa6d5e19e0056056ff2b1ee46f659bd"
    "f205849662530efdef280c2ebc99dc1d352d76a97e737afe0fcf254593b9bc53d5e65969f2c2d4e1"
    "5832b5d1c99c6ea086949b1602ff7f4cbb5127a2675d62eb4fbbe1ea8c5c409a27d87c8eb6826969"
    "8b8bddcfc26fbaf9b59cca5e10bdda9556883f10b084929b036daae12ba8df864a6eaf282fd97887"
    "2b0f39c1ddd7db17a82425e55f6665f034532055b9372946f0b6204472f51418050b852d6967308c"
    "9843cfd0b99a195aac6928614a5d6272a4909e5a179d9cbe61ff38ec885662ec76f11425d3b4b36c"
    "9c5ef85cacd7edbcc6b7cb8401c0d902623b234ae731dc86e2492910ccc7855be36b50fcf1869236"
    "e13c2cb4a7063e002ccdf7344da618e1553f6e7f19215df103815dfc504c8815ba8134bab1a02b73"
    "05950cf488f302af428d8da4dac04c8908cc15973857a97c12289806a59a3ff8c1c507bf54b3030a"
    "6a1851e8acac51997bc1209b33c99cb9e4d04459891f9fc15ba251dbcd0d4d211c15e8b74726d9df"
    "5e03f485d0f2ba47ec5da1dd2218fad40c8d02da41ec9c7837b17991d801d0f1e63d553a72e2dba1"
    "5cfdd7c06900b99fa2b124dac6c94525ec4929763ab38e6fdb714427955dc0e57eb03ed6b0fd44fb"
    "b333b7f985c6ec0899be4cabb3ea5e7b91dd95048936e90a5ca5226f9d98d1de705d8edbeb979a44"
    "13956b2ac9709c3a64298e76e95d2d542721af1ae2787f8f8ba430f46785a68f7fe059b426d720ee"
    "c4f09e3ba1f7c49600bf97a958c2edb9fb9ace34a9394873c3f273d2a9946be150947e36ec80a24d"
    "fd90e60f3955220b036b7dafa2e57e93de29f6b3d014e7300128f99c8085ea4011a637e36fd47e41"
    "8fe8dfdf0a4df13cb81b99fe094b6eb29c48d01a9fd8f89227a90ce231f77ff53ed78368700115bb"
    "d41f828cce6fd07b8d")
GOLDEN_DATA = (b"GOLDEN-V3-ROTATION-CHAIN-" * 170)[:4096] + \
    b"|son-4096-bayt-dogrulama|"
GOLDEN_PW = "golden-passphrase-2026"


def _keystream(nonce: bytes, nbytes: int = 32768) -> bytes:
    """Sifir-metnin ciphertext'i = saf keystream (STS girdisi)."""
    enc = hc._encrypt_deterministic(b"\x00" * nbytes, PW,
                                    use_hardware=False, salt=SALT,
                                    nonce=nonce, kdf_n=KDF_N)
    return enc[hc.HEADER_BYTES:-hc.TAG_BYTES]


def _bit_diff_ratio(a: bytes, b: bytes) -> float:
    if len(a) != len(b):
        return 1.0
    diff = sum((x ^ y).bit_count() for x, y in zip(a, b))
    return diff / (len(a) * 8)


# ---------------------------------------------------------------------------
class TestGoldenVector(unittest.TestCase):
    """Known-Answer Test: herhangi bir kod degisikligi ciktiyi bozarsa yakalanir."""

    def test_known_answer(self):
        enc = hc._encrypt_deterministic(GOLDEN_DATA, GOLDEN_PW,
                                        use_hardware=False,
                                        salt=b"\x01" * 32, nonce=b"\x02" * 24,
                                        kdf_n=1 << 14)
        self.assertEqual(enc, GOLDEN)

    def test_golden_roundtrip(self):
        self.assertEqual(hc.decrypt(GOLDEN, GOLDEN_PW), GOLDEN_DATA)

    def test_golden_header_fields(self):
        h = hc.parse_header(GOLDEN[:hc.HEADER_BYTES])
        self.assertEqual(h.version, 4)
        self.assertEqual(h.data_len, len(GOLDEN_DATA))
        self.assertFalse(h.flags & hc.FLAG_HARDWARE)
        # rotation_bytes header'a gomulmeli (varsayilan 1024 = 0x0400 LE)
        self.assertEqual(h.rotation_bytes, 1024)
        self.assertEqual(GOLDEN[2:4], b"\x00\x04")
        # kdf_n header'a gomulmeli (1<<14 = 0x4000 LE)
        self.assertEqual(h.kdf_n, 1 << 14)
        self.assertEqual(GOLDEN[4:8], b"\x00\x40\x00\x00")
        # KASITLI: magic yok - paket random veri gibi gorunur
        self.assertNotIn(b"HYPRC1", GOLDEN[:hc.HEADER_BYTES])

    def test_wrong_rotation_impossible(self):
        """GUCLU GUVENLIK: rotation_bytes header'dan okunur - kullanici yanlis
        rotation veremez (sessiz bozuk plaintext senaryosu kapatildi)."""
        data = os.urandom(5000)
        pw = "rotation-test"
        # 512 ile sifrele -> header'da 512 saklanir
        enc = hc.encrypt(data, pw, use_hardware=False,
                         rotation_bytes=512, kdf_n=KDF_N)
        self.assertEqual(
            hc.parse_header(enc[:hc.HEADER_BYTES]).rotation_bytes, 512)
        # decrypt parametre BILE ALMAZ - dogru rotation otomatik kullanilir
        self.assertEqual(hc.decrypt(enc, pw), data)
        # eski format (rotation alani 0) varsayilana doner
        legacy = bytearray(enc)
        legacy[2:4] = b"\x00\x00"
        h = hc.parse_header(bytes(legacy[:hc.HEADER_BYTES]))
        self.assertEqual(h.rotation_bytes, hc.ROTATION_BYTES)


# ---------------------------------------------------------------------------
class TestNISTSTS(unittest.TestCase):
    """NIST SP800-22: HyperCipher keystream'i rastgeleligin tum testlerini
    gecmeli (p >= 0.01)."""

    def test_hypercipher_keystreams_pass(self):
        """3 nonce x 10 STS testi = 30 p-degeri.

        Coklu karsilastirma dogrulamasi: alpha=0.01 ile tek basina 30 test
        ~%26 sahte-fail riski tasir (1 - 0.99^30). Gercek cipher zayifligi
        TEK testte degil, cogu testte ayni anda patlar. Dogru isleyis:
          - en fazla 2 test p<0.01 olabilir  (sahte-fail riski ~0.35%)
          - hicbir p < 1e-5 olamaz (felaket bias - 0.03% sahte risk)
        """
        p_values = []
        for nonce in (NONCE_A, NONCE_B, NONCE_C):
            p_values.extend(sts.run_all(_keystream(nonce)).values())
        failures = [p for p in p_values if p < 0.01]
        self.assertLessEqual(
            len(failures), 2,
            f"{len(failures)}/30 test basarisiz: "
            f"{[f'{p:.4f}' for p in failures]}")
        self.assertGreater(
            min(p_values), 1e-5,
            f"felaket bias: min p = {min(p_values):.2e}")

    @unittest.skipUnless(HAVE_CRYPTO, "pycryptodome yok - kalibrasyon atlandi")
    def test_aes_calibration(self):
        """STS motorunun saglam oldugunun kaniti: bilinen-iyi cipher gecmeli.
        [32] Sabit key/nonce -> deterministik (flaky %9.6 kaynagi kaldi)."""
        assert _CryptoAES is not None   # skipUnless garantisi (Pyright)
        key = b"AES-CALIBRATION-FIXED-KEY-32BYTE"   # tam 32 byte
        nonce = b"\x00\x01\x02\x03\x04\x05\x06\x07"
        aes = _CryptoAES.new(key, _CryptoAES.MODE_CTR, nonce=nonce)
        ks = aes.encrypt(b"\x00" * 32768)
        self.assertTrue(sts.all_pass(sts.run_all(ks)),
                        "AES keystream bile STS'den gecmedi - motor bozuk")

    @unittest.skipUnless(HAVE_CRYPTO, "pycryptodome yok")
    def test_aes_vs_hypercipher_direct_comparison(self):
        """Iki cipherin keystreamleri istatistiksel olarak ayirt edilememeli."""
        assert _CryptoAES is not None   # skipUnless garantisi (Pyright)
        key = b"AES-CALIBRATION-FIXED-KEY-32BYTE"
        nonce = b"\x00\x01\x02\x03\x04\x05\x06\x07"
        aes_ks = _CryptoAES.new(key, _CryptoAES.MODE_CTR,
                                nonce=nonce).encrypt(b"\x00" * 32768)
        hyp_ks = _keystream(NONCE_C)
        r = _bit_diff_ratio(aes_ks, hyp_ks)
        self.assertAlmostEqual(r, 0.5, delta=0.01,
                               msg="keystreamler bagimli gorunuyor")


# ---------------------------------------------------------------------------
class TestStatistical(unittest.TestCase):
    """Istatistiksel guclu testler (paylasilan 128 KiB keystream uzerinde)."""

    ks: bytes = b""

    @classmethod
    def setUpClass(cls):
        cls.ks = _keystream(NONCE_A, 128 * 1024)

    def test_chi_square_uniformity(self):
        counts = [0] * 256
        for b in self.ks:
            counts[b] += 1
        expected = len(self.ks) / 256
        chi2 = sum((c - expected) ** 2 / expected for c in counts)
        p = sts._chi2_pvalue(chi2, 255)
        self.assertGreater(p, 0.001, f"chi-square p={p:.2e} - bias var")

    def test_min_entropy_per_byte(self):
        counts = [0] * 256
        for b in self.ks:
            counts[b] += 1
        min_ent = -math.log2(max(counts) / len(self.ks))
        self.assertGreater(min_ent, 7.4,
                           f"min-entropy {min_ent:.2f} bit - zayif")

    def test_incompressible(self):
        compressed = len(zlib.compress(self.ks, 9))
        self.assertGreaterEqual(compressed, len(self.ks),
                                "ciphertext sikistirilabiliyor - bias")

    def test_no_keystream_block_repetition(self):
        blocks = {self.ks[i:i + 64] for i in range(0, len(self.ks), 64)}
        self.assertEqual(len(blocks), len(self.ks) // 64,
                         "64-byte blok tekrari bulundu!")


# ---------------------------------------------------------------------------
class TestAvalanche(unittest.TestCase):
    """Avalanche: 1 bit degisim -> ~%50 cikti biti degismeli.

    Istatistiksel dogruluk icin ornekler buyutulur (coklu rotasyon/blok
    birlestirilir) - tek 2048-bit ornekteki dogal dalgalanma (~%1) yanlis
    pozitife yol acmasin diye.
    """

    @staticmethod
    def _subkey_chain(master: bytes, nonce: bytes, steps: int) -> bytes:
        out = b""
        s = master
        for i in range(steps):
            s = hc._derive_subkey(s, master, nonce, i)
            out += s
        return out

    def test_master_bit_flip(self):
        master = os.urandom(256)
        flipped = bytearray(master)
        flipped[0] ^= 1
        a = self._subkey_chain(master, b"\x00" * 24, 16)
        b = self._subkey_chain(bytes(flipped), b"\x00" * 24, 16)
        # 16 x 2048 bit = 32768 bit -> sd ~0.0028, delta 0.015 ~ 5.4sd
        self.assertAlmostEqual(_bit_diff_ratio(a, b), 0.5, delta=0.015)

    def test_nonce_bit_flip(self):
        master = os.urandom(256)
        n0 = b"\x00" * 24
        n1 = b"\x01" + b"\x00" * 23
        a = self._subkey_chain(master, n0, 16)
        b = self._subkey_chain(master, n1, 16)
        self.assertAlmostEqual(_bit_diff_ratio(a, b), 0.5, delta=0.015)

    def test_subkey_chain_avalanche(self):
        master = os.urandom(256)
        nonce = b"\x00" * 24
        s = master
        chain = []
        for i in range(16):
            s = hc._derive_subkey(s, master, nonce, i)
            chain.append(s)
        # 15 ardil ciftin ortalama farki (15 x 2048 bit)
        mean = sum(_bit_diff_ratio(chain[i], chain[i + 1])
                   for i in range(15)) / 15
        self.assertAlmostEqual(mean, 0.5, delta=0.015)

    def test_keystream_blocks_distinct(self):
        """Farkli counter bloklari ayni subkey ile farkli cikti uretmeli.

        (Diversity testi - avalanche degil: giriste bit degisimi yok.)
        """
        sub = os.urandom(256)
        a = b"".join(hc._keystream_block(sub, i) for i in range(32))
        b = b"".join(hc._keystream_block(sub, i) for i in range(32, 64))
        self.assertNotEqual(a, b)

    def test_keystream_subkey_bit_flip_avalanche(self):
        """GERCEK avalanche: subkey'in 1 biti -> keystream ~%50 degismeli.

        32 x 512 bit = 16384 bit -> sd ~0.0039, delta 0.02 ~ 5.1sd.
        """
        sub = os.urandom(256)
        flipped = bytearray(sub)
        flipped[100] ^= 1
        a = b"".join(hc._keystream_block(sub, i) for i in range(32))
        b = b"".join(hc._keystream_block(bytes(flipped), i) for i in range(32))
        self.assertAlmostEqual(_bit_diff_ratio(a, b), 0.5, delta=0.02)

    def test_passphrase_avalanche(self):
        data = os.urandom(8192)
        a = hc._encrypt_deterministic(data, PW, use_hardware=False,
                                      salt=SALT, nonce=NONCE_A, kdf_n=KDF_N)
        b = hc._encrypt_deterministic(data, PW + "x", use_hardware=False,
                                      salt=SALT, nonce=NONCE_A, kdf_n=KDF_N)
        r = _bit_diff_ratio(a[hc.HEADER_BYTES:-hc.TAG_BYTES],
                            b[hc.HEADER_BYTES:-hc.TAG_BYTES])
        self.assertAlmostEqual(r, 0.5, delta=0.01)

    def test_plaintext_bit_changes_exactly_one_byte(self):
        """Stream cipher ozelligi: 1 bit plaintext -> SADECE ayni byte."""
        data = os.urandom(1024)
        a = hc._encrypt_deterministic(data, PW, use_hardware=False,
                                      salt=SALT, nonce=NONCE_A, kdf_n=KDF_N)
        pd = bytearray(data)
        pd[500] ^= 0x40
        b = hc._encrypt_deterministic(bytes(pd), PW, use_hardware=False,
                                      salt=SALT, nonce=NONCE_A, kdf_n=KDF_N)
        body_a = a[hc.HEADER_BYTES:-hc.TAG_BYTES]
        body_b = b[hc.HEADER_BYTES:-hc.TAG_BYTES]
        diffs = [i for i, (x, y) in enumerate(zip(body_a, body_b)) if x != y]
        self.assertEqual(diffs, [500])


# ---------------------------------------------------------------------------
class TestConcurrency(unittest.TestCase):
    def test_parallel_roundtrips(self):
        payloads = [os.urandom(200) for _ in range(50)]

        def worker(i):
            enc = hc.encrypt(payloads[i], PW, use_hardware=False,
                             kdf_n=KDF_N)
            return hc.decrypt(enc, PW) == payloads[i]

        with ThreadPoolExecutor(max_workers=8) as ex:
            results = list(ex.map(worker, range(len(payloads))))
        self.assertTrue(all(results), "paralel islemlerden biri bozuldu")


# ---------------------------------------------------------------------------
class TestCrossAPI(unittest.TestCase):
    def setUp(self):
        # [30] test izolasyonu: CWD-goreli sabit adlar yok
        self.d = tempfile.mkdtemp(prefix="hc_xapi_")

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def test_memory_and_file_api_identical(self):
        data = os.urandom(70_000)          # rotasyon sinirlarini asar
        salt, nonce = os.urandom(32), os.urandom(24)
        mem = hc._encrypt_deterministic(data, PW, use_hardware=False,
                                        salt=salt, nonce=nonce, kdf_n=KDF_N)
        inp = os.path.join(self.d, "_xapi_in.bin")
        hyp = os.path.join(self.d, "_xapi_out.hyp")
        try:
            with open(inp, "wb") as f:
                f.write(data)
            hc._encrypt_file_deterministic(inp, hyp, PW, use_hardware=False,
                                           kdf_n=KDF_N, salt=salt, nonce=nonce)
            with open(hyp, "rb") as f:
                self.assertEqual(mem, f.read())
        finally:
            for p in (inp, hyp, hyp + ".tmp"):
                if os.path.exists(p):
                    os.remove(p)


# ---------------------------------------------------------------------------
class TestAtomicity(unittest.TestCase):
    def setUp(self):
        # [30] test izolasyonu: CWD-goreli sabit adlar yok
        self.d = tempfile.mkdtemp(prefix="hc_atomic_")

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def test_failed_decrypt_leaves_no_output(self):
        inp = os.path.join(self.d, "_at_in.bin")
        hyp = os.path.join(self.d, "_at_in.hyp")
        out = os.path.join(self.d, "_at_out.bin")
        try:
            with open(inp, "wb") as f:
                f.write(os.urandom(100_000))
            hc.encrypt_file(inp, hyp, PW, use_hardware=False, kdf_n=KDF_N)
            with self.assertRaises(hc.CipherError):
                hc.decrypt_file(hyp, out, PW + "YANLIS")
            self.assertFalse(os.path.exists(out))
            leftovers = [n for n in os.listdir(self.d) if ".hyp-" in n]
            self.assertFalse(leftovers, f"tmp kalintisi kaldi: {leftovers}")
        finally:
            for p in (inp, hyp, out):
                if os.path.exists(p):
                    os.remove(p)

    def test_encrypt_failure_leaves_no_partial(self):
        out = os.path.join(self.d, "_never.hyp")
        try:
            with self.assertRaises(OSError):
                hc.encrypt_file(os.path.join(self.d, "_yok_boyle.bin"),
                                out, PW, use_hardware=False)
            self.assertFalse(os.path.exists(out))
            leftovers = [n for n in os.listdir(self.d) if ".hyp-" in n]
            self.assertFalse(leftovers, f"tmp kalintisi kaldi: {leftovers}")
        finally:
            for p in (out,):
                if os.path.exists(p):
                    os.remove(p)

    @unittest.skipUnless(os.name == "nt", "Windows ACL testi")
    def test_windows_tmp_acl_kullaniciya_ozel(self):
        """DENETIM 2 bulgu [1] fix'i: Windows'ta tmp dosya YALNIZCA
        mevcut kullaniciya erisilebilir olmali (protected DACL, kalitim
        yok). mkstemp(0600) Windows'ta ise yaramiyordu - SYSTEM/
        Administrators/Everyone kalitimsal ACL ile okuyabiliyordu."""
        import subprocess
        fd, tmp = hc._make_tmp_near(os.path.join(self.d, "_acl.hyp"))
        os.close(fd)
        try:
            out = subprocess.run(["icacls", tmp], capture_output=True,
                                 text=True, timeout=30)
            self.assertIn("(F)", out.stdout)
            # Saldirgan SID'ler ACL'de OLMAMALI (kalitim engellendi):
            for banned in ("Everyone", "Authenticated Users", "SYSTEM",
                           "BUILTIN\\Administrators"):
                self.assertNotIn(banned, out.stdout,
                                 f"kisitlanmasi gereken SID hala ACL'de: "
                                 f"{banned}")
        finally:
            os.remove(tmp)
            try:
                os.rmdir(self.d)
            except OSError:
                pass


# ---------------------------------------------------------------------------
class TestFormat(unittest.TestCase):
    def test_v1_packet_rejected(self):
        enc = bytearray(hc.encrypt(b"eski format", PW, use_hardware=False,
                                   kdf_n=KDF_N))
        enc[0] = 1  # version byte -> desteklenmeyen surum
        with self.assertRaises(hc.CipherError):
            hc.decrypt(bytes(enc), PW)

    def test_tamper_every_header_region(self):
        enc = bytearray(hc.encrypt(b"her bolge kurcalanmali", PW,
                                   use_hardware=False, kdf_n=KDF_N))
        # Yeni 104-byte header bolgeleri:
        # 0 version, 1 flags, 2-3 rotation, 4-7 kdf_n,
        # 8-39 salt, 40-63 nonce, 64-95 fp_hash, 96-103 data_len
        for off in (0, 1, 2, 4, 8, 40, 64, 96, hc.HEADER_BYTES, -64, -1):
            t = bytearray(enc)
            t[off] ^= 0x01
            with self.assertRaises(hc.CipherError,
                                   msg=f"offset {off} kurcalamasi gecti"):
                hc.decrypt(bytes(t), PW)

    def test_reserved_flags_not_set(self):
        # DENETIM 5 bulgu [12]: maske 0xFE yanlis - bit1 (FLAG_PADDED) ve bit2
        # (FLAG_KEYFILE) GECERLI flag'ler, rezevre degil. Gercek rezevre bitler
        # bit3+ oldugu icin maske 0xF8 olmali (bit0..2 bilincli olarak passe).
        enc = hc.encrypt(b"x", PW, use_hardware=False, kdf_n=KDF_N)
        h = hc.parse_header(enc[:hc.HEADER_BYTES])
        self.assertEqual(h.flags & 0xF8, 0)


# ---------------------------------------------------------------------------
class TestPerformance(unittest.TestCase):
    def test_throughput_smoke(self):
        data = os.urandom(1 << 20)         # 1 MiB
        t0 = time.time()
        enc = hc.encrypt(data, PW, use_hardware=False, kdf_n=KDF_N)
        dt = time.time() - t0
        mbps = len(data) / dt / 1048576
        self.assertEqual(hc.decrypt(enc, PW), data)
        self.assertGreater(mbps, 0.5, f"anormal derecede yavas: {mbps:.1f} MB/s")


if __name__ == "__main__":
    unittest.main()
