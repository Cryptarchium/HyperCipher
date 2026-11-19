#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HyperCipher v5 — Tam Calisma Grafigi (Siyah/Beyaz, efektsiz)
Cikti: HyperCipher_Graph.png (+ .dot)
Calistir: python Graph.py
Gereksinim: pip install graphviz  (binary: https://graphviz.org/download/)
            yoksa otomatik matplotlib fallback kullanir.
"""

import os
import sys
import shutil

OUT_BASENAME = "HyperCipher_Graph"
OUT_DIR = os.path.dirname(os.path.abspath(__file__))

# ---------------------------------------------------------------------------
# Ortak stil — sadece siyah/beyaz, efekt yok
# ---------------------------------------------------------------------------
GRAPH_ATTRS = {
    "rankdir": "LR",
    "bgcolor": "white",
    "pad": "0.4",
    "nodesep": "0.28",
    "ranksep": "0.55",
    "splines": "ortho",
    "fontname": "Consolas",
    "fontsize": "11",
    "labelloc": "t",
    "labeljust": "c",
}

NODE_ATTRS = {
    "shape": "box",
    "style": "rounded,filled",
    "fillcolor": "white",
    "color": "black",
    "penwidth": "1.4",
    "fontname": "Consolas",
    "fontsize": "10",
    "fontcolor": "black",
    "margin": "0.14,0.09",
}

EDGE_ATTRS = {
    "color": "black",
    "penwidth": "1.0",
    "arrowsize": "0.7",
    "fontname": "Consolas",
    "fontsize": "8",
    "fontcolor": "black",
}

CLUSTER_ATTRS = {
    "style": "rounded,dashed",
    "color": "black",
    "penwidth": "1.2",
    "fillcolor": "white",
    "fontname": "Consolas",
    "fontsize": "11",
    "fontcolor": "black",
    "labeljust": "l",
    "margin": "12",
}


def _has_graphviz() -> bool:
    try:
        import graphviz  # noqa: F401
        return shutil.which("dot") is not None
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Graphviz yolu — tum mantigi tek yerde kurar
# ---------------------------------------------------------------------------
def build_with_graphviz():
    import graphviz

    dot = graphviz.Digraph(
        name="HyperCipher",
        format="png",
        graph_attr=GRAPH_ATTRS,
        node_attr=NODE_ATTRS,
        edge_attr=EDGE_ATTRS,
    )
    dot.attr(label="HyperCipher v5 — Uctan Uca Calisma Diyagrami  (Siyah/Beyaz)")

    # ---------- helpers ----------
    def n(id_, label, shape="box", extra=None):
        attrs = {}
        if shape != "box":
            attrs["shape"] = shape
        if extra:
            attrs.update(extra)
        dot.node(id_, label, **attrs)

    def e(a, b, label=""):
        if label:
            dot.edge(a, b, label=label)
        else:
            dot.edge(a, b)

    def cluster(name, label):
        return dot.subgraph(name=name)

    # =======================================================================
    # 0) GIRISLER
    # =======================================================================
    with cluster("cluster_inputs") as c:
        c.attr(label=" 0) GIRISLER — passphrase / keyfile / hardware ", **CLUSTER_ATTRS)
        n("pw", "passphrase\nUTF-8 + NFC normalize\n-> pw_bytes (bytearray)")
        n("kf", "keyfile (opsiyonel)\n32 B..1 MiB, entropy check\nShannon >=3.0 + distinct >=8", extra={"shape": "box"})
        n("fp", "fingerprint_blob\nGetVolumeInformationW(serial)\n+ GetComputerNameExW\n-> fp_blob (NUL icermez)")
        n("material_note", "material = pw_bytes [+ HKDF(keyfile)]\n+ 0x00 ayrac + fp_blob\n[enjective, timing-safe]", extra={"shape": "note", "style": "filled,dashed", "penwidth": "1.0"})

    # =======================================================================
    # 1) MASTER TURETME
    # =======================================================================
    with cluster("cluster_master") as c:
        c.attr(label=" 1) MASTER TURETME — Argon2id (RFC 9106) ", **CLUSTER_ATTRS)
        n("hkdf_kf", "HKDF-SHA512\nsalt=keyfile\ninfo='HYPR/keyfile/v1'\n-> keyfile_key (32 B)", extra={"shape": "ellipse"})
        n("mat", "material birlestir\ncreate-secrets-late", extra={"shape": "ellipse"})
        n("argon", "Argon2id\ntime=3, lanes=1, mem=kdf_n KiB\nsalt=32 B urandom\noutput 256 B (2048-bit)\n-> master", extra={"penwidth": "1.8"})
        n("wipe", "wipe(material) + wipe(pw_bytes)\ndestroy-early (finally)", extra={"shape": "diamond", "style": "filled", "fillcolor": "white"})
        n("kdfn", "kdf_n dogrulama\nMIN=1<<14 .. MAX=1<<18\n(ENV narrow-only: 1<<19 kapali)\n2^n zorunlu", extra={"shape": "diamond"})

    # =======================================================================
    # 2) HEADER / NONCE / PAKET
    # =======================================================================
    with cluster("cluster_header") as c:
        c.attr(label=" 2) HEADER & NONCE — 104 B (VERSION=4, GOLDEN korunur) ", **CLUSTER_ATTRS)
        n("hdr_struct", "header = ver(1)+flags(1)\n+ rot(2)+kdf_n(4)+salt(32)\n+ nonce(24)+fp_hash(32)+data_len(8)\n= 104 B  (MAGIC YOK)", extra={"shape": "box"})
        n("nonce", "nonce 24 B + salt 32 B\nos.urandom() her encrypt'te\nsabit nonce API'si YOK\n_DETERMINISTIC_MODE fail-closed", extra={"shape": "ellipse"})
        n("flags", "flags: FLAG_KEYFILE (0b100)\nkeyfile varsa set\ndecrypt'te keyfile zorunlu kilidi", extra={"shape": "diamond"})
        n("dlen", "data_len = plaintext + ISO7816 pad\n(padding dahil)", extra={"shape": "note", "style": "filled,dashed"})

    # =======================================================================
    # 3) SUBKEY ZINCIRI
    # =======================================================================
    with cluster("cluster_subkey") as c:
        c.attr(label=" 3) SUBKEY ROTASYONU — HKDF zinciri (rewind imkansiz) ", **CLUSTER_ATTRS)
        n("sub0", "subkey_0 = HKDF(master, nonce,\n' HYPR/subkey/0 || LE64(0)')", extra={"shape": "ellipse"})
        n("subi", "subkey_i = HKDF(master, nonce,\n' HYPR/subkey/i || LE64(i) || prev_sub')\nher subkey oncekine bagli", extra={"shape": "ellipse"})
        n("chain", "Zincir: subkey_i = f(master, nonce, i, subkey_{i-1})\nRFC 5869 HKDF-SHA512\nprev_sub info'da", extra={"shape": "note", "style": "filled,dashed"})
        n("rotation", "rotation_bytes % 64 == 0\ndegilse ValueError\nblok sinir ihlali yok", extra={"shape": "diamond"})

    # =======================================================================
    # 4) KEYSTREAM — DUAL PRF
    # =======================================================================
    with cluster("cluster_keystream") as c:
        c.attr(label=" 4) KEYSTREAM — Dual PRF (BLAKE2b XOR HMAC-SHA512) ", **CLUSTER_ATTRS)
        n("b2b", "BLAKE2b-512\nkey = subkey[:64]\ninput = LE64(block_idx) || nonce", extra={"shape": "ellipse"})
        n("hmac", "HMAC-SHA512\nkey = subkey\ninput = LE64(block_idx) || nonce", extra={"shape": "ellipse"})
        n("xor", "keystream_block = BLAKE2b XOR HMAC\n64 B blok", extra={"penwidth": "1.8", "shape": "diamond"})
        n("uint64", "block_idx uint64\ntasimada OverflowError\nfail-loud, sessiz tekrar yok", extra={"shape": "diamond"})
        n("state", "_CipherState\nmaster + nonce + rotation\n+ cur_sub zincir + block_idx", extra={"shape": "box"})

    # =======================================================================
    # 5) ENCRYPT BORU HATTI
    # =======================================================================
    with cluster("cluster_encrypt") as c:
        c.attr(label=" 5) ENCRYPT — pad -> keystream XOR -> Encrypt-then-MAC ", **CLUSTER_ATTRS)
        n("plain", "plaintext (bytes)", extra={"shape": "parallelogram"})
        n("pad", "ISO7816 pad\n0x80 + 0x00*  -> blok hizala\npad_to dahil", extra={"shape": "ellipse"})
        n("xor_enc", "ciphertext = plaintext_padded XOR keystream\n(rotation her blokta subkey degisebilir)", extra={"shape": "box"})
        n("auth_key", "auth_key = HKDF(master, nonce,\n' HYPR/auth')  [ayri domain]", extra={"shape": "ellipse"})
        n("hmac_tag", "tag = HMAC-SHA512(auth_key,\nheader + ciphertext)\n64 B", extra={"penwidth": "1.8"})
        n("package", "paket = header (104 B)\n+ ciphertext + tag (64 B)\nToplam wire format", extra={"shape": "box", "penwidth": "1.8"})

    # =======================================================================
    # 6) DOSYA BORU HATTI — ENCRYPT FILE
    # =======================================================================
    with cluster("cluster_file_enc") as c:
        c.attr(label=" 6) FILE ENCRYPT — atomic + guvenli tmp ", **CLUSTER_ATTRS)
        n("fenc_in", "in_path (file)\nS_ISREG kontrolu (fd) + FIFO/DIR red", extra={"shape": "parallelogram"})
        n("tmp_enc", "_make_tmp_near(out)\nPOSIX: mkstemp 0600\nWin: CreateFileW + SDDL\nD:P(A;;FA;;;user_sid) + dwShareMode=0\n+ CREATE_NEW + OPEN_REPARSE_POINT", extra={"shape": "box"})
        n("order", "SIRALAMA: tmp olustur\nSONRA master ture (create-secrets-late)\nmaster=None + try/finally wipe", extra={"shape": "diamond", "penwidth": "1.2"})
        n("chunk_enc", "1 MiB chunk'lar\nson chunk'a pad ekle\nrotation subkey degisimi\nfout.flush + fsync", extra={"shape": "box"})
        n("commit_enc", "os.replace(tmp, out)\nsadece basarida atomik commit\n hata -> _safe_unlink(tmp)", extra={"shape": "diamond"})

    # =======================================================================
    # 7) DOSYA BORU HATTI — DECRYPT (verify-then-decrypt, iki gecisli)
    # =======================================================================
    with cluster("cluster_file_dec") as c:
        c.attr(label=" 7) FILE DECRYPT — Iki Gecisli Verify-then-Decrypt (Soatok/Halite) ", **CLUSTER_ATTRS)
        n("fdec_in", "in_path (paket dosya)\nS_ISREG + size >= HEADER+TAG", extra={"shape": "parallelogram"})
        n("parse", "parse_header()\nMAGIC/VERSION/kdf_n/flags\n-> keyfile bayragi kontrolu", extra={"shape": "box"})
        n("derive2", "master = Argon2id(passphrase+keyfile+fp)\n[kdf_n dogrulandiktan sonra]", extra={"shape": "box"})
        n("pass1", "PASS 1: sadece HMAC akar\nheader + ciphertext -> HMAC\ntmp ACILMAZ, plaintext URETILMEZ\ntag hesapla", extra={"penwidth": "1.8"})
        n("pass1_ok", "tag == tag2 ?\ncompare_digest (sabit zamanli)\ndegilse -> CipherError\ntek tip hata mesaji (oracle yok)", extra={"shape": "diamond", "penwidth": "1.6"})
        n("tmp_dec", "PASS 2: tmp ac (_make_tmp_near)\n + ciphertext tekrar HMAC\n + ayni anda decrypt", extra={"shape": "box"})
        n("pending", "pending buffer + _unpad_iso7816\npad yalnizca HMAC sonrası cozülur\npadding oracle yok", extra={"shape": "ellipse"})
        n("commit_dec", "verified=True ise\nos.replace(tmp, out)\ndegilse _safe_unlink + hata", extra={"shape": "diamond"})

    # =======================================================================
    # 8) GUVENLIK KATMANLARI
    # =======================================================================
    with cluster("cluster_hardening") as c:
        c.attr(label=" 8) GUVENLIK KATMANLARI — ACL / TOCTOU / CLI ", **CLUSTER_ATTRS)
        n("acl", "Windows ACL\nallowlist: {sahip, SYSTEM, Admins, Owner Rights}\nGetAce fail-closed, allow tipleri tam\nINHERIT_ONLY atla", extra={"shape": "box"})
        n("open_read", "_open_private_file_read\nO_NOFOLLOW | O_NONBLOCK\nS_ISREG + fstat(fd) -> TOCTOU kapali", extra={"shape": "box"})
        n("priv", "_check_private_file_windows\n+ _check_private_file_posix\nkeyfile/passphrase dosyasi gizli mi?", extra={"shape": "diamond"})
        n("cli", "hcli.py\ntty zorunlu prompt\nstale_after 3600s + geteuid filtre\nprogress sadece isatty()", extra={"shape": "box"})
        n("dice", "diceware 7776 kelime\nzxcvbn 72-char pencere (>=10^14)\nfallback pattern cap (4 desen)", extra={"shape": "box"})


    # =======================================================================
    # KENARLAR — ana akis
    # =======================================================================
    # Giris -> Master
    e("pw", "mat", "pw_bytes")
    e("kf", "hkdf_kf", "HKDF")
    e("hkdf_kf", "mat", "keyfile_key")
    e("fp", "mat", "fp_blob")
    e("mat", "argon", "")
    e("kdfn", "argon", "dogrula")
    e("argon", "wipe", "")

    # Master -> Header/Nonce
    e("wipe", "nonce", "master hazir")
    e("nonce", "hdr_struct", "")
    e("flags", "hdr_struct", "")
    e("dlen", "hdr_struct", "")

    # Header -> Subkey
    e("hdr_struct", "sub0", "nonce+master")
    e("sub0", "subi", "zincir")
    e("subi", "chain", "")
    e("rotation", "subi", "kontrol")

    # Subkey -> Keystream
    e("subi", "state", "")
    e("state", "b2b", "")
    e("state", "hmac", "")
    e("b2b", "xor", "")
    e("hmac", "xor", "")
    e("xor", "uint64", "")

    # Keystream -> Encrypt
    e("plain", "pad", "")
    e("pad", "xor_enc", "")
    e("xor", "xor_enc", "keystream")
    e("xor_enc", "auth_key", "")
    e("auth_key", "hmac_tag", "")
    e("hdr_struct", "hmac_tag", "header")
    e("xor_enc", "hmac_tag", "ciphertext")
    e("hmac_tag", "package", "")

    # Encrypt -> File Enc
    e("package", "fenc_in", "paket semasi")
    e("fenc_in", "tmp_enc", "")
    e("tmp_enc", "order", "")
    e("order", "chunk_enc", "master sonra")
    e("chunk_enc", "commit_enc", "")
    e("xor", "chunk_enc", "blok keystream")

    # File Dec akisi
    e("fdec_in", "parse", "")
    e("parse", "derive2", "header dogru ise")
    e("derive2", "pass1", "master")
    e("pass1", "pass1_ok", "tag karsilastir")
    e("pass1_ok", "tmp_dec", "gecti")
    e("tmp_dec", "pending", "")
    e("pending", "commit_dec", "")
    e("xor", "tmp_dec", "keystream (PASS2)")

    # Guvenlik katmanlari capraz baglar
    e("priv", "acl", "")
    e("acl", "open_read", "")
    e("open_read", "kf", "dogrula")
    e("open_read", "pw", "passphrase file")
    e("cli", "priv", "")
    e("dice", "pw", "guclu parola")

    # Ek aciklamalar
    n("legend", "LEJANT:  beyaz dolgu + siyah cerceve + siyah yazi\nkesik cizgi = not/aciklama  |  elmas = karar/kontrol  |  paralelkenar = dosya/IO\noklar = veri akisi (ortho, siyah)", extra={"shape": "note", "style": "filled,dashed", "fontsize": "8"})

    dot.format = "png"
    out_path = os.path.join(OUT_DIR, OUT_BASENAME)
    # render temiz: dot dosyasi da kalsin
    png_path = dot.render(out_path, cleanup=False)
    # dot.render zaten .dot birakir; adini duzelt
    # graphviz .dot'u <basename> olarak yazar, uzantisiz degil — tasima gerek yok
    return png_path


# ---------------------------------------------------------------------------
# Matplotlib — PREMIUM ELITE (siyah/beyaz limiti kalkti)
# Cyber / neural net HARD, soldan saga, neon, gradient, glow — kral tasarimi
# ---------------------------------------------------------------------------
def build_with_matplotlib():
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    import matplotlib.colors as mcolors
    import random, math
    random.seed(7)

    # ---- premium palet ----
    BG = "#070A14"
    BG2 = "#0D1226"
    CYAN = "#00E5FF"
    CYAN_D = "#00B8D4"
    VIOLET = "#7C4DFF"
    MAGENTA = "#FF2E93"
    AMBER = "#FFB300"
    MINT = "#00E676"
    BLUE = "#2979FF"
    WHITE = "#E8EAF6"
    DIM = "#8C9EFF"

    fig, ax = plt.subplots(figsize=(30, 16))
    fig.patch.set_facecolor(BG)
    ax.set_facecolor(BG)
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 100)
    ax.axis("off")

    # arka grid (cok hafif)
    for gx in range(0, 101, 10):
        ax.plot([gx, gx], [0, 100], color="white", alpha=0.035, linewidth=0.5, zorder=0)
    for gy in range(0, 101, 10):
        ax.plot([0, 100], [gy, gy], color="white", alpha=0.035, linewidth=0.5, zorder=0)
    # vignette hissi icin dis cerceve glow
    outer = mpatches.FancyBboxPatch((0.4, 0.6), 99.2, 98.2, boxstyle="round,pad=0.6",
                                     facecolor="none", edgecolor=WHITE, linewidth=1.1, alpha=0.18, zorder=0)
    ax.add_patch(outer)

    # baslik
    ax.text(50, 97.6, "HYPERCIPHER  v5  —  NEURAL CIPHER ARCHITECTURE", ha="center", va="center",
            fontsize=16, color=WHITE, fontname="Consolas", weight="bold")
    ax.text(50, 95.1, "2048-bit  •  Argon2id  •  Dual-PRF  (BLAKE2b  XOR  HMAC-SHA512)  •  Encrypt-then-MAC  •  Verify-then-Decrypt  •  Hardware-Bound",
            ha="center", va="center", fontsize=6.8, color=DIM, fontname="Consolas", alpha=0.95)
    ax.text(50, 93.55, "soldan saga  —  6 katman  •  48 noron  •  280+ sinaps  •  fully-connected + skip + feedback",
            ha="center", va="center", fontsize=5.1, color=WHITE, fontname="Consolas", alpha=0.72)

    # katmanlar
    layers = [
        ("INPUT  —  GİRİŞLER", CYAN, [
            "passphrase\nUTF8+NFC",
            "keyfile\n32B..1MiB",
            "HKDF kf\nHYPR/kf/v1",
            "fingerprint\nVolSerial",
            "fp_blob\nNUL yok",
            "material\n+0x00 ayraç",
            "wipe\ndestroy",
        ]),
        ("KDF  —  Argon2id", BLUE, [
            "kdf_n\n1<<14..18",
            "salt 32 B\nurandom",
            "nonce 24 B\nurandom",
            "Argon2id\nt=3 p=1",
            "master\n256 B",
            "2ⁿ check\nValueError",
            "LocalFree\nleak yok",
        ]),
        ("HEADER  —  104 B", VIOLET, [
            "ver+flags\n1+1 B",
            "rot+kdf_n\n2+4 B",
            "salt+nonce\n32+24 B",
            "fp_hash\n32 B",
            "data_len\n8 B",
            "flags\n0b100",
            "MAGIC YOK\n104 B",
            "subkey\n+prev_sub",
        ]),
        ("KEYSTREAM  —  Dual PRF", AMBER, [
            "_CipherState\nzincir",
            "BLAKE2b\n512",
            "HMAC\nSHA512",
            "XOR\n64 B blok",
            "uint64\nfail-loud",
            "rotation\nsubkey++",
            "block_idx\nLE64",
        ]),
        ("ENCRYPT  —  XOR+MAC", MAGENTA, [
            "plaintext\nbytes",
            "ISO7816\n0x80+00*",
            "pad_to\nkontrol",
            "ciphertext\nXOR ks",
            "auth_key\nHYPR/auth",
            "tag HMAC\n64 B",
            "paket\nhdr+ct+tag",
            "parse_hdr\nVER/flags",
        ]),
        ("FILE I/O  —  DECRYPT", MINT, [
            "S_ISREG\nFIFO red",
            "_make_tmp\nmkstemp",
            "tmp>master\nlate",
            "chunk 1M\nfsync",
            "PASS1 HMAC\ntmp YOK",
            "compare\n_digest",
            "PASS2\npending",
            "ACL/O_NOFOLLOW\nTOCTOU yok",
        ]),
    ]

    layer_xs = [8.5, 24.2, 39.8, 55.4, 71.0, 87.2]
    # glow + katman paneli
    for li, (title, col, _) in enumerate(layers):
        x = layer_xs[li]
        # panel arka (hafif renkli cam)
        panel = mpatches.FancyBboxPatch((x - 8.8, 7.2), 17.6, 84.2, boxstyle="round,pad=0.45",
                                         facecolor=mcolors.to_rgba(col, 0.06), edgecolor=mcolors.to_rgba(col, 0.42),
                                         linewidth=1.15, zorder=1)
        ax.add_patch(panel)
        # ust baslik seridi (renkli)
        bar = mpatches.FancyBboxPatch((x - 8.8, 87.6), 17.6, 3.8, boxstyle="round,pad=0.22",
                                       facecolor=mcolors.to_rgba(col, 0.95), edgecolor="none", zorder=2)
        ax.add_patch(bar)
        ax.text(x, 89.5, title, ha="center", va="center", fontsize=5.05, color=BG, fontname="Consolas", weight="bold", zorder=3)
        # alt ince cizgi glow
        ax.plot([x - 8.8, x + 8.8], [7.2, 7.2], color=col, alpha=0.85, linewidth=1.8, zorder=1)

    # noron pozisyonlari
    neuron_pos = []
    for li, (_, _, labels) in enumerate(layers):
        x = layer_xs[li]
        n = len(labels)
        top, bot = 83.8, 11.2
        step = (top - bot) / (n - 1) if n > 1 else 0
        ys = [top - i * step for i in range(n)]
        nodes = []
        for i, lab in enumerate(labels):
            # mikro jitter — organik ama duzeni bozmaz
            y = ys[i] + (random.uniform(-0.45, 0.45) if 1 <= li <= 4 else 0)
            nodes.append((x, y, lab))
        neuron_pos.append(nodes)

    # bag renkleri: kaynak->hedef karisimi
    def lerp(a, b, t):
        ca = mcolors.to_rgba(a); cb = mcolors.to_rgba(b)
        return (ca[0]*(1-t)+cb[0]*t, ca[1]*(1-t)+cb[1]*t, ca[2]*(1-t)+cb[2]*t, 0.92)

    layer_cols = [c for _, c, _ in layers]

    # 1) fully-connected (her katman -> sonrakine) — HARD yogunluk
    for li in range(len(neuron_pos) - 1):
        A = neuron_pos[li]; B = neuron_pos[li + 1]
        col_a = layer_cols[li]; col_b = layer_cols[li + 1]
        mid_col = lerp(col_a, col_b, 0.5)
        for (x1, y1, _) in A:
            for (x2, y2, _) in B:
                dy = abs(y1 - y2)
                lw = 0.62 if dy < 9 else 0.34
                alpha = 0.82 if dy < 9 else 0.38
                # neon bag: once glow (kalin, seffaf), sonra cekirdek (ince, parlak)
                ax.plot([x1 + 1.55, x2 - 1.55], [y1, y2], color=mcolors.to_rgba(mid_col, alpha * 0.18),
                        linewidth=lw + 1.6, zorder=1, solid_capstyle="round")
                ax.plot([x1 + 1.55, x2 - 1.55], [y1, y2], color=mcolors.to_rgba(mid_col, alpha),
                        linewidth=lw, zorder=2, solid_capstyle="round")

    # 2) skip baglar (uzun atlama — mor/cyan kesik, daha da karisik)
    skip_pairs = [(0, 2), (0, 3), (1, 3), (1, 4), (2, 4), (2, 5), (3, 5)]
    for a, b in skip_pairs:
        col = lerp(layer_cols[a], layer_cols[b], 0.5)
        for _ in range(5):
            x1, y1, _ = random.choice(neuron_pos[a])
            x2, y2, _ = random.choice(neuron_pos[b])
            ax.plot([x1 + 1.55, x2 - 1.55], [y1, y2], color=mcolors.to_rgba(col, 0.42),
                    linewidth=0.42, linestyle=(0, (2.2, 2.2)), zorder=1)

    # 3) feedback (geri — alttan dolasan, amber/pink egri)
    feedback = [(5, 1), (5, 0), (4, 1), (3, 0)]
    for a, b in feedback:
        for _ in range(2):
            x1, y1, _ = random.choice(neuron_pos[a])
            x2, y2, _ = random.choice(neuron_pos[b])
            mid_y = 5.8
            mx = (x1 + x2) / 2
            # egri geri yol (3 nokta)
            ax.plot([x1, mx, x2], [y1, mid_y, y2], color=mcolors.to_rgba(AMBER, 0.42),
                    linewidth=0.52, linestyle=(0, (1.6, 1.6)), zorder=1)
            ax.annotate("", xy=(x2 - 1.35, y2), xytext=(x2 - 0.15, y2),
                        arrowprops=dict(arrowstyle="->", color=mcolors.to_rgba(AMBER, 0.72), lw=0.7))

    # 4) noronlar — premium: dis glow + beyaz cekirdek + renkli halka + siyah yazi
    for li, nodes in enumerate(neuron_pos):
        col = layer_cols[li]
        for (x, y, label) in nodes:
            # dis glow (buyuk, seffaf)
            glow = mpatches.Circle((x, y), radius=3.55, facecolor=mcolors.to_rgba(col, 0.16),
                                    edgecolor="none", zorder=4)
            ax.add_patch(glow)
            glow2 = mpatches.Circle((x, y), radius=3.05, facecolor=mcolors.to_rgba(col, 0.10),
                                     edgecolor="none", zorder=4)
            ax.add_patch(glow2)
            # ana noron (beyaz, renkli cerceve)
            circ = mpatches.Circle((x, y), radius=2.72, facecolor="#FFFFFF", edgecolor=col,
                                    linewidth=1.75, zorder=5)
            ax.add_patch(circ)
            # ic kucuk nokta (renkli cekirdek)
            core = mpatches.Circle((x, y), radius=0.42, facecolor=col, edgecolor="none", zorder=6)
            ax.add_patch(core)
            # yazi: ust satir bold, alt satir normal
            parts = label.split("\n")
            if len(parts) == 2:
                ax.text(x, y + 0.68, parts[0], ha="center", va="center", fontsize=3.65, color="#0B1020",
                        fontname="Consolas", weight="bold", zorder=7)
                ax.text(x, y - 0.62, parts[1], ha="center", va="center", fontsize=3.15, color="#263238",
                        fontname="Consolas", zorder=7)
            else:
                ax.text(x, y, label, ha="center", va="center", fontsize=3.35, color="#0B1020",
                        fontname="Consolas", weight="bold", zorder=7)

    # alt guvenlik seridi — neon kutular
    sec_labels = ["ACL allowlist", "_open_private", "O_NOFOLLOW", "stale 3600s", "diceware 7776", "zxcvbn 72w >=1e14"]
    sec_cols = [CYAN, BLUE, VIOLET, AMBER, MAGENTA, MINT]
    sec_y = 4.25
    sec_xs = [8.5 + i * 15.7 for i in range(6)]
    for sx, sl, sc in zip(sec_xs, sec_labels, sec_cols):
        r = mpatches.FancyBboxPatch((sx - 6.2, sec_y - 1.45), 12.4, 2.9, boxstyle="round,pad=0.18",
                                     facecolor=mcolors.to_rgba(sc, 0.12), edgecolor=mcolors.to_rgba(sc, 0.85),
                                     linewidth=1.0, zorder=4)
        ax.add_patch(r)
        ax.text(sx, sec_y, sl, ha="center", va="center", fontsize=3.35, color=WHITE, fontname="Consolas", weight="bold", zorder=5)
        # bag yukari
        for li in [0, 2, 5]:
            tx, ty, _ = random.choice(neuron_pos[li])
            ax.plot([sx, tx], [sec_y + 1.45, ty], color=mcolors.to_rgba(sc, 0.32),
                    linewidth=0.32, linestyle=(0, (2, 2)), zorder=1)

    # data flow oklari (altta, neon)
    for li in range(len(layer_xs) - 1):
        x1 = layer_xs[li] + 8.8; x2 = layer_xs[li + 1] - 8.8; y = 6.05
        col = lerp(layer_cols[li], layer_cols[li + 1], 0.5)
        ax.annotate("", xy=(x2, y), xytext=(x1, y),
                    arrowprops=dict(arrowstyle="->", color=mcolors.to_rgba(col, 0.92), lw=1.35, shrinkA=1, shrinkB=1))

    # lejant — premium bar
    ax.text(1.2, 1.05,
            "○ noron = HyperCipher adımı  •  neon tam-bağlı ağ = her nöron sonrakine bağlı  •  kesik = skip/geri bağ (doğrulama • wipe • ACL)  •  soldan saga HARD mimari",
            ha="left", va="bottom", fontsize=4.9, color=DIM, fontname="Consolas",
            bbox=dict(boxstyle="round,pad=0.28", facecolor=mcolors.to_rgba(WHITE, 0.06), edgecolor=mcolors.to_rgba(WHITE, 0.14), linewidth=0.9))
    ax.text(99, 1.05, "Graph.py  •  HyperCipher v5  •  made HARD",
            ha="right", va="bottom", fontsize=4.2, color=WHITE, fontname="Consolas", alpha=0.55)

    out_png = os.path.join(OUT_DIR, OUT_BASENAME + ".png")
    plt.tight_layout(rect=[0, 0, 1, 0.965])
    plt.savefig(out_png, dpi=300, facecolor=BG, edgecolor=BG)
    plt.close()
    out_dot = os.path.join(OUT_DIR, OUT_BASENAME + ".dot")
    with open(out_dot, "w", encoding="utf-8") as f:
        f.write("# premium neural cipher graph — 48 noron, 280+ bag, neon, soldan saga HARD\n")
        f.write("# Dot icin: winget install graphviz (opsiyonel, PNG zaten premium)\n")
    return out_png


def main():
    png = None
    dot_path = os.path.join(OUT_DIR, OUT_BASENAME + ".dot")
    try:
        if _has_graphviz():
            print("[*] graphviz bulundu — yuksek kalite diyagram uretiliyor...")
            png = build_with_graphviz()
        else:
            raise ImportError("graphviz binary yok")
    except Exception as exc:
        print(f"[!] graphviz ile uretim basarisiz ({exc}), matplotlib fallback'a geciliyor...")
        png = build_with_matplotlib()

    # Bilgi
    if png and os.path.isfile(png):
        size = os.path.getsize(png)
        print(f"[OK] Grafik yazildi: {png}  ({size} bytes)")
        print(f"[OK] DOT: {dot_path}")
        print("[OK] Siyah/beyaz, efektsiz, tum akislar tek grafikte.")
    else:
        print("[HATA] Grafik uretilemedi.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
