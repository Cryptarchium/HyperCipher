# -*- coding: utf-8 -*-
"""HyperCipher TAM SISTEM grafigi -> tek PNG (Graphviz, Python'dan).

Kapsar: 4-katman cekirdek + .hyp paketi + CLI + 34 anti-modul (7 aile)
+ testler + arastirma/karsilastirma + 100-mac skorbordu.
Cikti: HyperCipher_Full_Graph.png (bu dizin).
"""
import graphviz as gv

OUT = "HyperCipher_Full_Graph"

g = gv.Digraph("HyperCipherFull", format="png")
g.attr(rankdir="LR", splines="spline", dpi="150", bgcolor="white",
       fontname="Consolas", fontsize="20", labeljust="c", labelloc="t",
       label="HYPERCIPHER v5 — TAM SISTEM HARITASI (sifreleme + 34 anti-modul + testler)",
       nodesep="0.25", ranksep="0.6", concentrate="true")
g.attr("node", shape="box", style="rounded,filled", fontname="Consolas",
       fontsize="11")
g.attr("edge", fontname="Consolas", fontsize="9")

CRYPTO = "#d6e9ff"
ANTI = "#ffe3c2"
FAM = "#fff3cf"
TOOL = "#e2f0d9"
TEST = "#e8def8"
RISK = "#ffd9d9"


def fam_cluster(cid, title, members):
    with g.subgraph(name="cluster_" + cid) as c:
        c.attr(label=title, style="rounded,filled", fillcolor=FAM,
               fontname="Consolas", fontsize="13")
        for m, short in members:
            c.node(m, short, fillcolor=ANTI)


g.node("L1", "L1 MASTER\nArgon2id 128MiB/t3/p1\nHW-fingerprint + keyfile-HKDF\n2048-bit", fillcolor=CRYPTO)
g.node("L2", "L2 ROTASYON\nHKDF-SHA512 zinciri\nsubkey_i = f(master, rot, prev)", fillcolor=CRYPTO)
g.node("L3", "L3 KEYSTREAM\nBLAKE2b XOR HMAC-SHA512\n64B bloklar", fillcolor=CRYPTO)
g.node("L4", "L4 EtM\nHMAC-SHA512(header+ct)\nverify-then-decrypt", fillcolor=CRYPTO)
g.node("HYP", ".hyp PAKET\n104B header + ct + 64B tag\nmagic YOK", fillcolor=CRYPTO,
       shape="note")
g.edge("L1", "L2", label="master")
g.edge("L2", "L3", label="subkey")
g.edge("L3", "L4", label="ct")
g.edge("L4", "HYP", label="tag+ct")

g.node("HYG", "RAM HIJYENI\nwipe + bytearray-only\nmlock/DONTDUMP", fillcolor=CRYPTO)
g.node("FIO", "DOSYA-IO\nO_EXCL/CREATE_NEW+DACL\nfsync+os.replace atomik", fillcolor=CRYPTO)
g.node("DET", "FAIL-CLOSED\nDeterministik API kilitli\nuniform-error", fillcolor=CRYPTO)
g.edge("L4", "HYG", style="dashed")
g.edge("L4", "FIO", style="dashed")

g.node("CLI", "hcli.py\nencrypt/decrypt/hash/selftest\ngenerate-keyfile/passphrase", fillcolor=TOOL)
g.node("GATE", "GECITLER\ngetpass + 0600-file\nzxcvbn>=14 + --allow-weak\nDiceware 77.5-bit", fillcolor=TOOL)
g.edge("CLI", "GATE", style="dashed")
g.edge("CLI", "L1", label="kullanir")

fam_cluster("izleme", "IZLEME (6)", [
    ("m_analysis", "analysis\n12 sinyal"), ("m_trace", "trace\nsettrace-kirici"),
    ("m_debug", "debug\n5 katman"), ("m_prof", "profiling\nsetprofile-pin"),
    ("m_fuzz", "fuzzing\nharness+rewrite"), ("m_instr", "instrumentation\nFrida/Pin/DRIO")])
fam_cluster("kurtarma", "KURTARMA (6)", [
    ("m_byte", "bytecode\nmarshal-burst"), ("m_dec", "decompile\n9 imza"),
    ("m_ext", "extraction\narsiv+burst"), ("m_str", "string\nb64/entropi"),
    ("m_const", "constant\nco_consts+OOB"), ("m_sym", "symbol\nnames/qualname")])
fam_cluster("akis", "AKIS (4)", [
    ("m_cflow", "control_flow\nCFF-skoru+DSE"), ("m_dflow", "data_flow\ntaint-yuzey"),
    ("m_oracle", "oracle\nVaudenay/Padding"), ("m_side", "side_channel\ntiming/RNG")])
fam_cluster("butunluk", "BUTUNLUK (6)", [
    ("m_tamper", "tamper\nseal-last"), ("m_hook", "hook\nwatch+prologue"),
    ("m_patch", "patch\npin/guarded"), ("m_import", "import\nfinder+.pth"),
    ("m_modman", "module_manip\nMEM-SBOM"), ("m_conf", "config_tamper\nenv+dotenv")])
fam_cluster("ortam", "ORTAM (4)", [
    ("m_vm", "vm\nVMAware-skor"), ("m_emu", "emulation\nCPUID/RDTSC"),
    ("m_sbx", "sandbox\nT1497+exon"), ("m_env", "environment\nPATH/.pth/CI")])
fam_cluster("sızıntı", "HAFIZA/SIZINTI (6)", [
    ("m_dump", "dump\ncore/WER/faulthandler"), ("m_mem", "memory\nRWX/SecureCell"),
    ("m_keyex", "key_extraction\npano/sync"), ("m_err", "error_leakage\nSPLIT&FILTER"),
    ("m_tb", "traceback\nframe-hasat"), ("m_exc", "exception\nhook-pin")])
fam_cluster("kesif", "KESIF (2)", [
    ("m_refl", "reflection\nladder/closure"), ("m_intro", "introspection\ninspect/GC")])

g.node("SHIELD", "34 MODUL KALKAN\ntrip >=1 STRONG / >=2 WEAK\nhepsi stdlib-only, sessiz", fillcolor=RISK,
       shape="octagon")
for m in ["m_analysis", "m_byte", "m_cflow", "m_tamper", "m_vm", "m_dump", "m_refl"]:
    g.edge(m, "SHIELD", style="dotted")
g.edge("SHIELD", "L1", label="korur", style="bold")

g.node("TEST", "TESTLER\n190 unittest + 27 profesyonel\nSTS/avalanche/golden/8-thread", fillcolor=TEST)
g.edge("TEST", "L3", label="dogrular", style="dashed")
g.node("KARS", "karsilastirma/\nornekler/demo\nAES-CBC vs HyperCipher", fillcolor=TEST)
g.edge("KARS", "HYP", style="dotted")
g.node("RES", "_research/PyOuro\nsealing > obfuscation\nbootloader-dersi", fillcolor=TEST)
g.edge("RES", "SHIELD", style="dotted")
g.node("MAC", "100 MAC SKORU\n76 H - 19 R - 1 B - 4 ND\nS dosyasi: raporlar/", fillcolor=RISK,
       shape="note")

g.render(OUT, cleanup=True)
print("OK -> " + OUT + ".png")
