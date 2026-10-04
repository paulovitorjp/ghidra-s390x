#!/usr/bin/env python3
"""gen_decimal_corpus.py — build tests/corpus_decimal.json.

Each vector: bytes_hex, expected_len, capstone_mnemonic (or null),
category, notes. Capstone is the ground truth for the encoding.
"""
import json
import os
import sys

try:
    from capstone import Cs, CS_ARCH_SYSZ, CS_MODE_BIG_ENDIAN
except ImportError:
    sys.exit("capstone not installed")

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.normpath(os.path.join(HERE, ".."))
OUT = os.path.join(REPO, "tests", "corpus_decimal.json")

# (bytes_hex, category, notes). capstone_mnemonic filled by Capstone.
VECTORS = [
    # ---- SS-c/SS-b: decimal arithmetic (6 bytes: OP L1L2 B1D1 B2D2) ----
    ("fa2101234567", "ssc", "AP basic"),
    ("fa1012345678", "ssc", "AP L1=1 L2=0"),
    ("fb3212345678", "ssc", "SP basic"),
    ("fc2101234567", "ssc", "MP basic"),
    ("fd2101234567", "ssc", "DP basic"),
    ("f92101234567", "ssc", "CP basic"),
    ("f82101234567", "ssc", "ZAP basic"),
    ("f02101234567", "ssc", "SRP (uses SSc token, I3=1)"),
    # ---- SS-b: pack/unpack (6 bytes) ----
    ("f21012345678", "ssb", "PACK basic"),
    ("f31012345678", "ssb", "UNPK basic"),
    ("f11012345678", "ssb", "MVO basic"),
    # ---- SS-f: pack ascii/unicode (6 bytes: OP L2 B1D1 B2D2) ----
    ("e91234012345", "ssf", "PKA basic"),
    ("e11234012345", "ssf", "PKU basic"),
    # ---- SS-a: translate/edit/move (6 bytes: OP L B1D1 B2D2) ----
    ("dc1012345678", "ssa", "TR basic"),
    ("dd1012345678", "ssa", "TRT basic"),
    ("d01012345678", "ssa", "TRTR basic"),
    ("d11012345678", "ssa", "MVN basic"),
    ("d31012345678", "ssa", "MVZ basic"),
    ("ea1012345678", "ssa", "UNPKA basic"),
    ("de1012345678", "ssa", "ED basic"),
    ("df1012345678", "ssa", "EDMK basic"),
    # ---- RRE: string ----
    ("b2550012", "rre", "MVST basic"),
    ("b25d0012", "rre", "CLST basic"),
    ("b25e0012", "rre", "SRST basic"),
    ("b2a50012", "rre", "TRE basic"),
    # ---- RRF-c: translate extended ----
    ("b9bf0046", "rrfc", "TRTE M3=0"),
    ("b9910046", "rrfc", "TRTO M3=0"),
    ("b9920046", "rrfc", "TROT M3=0"),
    ("b9930046", "rrfc", "TROO M3=0"),
    # ---- RS-a / RSY-a: compare logical long ----
    ("a9243456", "rsa", "CLCLE basic"),
    ("eb243456788f", "rsya", "CLCLU basic"),
    # ---- RSL-a: test decimal ----
    ("eb10003000c0", "rsla", "TP basic"),
]

def main():
    md = Cs(CS_ARCH_SYSZ, CS_MODE_BIG_ENDIAN)
    md.detail = False
    out = []
    for hx, cat, notes in VECTORS:
        b = bytes.fromhex(hx)
        insns = list(md.disasm(b, 0x1000))
        if not insns:
            print(f"SKIP (capstone no decode): {hx} {notes}", file=sys.stderr)
            cap = None
        else:
            i = insns[0]
            cap = i.mnemonic
            if i.size != len(b):
                print(f"WARN size mismatch {hx}: capstone size {i.size}", file=sys.stderr)
        out.append({
            "bytes_hex": hx,
            "expected_len": len(b),
            "capstone_mnemonic": cap,
            "category": cat,
            "notes": notes,
        })
    # report mnemonics
    for v in out:
        print(f"{v['bytes_hex']:14s} -> {v['capstone_mnemonic']}")
    with open(OUT, "w") as f:
        json.dump(out, f, indent=2)
    print(f"\nwrote {OUT} ({len(out)} vectors)")

if __name__ == "__main__":
    main()
