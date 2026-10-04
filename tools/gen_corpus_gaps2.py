#!/usr/bin/env python3
"""gen_corpus_gaps2.py — build tests/corpus_gaps2.json for the W3 gap fillers.

Hand-encodes vectors for BSM/BASSM/LAE/TRACE/LAM/STAM with the same
format helpers as tests/diff_harness.py, cross-checks each against
Capstone SystemZ 5.0.7 (recording its exact mnemonic/op_str as oracle),
and writes tests/corpus_gaps2.json.

Vectors Capstone cannot decode are dropped and logged (none expected).
"""
import json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.normpath(os.path.join(HERE, "..", "tests", "corpus_gaps2.json"))

from capstone import Cs, CS_ARCH_SYSZ, CS_MODE_BIG_ENDIAN

cs = Cs(CS_ARCH_SYSZ, CS_MODE_BIG_ENDIAN)

def rr(op, r1, r2):
    return bytes([op, (r1 << 4) | r2])

def rx(op, r1, x2, b2, d2):
    return bytes([op, (r1 << 4) | x2, (b2 << 4) | ((d2 >> 8) & 15), d2 & 0xff])

def rs(op, r1, r3, b2, d2):
    return bytes([op, (r1 << 4) | r3, (b2 << 4) | ((d2 >> 8) & 15), d2 & 0xff])

# (name, bytes, category, notes)
VECS = [
    # BSM: all four (R1,R2)-zero groups
    ("BSM r0,r0",  rr(0x0B, 0, 0),   "branch", "BSM: R1=0,R2=0 -> no-op"),
    ("BSM r3,r0",  rr(0x0B, 3, 0),   "branch", "BSM: R1 save only"),
    ("BSM r0,r5",  rr(0x0B, 0, 5),   "branch", "BSM: branch + mode set only"),
    ("BSM r3,r5",  rr(0x0B, 3, 5),   "branch", "BSM: R1 save + branch + mode set"),
    ("BSM r1,r0",  rr(0x0B, 1, 0),   "branch", "BSM: R1=1 save only"),
    ("BSM r15,r15", rr(0x0B, 15, 15), "branch", "BSM: max registers"),
    # BASSM: same four groups
    ("BASSM r0,r0",  rr(0x0C, 0, 0),   "branch", "BASSM: R1=0,R2=0 -> link save only"),
    ("BASSM r3,r0",  rr(0x0C, 3, 0),   "branch", "BASSM: link save, no branch"),
    ("BASSM r0,r5",  rr(0x0C, 0, 5),   "branch", "BASSM: branch + mode set only"),
    ("BASSM r3,r5",  rr(0x0C, 3, 5),   "branch", "BASSM: link + branch + mode set"),
    ("BASSM r14,r2", rr(0x0C, 14, 2),  "branch", "BASSM: typical return-register form"),
    ("BASSM r15,r15", rr(0x0C, 15, 15), "branch", "BASSM: max registers"),
    # LAE: R1 x B2 coverage incl. B2=0 (AR<-0 in AR mode) and X2=0
    ("LAE r2,x0,b0",   rx(0x51, 2, 0, 0, 0),     "load", "LAE: no index/base"),
    ("LAE r2,x3,b0",   rx(0x51, 2, 3, 0, 0),     "load", "LAE: index only"),
    ("LAE r2,x3,b4",   rx(0x51, 2, 3, 4, 0x123), "load", "LAE: index+base+disp"),
    ("LAE r15,x0,b0",  rx(0x51, 15, 0, 0, 0x10), "load", "LAE: max R1, disp only"),
    ("LAE r0,x5,b15",  rx(0x51, 0, 5, 15, 0),    "load", "LAE: R1=0, full address"),
    ("LAE r7,x0,b9",   rx(0x51, 7, 0, 9, 0xfff), "load", "LAE: base only, max disp"),
    # TRACE (privileged)
    ("TRACE r1,r3",   rs(0x99, 1, 3, 2, 0),      "system", "TRACE: basic form"),
    ("TRACE r0,r0",   rs(0x99, 0, 0, 0, 0),      "system", "TRACE: zero regs"),
    ("TRACE r15,r15", rs(0x99, 15, 15, 15, 0xfff), "system", "TRACE: max regs/disp"),
    # LAM: incl. wraparound a15->a0 and single-register
    ("LAM a1,a3",   rs(0x9A, 1, 3, 2, 0),      "load", "LAM: 3 access registers"),
    ("LAM a0,a0",   rs(0x9A, 0, 0, 1, 0),      "load", "LAM: single register"),
    ("LAM a15,a0",  rs(0x9A, 15, 0, 3, 0xfff), "load", "LAM: wraparound a15->a0"),
    ("LAM a5,a1",   rs(0x9A, 5, 1, 2, 0x10),   "load", "LAM: wraparound a5..a1"),
    ("LAM a0,a15",  rs(0x9A, 0, 15, 4, 0x100), "load", "LAM: all 16 registers"),
    # STAM: same shapes
    ("STAM a1,a3",  rs(0x9B, 1, 3, 2, 0),      "store", "STAM: 3 access registers"),
    ("STAM a0,a0",  rs(0x9B, 0, 0, 1, 0),      "store", "STAM: single register"),
    ("STAM a15,a0", rs(0x9B, 15, 0, 3, 0xfff), "store", "STAM: wraparound a15->a0"),
    ("STAM a5,a1",  rs(0x9B, 5, 1, 2, 0x10),   "store", "STAM: wraparound a5..a1"),
    ("STAM a0,a15", rs(0x9B, 0, 15, 4, 0x100), "store", "STAM: all 16 registers"),
]

def main():
    corpus = []
    dropped = []
    for name, code, cat, notes in VECS:
        ins = list(cs.disasm(code, 0x1000))
        if len(ins) != 1 or ins[0].size != len(code):
            dropped.append((name, code.hex()))
            continue
        i = ins[0]
        corpus.append({
            "bytes_hex": code.hex(),
            "capstone_mnemonic": i.mnemonic,
            "capstone_op_str": i.op_str,
            "category": cat,
            "notes": notes,
        })
    with open(OUT, "w") as f:
        json.dump(corpus, f, indent=1)
        f.write("\n")
    print("wrote %s: %d vectors, %d dropped" % (OUT, len(corpus), len(dropped)))
    for name, hx in dropped:
        print("DROPPED (capstone NODECODE): %s %s" % (name, hx))
    if dropped:
        sys.exit(1)

if __name__ == "__main__":
    main()
