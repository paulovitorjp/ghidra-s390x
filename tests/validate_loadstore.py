#!/usr/bin/env python3
"""Validate hand-encoded s390x test vectors against Capstone (SystemZ).
Each vector: (name, hex_bytes, expected_mnemonic). Fails loudly on mismatch.
Capstone 5.0.7 uses CS_ARCH_SYSZ."""
import sys
from capstone import Cs, CS_ARCH_SYSZ, CS_MODE_BIG_ENDIAN

VECTORS = [
    # (name, hex, expected mnemonic)
    ("LR",   "181f",           "lr"),
    ("LGR",  "b904001f",       "lgr"),
    ("L",    "5810f000",       "l"),
    ("LY",   "e310f0000058",   "ly"),
    ("LG",   "e310f0000004",   "lg"),
    ("LH",   "4810f000",       "lh"),
    ("LHY",  "e310f0000078",   "lhy"),
    ("LB",   "e310f0000076",   "lb"),
    ("LGB",  "e310f0000077",   "lgb"),
    ("LGH",  "e310f0000015",   "lgh"),
    ("LHI",  "a7180005",       "lhi"),
    ("LGHI", "a7190005",       "lghi"),
    ("LA",   "4110f000",       "la"),
    ("LAY",  "e310f0000071",   "lay"),
    ("LARL", "c01000000000",   "larl"),
    ("ST",   "5010f000",       "st"),
    ("STY",  "e310f0000050",   "sty"),
    ("STG",  "e310f0000024",   "stg"),
    ("STH",  "4010f000",       "sth"),
    ("STHY", "e310f0000070",   "sthy"),
    ("STC",  "4210f000",       "stc"),
    ("STCY", "e310f0000072",   "stcy"),
    ("LM",   "9837f000",       "lm"),    # R1=3,R3=7
    ("STM",  "9037f000",       "stm"),
    ("LMG",  "eb37f0000004",   "lmg"),
    ("LMH",  "eb37f0000096",   "lmh"),
    ("STMG", "eb37f0000024",   "stmg"),
    ("STMH", "eb37f0000026",   "stmh"),
    ("MVC",  "d208f000f000",   "mvc"),
    ("MVI",  "9200f000",       "mvi"),
    ("MVHI", "e54c0000f000",   "mvhi"),
    ("ICM",  "bf13f000",       "icm"),    # R1=1,M3=3
    ("STCM", "be13f000",       "stcm"),
    ("EX",   "4410f000",       "ex"),
]

def main():
    md = Cs(CS_ARCH_SYSZ, CS_MODE_BIG_ENDIAN)
    fails = 0
    for name, hx, want in VECTORS:
        code = bytes.fromhex(hx)
        got = [(i.mnemonic, i.op_str, i.size) for i in md.disasm(code, 0x1000)]
        if len(got) != 1:
            print(f"FAIL {name:5s} {hx}: decoded {len(got)} insns: {got}")
            fails += 1
            continue
        mnem, opstr, size = got[0]
        status = "ok" if mnem == want and size == len(code) else "FAIL"
        if status == "FAIL":
            fails += 1
        print(f"{status:4s} {name:5s} {hx:14s} -> {mnem} {opstr} (size {size})")
    print(f"\n{len(VECTORS)-fails}/{len(VECTORS)} passed")
    return 1 if fails else 0

sys.exit(main())
