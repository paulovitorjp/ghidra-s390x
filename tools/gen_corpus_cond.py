#!/usr/bin/env python3
"""Generate tests/corpus_cond.json: differential corpus for s390x_cond.sinc.

Uses Capstone (5.0.7) to generate expected mnemonics/operands where supported.
SELECT (SELR/SELGR/SELFHR) is not decodable by Capstone 5.0.7, so those vectors
are marked decode-only (expected_len only).
"""
import json
from capstone import Cs, CS_ARCH_SYSZ, CS_MODE_BIG_ENDIAN
import os

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

cs = Cs(CS_ARCH_SYSZ, CS_MODE_BIG_ENDIAN)
cs.detail = False

vectors = []

def add(bytes_hex, category, notes, decode_only=False):
    data = bytes.fromhex(bytes_hex)
    if decode_only:
        vectors.append({
            "bytes_hex": bytes_hex,
            "capstone_mnemonic": None,
            "capstone_op_str": None,
            "category": category,
            "notes": notes,
            "expected_len": len(data),
        })
        return
    insns = list(cs.disasm(data, 0x1000))
    if not insns:
        raise RuntimeError(f"Capstone failed to decode {bytes_hex}")
    insn = insns[0]
    vectors.append({
        "bytes_hex": bytes_hex,
        "capstone_mnemonic": insn.mnemonic,
        "capstone_op_str": insn.op_str,
        "category": category,
        "notes": notes,
    })

def rrfc(op, m3, r1, r2):
    # RRF-c: OP(16) | M3(4) | 0(4) | R1(4) | R2(4)
    return f"{op:04x}{m3:x}0{r1:x}{r2:x}"

def rsyb(op, r1, m3, b2, dl2, dh2, op2):
    # RSY-b: OP(8) | R1(4) | M3(4) | B2(4) | DL2(12) | DH2(8) | OP2(8)
    word = (r1 << 20) | (m3 << 16) | (b2 << 12) | dl2
    return f"{op:02x}{word:06x}{dh2:02x}{op2:02x}"

def rieg(op, r1, m3, i2, op2):
    # RIE-g: OP(8) | R1(4) | M3(4) | I2(16) | 0(8) | OP2(8)
    return f"{op:02x}{r1:x}{m3:x}{i2:04x}00{op2:02x}"

def riea(op, r1, ign1, i2, m3, ign2, op2):
    # RIE-a: OP(8) | R1(4) | IGN(4) | I2(16) | M3(4) | IGN(4) | OP2(8)
    # Layout: byte0=OP, byte1=R1|IGN1, bytes2-3=I2, byte4=M3|IGN2, byte5=OP2
    return f"{op:02x}{r1:x}{ign1:x}{i2:04x}{m3:x}{ign2:x}{op2:02x}"

def rrfa(op, r1, r3, m4, r2):
    # RRF-a: OP(16) | R1(4) | R3(4) | M4(4) | R2(4)
    return f"{op:04x}{r1:x}{r3:x}{m4:x}{r2:x}"

def rxya(op, r1, x2, b2, dl2, dh2, op2):
    # RXY-a: OP(8) | R1(4) | X2(4) | B2(4) | DL2(12) | DH2(8) | OP2(8)
    word = (r1 << 20) | (x2 << 16) | (b2 << 12) | dl2
    return f"{op:02x}{word:06x}{dh2:02x}{op2:02x}"

def sse(op, b1, d1, b2, d2):
    # SSE: OP(16) | B1(4) | D1(12) | B2(4) | D2(12)
    return f"{op:04x}{b1:x}{d1:03x}{b2:x}{d2:03x}"

def ssa(op, l, b1, d1, b2, d2):
    # SS-a: OP(8) | L(8) | B1(4) | D1(12) | B2(4) | D2(12)
    return f"{op:02x}{l:02x}{b1:x}{d1:03x}{b2:x}{d2:03x}"

def sse1(op, b1, d1, b2, d2):
    # SSE with 1-byte opcode: OP(8) | B1(4) | D1(12) | B2(4) | D2(12)
    # (for MVCIN which is E8, not 00E8)
    return f"{op:02x}{b1:x}{d1:03x}{b2:x}{d2:03x}"

def rre(op, r1, r2):
    # RRE: OP(16) | 0(8) | R1(4) | R2(4)
    return f"{op:04x}00{r1:x}{r2:x}"

def si(op, i2, b1, d1):
    # SI: OP(8) | I2(8) | B1(4) | D1(12)
    return f"{op:02x}{i2:02x}{b1:x}{d1:03x}"

# --- Load-on-condition RRF-c (LOCR/LOCGR/LOCFHR), several masks ---
# LOCR B9F2, LOCGR B9E2, LOCFHR B9C0.
# Capstone 5.0.7 cannot decode LOCFHR -> decode-only vectors.
for base, op in [("LOCR", 0xB9F2), ("LOCGR", 0xB9E2)]:
    for m3 in [0, 1, 2, 4, 7, 8, 14, 15]:
        add(rrfc(op, m3, 1, 2), "cond",
            f"{base} mask {m3:X} (R1=1,R2=2)")
for m3 in [0, 2, 4, 8, 15]:
    add(rrfc(0xB9C0, m3, 1, 2), "cond",
        f"LOCFHR mask {m3:X} (R1=1,R2=2); decode-only: Capstone 5.0.7 lacks LOCFHR",
        decode_only=True)

# --- Load/store-on-condition RSY-b (LOC/LOCG/LOCFH/STOC/STOCG/STOCFH) ---
# LOC EBF2, LOCG EBE2, LOCFH EBE0, STOC EBF3, STOCG EBE3, STOCFH EBE1.
# Capstone 5.0.7 cannot decode LOCFH/STOCFH -> decode-only vectors.
for base, op2 in [("LOC", 0xF2), ("LOCG", 0xE2), ("STOC", 0xF3), ("STOCG", 0xE3)]:
    for m3 in [0, 7, 8, 15]:
        add(rsyb(0xEB, 1, m3, 2, 0x100, 0x00, op2), "cond",
            f"{base} mask {m3:X} (R1=1, mem 0x100(R2))")
for base, op2 in [("LOCFH", 0xE0), ("STOCFH", 0xE1)]:
    for m3 in [0, 7, 8, 15]:
        add(rsyb(0xEB, 1, m3, 2, 0x100, 0x00, op2), "cond",
            f"{base} mask {m3:X} (R1=1, mem 0x100(R2)); decode-only: Capstone 5.0.7 lacks {base}",
            decode_only=True)

# --- Load-on-condition immediate RIE-g (LOCHI/LOCGHI/LOCHHI) ---
# LOCHI EC42, LOCGHI EC46, LOCHHI EC4E
for base, op2 in [("LOCHI", 0x42), ("LOCGHI", 0x46), ("LOCHHI", 0x4E)]:
    for m3 in [0, 7, 8, 15]:
        add(rieg(0xEC, 1, m3, 0x1234, op2), "cond",
            f"{base} mask {m3:X} (R1=1, I2=0x1234)")

# --- SELECT RRF-a (decode-only; Capstone 5.0.7 cannot decode) ---
# SELR B9F0, SELGR B9E3, SELFHR B9C0; M4 uses IBM Appendix J arithmetic set
for base, op in [("SELR", 0xB9F0), ("SELGR", 0xB9E3), ("SELFHR", 0xB9C0)]:
    for m4 in [0, 2, 4, 8, 15]:
        add(rrfa(op, 1, 3, m4, 2), "cond",
            f"{base} M4={m4:X} (R1=1,R3=3,R2=2); decode-only: Capstone 5.0.7 lacks SEL*",
            decode_only=True)

# --- Compare-and-trap RRF-c (CRT/CLRT/CGRT/CLGRT) ---
# CRT B972, CLRT B973, CGRT B960, CLGRT B961
for base, op in [("CRT", 0xB972), ("CLRT", 0xB973),
                 ("CGRT", 0xB960), ("CLGRT", 0xB961)]:
    for m3 in [2, 4, 8]:
        add(rrfc(op, m3, 1, 2), "cond",
            f"{base} mask {m3:X} (R1=1,R2=2)")

# --- Compare-and-trap immediate RIE-a (CIT/CGIT/CLFIT/CLGIT) ---
# CIT EC72, CGIT EC70, CLFIT EC73, CLGIT EC71
for base, op2 in [("CIT", 0x72), ("CGIT", 0x70),
                  ("CLFIT", 0x73), ("CLGIT", 0x71)]:
    for m3 in [2, 4, 8]:
        add(riea(0xEC, 1, 0, 0x00FF, m3, 0, op2), "cond",
            f"{base} mask {m3:X} (R1=1, I2=0xFF)")

# --- Compare-and-trap storage RSY-b (CLT/CLGT) ---
# CLT EB23, CLGT EB2B
for base, op2 in [("CLT", 0x23), ("CLGT", 0x2B)]:
    for m3 in [2, 4, 8]:
        add(rsyb(0xEB, 1, m3, 2, 0x100, 0x00, op2), "cond",
            f"{base} mask {m3:X} (R1=1, mem 0x100(R2))")

# --- Load-and-trap RXY-a (LAT/LGAT/LLGFAT/LLGTAT/LFHAT) ---
# LAT E39F, LGAT E385, LLGFAT E39D, LLGTAT E39C, LFHAT E3C8
for base, op2 in [("LAT", 0x9F), ("LGAT", 0x85), ("LLGFAT", 0x9D),
                  ("LLGTAT", 0x9C), ("LFHAT", 0xC8)]:
    add(rxya(0xE3, 1, 0, 2, 0x100, 0x00, op2), "cond",
        f"{base} (R1=1, mem 0x100(R2))")

# --- MVCIN (SS-a E8), MVPG (RRE B254), LFPC (S B29D) ---
# Capstone 5.0.7 cannot decode MVCIN/MVPG -> decode-only vectors.
add(ssa(0xE8, 0x00, 1, 0x100, 2, 0x200), "cond",
    "MVCIN (L=0,B1=1,D1=0x100,B2=2,D2=0x200); decode-only: Capstone 5.0.7 lacks MVCIN",
    decode_only=True)
add(rre(0xB254, 1, 2), "cond",
    "MVPG (R1=1,R2=2); decode-only: Capstone 5.0.7 lacks MVPG; privileged stub",
    decode_only=True)
add(f"b29d2100", "cond", "LFPC (B2=1,D2=0x100)")

with open(os.path.join(REPO_ROOT, "tests/corpus_cond.json"), "w") as f:
    json.dump(vectors, f, indent=2)
print(f"Wrote {len(vectors)} vectors")
