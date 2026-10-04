#!/usr/bin/env python3
"""diff_harness.py — build + validate the s390x ground-truth corpus.

No s390x cross-assembler is available in this environment (binutils-s390x-
linux-gnu is not in the apt repos), so vectors are hand-encoded with format
helpers and cross-checked against Capstone SystemZ (5.0.7). Every vector must
decode to exactly one instruction consuming all bytes; anything Capstone
cannot decode is skipped and logged to tests/decode_failures.log.

Opcode sources: IBM z/Architecture Principles of Operation (MULTIPLY SINGLE:
MSR=B252; ADD/SUBTRACT (64): AG=E308, SG=E309, ALG=E30A, SLG=E30B), the
z/Architecture Reference Summary (LCGR=B903, LNGR=B901, LPGR=B900,
LCGFR=B913, LNGFR=B911, LPGFR=B910, CLMY=EB21, CLST=B25D), and Capstone's own
decode output cross-checked against both.

RRE layout note: IBM RRE is [op1, op2, 0x00, R1R2] — registers in the LAST
byte. The rre() helper below emits exactly that layout, and Capstone 5.0.7
decodes it correctly (e.g. B9 04 00 23 -> "lgr %r2, %r3").

Known Capstone 5.0.7 SystemZ rendering notes (oracle records Capstone's
spelling; SLEIGH constructors must follow IBM):
1. BRCL (RIL-b) extended mnemonics differ from IBM's, e.g. mask 8 -> "jge"
   (IBM: JE), mask 7 -> "jgne" (IBM: JNE), mask 10 -> "jghe" (IBM: JGE),
   mask 15 -> "jg" (IBM: J). The BRC (RI-c) table is correct (mask 8 -> je).
2. M/D (RX) and MR/DR/MVCL/CLCL (RR) only decode with an even R1 — matching
   the architecture's even-odd pair requirement.

Outputs:
  tests/corpus.json — [{bytes_hex, capstone_mnemonic, capstone_op_str,
                        category, notes}, ...]
"""
import json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
CORPUS_PATH = os.path.join(HERE, "corpus.json")
FAIL_LOG = os.path.join(HERE, "decode_failures.log")

from capstone import Cs, CS_ARCH_SYSZ, CS_MODE_BIG_ENDIAN
import capstone

# ---------- format encoders (IBM-correct byte layouts) ----------
def rr(op, r1, r2):          return bytes([op, (r1 << 4) | r2])
def rre(op1, op2, r1, r2):   # RRE: [op1, op2, 0x00, R1R2]
    return bytes([op1, op2, 0, (r1 << 4) | r2])
def rx(op, r1, x2, b2, d2):  return bytes([op, (r1 << 4) | x2,
                                           (b2 << 4) | ((d2 >> 8) & 15), d2 & 0xff])
def rxy(op1, r1, x2, b2, d2, i2):   # E3 | R1X2 | B2 DL2hi | DL2lo | DH2 | I2
    return bytes([op1, (r1 << 4) | x2, (b2 << 4) | ((d2 >> 8) & 15),
                  d2 & 0xff, (d2 >> 16) & 0xff, i2])
def rs(op, r1, r3, b2, d2):  return bytes([op, (r1 << 4) | r3,
                                           (b2 << 4) | ((d2 >> 8) & 15), d2 & 0xff])
def rsy(op1, r1, r3, b2, d2, i2):   # EB | R1R3 | B2 DL2hi | DL2lo | DH2 | I2
    return bytes([op1, (r1 << 4) | r3, (b2 << 4) | ((d2 >> 8) & 15),
                  d2 & 0xff, (d2 >> 16) & 0xff, i2])
def si(op, i2, b1, d1):      return bytes([op, i2, (b1 << 4) | ((d1 >> 8) & 15), d1 & 0xff])
def s2(op1, op2, b1, d1):    return bytes([op1, op2, (b1 << 4) | ((d1 >> 8) & 15), d1 & 0xff])
def ii(op, imm8):            return bytes([op, imm8])
def ri(op1, op2n, r1, i2):   return bytes([op1, (r1 << 4) | op2n, (i2 >> 8) & 0xff, i2 & 0xff])
def ril(op1, r1, op2n, i2):
    return bytes([op1, (r1 << 4) | op2n, (i2 >> 24) & 0xff, (i2 >> 16) & 0xff,
                  (i2 >> 8) & 0xff, i2 & 0xff])
def ss(op, lb, b1, d1, b2, d2):
    return bytes([op, lb, (b1 << 4) | ((d1 >> 8) & 15), d1 & 0xff,
                  (b2 << 4) | ((d2 >> 8) & 15), d2 & 0xff])
def sil(op1, op2, b1, d1, i16):     # SIL: E5 | op2 | B1 D1(12) | I2(16)
    return bytes([op1, op2, (b1 << 4) | ((d1 >> 8) & 15), d1 & 0xff,
                  (i16 >> 8) & 0xff, i16 & 0xff])

# Each entry: (name, code_bytes, {acceptable capstone mnemonics}, category, notes)
C = []
def add(name, code, mnems, cat, notes=""):
    if isinstance(mnems, str):
        mnems = {mnems}
    C.append((name, code, set(mnems), cat, notes or name))

# Instructions Capstone 5.0.7 cannot decode at all (dropped from corpus).
DROPPED = [
    ("PR", "0100", "program return (E); correct IBM encoding, Capstone 5.0.7 "
                   "has no PR entry"),
]

# ---------------- loads ----------------
add("LR",      rr(0x18, 1, 15),        "lr",   "load",  "load register 32-bit")
add("LGR",     rre(0xb9, 0x04, 2, 3),  "lgr",  "load",  "load register 64-bit")
add("L",       rx(0x58, 1, 0, 15, 0),  "l",    "load",  "load 32-bit, RX")
add("LY",      rxy(0xe3, 1, 0, 15, 0, 0x58), "ly", "load", "load 32-bit, 20-bit disp")
add("LG",      rxy(0xe3, 1, 0, 15, 0, 0x04), "lg", "load", "load 64-bit")
add("LH",      rx(0x48, 2, 0, 3, 0),   "lh",   "load")
add("LHY",     rxy(0xe3, 2, 0, 3, 0, 0x78), "lhy", "load")
add("LB",      rxy(0xe3, 2, 0, 3, 0, 0x76), "lb", "load", "load byte sign-extended")
add("LGB",     rxy(0xe3, 2, 0, 3, 0, 0x77), "lgb", "load")
add("LGH",     rxy(0xe3, 2, 0, 3, 0, 0x15), "lgh", "load")
add("LGF",     rxy(0xe3, 2, 0, 3, 0, 0x14), "lgf", "load", "load word -> 64 sign-ext")
add("LLGF",    rxy(0xe3, 2, 0, 3, 0, 0x16), "llgf", "load", "load logical word")
add("LLGC",    rxy(0xe3, 2, 0, 3, 0, 0x90), "llgc", "load")
add("LLGH",    rxy(0xe3, 2, 0, 3, 0, 0x91), "llgh", "load")
add("LHI",     ri(0xa7, 0x8, 7, 5),    "lhi",  "load",  "load halfword immediate +5")
add("LHIneg",  ri(0xa7, 0x8, 1, 0xfffb), "lhi", "load", "LHI r1,-5")
add("LGHI",    ri(0xa7, 0x9, 9, 5),    "lghi", "load")
add("LA",      rx(0x41, 1, 0, 15, 0),  "la",   "load",  "load address")
add("LAY",     rxy(0xe3, 1, 0, 15, 0, 0x71), "lay", "load")
add("LARL",    ril(0xc0, 1, 0x0, 0),   "larl", "load",  "load addr relative long")
add("LM",      rs(0x98, 3, 7, 15, 0),  "lm",   "load",  "load multiple r3-r7")
add("LMG",     rsy(0xeb, 3, 7, 15, 0, 0x04), "lmg", "load")
add("LMH",     rsy(0xeb, 3, 7, 15, 0, 0x96), "lmh", "load", "high halves")
add("ICM",     rs(0xbf, 1, 3, 15, 0),  "icm",  "load",  "insert chars under mask")
add("EX",      rx(0x44, 1, 0, 15, 0),  "ex",   "load",  "execute (target modifier)")
add("IIHH",    ri(0xa5, 0x0, 1, 0x1234), "iihh", "load", "insert imm high-high")
add("IILF",    ril(0xc0, 1, 0x9, 0x12345678), "iilf", "load", "insert imm low full")
add("IIHF",    ril(0xc0, 1, 0x8, 0x12345678), "iihf", "load")
# ---------------- stores ----------------
add("ST",      rx(0x50, 1, 0, 15, 0),  "st",   "store")
add("STY",     rxy(0xe3, 1, 0, 15, 0, 0x50), "sty", "store")
add("STG",     rxy(0xe3, 1, 0, 15, 0, 0x24), "stg", "store")
add("STH",     rx(0x40, 2, 0, 3, 0),   "sth",  "store")
add("STHY",    rxy(0xe3, 2, 0, 3, 0, 0x70), "sthy", "store")
add("STC",     rx(0x42, 2, 0, 3, 0),   "stc",  "store")
add("STCY",    rxy(0xe3, 2, 0, 3, 0, 0x72), "stcy", "store")
add("STM",     rs(0x90, 3, 7, 15, 0),  "stm",  "store", "store multiple r3-r7")
add("STMG",    rsy(0xeb, 3, 7, 15, 0, 0x24), "stmg", "store")
add("STMH",    rsy(0xeb, 3, 7, 15, 0, 0x26), "stmh", "store")
add("STCM",    rs(0xbe, 1, 3, 15, 0),  "stcm", "store")
add("STRL",    ril(0xc4, 1, 0xf, 0),   "strl", "store", "store relative long")
add("STMY",    rsy(0xeb, 1, 3, 15, 0, 0x90), "stmy", "store")
add("MVC",     ss(0xd2, 7, 15, 0, 14, 0), "mvc", "store", "move 8 bytes")
add("MVC1",    ss(0xd2, 0, 15, 0, 14, 0), "mvc", "store", "move 1 byte")
add("MVI",     si(0x92, 0xab, 15, 0),  "mvi",  "store", "move immediate")
add("MVHI",    sil(0xe5, 0x4c, 15, 0, 5), "mvhi", "store", "move halfword imm, SIL")
add("MVST",    rre(0xb2, 0x55, 1, 2),  "mvst", "store", "move string (RRE B255)")
add("XC",      ss(0xd7, 3, 15, 0, 14, 0), "xc", "store", "xor mem (zeroing idiom)")
add("NC",      ss(0xd4, 3, 15, 0, 14, 0), "nc",   "store")
add("OC",      ss(0xd6, 3, 15, 0, 14, 0), "oc",   "store")
add("TR",      ss(0xdc, 3, 15, 0, 14, 0), "tr",   "store", "translate")
add("TRT",     ss(0xdd, 3, 15, 0, 14, 0), "trt",  "store", "translate and test")
add("UNPK",    ss(0xf3, 0x21, 15, 0, 14, 0), "unpk", "store", "unpack L1=2,L2=1")
add("PACK",    ss(0xf2, 0x12, 15, 0, 14, 0), "pack", "store")
# ---------------- arithmetic ----------------
add("AR",      rr(0x1a, 1, 15),        "ar",   "arith")
add("AGR",     rre(0xb9, 0x08, 2, 3),  "agr",  "arith")
add("AGFR",    rre(0xb9, 0x18, 2, 3),  "agfr", "arith")
add("A",       rx(0x5a, 1, 0, 15, 0),  "a",    "arith")
add("AG",      rxy(0xe3, 1, 0, 15, 0, 0x08), "ag", "arith", "add 64-bit (E308)")
add("AGF",     rxy(0xe3, 1, 0, 15, 0, 0x18), "agf", "arith", "add 64<-32")
add("ALG",     rxy(0xe3, 1, 0, 15, 0, 0x0a), "alg", "arith", "add logical 64")
add("ALGF",    rxy(0xe3, 1, 0, 15, 0, 0x1a), "algf", "arith")
add("SR",      rr(0x1b, 1, 2),         "sr",   "arith")
add("SGR",     rre(0xb9, 0x09, 2, 3),  "sgr",  "arith")
add("S",       rx(0x5b, 1, 0, 15, 0),  "s",    "arith")
add("SG",      rxy(0xe3, 1, 0, 15, 0, 0x09), "sg", "arith", "subtract 64-bit (E309)")
add("SGF",     rxy(0xe3, 1, 0, 15, 0, 0x19), "sgf", "arith")
add("SLG",     rxy(0xe3, 1, 0, 15, 0, 0x0b), "slg", "arith", "subtract logical 64")
add("SLGF",    rxy(0xe3, 1, 0, 15, 0, 0x1b), "slgf", "arith")
add("MSR",     rre(0xb2, 0x52, 1, 2),  "msr",  "arith", "multiply single reg (B252)")
add("MSGR",    rre(0xb9, 0x0c, 2, 3),  "msgr", "arith")
add("MSG",     rxy(0xe3, 1, 0, 15, 0, 0x0c), "msg", "arith")
add("MSY",     rxy(0xe3, 1, 0, 15, 0, 0x51), "msy", "arith")
add("MHY",     rxy(0xe3, 1, 0, 15, 0, 0x7c), "mhy", "arith", "multiply halfword")
add("MR",      rr(0x1c, 0, 2),         "mr",   "arith",
    "even R1 required (even-odd pair)")
add("M",       rx(0x5c, 0, 0, 15, 0),  "m",    "arith",
    "even R1 required (even-odd pair)")
add("DR",      rr(0x1d, 0, 2),         "dr",   "arith",
    "even R1 required (even-odd pair)")
add("D",       rx(0x5d, 0, 0, 15, 0),  "d",    "arith",
    "even R1 required (even-odd pair)")
add("ALR",     rr(0x1e, 1, 2),         "alr",  "arith", "add logical reg")
add("ALGR",    rre(0xb9, 0x0a, 1, 2),  "algr", "arith")
add("AL",      rx(0x5e, 1, 0, 15, 0),  "al",   "arith")
add("SLR",     rr(0x1f, 1, 2),         "slr",  "arith")
add("SLGR",    rre(0xb9, 0x0b, 1, 2),  "slgr", "arith")
add("SL",      rx(0x5f, 1, 0, 15, 0),  "sl",   "arith")
add("AHI",     ri(0xa7, 0xa, 1, 5),    "ahi",  "arith", "add halfword imm")
add("AHIneg",  ri(0xa7, 0xa, 1, 0xfffb), "ahi", "arith", "AHI r1,-5")
add("AGHI",    ri(0xa7, 0xb, 1, 5),    "aghi", "arith")
add("MHI",     ri(0xa7, 0xc, 1, 5),    "mhi",  "arith")
add("MGHI",    ri(0xa7, 0xd, 1, 5),    "mghi", "arith")
add("AFI",     ril(0xc2, 1, 0x9, 0x12345678), "afi", "arith", "add fullword imm")
add("AGFI",    ril(0xc2, 1, 0x8, 0x12345678), "agfi", "arith")
add("LCR",     rr(0x13, 1, 2),         "lcr",  "arith", "load complement")
add("LCGR",    rre(0xb9, 0x03, 1, 2),  "lcgr", "arith", "load complement 64 (B903)")
add("LCGFR",   rre(0xb9, 0x13, 1, 2),  "lcgfr", "arith", "load complement 64<-32")
add("LNR",     rr(0x11, 1, 2),         "lnr",  "arith", "load negative")
add("LNGR",    rre(0xb9, 0x01, 1, 2),  "lngr", "arith", "load negative 64 (B901)")
add("LNGFR",   rre(0xb9, 0x11, 1, 2),  "lngfr", "arith")
add("LPR",     rr(0x10, 1, 2),         "lpr",  "arith", "load positive")
add("LPGR",    rre(0xb9, 0x00, 1, 2),  "lpgr", "arith", "load positive 64 (B900)")
add("LPGFR",   rre(0xb9, 0x10, 1, 2),  "lpgfr", "arith")
add("CVB",     rx(0x4f, 1, 0, 15, 0),  "cvb",  "arith", "convert to binary")
add("CVD",     rx(0x4e, 1, 0, 15, 0),  "cvd",  "arith", "convert to decimal")
# ---------------- logicals / shifts ----------------
add("NR",      rr(0x14, 1, 2),         "nr",   "logic")
add("NGR",     rre(0xb9, 0x80, 2, 3),  "ngr",  "logic")
add("N",       rx(0x54, 1, 0, 15, 0),  "n",    "logic")
add("NY",      rxy(0xe3, 1, 0, 15, 0, 0x54), "ny", "logic")
add("OR",      rr(0x16, 1, 2),         "or",   "logic")
add("OGR",     rre(0xb9, 0x81, 1, 2),  "ogr",  "logic")
add("O",       rx(0x56, 1, 0, 15, 0),  "o",    "logic")
add("OY",      rxy(0xe3, 1, 0, 15, 0, 0x56), "oy", "logic")
add("XR",      rr(0x17, 1, 2),         "xr",   "logic")
add("XGR",     rre(0xb9, 0x82, 1, 2),  "xgr",  "logic")
add("X",       rx(0x57, 1, 0, 15, 0),  "x",    "logic")
add("XY",      rxy(0xe3, 1, 0, 15, 0, 0x57), "xy", "logic")
add("NI",      si(0x94, 0x0f, 15, 0),  "ni",   "logic")
add("OI",      si(0x96, 0x0f, 15, 0),  "oi",   "logic")
add("XI",      si(0x97, 0x0f, 15, 0),  "xi",   "logic")
add("NILL",    ri(0xa5, 0x7, 1, 0x00ff), "nill", "logic", "and imm low-low")
add("NILH",    ri(0xa5, 0x6, 1, 0x00ff), "nilh", "logic")
add("OILL",    ri(0xa5, 0xb, 1, 0x00ff), "oill", "logic")
add("NIHF",    ril(0xc0, 1, 0xa, 0x12345678), "nihf", "logic")
add("OILF",    ril(0xc0, 1, 0xd, 0x12345678), "oilf", "logic")
add("SLL",     rs(0x89, 1, 0, 3, 0),   "sll",  "logic", "shift left logical")
add("SRL",     rs(0x88, 1, 0, 3, 0),   "srl",  "logic")
add("SLA",     rs(0x8b, 1, 0, 3, 0),   "sla",  "logic", "shift left arith")
add("SRA",     rs(0x8a, 1, 0, 3, 0),   "sra",  "logic")
add("SLLG",    rsy(0xeb, 1, 3, 0, 0, 0x0d), "sllg", "logic")
add("SRLG",    rsy(0xeb, 1, 3, 0, 0, 0x0c), "srlg", "logic")
add("SLAG",    rsy(0xeb, 1, 3, 0, 0, 0x0b), "slag", "logic")
add("SRAG",    rsy(0xeb, 1, 3, 0, 0, 0x0a), "srag", "logic")
# ---------------- compares / tests ----------------
add("CR",      rr(0x19, 1, 2),         "cr",   "cmp")
add("CGR",     rre(0xb9, 0x20, 1, 2),  "cgr",  "cmp")
add("C",       rx(0x59, 1, 0, 15, 0),  "c",    "cmp")
add("CG",      rxy(0xe3, 1, 0, 15, 0, 0x20), "cg", "cmp")
add("CGF",     rxy(0xe3, 1, 0, 15, 0, 0x30), "cgf", "cmp", "compare 64<-32")
add("CH",      rx(0x49, 1, 0, 15, 0),  "ch",   "cmp")
add("CLR",     rr(0x15, 1, 2),         "clr",  "cmp", "compare logical reg")
add("CLGR",    rre(0xb9, 0x21, 1, 2),  "clgr", "cmp")
add("CL",      rx(0x55, 1, 0, 15, 0),  "cl",   "cmp")
add("CLG",     rxy(0xe3, 1, 0, 15, 0, 0x21), "clg", "cmp")
add("CLGF",    rxy(0xe3, 1, 0, 15, 0, 0x31), "clgf", "cmp")
add("CHI",     ri(0xa7, 0xe, 1, 5),    "chi",  "cmp")
add("CGHI",    ri(0xa7, 0xf, 1, 5),    "cghi", "cmp")
add("CLI",     si(0x95, 5, 15, 0),     "cli",  "cmp")
add("CLC",     ss(0xd5, 3, 15, 0, 14, 0), "clc", "cmp", "compare logical char")
add("CLM",     rs(0xbd, 1, 3, 15, 0),  "clm",  "cmp", "compare under mask (RS BD)")
add("CLMY",    rsy(0xeb, 1, 2, 15, 0, 0x21), "clmy", "cmp",
    "compare under mask, 20-bit disp (RSY EB21)")
add("CLCL",    rr(0x0f, 0, 2),         "clcl", "cmp",
    "even R1/R2 required (even-odd pairs)")
add("CLST",    rre(0xb2, 0x5d, 1, 2),  "clst", "cmp", "compare logical string (B25D)")
add("SRST",    rre(0xb2, 0x5e, 1, 2),  "srst", "cmp", "search string (B25E)")
add("TM",      si(0x91, 0x0f, 15, 0),  "tm",   "cmp", "test under mask")
add("LTR",     rr(0x12, 1, 2),         "ltr",  "cmp", "load and test")
add("LTGR",    rre(0xb9, 0x02, 1, 2),  "ltgr", "cmp")
add("LT",      rxy(0xe3, 1, 0, 15, 0, 0x12), "lt", "cmp")
add("LTG",     rxy(0xe3, 1, 0, 15, 0, 0x02), "ltg", "cmp")
add("LTGF",    rxy(0xe3, 1, 0, 15, 0, 0x32), "ltgf", "cmp")
add("MVCL",    rr(0x0e, 0, 2),         "mvcl", "cmp",
    "even R1/R2 required (even-odd pairs)")
# ---------------- branches ----------------
add("NOPR",    rr(0x07, 0, 0),         {"bcr", "nopr"}, "branch", "NOPR = BCR 0,0")
add("BCR",     rr(0x07, 15, 1),        "br",   "branch",
    "BCR 15,r1; Capstone prints extended 'br'")
add("BR",      rr(0x07, 15, 14),       {"bcr", "br"}, "branch", "BR r14")
add("BC",      rx(0x47, 8, 0, 15, 0x10), "be", "branch",
    "BC 8,...; Capstone prints extended 'be'")
add("BCidx",   rx(0x47, 15, 2, 15, 0x30), "b", "branch",
    "BC 15 with index reg; Capstone prints 'b'")
add("BRC",     ri(0xa7, 0x4, 8, 0x10), "je",   "branch",
    "BRC mask 8; Capstone prints extended 'je'")
add("BRAS",    ri(0xa7, 0x5, 1, 0x10), "bras", "branch", "branch rel and save")
add("BRCT",    ri(0xa7, 0x6, 1, 0x10), "brct", "branch", "branch on count")
add("BRCTG",   ri(0xa7, 0x7, 1, 0x10), "brctg", "branch")
add("BRASL",   ril(0xc0, 1, 0x5, 0),   "brasl", "branch", "branch rel and save long")
add("BRCL8",   ril(0xc0, 8, 0x4, 0),   "jge",  "branch",
    "BRCL mask 8; Capstone 5.0.7 prints 'jge' (IBM: JE) - see header notes")
add("BRCL7",   ril(0xc0, 7, 0x4, 0),   "jgne", "branch",
    "BRCL mask 7; Capstone prints 'jgne' (IBM: JNE)")
add("BRCL4",   ril(0xc0, 4, 0x4, 0),   "jgl",  "branch",
    "BRCL mask 4; Capstone prints 'jgl' (IBM: JL)")
add("BRCL2",   ril(0xc0, 2, 0x4, 0),   "jgh",  "branch",
    "BRCL mask 2; Capstone prints 'jgh' (IBM: JH)")
add("BRCL10",  ril(0xc0, 10, 0x4, 0),  "jghe", "branch",
    "BRCL mask 10; Capstone prints 'jghe' (IBM: JGE)")
add("J",       ril(0xc0, 15, 0x4, 0),  "jg",   "branch",
    "BRCL mask 15; Capstone prints 'jg' (IBM: J)")
add("BASR",    rr(0x0d, 1, 2),         "basr", "branch")
add("BALR",    rr(0x05, 1, 2),         "balr", "branch", "branch and link reg (05)")
add("BAL",     rx(0x45, 1, 0, 15, 0x20), "bal", "branch")
add("BAS",     rx(0x4d, 1, 0, 15, 0x20), "bas", "branch")
# ---------------- privileged / misc ----------------
add("SVC0",    ii(0x0a, 0),            "svc",  "priv", "supervisor call 0")
add("SVCab",   ii(0x0a, 0xab),         "svc",  "priv")
add("BAKR",    rre(0xb2, 0x40, 1, 2),  "bakr", "priv", "branch and stack (B240)")
add("STCK",    s2(0xb2, 0x05, 0, 0),   "stck", "priv", "store clock (semipriv)")
add("LPSW",    bytes([0x82, 0x00, 0xf0, 0x00]), "lpsw", "priv",
    "load PSW, S-format (82)")
add("LPSWE",   s2(0xb2, 0xb2, 15, 0),  "lpswe", "priv")
add("SSM",     s2(0x80, 0x00, 15, 0),  "ssm",  "priv", "set system mask")
add("SPM",     rr(0x04, 1, 0),         "spm",  "priv",
    "set program mask; low nibble of RR byte must be 0")
add("IPM",     rre(0xb2, 0x22, 1, 0),  "ipm",  "misc", "insert program mask")
# ---------------- floating point ----------------
add("LER",     rr(0x38, 1, 2),         "ler",  "fp")
add("LDR",     rr(0x28, 1, 2),         "ldr",  "fp")
add("LE",      rx(0x78, 1, 0, 15, 0),  "le",   "fp")
add("LD",      rx(0x68, 1, 0, 15, 0),  "ld",   "fp")
add("STE",     rx(0x70, 1, 0, 15, 0),  "ste",  "fp")
add("STD",     rx(0x60, 1, 0, 15, 0),  "std",  "fp")
add("AER",     rr(0x3a, 1, 2),         "aer",  "fp")
add("ADR",     rr(0x2a, 1, 2),         "adr",  "fp")
add("AE",      rx(0x7a, 1, 0, 15, 0),  "ae",   "fp")
add("AD",      rx(0x6a, 1, 0, 15, 0),  "ad",   "fp")
add("SER",     rr(0x3b, 1, 2),         "ser",  "fp")
add("SDR",     rr(0x2b, 1, 2),         "sdr",  "fp")
add("SE",      rx(0x7b, 1, 0, 15, 0),  "se",   "fp")
add("SD",      rx(0x6b, 1, 0, 15, 0),  "sd",   "fp")
add("CER",     rr(0x39, 1, 2),         "cer",  "fp")
add("CDR",     rr(0x29, 1, 2),         "cdr",  "fp")
add("CE",      rx(0x79, 1, 0, 15, 0),  "ce",   "fp")
add("CD",      rx(0x69, 1, 0, 15, 0),  "cd",   "fp")

def main():
    print(f"capstone {capstone.__version__}, vectors: {len(C)}")
    md = Cs(CS_ARCH_SYSZ, CS_MODE_BIG_ENDIAN)
    md.detail = False
    corpus, failures = [], []
    for name, hx, why in DROPPED:
        failures.append((name, hx, "dropped: " + why +
                         " not decodable by Capstone 5.0.7"))
    for name, code, mnems, cat, notes in C:
        got = list(md.disasm(code, 0x0))
        if len(got) != 1:
            failures.append((name, code.hex(), f"decoded {len(got)} insns: "
                             + str([(i.mnemonic, i.op_str) for i in got])))
            continue
        i = got[0]
        if i.size != len(code):
            failures.append((name, code.hex(),
                             f"size {i.size} != {len(code)}: {i.mnemonic} {i.op_str}"))
            continue
        if i.mnemonic not in mnems:
            failures.append((name, code.hex(),
                             f"mnemonic '{i.mnemonic}' not in {sorted(mnems)}: {i.op_str}"))
            continue
        corpus.append({
            "bytes_hex": code.hex(),
            "capstone_mnemonic": i.mnemonic,
            "capstone_op_str": i.op_str,
            "category": cat,
            "notes": notes,
        })
    with open(FAIL_LOG, "w") as f:
        for name, hx, why in failures:
            f.write(f"{name:8s} {hx:16s} {why}\n")
    with open(CORPUS_PATH, "w") as f:
        json.dump(corpus, f, indent=2)
    cats = {}
    for e in corpus:
        cats[e["category"]] = cats.get(e["category"], 0) + 1
    print(f"corpus: {len(corpus)} entries -> {CORPUS_PATH}")
    print(f"failures/dropped: {len(failures)} -> {FAIL_LOG}")
    print("by category:", cats)
    return 0

if __name__ == "__main__":
    sys.exit(main())
