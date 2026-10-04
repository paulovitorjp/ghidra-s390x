import os

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

#!/usr/bin/env python3
"""Generate unrolled even/odd pair-register multiply/divide constructors.

Rationale: M/MR/MG/ML/D/DL/DSG-family instructions take an even/odd
register PAIR in R1 (R1 must be even; odd R1 is a specification
exception). SLEIGH has no verified pattern for dynamic register
indexing (R1+1), so each even R1 value (0,2,...,14) is emitted as an
explicit constructor with the odd register hardcoded, plus one opaque
fallback constructor for odd R1 (decode-only, like the EX stub).

Opcodes verified against SA22-7832-14 Appendix A; semantics against the
Chapter 7 sections DIVIDE (7-290), DIVIDE LOGICAL (7-290/7-291),
DIVIDE SINGLE (7-291), MULTIPLY (7-345), MULTIPLY LOGICAL (7-347).
Shared pcode macros (sx32, mul128u, udiv64, udiv128, sdiv32_exc,
sdiv64_exc, trap_fixed_point_divide) live in
s390x_muldiv.sinc, which must be @included BEFORE the generated file.

Output: data/languages/s390x_muldiv_gen.sinc
Idempotent: re-running overwrites the file.
"""

EVENS = [0, 2, 4, 6, 8, 10, 12, 14]

# name, token, opcode pattern, display format, ea kind, body kind, src kind
PAIR = [
    ("M",     "RXa",  "RXa_OP=0x5C",                  "RX",  "ea12", "mul32",    "mem32"),
    ("MFY",   "RXYa", "RXYa_OP=0xE3 & RXYa_OP2=0x5C", "RXY", "ea20", "mul32",    "mem32"),
    ("MR",    "RR",   "RR_OP=0x1C",                   "RR",  "none", "mul32",    "reg32"),
    ("MG",    "RXYa", "RXYa_OP=0xE3 & RXYa_OP2=0x84", "RXY", "ea20", "mul128s",  "mem64"),
    ("ML",    "RXYa", "RXYa_OP=0xE3 & RXYa_OP2=0x96", "RXY", "ea20", "mul32u",   "mem32"),
    ("MLR",   "RRE",  "RRE_OP=0xB996",                "RRE", "none", "mul32u",   "reg32"),
    ("MLG",   "RXYa", "RXYa_OP=0xE3 & RXYa_OP2=0x86", "RXY", "ea20", "mul128u",  "mem64"),
    ("MLGR",  "RRE",  "RRE_OP=0xB986",                "RRE", "none", "mul128u",  "reg64"),
    ("D",     "RXa",  "RXa_OP=0x5D",                  "RX",  "ea12", "div32s",   "mem32"),
    ("DR",    "RR",   "RR_OP=0x1D",                   "RR",  "none", "div32s",   "reg32"),
    ("MLR2",  "XXX",  "XXX",                          "RR",  "none", "div32s",   "reg32"),  # placeholder, removed below
    ("DL",    "RXYa", "RXYa_OP=0xE3 & RXYa_OP2=0x97", "RXY", "ea20", "div32u",   "mem32"),
    ("DLR",   "RRE",  "RRE_OP=0xB997",                "RRE", "none", "div32u",   "reg32"),
    ("DLG",   "RXYa", "RXYa_OP=0xE3 & RXYa_OP2=0x87", "RXY", "ea20", "div128u",  "mem64"),
    ("DLGR",  "RRE",  "RRE_OP=0xB987",                "RRE", "none", "div128u",  "reg64"),
    ("DSG",   "RXYa", "RXYa_OP=0xE3 & RXYa_OP2=0x0D", "RXY", "ea20", "div64s",   "mem64"),
    ("DSGR",  "RRE",  "RRE_OP=0xB90D",                "RRE", "none", "div64s",   "reg64"),
    ("DSGF",  "RXYa", "RXYa_OP=0xE3 & RXYa_OP2=0x1D", "RXY", "ea20", "div64s32", "mem32"),
    ("DSGFR", "RRE",  "RRE_OP=0xB91D",                "RRE", "none", "div64s32", "reg32"),
]
PAIR = [p for p in PAIR if p[1] != "XXX"]

def disp_for(dfmt, m, T, r1):
    # Constrained (even) R1 prints as a literal number, exactly like the
    # generated LM/STM constructors (a pattern-constrained operand cannot
    # also be a display operand). The odd fallback keeps R1 as an operand.
    r1d = f'"{r1}"' if r1 is not None else f"{T}_R1"
    if dfmt == "RX":
        return f'"{m} " {r1d} "," {T}_D2 "(" {T}_X2 "," {T}_B2 ")"'
    if dfmt == "RXY":
        return f'"{m} " {r1d} "," {T}_DL2 "(" {T}_X2 "," {T}_B2 ")"'
    return f'"{m} " {r1d} "," {T}_R2'

# {r1} is either "=N" (even, constrained) or "" (fallback, free)
PATF = {
    "RX":  "{T}_R1{r1} & {T}_X2 & {T}_B2 & {T}_D2",
    "RXY": "{T}_R1{r1} & {T}_X2 & {T}_B2 & {T}_DL2 & {T}_DH2",
    "RR":  "{T}_R1{r1} & {T}_R2",
    "RRE": "{T}_R1{r1} & {T}_R2",
}

OUT_PATH = os.path.join(REPO_ROOT, "data/languages/s390x_muldiv_gen.sinc")


def src32(T, src, dest, signed):
    """pcode to load the 32-bit multiplier/divisor into 8-byte `dest`."""
    if src == "mem32":
        op = "sext" if signed else "zext"
        return [f"w = *:4 ea;", f"{dest} = {op}(w);"]
    if signed:
        return [f"{dest} = {T}_R2 & 0xffffffff;", f"sx32({dest}, {dest});"]
    return [f"{dest} = {T}_R2 & 0xffffffff;"]


def src64(T, src):
    return "*:8 ea" if src == "mem64" else f"{T}_R2"


def pcode(kind, T, E, O, ea_kind, src, lc):
    L = []
    if ea_kind == "ea12":
        L += ["local ea:8;", f"ea_D12(ea, {T}_B2, {T}_X2, {T}_D2);"]
    elif ea_kind == "ea20":
        L += ["local ea:8;", f"ea_D20(ea, {T}_B2, {T}_X2, {T}_DH2, {T}_DL2);"]
    if src == "mem32":
        L.append("local w:4;")

    if kind == "mul32":
        # signed 32x32 -> 64-bit product, split across the pair (PoP 7-345)
        L += ["local mc:8; local mp:8; local p:8;"]
        L += src32(T, src, "mp", signed=True)
        L += [f"mc = {O} & 0xffffffff;",
              "sx32(mc, mc);",
              "p = mc * mp;",
              f"{E} = ({E} & (0xFFFFFFFF << 32)) | ((p >> 32) & 0xffffffff);",
              f"{O} = ({O} & (0xFFFFFFFF << 32)) | (p & 0xffffffff);"]
    elif kind == "mul32u":
        # unsigned 32x32 -> 64 (PoP 7-347)
        L += ["local mc:8; local mp:8; local p:8;"]
        L += src32(T, src, "mp", signed=False)
        L += [f"mc = {O} & 0xffffffff;",
              "p = mc * mp;",
              f"{E} = ({E} & (0xFFFFFFFF << 32)) | ((p >> 32) & 0xffffffff);",
              f"{O} = ({O} & (0xFFFFFFFF << 32)) | (p & 0xffffffff);"]
    elif kind == "mul128s":
        # signed 128 = 128s * 64s via abs values + unsigned core (7-345)
        L += ["local a:8; local b:8; local hi:8; local lo:8;",
              "local sa:8; local sb:8; local nhi:8; local nlo:8;",
              f"a = {O};",
              "b = *:8 ea;",
              "sa = (a >> 63) & 1;",
              "sb = (b >> 63) & 1;",
              f"if (sa == 0) goto <{lc}_apos>;",
              "a = 0 - a;",
              f"<{lc}_apos>",
              f"if (sb == 0) goto <{lc}_bpos>;",
              "b = 0 - b;",
              f"<{lc}_bpos>",
              "mul128u(hi, lo, a, b);",
              f"if (sa == sb) goto <{lc}_done>;",
              "nlo = 0 - lo;",
              "nhi = 0 - hi;",
              f"if (lo == 0) goto <{lc}_set>;",
              "nhi = nhi - 1;",
              f"<{lc}_set>",
              "hi = nhi;",
              "lo = nlo;",
              f"<{lc}_done>",
              f"{E} = hi;",
              f"{O} = lo;"]
    elif kind == "mul128u":
        L += ["local b:8; local hi:8; local lo:8;",
              f"b = {src64(T, src)};",
              f"mul128u(hi, lo, {O}, b);",
              f"{E} = hi;",
              f"{O} = lo;"]
    elif kind == "div32s":
        # 64s / 32s -> 32-bit quotient/remainder in the pair (PoP 7-290).
        # Fixed-point-divide exception (divisor zero / quotient overflow)
        # via sdiv32_exc; the trap path feeds the original low halves
        # back so the operation is suppressed (registers preserved).
        L += ["local dvd:8; local dvs:8; local q:8; local r:8;"]
        L += src32(T, src, "dvs", signed=True)
        L += [f"dvd = (({E} & 0xffffffff) << 32) | ({O} & 0xffffffff);",
              f"sdiv32_exc(q, r, dvd, dvs, {O} & 0xffffffff, {E} & 0xffffffff);",
              f"{E} = ({E} & (0xFFFFFFFF << 32)) | (r & 0xffffffff);",
              f"{O} = ({O} & (0xFFFFFFFF << 32)) | (q & 0xffffffff);"]
    elif kind == "div32u":
        L += ["local dvd:8; local dvs:8; local q:8; local r:8;"]
        L += src32(T, src, "dvs", signed=False)
        L += [f"dvd = (({E} & 0xffffffff) << 32) | ({O} & 0xffffffff);",
              "# Exception via udiv64 (zero divisor / quotient overflow ->",
              "# trap_fixed_point_divide; registers preserved on trap).",
              "udiv64(q, r, dvd, dvs);",
              f"{E} = ({E} & (0xFFFFFFFF << 32)) | (r & 0xffffffff);",
              f"{O} = ({O} & (0xFFFFFFFF << 32)) | (q & 0xffffffff);"]
    elif kind == "div128u":
        L += ["local d:8; local q:8; local r:8;",
              f"d = {src64(T, src)};",
              "# Exception via udiv128 (zero divisor / quotient overflow ->",
              "# trap_fixed_point_divide; registers preserved on trap).",
              f"udiv128(q, r, {E}, {O}, d);",
              f"{E} = r;",
              f"{O} = q;"]
    elif kind == "div64s":
        # 64s / 64s -> 64-bit quotient/remainder (PoP 7-291). Exception
        # via sdiv64_exc; trap path preserves the original registers.
        L += ["local dvd:8; local dvs:8; local q:8; local r:8;",
              f"dvd = {O};",
              f"dvs = {src64(T, src)};",
              f"sdiv64_exc(q, r, dvd, dvs, {O}, {E});",
              f"{E} = r;",
              f"{O} = q;"]
    elif kind == "div64s32":
        # 64s / 32s -> 64-bit quotient/remainder (PoP 7-291). Exception
        # via sdiv64_exc; trap path preserves the original registers.
        L += ["local dvd:8; local dvs:8; local q:8; local r:8;"]
        L += src32(T, src, "dvs", signed=True)
        L += [f"dvd = {O};",
              f"sdiv64_exc(q, r, dvd, dvs, {O}, {E});",
              f"{E} = r;",
              f"{O} = q;"]
    return L


def main():
    out = [
        "# GENERATED FILE — do not hand-edit.",
        "# Produced by tools/gen_muldiv.py: unrolled even-R1 pair-register",
        "# multiply/divide constructors (M, MFY, MR, MG, ML, MLR, MLG, MLGR,",
        "# D, DR, DL, DLR, DLG, DLGR, DSG, DSGR, DSGF, DSGFR).",
        "# Each instruction: 8 even-R1 constructors with exact pair pcode,",
        "# plus 1 opaque odd-R1 fallback (specification exception on HW).",
        "# Opcodes/semantics verified against SA22-7832-14 (see script header).",
        "# Shared macros (sx32, mul128u, udiv64, udiv128, sdiv32_exc,",
        "# sdiv64_exc, trap_fixed_point_divide) are in",
        "# s390x_muldiv.sinc — include it BEFORE this file.",
        "",
    ]
    n = 0
    for (name, tok, opc, dfmt, ea_kind, kind, src) in PAIR:
        T = tok
        for e in EVENS:
            E, O = f"r{e}", f"r{e+1}"
            lc = f"{name.lower()}_{e}"
            disp = disp_for(dfmt, name, T, e)
            pat = opc + " & " + PATF[dfmt].format(T=T, r1=f"={e}")
            out.append(f":{name}_{e} {disp} is {pat}")
            out.append("    {")
            for bl in pcode(kind, T, E, O, ea_kind, src, lc):
                out.append(f"        {bl}")
            out.append("    }")
            out.append("")
            n += 1
        # odd-R1 fallback: decode-only, listed last (most-specific-wins).
        disp = disp_for(dfmt, name, T, None)
        pat = opc + " & " + PATF[dfmt].format(T=T, r1="")
        out.append(f":{name}_odd {disp} is {pat}")
        out.append("    {")
        out.append("        # R1 is odd: the hardware raises a specification exception")
        out.append("        # (PoP 7-290/7-291/7-345/7-347). Decode only; not modeled.")
        out.append("    }")
        out.append("")
        n += 1
    with open(OUT_PATH, "w") as f:
        f.write("\n".join(out))
    print(f"wrote {n} constructors to {OUT_PATH}")


if __name__ == "__main__":
    main()
