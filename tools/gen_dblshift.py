import os

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

#!/usr/bin/env python3
"""Generate unrolled even/odd pair-register double-shift constructors.

Rationale: SRDL/SLDL/SRDA/SLDA (opcodes 0x8C/0x8D/0x8E/0x8F, RS-a format)
shift the 64-bit value formed by R1||R1+1 (R1 must be even; odd R1 is a
specification exception). SLEIGH has no verified pattern for dynamic
register indexing (R1+1), so each even R1 value (0,2,...,14) is emitted
as an explicit constructor with the odd register hardcoded, plus one
opaque fallback constructor for odd R1 (decode-only).

Opcodes verified against SA22-7832-14 Appendix A; semantics against the
Chapter 7 sections SHIFT LEFT DOUBLE LOGICAL (7-438), SHIFT RIGHT DOUBLE
LOGICAL (7-440), SHIFT LEFT DOUBLE ARITHMETIC (7-439), SHIFT RIGHT
DOUBLE ARITHMETIC (7-441).
Shared pcode macros (sla_core64, sra_core64) live in s390x_arith.sinc,
which must be @included BEFORE the generated file.

Output: data/languages/s390x_dblshift_gen.sinc
Idempotent: re-running overwrites the file.
"""

EVENS = [0, 2, 4, 6, 8, 10, 12, 14]

# name, opcode, kind
OPS = [
    ("SRDL", "0x8C", "logical_right"),
    ("SLDL", "0x8D", "logical_left"),
    ("SRDA", "0x8E", "arith_right"),
    ("SLDA", "0x8F", "arith_left"),
]

OUT_PATH = os.path.join(REPO_ROOT, "data/languages/s390x_dblshift_gen.sinc")


def pcode(kind, E, O, lc):
    L = [
        "local sh:8; local amt:8; local pair:8; local r:8;",
        "ea_D12(sh, RSa_B2, zero, RSa_D2);",
        "amt = sh & 63;",
        f"pair = (({E} & 0xffffffff) << 32) | ({O} & 0xffffffff);",
    ]
    if kind == "logical_right":
        L += [
            "r = pair >> amt;",
        ]
    elif kind == "logical_left":
        L += [
            "r = pair << amt;",
        ]
    elif kind == "arith_right":
        L += [
            "local ncc:1;",
            "sra_core64(pair, amt, r, ncc);",
        ]
    elif kind == "arith_left":
        L += [
            "local ncc:1;",
            "sla_core64(pair, amt, r, ncc);",
        ]
    L += [
        f"{E} = ({E} & (0xFFFFFFFF << 32)) | ((r >> 32) & 0xffffffff);",
        f"{O} = ({O} & (0xFFFFFFFF << 32)) | (r & 0xffffffff);",
    ]
    if kind in ("arith_right", "arith_left"):
        L += ["cc_set(ncc);"]
    else:
        L += ["# CC unchanged (PoP 7-438/7-440)."]
    return L


def main():
    out = [
        "# GENERATED FILE — do not hand-edit.",
        "# Produced by tools/gen_dblshift.py: unrolled even-R1 pair-register",
        "# double-shift constructors (SRDL, SLDL, SRDA, SLDA).",
        "# Each instruction: 8 even-R1 constructors with exact pair pcode,",
        "# plus 1 opaque odd-R1 fallback (specification exception on HW).",
        "# Opcodes/semantics verified against SA22-7832-14 (see script header).",
        "# Shared macros (sla_core64, sra_core64) are in s390x_arith.sinc —",
        "# include it BEFORE this file.",
        "",
    ]
    n = 0
    for (name, opc, kind) in OPS:
        for e in EVENS:
            E, O = f"r{e}", f"r{e+1}"
            lc = f"{name.lower()}_{e}"
            disp = f'"{name} " "{e}" "," RSa_D2 "(" RSa_B2 ")"'
            pat = f"RSa_OP={opc} & RSa_R1={e} & RSa_B2 & RSa_D2"
            out.append(f":{name}_{e} {disp} is {pat}")
            out.append("    {")
            for bl in pcode(kind, E, O, lc):
                out.append(f"        {bl}")
            out.append("    }")
            out.append("")
            n += 1
        # odd-R1 fallback: decode-only, listed last (most-specific-wins).
        disp = f'"{name} " RSa_R1 "," RSa_D2 "(" RSa_B2 ")"'
        pat = f"RSa_OP={opc} & RSa_R1 & RSa_B2 & RSa_D2"
        out.append(f":{name}_odd {disp} is {pat}")
        out.append("    {")
        out.append("        # R1 is odd: the hardware raises a specification exception")
        out.append("        # (PoP 7-438..7-441). Decode only; not modeled.")
        out.append("    }")
        out.append("")
        n += 1
    with open(OUT_PATH, "w") as f:
        f.write("\n".join(out))
    print(f"wrote {n} constructors to {OUT_PATH}")


if __name__ == "__main__":
    main()
