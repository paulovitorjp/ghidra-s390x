import os

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

#!/usr/bin/env python3
"""Generate unrolled LM/STM/LMG/STMG/LMH/STMH constructors.

Rationale: LM/STM-family instructions take a register RANGE (R1..R3 with
wraparound from 15 to 0). SLEIGH has no verified pattern for dynamic
register indexing, so each of the 16x16 (R1,R3) combinations is emitted
as an explicit constructor with straight-line pcode. Every emitted
constructor is trivially auditable: a flat sequence of loads/stores.

Opcodes verified against SA22-7832-14 Appendix A; semantics against the
LOAD MULTIPLE / LOAD MULTIPLE HIGH / STORE MULTIPLE / STORE MULTIPLE
HIGH sections (7-323, 7-324, 7-451, 7-452):
  * LM/STM:   32-bit words <-> bits 32-63 (other half unchanged)
  * LMG/STMG: 64-bit words <-> bits 0-63
  * LMH/STMH: 32-bit words <-> bits 0-31 (other half unchanged)
  * registers ascending R1..R3, wrapping 15 -> 0; CC unchanged.

Output: data/languages/s390x_loadstore_gen.sinc
Idempotent: re-running overwrites the file.
"""

INSTRS = [
    # name, token, op1, op2, is_rsy, kind
    ("LM",   "RSa",  0x98, None, False, "load32"),
    ("STM",  "RSa",  0x90, None, False, "store32"),
    ("LMG",  "RSYa", 0xEB, 0x04, True,  "load64"),
    ("STMG", "RSYa", 0xEB, 0x24, True,  "store64"),
    ("LMH",  "RSYa", 0xEB, 0x96, True,  "loadhigh"),
    ("STMH", "RSYa", 0xEB, 0x26, True,  "storehigh"),
]

ELEM_BYTES = {"load32": 4, "store32": 4, "load64": 8, "store64": 8,
              "loadhigh": 4, "storehigh": 4}


def reg_seq(r1, r3):
    seq, r = [], r1
    while True:
        seq.append(r)
        if r == r3:
            break
        r = (r + 1) % 16
    return seq


def body(kind, seq, is_rsy):
    step = ELEM_BYTES[kind]
    ea = ("ea_D20(ea, B2, zero, DH2, DL2);"
          if is_rsy else "ea_D12(ea, B2, zero, D2);")
    lines = []
    for i, r in enumerate(seq):
        if kind == "load32":
            lines.append(f"w = *:4 ea; r{r} = (r{r} & 0xffffffff00000000) | zext(w);")
        elif kind == "load64":
            lines.append(f"r{r} = *:8 ea;")
        elif kind == "loadhigh":
            lines.append(f"w = *:4 ea; q = zext(w); q = q << 32; "
                         f"r{r} = (r{r} & 0x00000000ffffffff) | q;")
        elif kind == "store32":
            lines.append(f"w = r{r}:4; *:4 ea = w;")
        elif kind == "store64":
            lines.append(f"*:8 ea = r{r};")
        elif kind == "storehigh":
            lines.append(f"w = (r{r} >> 32):4; *:4 ea = w;")
        if i != len(seq) - 1:
            lines.append(f"ea = ea + {step};")
    return ea, lines


def main():
    out = []
    out.append("# GENERATED FILE — do not hand-edit.")
    out.append("# Produced by tools/gen_lmstm.py: unrolled LM/STM/LMG/STMG/LMH/STMH")
    out.append("# constructors, one per (R1,R3) combination (16x16 each).")
    out.append("# Opcodes/semantics verified against SA22-7832-14 (see script header).")
    out.append("")
    n = 0
    for name, token, op1, op2, is_rsy, kind in INSTRS:
        for r1 in range(16):
            for r3 in range(16):
                seq = reg_seq(r1, r3)
                if is_rsy:
                    pat = (f"{name}_{r1}_{r3} {token} OP=0x{op1:02X}, R1={r1}, "
                           f"R3={r3}, B2, DL2, DH2, OP2=0x{op2:02X}")
                    isc = (f"OP=0x{op1:02X} & R1={r1} & R3={r3} & B2 & DL2 & "
                           f"DH2 & OP2=0x{op2:02X}")
                else:
                    pat = (f"{name}_{r1}_{r3} {token} OP=0x{op1:02X}, R1={r1}, "
                           f"R3={r3}, B2, D2")
                    isc = f"OP=0x{op1:02X} & R1={r1} & R3={r3} & B2 & D2"
                disp = (f'[ "{name} ", R1, ",", R3, ",", DL2, "(", B2, ")" ]'
                        if is_rsy else
                        f'[ "{name} ", R1, ",", R3, ",", D2, "(", B2, ")" ]')
                out.append(f":{pat} is {isc}")
                out.append(f"    {disp}")
                out.append("    {")
                locals_ = "local ea:8; local w:4;"
                if kind == "loadhigh":
                    locals_ += " local q:8;"
                out.append(f"        {locals_}")
                ea_line, blines = body(kind, seq, is_rsy)
                out.append(f"        {ea_line}")
                for bl in blines:
                    out.append(f"        {bl}")
                out.append("    }")
                out.append("")
                n += 1
    path = os.path.join(REPO_ROOT, "data/languages/s390x_loadstore_gen.sinc")
    with open(path, "w") as f:
        f.write("\n".join(out))
    print(f"wrote {n} constructors to {path}")


if __name__ == "__main__":
    main()
