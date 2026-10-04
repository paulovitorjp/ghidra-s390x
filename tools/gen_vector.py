#!/usr/bin/env python3
"""Generate data/languages/s390x_vector.sinc -- z/Architecture vector facility.

Vector registers v0-v31 are selected by a 4-bit V field plus an RXB extension
bit. Since SLEIGH fields must be contiguous, each V field is defined twice
(same bits): {F}a attaches to v0-v15 (RXB=0), {F}b attaches to v16-v31
(RXB=1). Constructors are generated for all RXB combinations.

Bit numbering: PoP MSB=0 -> SLEIGH LSB=0 via (s,e) -> (N-1-e,N-1-s).
"""
import sys, itertools

OUT = []
def emit(s=""): OUT.append(s)

# ---------------------------------------------------------------- tokens
# (name, PoP_msb, PoP_lsb) -- PoP MSB=0 bit numbering.
# Converted to SLEIGH LSB=0 via (s,e) -> (N-1-e, N-1-s).
TOKENS = {
 "VVRX": (48, [
    ("OP",0,7), ("V1a",8,11), ("V1b",8,11), ("X2",12,15), ("B2",16,19),
    ("D2",20,31), ("M3",32,35), ("RXB",36,39), ("OP2",40,47), ("V1X",36,36),
 ]),
 "VVRSa": (48, [
    ("OP",0,7), ("V1a",8,11), ("V1b",8,11), ("V3a",12,15), ("V3b",12,15),
    ("B2",16,19), ("D2",20,31), ("M4",32,35), ("RXB",36,39), ("OP2",40,47),
    ("V1X",36,36), ("V3X",38,38),
 ]),
 "VVRSb": (48, [
    ("OP",0,7), ("V1a",8,11), ("V1b",8,11), ("R3",12,15), ("B2",16,19),
    ("D2",20,31), ("M4",32,35), ("RXB",36,39), ("OP2",40,47), ("V1X",36,36),
 ]),
 "VVRSc": (48, [
    ("OP",0,7), ("R1",8,11), ("V3a",12,15), ("V3b",12,15), ("B2",16,19),
    ("D2",20,31), ("M4",32,35), ("RXB",36,39), ("OP2",40,47), ("V3X",37,37),
 ]),
 "VVRRe": (48, [
    ("OP",0,7), ("V1a",8,11), ("V1b",8,11), ("V2a",12,15), ("V2b",12,15),
    ("V3a",16,19), ("V3b",16,19), ("M6",20,23), ("M5",24,27),
    ("V4a",28,31), ("V4b",28,31), ("RXB",36,39), ("OP2",40,47),
    ("V1X",36,36), ("V2X",37,37), ("V3X",38,38), ("V4X",39,39),
 ]),
 "VVRRa": (48, [
    ("OP",0,7), ("V1a",8,11), ("V1b",8,11), ("V2a",12,15), ("V2b",12,15),
    ("M5",20,23), ("M4",24,27), ("M3",28,31),
    ("RXB",36,39), ("OP2",40,47),
    ("V1X",36,36), ("V2X",37,37),
 ]),
 "VVRRb": (48, [
    ("OP",0,7), ("V1a",8,11), ("V1b",8,11), ("V2a",12,15), ("V2b",12,15),
    ("V3a",16,19), ("V3b",16,19), ("M5",24,27), ("M4",28,31),
    ("RXB",36,39), ("OP2",40,47),
    ("V1X",36,36), ("V2X",37,37), ("V3X",38,38),
 ]),
 "VVRRc": (48, [
    ("OP",0,7), ("V1a",8,11), ("V1b",8,11), ("V2a",12,15), ("V2b",12,15),
    ("V3a",16,19), ("V3b",16,19), ("M6",20,23), ("M5",24,27), ("M4",28,31),
    ("M3",32,35), ("RXB",36,39), ("OP2",40,47),
    ("V1X",36,36), ("V2X",37,37), ("V3X",38,38),
 ]),
 "VVRRd": (48, [
    ("OP",0,7), ("V1a",8,11), ("V1b",8,11), ("V2a",12,15), ("V2b",12,15),
    ("V3a",16,19), ("V3b",16,19), ("M5",24,27), ("M4",28,31), ("I4",32,35),
    ("RXB",36,39), ("OP2",40,47),
    ("V1X",36,36), ("V2X",37,37), ("V3X",38,38),
 ]),
 "VVRIa": (48, [
    ("OP",0,7), ("V1a",8,11), ("V1b",8,11), ("I2",16,31),
    ("M3",32,35), ("RXB",36,39), ("OP2",40,47), ("V1X",36,36),
 ]),
 "VVRIc": (48, [
    ("OP",0,7), ("V1a",8,11), ("V1b",8,11), ("V3a",16,19), ("V3b",16,19),
    ("I2",20,31), ("M3",32,35), ("RXB",36,39), ("OP2",40,47),
    ("V1X",36,36), ("V3X",38,38),
 ]),
 "VVRId": (48, [
    ("OP",0,7), ("V1a",8,11), ("V1b",8,11), ("V2a",12,15), ("V2b",12,15),
    ("V3a",16,19), ("V3b",16,19), ("I4",24,31),
    ("RXB",36,39), ("OP2",40,47),
    ("V1X",36,36), ("V2X",37,37), ("V3X",38,38),
 ]),
}

VFIELDS = [
 ("VVRX","V1","V1X"),
 ("VVRSa","V1","V1X"), ("VVRSa","V3","V3X"),
 ("VVRSb","V1","V1X"),
 ("VVRSc","V3","V3X"),
 ("VVRRe","V1","V1X"), ("VVRRe","V2","V2X"), ("VVRRe","V3","V3X"), ("VVRRe","V4","V4X"),
 ("VVRRa","V1","V1X"), ("VVRRa","V2","V2X"),
 ("VVRRb","V1","V1X"), ("VVRRb","V2","V2X"), ("VVRRb","V3","V3X"),
 ("VVRRc","V1","V1X"), ("VVRRc","V2","V2X"), ("VVRRc","V3","V3X"),
 ("VVRRd","V1","V1X"), ("VVRRd","V2","V2X"), ("VVRRd","V3","V3X"),
 ("VVRIa","V1","V1X"),
 ("VVRIc","V1","V1X"), ("VVRIc","V3","V3X"),
 ("VVRId","V1","V1X"), ("VVRId","V2","V2X"), ("VVRId","V3","V3X"),
]

def gen_tokens():
    emit("# --- Vector tokens (48-bit; globally prefixed fields) ---")
    for t,(sz,fields) in TOKENS.items():
        parts = []
        for name,msb,lsb in fields:
            # PoP MSB=0 -> SLEIGH LSB=0: SLEIGH range is (N-1-lsb, N-1-msb)
            lo, hi = sz-1-lsb, sz-1-msb
            parts.append(f"{t}_{name}=({lo},{hi})")
        emit(f"define token {t}({sz}) " + " ".join(parts) + " ;")
    emit()

def gen_attach():
    emit("# --- GPR attachments ---")
    emit("# X2/B2 are base/index: 0 means none -> zero pseudo-register.")
    for f in ["X2","B2"]:
        emit(f"attach variables [ VVRX_{f} ] [ zero r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 ];")
    for t in ["VVRSa","VVRSb","VVRSc"]:
        emit(f"attach variables [ {t}_B2 ] [ zero r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 ];")
    emit("# R3/R1 are true GPR operands: 0 selects r0.")
    emit("attach variables [ VVRSb_R3 ] [ r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 ];")
    emit("attach variables [ VVRSc_R1 ] [ r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 ];")
    emit("# Vector fields: {F}a -> v0-v15 (RXB=0), {F}b -> v16-v31 (RXB=1).")
    lo = " ".join(f"v{i}" for i in range(16))
    hi = " ".join(f"v{i}" for i in range(16,32))
    for t, base, xf in VFIELDS:
        emit(f"attach variables [ {t}_{base}a ] [ {lo} ];")
        emit(f"attach variables [ {t}_{base}b ] [ {hi} ];")
    emit()

HEADER = """# s390x_vector.sinc -- z/Architecture vector facility.
#
# Tokens, attachments and constructors were generated by
# tools/gen_vector.py. Element-wise p-code for VA/VS (vab/vah/vaf/vag,
# vsb/vsh/vsf/vsg) and VGBM is emitted by the generator's pcode_fn
# lambdas via the shared macros velem_op/vgbm16 below; regenerating is
# safe.
#
# Semantics (SA22-7832, Chapter 22 "Vector Facility"):
#   * VA/VS: element-wise integer add/subtract, result taken modulo
#     2**(8/16/32/64) per element; condition code unchanged; no
#     arithmetic exceptions.
#   * VGBM: byte i of V1 = 0xFF if bit i of the 16-bit I2 is 1, else
#     0x00. The M3 field is ignored by the architecture (the VRI-a
#     format diagram marks it '/')."""

MACROS = """# --- Vector integer p-code ---
# Vector registers are 128-bit (16-byte) varnodes.

# Element-wise vector integer add/subtract: d = a +/- b computed
# independently per esz-byte element, modulo 2**(8*esz).
# esz, sub are 8-byte varnodes: esz in {1,2,4,8}, sub 0=add / 1=sub.
macro velem_op(d, a, b, esz, sub) {
    local n:8; local i:8;
    local ebits:8; local sh8:8;
    local sh:16; local m:16; local one:16;
    local ea:16; local eb:16; local er:16; local acc:16;
    n = 16 / esz;
    ebits = esz << 3;
    one = 1;
    sh = zext(ebits);
    m = (one << sh) - one;
    acc = 0;
    i = 0;
    <velem_loop>
    sh8 = i * esz;
    sh8 = sh8 << 3;
    sh = zext(sh8);
    ea = (a >> sh) & m;
    eb = (b >> sh) & m;
    er = ea + eb;
    if (sub == 0) goto <velem_have>;
    er = ea - eb;
    <velem_have>
    er = er & m;
    acc = acc | (er << sh);
    i = i + 1;
    if (i != n) goto <velem_loop>;
    d = acc;
}

# VECTOR GENERATE BYTE MASK: byte i of d is all-ones iff bit i of w
# (the zero-extended 16-bit I2 immediate) is one, else all-zeros.
# Bit/byte numbering: (w >> i) & 1 tests the bit of value 2^i, which is
# architectural bit (15-i); placing 0xFF at shift 8*i targets
# architectural byte (15-i).  Thus architectural bit k maps to
# architectural byte k (bit 0 = 0x8000 -> leftmost byte), as PoP requires.
# M3 is ignored (not an operand here).
macro vgbm16(d, w) {
    local i:8; local bit:8;
    local sh8:8; local sh:16; local by:16; local acc:16;
    acc = 0;
    i = 0;
    <vgbm_loop>
    bit = (w >> i) & 1;
    sh8 = i << 3;
    sh = zext(sh8);
    by = 0;
    if (bit == 0) goto <vgbm_have>;
    by = 0xff;
    <vgbm_have>
    acc = acc | (by << sh);
    i = i + 1;
    if (i != 16) goto <vgbm_loop>;
    d = acc;
}"""

def gen_macros():
    for _l in MACROS.split("\n"):
        emit(_l)
    emit()

# ---------------------------------------------------------------- constructors
# A spec is (name, token, op2, masks, vops, displist_fn, pcode_fn)
# vops: list of base names ["V1","V2",...] in display order
# displist_fn(vfields): returns list of display tokens (strings quoted, field names bare)
# pcode_fn(vfields, efields): returns pcode string; vfields=dict base->fieldname, efields=dict extra->fieldname

SPECS = []

def spec(name, token, op2, masks, vops, displist_fn, pcode_fn, extra_fields=None):
    SPECS.append((name, token, op2, masks, vops, displist_fn, pcode_fn, extra_fields or []))

def emit_ctors():
    emit("# --- Vector constructors ---")
    for name, token, op2, masks, vops, displist_fn, pcode_fn, extra in SPECS:
        k = len(vops)
        for combo in itertools.product([0,1], repeat=k):
            vfields = {}
            conds = [f"{token}_OP=0xE7", f"{token}_OP2=0x{op2:02X}"]
            for mf, mv in masks.items():
                conds.append(f"{token}_{mf}=0x{mv:X}")
            ops = []
            for base, b in zip(vops, combo):
                suf = "a" if b==0 else "b"
                fname = f"{token}_{base}{suf}"
                vfields[base] = fname
                ops.append(fname)
                conds.append(f"{token}_{base}X={b}")
            efields = {}
            for f in extra:
                fname = f"{token}_{f}"
                efields[f] = fname
                ops.append(fname)  # all extra fields must be in pattern
            dparts = displist_fn(vfields, efields)
            disp = " ".join(dparts)
            pat = " & ".join(conds + ops)
            emit(f":{name} {disp} is {pat}")
            pcode = pcode_fn(vfields, efields)
            if pcode.strip():
                emit("{")
                for line in pcode.split("\n"):
                    if line.strip():
                        emit(f"    {line}")
                emit("}")
            else:
                emit("{ }")
            emit()

# Display helpers
def disp_vrx(vf, ef):
    # vl v1,0(r1)  -- D2(X2,B2)
    return [f'"vl "', vf["V1"], '","', ef["D2"], '"("', ef["X2"], '","', ef["B2"], '")"']

def build_specs():
    # VL / VST
    for op2, nm, is_load in [(0x06,"vl",True),(0x0E,"vst",False)]:
        def make_dl(nm):
            return lambda vf, ef: [f'"{nm} "', vf["V1"], '","', ef["D2"], '"("', ef["X2"], '","', ef["B2"], '")"']
        def make_pc(is_load):
            if is_load:
                return lambda vf, ef: f'local ea:8;\nea_D12(ea, {ef["B2"]}, {ef["X2"]}, {ef["D2"]});\n{vf["V1"]} = *:16 ea;'
            else:
                return lambda vf, ef: f'local ea:8;\nea_D12(ea, {ef["B2"]}, {ef["X2"]}, {ef["D2"]});\n*:16 ea = {vf["V1"]};'
        spec(nm, "VVRX", op2, {"M3":0}, ["V1"], make_dl(nm), make_pc(is_load),
             extra_fields=["D2","X2","B2"])

    # VLR
    spec("vlr", "VVRRa", 0x56, {}, ["V1","V2"],
         lambda vf, ef: ['"vlr "', vf["V1"], '","', vf["V2"]],
         lambda vf, ef: f'{vf["V1"]} = {vf["V2"]};')

    # VA / VS b/h/f/g (VRR-c, M3=0..3 at PoP 32-35): per-lane integer
    # add/subtract via the velem_op shared macro (modulo 2**(8*esz),
    # CC unchanged, no exceptions).
    for m3, sfx, esz in [(0,"b",1),(1,"h",2),(2,"f",4),(3,"g",8)]:
        for nm in ["va", "vs"]:
            sub = 0 if nm == "va" else 1
            op2 = 0xF3 if nm=="va" else 0xF7
            opname = "add" if sub == 0 else "subtract"
            spec(f"{nm}{sfx}", "VVRRc", op2, {"M3":m3}, ["V1","V2","V3"],
                 lambda vf, ef, nm=nm, sfx=sfx: [f'"{nm}{sfx} "', vf["V1"], '","', vf["V2"], '","', vf["V3"]],
                 lambda vf, ef, esz=esz, sub=sub, opname=opname:
                     f"# Element-wise {opname}, {esz}-byte elements (PoP VA/VS).\n"
                     f"local esz:8; local sub:8;\n"
                     f"esz = {esz}; sub = {sub};\n"
                     f"velem_op({vf['V1']}, {vf['V2']}, {vf['V3']}, esz, sub);")

    # VGBM (VRI-a, OP2=0x44): vgbm v1, imm16
    # Note: Capstone aliases I2=0 -> vzero, I2=0xFFFF -> vone. We emit generic vgbm.
    spec("vgbm", "VVRIa", 0x44, {}, ["V1"],
         lambda vf, ef: ['"vgbm "', vf["V1"], '","', ef["I2"]],
         lambda vf, ef:
             "# VGBM: byte i = (I2 bit i) ? 0xFF : 0x00; M3 ignored.\n"
             "local imm:2; local w:8;\n"
             f"imm = {ef['I2']};\n"
             "w = zext(imm);\n"
             f"vgbm16({vf['V1']}, w);",
         extra_fields=["I2","M3"])

if __name__ == "__main__":
    for _l in HEADER.split("\n"):
        emit(_l)
    emit()
    gen_tokens()
    gen_attach()
    gen_macros()
    build_specs()
    emit_ctors()
    sys.stdout.write("\n".join(OUT) + "\n")
