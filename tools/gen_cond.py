#!/usr/bin/env python3
"""Generate data/languages/s390x_cond.sinc — integer/conditional tails.

One-shot generator (kept in /tmp); the checked-in artifact is s390x_cond.sinc.
All opcodes, formats, mask semantics verified against IBM SA22-7832-14 (PoP).
"""
import io
import os

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

out = io.StringIO()

def w(s=""):
    out.write(s + "\n")

# ---------------------------------------------------------------- header
w("# ===========================================================================")
w("# s390x_cond.sinc — conditional integer tails: load/store-on-condition,")
w("# SELECT, compare-and-trap, load-and-trap, MVCIN, MVPG, LFPC.")
w("#")
w("# Reference: IBM z/Architecture Principles of Operation SA22-7832-14.")
w("# Bit-numbering convention (CONVENTIONS.md): PoP Figure 5-1 numbers bits")
w("# with bit 0 = MSB; SLEIGH numbers bit 0 = LSB, so every PoP range (s,e) on")
w("# an N-bit token is written here as (N-1-e, N-1-s).")
w("#")
w("# Condition-code mask convention (PoP 7-315, 7-326): the M3/M4 field is a")
w("# 4-bit mask; CC values 0/1/2/3 correspond to mask bits 8/4/2/1. The")
w("# existing 'cc' byte register holds the CC in bits 4-5, so")
w("#   ccval = (cc >> 4) & 3;  bit = 8 >> ccval;  matched = (mask & bit) != 0")
w("# (same idiom as s390x_branch.sinc).")
w("#")
w("# CORRECTION to the original task text: for load/store-on-condition, M3=0")
w("# does NOT mean unconditional. PoP 7-326: M3=0 matches no CC value, so the")
w("# instruction is a NOP (destination unchanged); M3=15 matches every CC")
w("# value, so the move/store is unconditional. Implemented as stated in PoP.")
w("#")
w("# Display conventions: one constructor per (mnemonic, mask) encoding — two")
w("# constructors must never share an encoding (SLEIGH disassembly takes the")
w("# first match, and the differential harness requires a unique decode).")
w("# Where Capstone folds a mask to a suffix, the constructor uses Capstone's")
w("# spelling so the Capstone-generated corpus matches directly. IBM")
w("# Appendix J synonyms with no Capstone counterpart (LOCRP, LOCRM, LOCRNZ,")
w("# LOCRZ, LOCRNM, LOCRNP and the SELECT equivalents) are NOT separate")
w("# constructors; the base-mnemonic+mask form covers those encodings.")
w("# Compare-style vs arithmetic-style: Capstone folds load-on-condition")
w("# masks 3/5/6/9/10/12 as NLE/NHE/LH/NLH/HE/LE (IBM J-1 defines no")
w("# extended mnemonic for those masks); both spellings from the union are")
w("# implemented. For compare-and-trap mask 6/10/12 Capstone uses LH/HE/LE")
w("# where IBM J-1 uses NE/NL/NH — Capstone's spelling is implemented since")
w("# the corpus is Capstone-generated.")
w("#")
w("# Compare-and-trap / load-and-trap: the data exception (DXC FF) is modeled")
w("# explicitly via the trap_compare_data user p-code op (callother) on the")
w("# mask-match path — never silently dropped. The comparison itself sets CC")
w("# (0=equal, 1=low, 2=high) like the corresponding COMPARE instruction.")
w("#")
w("# SELECT (SELR/SELGR/SELFHR): Capstone 5.0.7 does not decode these at all;")
w("# implemented from PoP with IBM J-1 extended mnemonics; corpus vectors are")
w("# decode-only (expected_len, no Capstone mnemonic).")
w("#")
w("# MVPG (B254, RRE) is privileged (special-operation exception, DAT,")
w("# storage keys) and is decode-only, like the existing TRAP2/TRAP4 stubs.")
w("# ===========================================================================")
w("")
w("# User p-code op for the compare-and-trap / load-and-trap data exception")
w("# (PoP: compare-and-trap-instruction data exception, DXC FF). Emitted on")
w("# the mask-match path so the trap is explicit in p-code; Ghidra renders it")
w("# as a CALLOTHER to this userop.")
w("define pcodeop trap_compare_data;")
w("")
w("# RRF-a: 4 bytes. OP(0-15), R3(16-19), M4(20-23), R1(24-27), R2(28-31).")
w("# Used by SELECT. M4 stays numeric (condition mask).")
w("define token RRFa(32)")
w("    RRFa_OP = (16,31)")
w("    RRFa_R3 = (12,15)")
w("    RRFa_M4 = (8,11)")
w("    RRFa_R1 = (4,7)")
w("    RRFa_R2 = (0,3)")
w(";")
w("attach variables [ RRFa_R3 ] [ r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 ];")
w("attach variables [ RRFa_R1 ] [ r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 ];")
w("attach variables [ RRFa_R2 ] [ r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 ];")
w("")
w("# RIE-a: 6 bytes. OP(0-7), R1(8-11), ignored(12-15), I2(16-31),")
w("# M3(32-35), ignored(36-39), OP2(40-47). Used by CIT/CGIT/CLFIT/CLGIT.")
w("define token RIEa(48)")
w("    RIEa_OP = (40,47)")
w("    RIEa_R1 = (36,39)")
w("    RIEa_IGN1 = (32,35)")
w("    RIEa_I2 = (16,31)")
w("    RIEa_M3 = (12,15)")
w("    RIEa_IGN2 = (8,11)")
w("    RIEa_OP2 = (0,7)")
w(";")
w("attach variables [ RIEa_R1 ] [ r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 ];")
w("")
w("# RIE-g: 6 bytes. OP(0-7), R1(8-11), M3(12-15), I2(16-31),")
w("# ignored(32-39), OP2(40-47). Used by LOCHI/LOCGHI/LOCHHI.")
w("define token RIEg(48)")
w("    RIEg_OP = (40,47)")
w("    RIEg_R1 = (36,39)")
w("    RIEg_M3 = (32,35)")
w("    RIEg_I2 = (16,31)")
w("    RIEg_IGN = (8,15)")
w("    RIEg_OP2 = (0,7)")
w(";")
w("attach variables [ RIEg_R1 ] [ r0 r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 r12 r13 r14 r15 ];")
w("")

# ------------------------------------------------------------- helpers
LOC_SUFFIX = {1:"O", 2:"H", 3:"NLE", 4:"L", 5:"NHE", 6:"LH", 7:"NE",
              8:"E", 9:"NLH", 10:"HE", 11:"NL", 12:"LE", 13:"NH", 14:"NO"}
SEL_SUFFIX = {1:"O", 2:"H", 4:"L", 7:"NE", 8:"E", 11:"NL", 13:"NH", 14:"NO"}
TRAP_SUFFIX = {2:"H", 4:"L", 6:"LH", 8:"E", 10:"HE", 12:"LE"}

def mask_decls(pfx="c"):
    return [
        f"    local _{pfx}_m:1;",
        f"    local _{pfx}_ccval:1;",
        f"    local _{pfx}_bit:1;",
    ]

def mask_logic(mask_expr, pfx="c"):
    return [
        f"    _{pfx}_m = {mask_expr};",
        f"    _{pfx}_ccval = (cc >> 4) & 0x3;",
        f"    _{pfx}_bit = 8 >> _{pfx}_ccval;",
        f"    if ((_{pfx}_m & _{pfx}_bit) != 0) goto <{pfx}_do>;",
        f"    goto <{pfx}_done>;",
        f"<{pfx}_do>",
    ]

def mask_test(mask_expr, pfx="c"):
    return mask_decls(pfx) + mask_logic(mask_expr, pfx)

def trap_decls():
    return [
        "    local _t_ccval:1;",
        "    local _t_bit:1;",
    ]

def trap_logic(mask_expr):
    return [
        f"    _t_ccval = (cc >> 4) & 0x3;",
        # M3 bit 0 (value 4)=equal, bit 1 (value 2)=low, bit 2 (value 1)=high.
        f"    _t_bit = 4 >> _t_ccval;",
        f"    if (({mask_expr} & _t_bit) != 0) goto <trap_fire>;",
        f"    goto <trap_done>;",
        f"<trap_fire>",
        f"    trap_compare_data();",
        f"<trap_done>",
    ]

def trap_test(mask_expr):
    return trap_decls() + trap_logic(mask_expr)

# ============================================================ RRF-c loads
w("# ===========================================================================")
w("# LOAD ON CONDITION, register forms (RRF-c). PoP 7-315.")
w("# LOCR B9F2 (32<-32, low half), LOCGR B9E2 (64<-64), LOCFHR B9E0 (32<-32,")
w("# high half). CC unchanged. M3=0: NOP; M3=15: unconditional (PoP 7-326).")
w("# ===========================================================================")

rrfc_loads = [
    # (base, op, move_stmt, comment)
    ("LOCR", 0xB9F2,
     "RRFc_R1 = (RRFc_R1 & (0xFFFFFFFF << 32)) | (RRFc_R2 & 0xFFFFFFFF);",
     "low 32 bits"),
    ("LOCGR", 0xB9E2,
     "RRFc_R1 = RRFc_R2;",
     "all 64 bits"),
    ("LOCFHR", 0xB9E0,
     "RRFc_R1 = (RRFc_R1 & 0xFFFFFFFF) | (RRFc_R2 & (0xFFFFFFFF << 32));",
     "high 32 bits"),
]
for base, op, move, comment in rrfc_loads:
    w(f"# {base}: {comment}.")
    for mask in sorted(LOC_SUFFIX):
        suf = LOC_SUFFIX[mask]
        w(f":{base}{suf} \"{base}{suf} \" RRFc_R1 \",\" RRFc_R2 is RRFc_OP=0x{op:04X} & RRFc_M3={mask} & RRFc_R1 & RRFc_R2")
        w("{")
        for line in mask_test(str(mask)):
            w(line)
        w(f"    {move}")
        w("<c_done>")
        w("}")
        w("")
    # generic: masks 0 and 15 (Capstone prints explicit mask)
    w(f":{base} \"{base} \" RRFc_R1 \",\" RRFc_R2 \",\" RRFc_M3 is RRFc_OP=0x{op:04X} & RRFc_M3 & RRFc_R1 & RRFc_R2")
    w("{")
    for line in mask_test("RRFc_M3"):
        w(line)
    w(f"    {move}")
    w("<c_done>")
    w("}")
    w("")

# ============================================================ RRF-c traps
w("# ===========================================================================")
w("# COMPARE AND TRAP, register forms (RRF-c). PoP 7-169.")
w("# CRT B972 (signed 32), CLRT B973 (unsigned 32), CGRT B960 (signed 64),")
w("# CLGRT B961 (unsigned 64). Comparison sets CC (0=equal,1=low,2=high); if")
w("# the M3 bit for that result is one, the compare-and-trap data exception")
w("# (DXC FF) is recognized — modeled explicitly via trap_compare_data().")
w("# M3 bit 3 is reserved; only bits 0-2 participate in the trap test.")
w("# ===========================================================================")

rrfc_traps = [
    ("CRT", 0xB972, "cc_scmp32", 4,
     "a = RRFc_R1 & 0xffffffff;", "b = RRFc_R2 & 0xffffffff;"),
    ("CLRT", 0xB973, "cc_ucmp", 4,
     "a = RRFc_R1 & 0xffffffff;", "b = RRFc_R2 & 0xffffffff;"),
    ("CGRT", 0xB960, "cc_scmp64", 8,
     "a = RRFc_R1;", "b = RRFc_R2;"),
    ("CLGRT", 0xB961, "cc_ucmp", 8,
     "a = RRFc_R1;", "b = RRFc_R2;"),
]
for base, op, ccmacro, sz, a_stmt, b_stmt in rrfc_traps:
    w(f"# {base}: {ccmacro}, {sz*8}-bit operands.")
    for mask in sorted(TRAP_SUFFIX):
        suf = TRAP_SUFFIX[mask]
        w(f":{base}{suf} \"{base}{suf} \" RRFc_R1 \",\" RRFc_R2 is RRFc_OP=0x{op:04X} & RRFc_M3={mask} & RRFc_R1 & RRFc_R2")
        w("{")
        w("    local a:8;")
        w("    local b:8;")
        for line in trap_decls():
            w(line)
        w(f"    {a_stmt}")
        w(f"    {b_stmt}")
        w(f"    {ccmacro}(a, b);")
        for line in trap_logic(str(mask)):
            w(line)
        w("}")
        w("")
    w(f":{base} \"{base} \" RRFc_R1 \",\" RRFc_R2 \",\" RRFc_M3 is RRFc_OP=0x{op:04X} & RRFc_M3 & RRFc_R1 & RRFc_R2")
    w("{")
    w("    local a:8;")
    w("    local b:8;")
    for line in trap_decls():
        w(line)
    w(f"    {a_stmt}")
    w(f"    {b_stmt}")
    w(f"    {ccmacro}(a, b);")
    for line in trap_logic("RRFc_M3"):
        w(line)
    w("}")
    w("")

# ============================================================ RSY-b loads/stores
w("# ===========================================================================")
w("# LOAD/STORE ON CONDITION, storage forms (RSY-b, 20-bit displacement).")
w("# PoP 7-315 (load), 7-452 (store). Display order follows Capstone/HLASM:")
w("# the mask is the LAST operand: LOC R1,D2(B2),M3 / STOC R1,D2(B2),M3.")
w("# ===========================================================================")

rsyb = [
    ("LOC", 0xF2, "load", "w = *:4 ea;",
     "RSYb_R1 = (RSYb_R1 & (0xFFFFFFFF << 32)) | zext(w);", "32-bit, low half"),
    ("LOCG", 0xE2, "load", None,
     "RSYb_R1 = *:8 ea;", "64-bit"),
    ("LOCFH", 0xE0, "load", "w = *:4 ea;",
     "RSYb_R1 = (RSYb_R1 & 0xFFFFFFFF) | (zext(w) << 32);", "32-bit, high half"),
    ("STOC", 0xF3, "store", None,
     "*:4 ea = RSYb_R1;", "32-bit, low half"),
    ("STOCG", 0xE3, "store", None,
     "*:8 ea = RSYb_R1;", "64-bit"),
    ("STOCFH", 0xE1, "store", None,
     "*:4 ea = (RSYb_R1 >> 32);", "32-bit, high half"),
]
for base, op2, kind, pre, action, comment in rsyb:
    w(f"# {base}: {comment} ({kind}).")
    # STOCFH needs a shift-amount local (SLEIGH requires shift output size
    # to match; assign 8-byte shifted value to tmp, then store truncates).
    need_sh = base == "STOCFH"
    if need_sh:
        action = "sh = 32;\n    tmp = RSYb_R1 >> sh;\n    *:4 ea = tmp;"
    for mask in sorted(LOC_SUFFIX):
        suf = LOC_SUFFIX[mask]
        w(f":{base}{suf} \"{base}{suf} \" RSYb_R1 \",\" RSYb_DL2 \"(\" RSYb_B2 \")\" is RSYb_OP=0xEB & RSYb_R1 & RSYb_M3={mask} & RSYb_B2 & RSYb_DL2 & RSYb_DH2 & RSYb_OP2=0x{op2:02X}")
        w("{")
        w("    local ea:8;")
        if pre and "w = " in pre:
            w("    local w:4;")
        if need_sh:
            w("    local tmp:8;")
            w("    local sh:8;")
        for line in mask_decls():
            w(line)
        w("    ea_D20(ea, RSYb_B2, zero, RSYb_DH2, RSYb_DL2);")
        for line in mask_logic(str(mask)):
            w(line)
        if pre:
            w(f"    {pre}")
        w(f"    {action}")
        w("<c_done>")
        w("}")
        w("")
    w(f":{base} \"{base} \" RSYb_R1 \",\" RSYb_DL2 \"(\" RSYb_B2 \"),\" RSYb_M3 is RSYb_OP=0xEB & RSYb_R1 & RSYb_M3 & RSYb_B2 & RSYb_DL2 & RSYb_DH2 & RSYb_OP2=0x{op2:02X}")
    w("{")
    w("    local ea:8;")
    if pre and "w = " in pre:
        w("    local w:4;")
    if need_sh:
        w("    local tmp:8;")
        w("    local sh:8;")
    for line in mask_decls():
        w(line)
    w("    ea_D20(ea, RSYb_B2, zero, RSYb_DH2, RSYb_DL2);")
    for line in mask_logic("RSYb_M3"):
        w(line)
    if pre:
        w(f"    {pre}")
    w(f"    {action}")
    w("<c_done>")
    w("}")
    w("")

# ============================================================ RSY-b traps
w("# ===========================================================================")
w("# COMPARE LOGICAL AND TRAP, storage forms (RSY-b). PoP 7-169.")
w("# CLT EB23 (unsigned 32), CLGT EB2B (unsigned 64). HLASM/Capstone order:")
w("# the mask is the SECOND operand: CLT R1,M3,D2(B2).")
w("# ===========================================================================")

for base, op2, ccmacro, sz in [("CLT", 0x23, "cc_ucmp", 4), ("CLGT", 0x2B, "cc_ucmp", 8)]:
    w(f"# {base}: unsigned {sz*8}-bit compare against storage operand.")
    for mask in sorted(TRAP_SUFFIX):
        suf = TRAP_SUFFIX[mask]
        w(f":{base}{suf} \"{base}{suf} \" RSYb_R1 \",\" RSYb_DL2 \"(\" RSYb_B2 \")\" is RSYb_OP=0xEB & RSYb_R1 & RSYb_M3={mask} & RSYb_B2 & RSYb_DL2 & RSYb_DH2 & RSYb_OP2=0x{op2:02X}")
        w("{")
        w("    local ea:8;")
        w("    local a:8;")
        w("    local b:8;")
        for line in trap_decls():
            w(line)
        w("    ea_D20(ea, RSYb_B2, zero, RSYb_DH2, RSYb_DL2);")
        if sz == 4:
            w("    a = RSYb_R1 & 0xffffffff;")
            w(f"    b = zext(*:{sz} ea);")
        else:
            w("    a = RSYb_R1;")
            w(f"    b = *:{sz} ea;")
        w(f"    {ccmacro}(a, b);")
        for line in trap_logic(str(mask)):
            w(line)
        w("}")
        w("")
    w(f":{base} \"{base} \" RSYb_R1 \",\" RSYb_M3 \",\" RSYb_DL2 \"(\" RSYb_B2 \")\" is RSYb_OP=0xEB & RSYb_R1 & RSYb_M3 & RSYb_B2 & RSYb_DL2 & RSYb_DH2 & RSYb_OP2=0x{op2:02X}")
    w("{")
    w("    local ea:8;")
    w("    local a:8;")
    w("    local b:8;")
    for line in trap_decls():
        w(line)
    w("    ea_D20(ea, RSYb_B2, zero, RSYb_DH2, RSYb_DL2);")
    if sz == 4:
        w("    a = RSYb_R1 & 0xffffffff;")
        w(f"    b = zext(*:{sz} ea);")
    else:
        w("    a = RSYb_R1;")
        w(f"    b = *:{sz} ea;")
    w(f"    {ccmacro}(a, b);")
    for line in trap_logic("RSYb_M3"):
        w(line)
    w("}")
    w("")

# ============================================================ RIE-g loads
w("# ===========================================================================")
w("# LOAD HALFWORD IMMEDIATE ON CONDITION (RIE-g). PoP 7-315.")
w("# LOCHI EC42: sign-extended I2 -> bits 32-63 of R1 (low 32).")
w("# LOCGHI EC46: sign-extended I2 -> bits 0-63 of R1 (all 64).")
w("# LOCHHI EC4E: sign-extended I2 -> bits 0-31 of R1 (high 32).")
w("# CC unchanged. (There is no LOCFHI; LOCHHI is the high-half form.)")
w("# ===========================================================================")

rieg = [
    ("LOCHI", 0x42,
     "RIEg_R1 = (RIEg_R1 & (0xFFFFFFFF << 32)) | zext(w);",
     "sign-extended I2 into low 32 bits"),
    ("LOCGHI", 0x46,
     "RIEg_R1 = sext(_ext_rieg_i2);",
     "sign-extended I2 into all 64 bits"),
    ("LOCHHI", 0x4E,
     "RIEg_R1 = (RIEg_R1 & 0xFFFFFFFF) | (zext(w) << 32);",
     "sign-extended I2 into high 32 bits"),
]
for base, op2, action, comment in rieg:
    w(f"# {base}: {comment}.")
    need_w = "zext(w)" in action
    for mask in sorted(LOC_SUFFIX):
        suf = LOC_SUFFIX[mask]
        w(f":{base}{suf} \"{base}{suf} \" RIEg_R1 \",\" RIEg_I2 is RIEg_OP=0xEC & RIEg_R1 & RIEg_M3={mask} & RIEg_I2 & RIEg_IGN & RIEg_OP2=0x{op2:02X}")
        w("{")
        w("    local _ext_rieg_i2:2;")
        if need_w:
            w("    local w:4;")
        for line in mask_decls():
            w(line)
        w("    _ext_rieg_i2 = RIEg_I2;")
        if need_w:
            w("    w = sext(_ext_rieg_i2);")
        for line in mask_logic(str(mask)):
            w(line)
        w(f"    {action}")
        w("<c_done>")
        w("}")
        w("")
    w(f":{base} \"{base} \" RIEg_R1 \",\" RIEg_I2 \",\" RIEg_M3 is RIEg_OP=0xEC & RIEg_R1 & RIEg_M3 & RIEg_I2 & RIEg_IGN & RIEg_OP2=0x{op2:02X}")
    w("{")
    w("    local _ext_rieg_i2:2;")
    if need_w:
        w("    local w:4;")
    for line in mask_decls():
        w(line)
    w("    _ext_rieg_i2 = RIEg_I2;")
    if need_w:
        w("    w = sext(_ext_rieg_i2);")
    for line in mask_logic("RIEg_M3"):
        w(line)
    w(f"    {action}")
    w("<c_done>")
    w("}")
    w("")

# ============================================================ RIE-a traps
w("# ===========================================================================")
w("# COMPARE (LOGICAL) IMMEDIATE AND TRAP (RIE-a). PoP 7-169.")
w("# CIT EC72 (signed 32; I2 sign-extended), CGIT EC70 (signed 64; I2")
w("# sign-extended), CLFIT EC73 (unsigned 32; I2 zero-extended), CLGIT EC71")
w("# (unsigned 64; I2 zero-extended). CC set from the comparison; the")
w("# compare-and-trap data exception is modeled via trap_compare_data().")
w("# ===========================================================================")

riea = [
    ("CIT", 0x72, "cc_scmp32", "sext",
     "a = RIEa_R1 & 0xffffffff;", "b = sext(_ext_riea_i2) & 0xffffffff;"),
    ("CGIT", 0x70, "cc_scmp64", "sext",
     "a = RIEa_R1;", "b = sext(_ext_riea_i2);"),
    ("CLFIT", 0x73, "cc_ucmp", "zext",
     "a = RIEa_R1 & 0xffffffff;", "b = zext(_ext_riea_i2) & 0xffffffff;"),
    ("CLGIT", 0x71, "cc_ucmp", "zext",
     "a = RIEa_R1;", "b = zext(_ext_riea_i2);"),
]
for base, op2, ccmacro, extkind, a_stmt, b_stmt in riea:
    w(f"# {base}: {ccmacro}, I2 {extkind}-extended.")
    for mask in sorted(TRAP_SUFFIX):
        suf = TRAP_SUFFIX[mask]
        w(f":{base}{suf} \"{base}{suf} \" RIEa_R1 \",\" RIEa_I2 is RIEa_OP=0xEC & RIEa_R1 & RIEa_IGN1 & RIEa_I2 & RIEa_M3={mask} & RIEa_IGN2 & RIEa_OP2=0x{op2:02X}")
        w("{")
        w("    local a:8;")
        w("    local b:8;")
        w("    local _ext_riea_i2:2;")
        for line in trap_decls():
            w(line)
        w("    _ext_riea_i2 = RIEa_I2;")
        w(f"    {a_stmt}")
        w(f"    {b_stmt}")
        w(f"    {ccmacro}(a, b);")
        for line in trap_logic(str(mask)):
            w(line)
        w("}")
        w("")
    w(f":{base} \"{base} \" RIEa_R1 \",\" RIEa_I2 \",\" RIEa_M3 is RIEa_OP=0xEC & RIEa_R1 & RIEa_IGN1 & RIEa_I2 & RIEa_M3 & RIEa_IGN2 & RIEa_OP2=0x{op2:02X}")
    w("{")
    w("    local a:8;")
    w("    local b:8;")
    w("    local _ext_riea_i2:2;")
    for line in trap_decls():
        w(line)
    w("    _ext_riea_i2 = RIEa_I2;")
    w(f"    {a_stmt}")
    w(f"    {b_stmt}")
    w(f"    {ccmacro}(a, b);")
    for line in trap_logic("RIEa_M3"):
        w(line)
    w("}")
    w("")

# ============================================================ SELECT
w("# ===========================================================================")
w("# SELECT (RRF-a). PoP 7-401. R1 = M4-matched ? R2 : R3. CC unchanged.")
w("# SELR B9F0 (32-bit, low halves), SELGR B9E3 (64-bit), SELFHR B9C0")
w("# (32-bit, high halves). Extended mnemonics from IBM Appendix J (the")
w("# arithmetic set O/H/L/NE/E/NL/NH/NO); Capstone 5.0.7 cannot decode these")
w("# instructions, so the corpus vectors are decode-only.")
w("# ===========================================================================")

selects = [
    ("SELR", 0xB9F0,
     "RRFa_R1 = (RRFa_R1 & (0xFFFFFFFF << 32)) | (RRFa_R3 & 0xFFFFFFFF);",
     "RRFa_R1 = (RRFa_R1 & (0xFFFFFFFF << 32)) | (RRFa_R2 & 0xFFFFFFFF);",
     "32-bit, low halves"),
    ("SELGR", 0xB9E3,
     "RRFa_R1 = RRFa_R3;",
     "RRFa_R1 = RRFa_R2;",
     "64-bit"),
    ("SELFHR", 0xB9C0,
     "RRFa_R1 = (RRFa_R1 & 0xFFFFFFFF) | (RRFa_R3 & (0xFFFFFFFF << 32));",
     "RRFa_R1 = (RRFa_R1 & 0xFFFFFFFF) | (RRFa_R2 & (0xFFFFFFFF << 32));",
     "32-bit, high halves"),
]
for base, op, else_move, then_move, comment in selects:
    w(f"# {base}: {comment}.")
    for mask in sorted(SEL_SUFFIX):
        suf = SEL_SUFFIX[mask]
        w(f":{base}{suf} \"{base}{suf} \" RRFa_R1 \",\" RRFa_R2 \",\" RRFa_R3 is RRFa_OP=0x{op:04X} & RRFa_R3 & RRFa_M4={mask} & RRFa_R1 & RRFa_R2")
        w("{")
        w("    local _s_ccval:1;")
        w("    local _s_bit:1;")
        w("    _s_ccval = (cc >> 4) & 0x3;")
        w("    _s_bit = 8 >> _s_ccval;")
        w(f"    if (({mask} & _s_bit) != 0) goto <sel_r2>;")
        w(f"    {else_move}")
        w("    goto <sel_done>;")
        w("<sel_r2>")
        w(f"    {then_move}")
        w("<sel_done>")
        w("}")
        w("")
    w(f":{base} \"{base} \" RRFa_R1 \",\" RRFa_R2 \",\" RRFa_R3 \",\" RRFa_M4 is RRFa_OP=0x{op:04X} & RRFa_R3 & RRFa_M4 & RRFa_R1 & RRFa_R2")
    w("{")
    w("    local _s_ccval:1;")
    w("    local _s_bit:1;")
    w("    _s_ccval = (cc >> 4) & 0x3;")
    w("    _s_bit = 8 >> _s_ccval;")
    w("    if ((RRFa_M4 & _s_bit) != 0) goto <sel_r2>;")
    w(f"    {else_move}")
    w("    goto <sel_done>;")
    w("<sel_r2>")
    w(f"    {then_move}")
    w("<sel_done>")
    w("}")
    w("")

# ============================================================ LOAD AND TRAP
w("# ===========================================================================")
w("# LOAD AND TRAP (RXY-a). PoP 7-309. The second operand is placed unchanged")
w("# at the first-operand location; if all zeros are placed there, a")
w("# compare-and-trap-instruction data exception is recognized (DXC FF) —")
w("# modeled explicitly via trap_compare_data(). CC unchanged.")
w("# LAT E39F: 32-bit -> bits 32-63 of R1 (low half), bits 0-31 unchanged.")
w("# LGAT E385: 64-bit -> all of R1.")
w("# LLGFAT E39D: 32-bit -> bits 32-63 of R1, zeros in bits 0-31.")
w("# LLGTAT E39C: bits 1-31 of the word -> bits 33-63 of R1, zeros in 0-32.")
w("# LFHAT E3C8: 32-bit -> bits 0-31 of R1 (high half), bits 32-63 unchanged.")
w("# ===========================================================================")

lats = [
    # NOTE: zero_test must use the 4-byte local `w` directly, not zext(w):
    # zext in an `if` condition has unresolvable output size (sleigh_opt
    # "Main section: Could not resolve at least 1 variable size").
    ("LAT", 0x9F,
     "    local w:4;\n    w = *:4 ea;\n    RXYa_R1 = (RXYa_R1 & (0xFFFFFFFF << 32)) | zext(w);",
     "w"),
    ("LGAT", 0x85,
     "    RXYa_R1 = *:8 ea;",
     "RXYa_R1"),
    ("LLGFAT", 0x9D,
     "    local w:4;\n    w = *:4 ea;\n    RXYa_R1 = zext(w);",
     "w"),
    ("LLGTAT", 0x9C,
     "    local w:4;\n    w = *:4 ea;\n    RXYa_R1 = zext(w) & 0x7fffffff;",
     "w & 0x7fffffff"),
    ("LFHAT", 0xC8,
     "    local w:4;\n    w = *:4 ea;\n    RXYa_R1 = (RXYa_R1 & 0xFFFFFFFF) | (zext(w) << 32);",
     "w"),
]
for base, op2, body, zero_test in lats:
    w(f":{base} \"{base} \" RXYa_R1 \",\" RXYa_DL2 \"(\" RXYa_X2 \",\" RXYa_B2 \")\" is RXYa_OP=0xE3 & RXYa_R1 & RXYa_X2 & RXYa_B2 & RXYa_DL2 & RXYa_DH2 & RXYa_OP2=0x{op2:02X}")
    w("{")
    w("    local ea:8;")
    if "local w:4;" in body:
        w("    local w:4;")
        body = body.replace("    local w:4;\n", "")
    w("    ea_D20(ea, RXYa_B2, RXYa_X2, RXYa_DH2, RXYa_DL2);")
    w(body)
    w(f"    if (({zero_test}) == 0) goto <lat_trap>;")
    w("    goto <lat_done>;")
    w("<lat_trap>")
    w("    trap_compare_data();")
    w("<lat_done>")
    w("}")
    w("")

# ============================================================ MVCIN
w("# ===========================================================================")
w("# MOVE INVERSE (MVCIN), SS-a, opcode E8. PoP 7-330: the second operand is")
w("# placed at the first-operand location with the left-to-right order")
w("# inverted (byte-reversed copy of L+1 bytes). The result is obtained as if")
w("# the second operand were processed right to left and the first operand")
w("# left to right. Overlapping by more than one byte => unpredictable.")
w("# CC unchanged. Loop follows the NC (s390x_arith.sinc) counted-loop idiom.")
w("# Harness note: display prints the raw L field (length-1); the harness")
w("# adds 1 for the 'mvcin' mnemonic (SS_LEN_MNEMS), like mvc/xc/nc/oc/clc.")
w("# ===========================================================================")
w(":MVCIN \"MVCIN \" SSa_D1 \"(\" SSa_L \",\" SSa_B1 \"),\" SSa_D2 \"(\" SSa_B2 \")\" is SSa_OP=0xE8 & SSa_L & SSa_B1 & SSa_D1 & SSa_B2 & SSa_D2")
w("{")
w("    local ea1:8;")
w("    local ea2:8;")
w("    local len:8;")
w("    local b:1;")
w("    local _ext_mvcin_l:1;")
w("    ea_D12(ea1, SSa_B1, zero, SSa_D1);")
w("    ea_D12(ea2, SSa_B2, zero, SSa_D2);")
w("    _ext_mvcin_l = SSa_L;")
w("    # Second operand processed right-to-left: start at its last byte.")
w("    ea2 = ea2 + zext(_ext_mvcin_l);")
w("    len = zext(_ext_mvcin_l) + 1;")
w("    <mcv_loop>")
w("    if (len == 0) goto <mcv_done>;")
w("    b = *:1 (ea2);")
w("    *:1 ea1 = b;")
w("    ea1 = ea1 + 1;")
w("    ea2 = ea2 - 1;")
w("    len = len - 1;")
w("    goto <mcv_loop>;")
w("    <mcv_done>")
w("}")
w("")

# ============================================================ MVPG / LFPC
w("# ===========================================================================")
w("# MOVE PAGE (MVPG), RRE, opcode B254 — decode-only. PoP 10-x: privileged")
w("# (special-operation exception in problem state; DAT and storage-key")
w("# controlled) 4 KiB page copy. Cannot be modeled honestly in p-code.")
w("# ===========================================================================")
w(":MVPG \"MVPG \" RRE_R1 \",\" RRE_R2 is RRE_OP=0xB254 & RRE_R1 & RRE_R2")
w("{")
w("}")
w("")
w("# ===========================================================================")
w("# LOAD FPC (LFPC), S format, opcode B29D. PoP 9-31: the 4-byte second")
w("# operand in storage is placed into the FPC (floating-point-control)")
w("# register. CC unchanged. (LFAS, the signaling variant, is not covered.)")
w("# ===========================================================================")
w(":LFPC \"LFPC \" S_D2 \"(\" S_B2 \")\" is S_OP=0xB29D & S_B2 & S_D2")
w("{")
w("    local ea:8;")
w("    ea_D12(ea, S_B2, zero, S_D2);")
w("    fpc = *:4 ea;")
w("}")
w("")

open(os.path.join(REPO_ROOT, "data/languages/s390x_cond.sinc"), "w").write(out.getvalue())
print("wrote", len(out.getvalue().splitlines()), "lines")
