#!/usr/bin/env python3
"""gen_gaps2.py — generate data/languages/s390x_gaps2.sinc.

Second-round gap fillers: the six instructions that were NODECODE in the
base spec (confirmed by the 20,000-input differential fuzzer, 2026-09-21):

  BSM    0x0B  RR    BRANCH AND SET MODE            (PoP 7-39)
  BASSM  0x0C  RR    BRANCH AND SAVE AND SET MODE   (PoP 7-38)
  LAE    0x51  RX-a  LOAD ADDRESS EXTENDED          (PoP 7-304)
  TRACE  0x99  RS-a  TRACE                          (PoP 10-187, privileged)
  LAM    0x9A  RS-a  LOAD ACCESS MULTIPLE           (PoP 7-303)
  STAM   0x9B  RS-a  STORE ACCESS MULTIPLE          (PoP 7-443)

All opcodes, formats, and semantics verified against IBM z/Architecture
Principles of Operation SA22-7832-14 (15th edition, April 2025).

Design notes (follow repo precedent, esp. tools/gen_lmstm.py):
- "R field is zero" conditions are on the FIELD VALUE, so constructors are
  fully unrolled over the constrained fields: BSM/BASSM over (R1,R2),
  LAE over (R1,B2), LAM/STAM over (R1,R3). Every combination is mutually
  exclusive, so no disambiguation ordering is relied upon.
- SLEIGH requires that a field constrained with =N in the `is` clause NOT
  appear in the display section, so generated constructors print register
  names as literals ("r3", "a2") and hardcode them in p-code, exactly like
  the generated LM/STM constructors.
- BSM/BASSM: the R1 mode-bit save and the R2 branch + addressing-mode
  change are exact; the new addressing-mode bits (PSW bits 31,32 = pswm
  value-bits 32,31, per the SSM convention that PoP PSW bit p lives at
  pswm value-bit (63-p)) are a conservative unkval() clobber, since the
  post-branch mode is dynamic. The branch target honors "bit 63 of R2
  treated as zero" (PoP 7-39). CC unchanged.
- LAE: address part follows :LA (64-bit addressing mode assumed);
  access-register part implements the PoP 7-304 ASC table exactly
  (00->0, 10->1, 11->2, 01->0 if B2=0 else AR(B2)).
- LAM/STAM: exact register-range loads/stores with a15->a0 wraparound
  (PoP 7-303/7-443: "access register 0 following access register 15").
  12-bit unsigned displacement via ea_D12; CC unchanged.
- TRACE: privileged; the trace table, TOD clock, and serialization have
  no modeled varnode, and the fetched word is consumed only by the trace
  entry, so the constructor is decode-only by design (cf. :svc, :trap2).

Reuse: tokens RR/RXa/RSa (core s390x.slaspec), macro ea_D12 (core),
registers r0-r15, a0-a15, pswm, pswia, and the unkval pcodeop defined in
s390x_system.sinc — include this file AFTER s390x_system.sinc
(recommended: right after s390x_gaps.sinc).

Usage: python3 tools/gen_gaps2.py   # writes data/languages/s390x_gaps2.sinc
"""

import os

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.normpath(os.path.join(HERE, "..", "data", "languages",
                                    "s390x_gaps2.sinc"))

LINES = []

# ---------------------------------------------------------------------------
# BSM / BASSM p-code fragments (registers hardcoded per constructor)
# ---------------------------------------------------------------------------

def r1_mode_save(p, r1):
    """BSM R1 update (PoP 7-39): save current addressing-mode bit into R1."""
    return """\
    # PoP 7-39: save the current addressing-mode bit into r%(r1)d. In 64-bit
    # mode (PSW bit 31 = pswm value-bit 32) a one is inserted into bit 63
    # of the register (value-bit 0); in 24/31-bit mode the PSW basic-
    # addressing-mode bit (PSW bit 32 = pswm value-bit 31) is inserted into
    # bit 32 of the register (value-bit 31). Other bits are unchanged.
    local is64:8;
    is64 = (pswm >> 32) & 1;
    if (is64 == 0) goto <%(p)s_2431>;
    r%(r1)d = r%(r1)d | 1;
    goto <%(p)s_r1done>;
<%(p)s_2431>
    r%(r1)d = (r%(r1)d & 0xFFFFFFFF7FFFFFFF) | (((pswm >> 31) & 1) << 31);
<%(p)s_r1done>""" % {"p": p, "r1": r1}


def bassm_link_save(p, r1):
    """BASSM R1 link save (PoP 7-38) from the CURRENT (old) PSW."""
    return """\
    # PoP 7-38: save link information from the current PSW (read BEFORE
    # the PSW is updated below). 64-bit mode: updated instruction address
    # with a one appended on the right. 24/31-bit mode: the PSW basic-
    # addressing-mode bit (PSW bit 32 = pswm value-bit 31) into bit 32 of
    # r%(r1)d (value-bit 31) and the low 31 bits of the updated instruction
    # address into bits 33-63 (value-bits 30-0); bits 0-31 unchanged.
    # inst_next is the updated instruction address.
    local is64:8;
    is64 = (pswm >> 32) & 1;
    if (is64 == 0) goto <%(p)s_2431>;
    r%(r1)d = (inst_next & 0xFFFFFFFFFFFFFFFE) | 1;
    goto <%(p)s_lnkdone>;
<%(p)s_2431>
    r%(r1)d = (r%(r1)d & 0xFFFFFFFF00000000) | (((pswm >> 31) & 1) << 31) | (inst_next & 0x7FFFFFFF);
<%(p)s_lnkdone>""" % {"p": p, "r1": r1}


def branch_and_set_mode(p, r2):
    """BSM/BASSM R2 action (PoP 7-38/7-39): set addressing mode + branch."""
    return """\
    # The R2 field is nonzero here (field-constrained constructors).
    # Addressing-mode bits (PSW bits 31,32 = pswm value-bits 32,31) take
    # unknown values -- conservative clobber, the new mode is dynamic.
    # Branch to r%(r2)d with bit 63 treated as zero when it selects 64-bit mode.
    local amode:8;
    amode = unkval();
    pswm = (pswm & 0xFFFFFFFE7FFFFFFF) | (amode & 0x180000000);
    if ((r%(r2)d & 1) == 0) goto <%(p)s_tgt>;
    pswia = r%(r2)d & 0x7FFFFFFFFFFFFFFF;
    goto <%(p)s_tgtdone>;
<%(p)s_tgt>
    pswia = r%(r2)d;
<%(p)s_tgtdone>""" % {"p": p, "r2": r2}


def emit_bsm_bassm(mnem, op):
    is_bassm = (mnem == "bassm")
    LINES.append("# " + "-" * 74)
    LINES.append("# %s — %s (PoP %s)." % (
        mnem.upper(),
        "BRANCH AND SAVE AND SET MODE" if is_bassm else "BRANCH AND SET MODE",
        "7-38" if is_bassm else "7-39"))
    LINES.append("# " + "-" * 74)
    for r1 in range(16):
        for r2 in range(16):
            p = "%s_%d_%d" % (mnem, r1, r2)
            body = []
            if r1 != 0:
                body.append(bassm_link_save(p, r1) if is_bassm
                            else r1_mode_save(p, r1))
            if r2 != 0:
                body.append(branch_and_set_mode(p, r2))
            if not body:
                body.append("    # R1 field and R2 field are both zero: no operand action\n"
                            "    # is performed (no R1 update, no branch, no addressing-mode\n"
                            "    # change). CC unchanged.")
            LINES.append(':%s "%s " "r%d" "," "r%d"'
                         ' is RR_OP=0x%02X & RR_R1=%d & RR_R2=%d'
                         % (p, mnem, r1, r2, op, r1, r2))
            LINES.append("{")
            LINES.extend(body)
            LINES.append("}")
            LINES.append("")


# ---------------------------------------------------------------------------
# LAE
# ---------------------------------------------------------------------------

def emit_lae():
    LINES.append("# " + "-" * 74)
    LINES.append("# LAE — LOAD ADDRESS EXTENDED (PoP 7-304).")
    LINES.append("# " + "-" * 74)
    for r1 in range(16):
        for b2 in range(16):
            p = "lae_%d_%d" % (r1, b2)
            ar_src = "a%d" % b2 if b2 != 0 else "0"
            b2disp = "zero" if b2 == 0 else "r%d" % b2
            b2reg = "zero" if b2 == 0 else "r%d" % b2
            LINES.append(
                ':%s "lae " "r%d" "," RXa_D2 "(" RXa_X2 "," "%s" ")"'
                ' is RXa_OP=0x51 & RXa_R1=%d & RXa_X2 & RXa_B2=%d & RXa_D2'
                % (p, r1, b2disp, r1, b2))
            LINES.append("{")
            LINES.append("""\
    local ea:8;
    local asc:8;
    # NOTE: RXa_B2 is field-constrained, so it cannot be named in p-code;
    # the base register is hardcoded per constructor (zero for B2=0).
    ea_D12(ea, %(breg)s, RXa_X2, RXa_D2);
    # Address part: 64-bit addressing mode assumed (as :LA, PoP 7-304).
    r%(r1)d = ea;
    # Access-register part (PoP 7-304 table) from the PSW address-space-
    # control bits (PSW bits 16-17 = pswm value-bits 47-46): 00 primary
    # -> 0; 10 secondary -> 1; 11 home -> 2; 01 access-register mode ->
    # 0 when the B2 field is zero, else the contents of access register B2.
    asc = (pswm >> 46) & 3;
    if (asc == 2) goto <%(p)s_s>;
    if (asc == 3) goto <%(p)s_h>;
    if (asc == 1) goto <%(p)s_a>;
    a%(r1)d = 0;
    goto <%(p)s_done>;
<%(p)s_s>
    a%(r1)d = 1;
    goto <%(p)s_done>;
<%(p)s_h>
    a%(r1)d = 2;
    goto <%(p)s_done>;
<%(p)s_a>
    a%(r1)d = %(src)s;
<%(p)s_done>""" % {"p": p, "r1": r1, "src": ar_src, "breg": b2reg})
            LINES.append("}")
            LINES.append("")


# ---------------------------------------------------------------------------
# LAM / STAM
# ---------------------------------------------------------------------------

def reg_range(r1, r3):
    """Access-register numbers R1..R3 with a15->a0 wraparound (PoP 7-303)."""
    out = []
    r = r1
    while True:
        out.append(r)
        if r == r3:
            break
        r = (r + 1) % 16
    return out


def emit_lam_stam(mnem, op, is_lam):
    LINES.append("# " + "-" * 74)
    LINES.append("# %s — %s (PoP %s)." % (
        mnem.upper(),
        "LOAD ACCESS MULTIPLE" if is_lam else "STORE ACCESS MULTIPLE",
        "7-303" if is_lam else "7-443"))
    LINES.append("# " + "-" * 74)
    for r1 in range(16):
        for r3 in range(16):
            p = "%s_%d_%d" % (mnem, r1, r3)
            regs = reg_range(r1, r3)
            LINES.append(
                ':%s "%s " "a%d" "," "a%d" "," RSa_D2 "(" RSa_B2 ")"'
                ' is RSa_OP=0x%02X & RSa_R1=%d & RSa_R3=%d & RSa_B2 & RSa_D2'
                % (p, mnem, r1, r3, op, r1, r3))
            LINES.append("{")
            if is_lam:
                LINES.append(
                    "    # PoP 7-303: load access registers %s from consecutive"
                    " words starting at the second-operand address." %
                    ",".join("a%d" % r for r in regs))
            else:
                LINES.append(
                    "    # PoP 7-443: store access registers %s to consecutive"
                    " words starting at the second-operand address." %
                    ",".join("a%d" % r for r in regs))
            LINES.append("    local ea:8;")
            LINES.append("    ea_D12(ea, RSa_B2, zero, RSa_D2);")
            for r in regs:
                if is_lam:
                    LINES.append("    a%d = *:4 ea;" % r)
                else:
                    LINES.append("    *:4 ea = a%d;" % r)
                LINES.append("    ea = ea + 4;")
            LINES.append("}")
            LINES.append("")


# ---------------------------------------------------------------------------
# TRACE
# ---------------------------------------------------------------------------

def emit_trace():
    LINES.append("# " + "-" * 74)
    LINES.append("# TRACE — TRACE (PoP 10-187). Privileged.")
    LINES.append("# " + "-" * 74)
    LINES.append(':trace "trace " RSa_R1 "," RSa_R3 "," RSa_D2 "(" RSa_B2 ")"'
                 ' is RSa_OP=0x99 & RSa_R1 & RSa_R3 & RSa_B2 & RSa_D2')
    LINES.append("{")
    LINES.append("""\
    # TRACE (PoP 10-187): privileged. Fetches the 32-bit second operand;
    # when explicit tracing is on (control register 12, bit 63) and bit 0
    # of the operand is zero, a trace entry is formed at the real-storage
    # location designated by control register 12, recording TOD-clock bits
    # and general registers R1..R3. The clobbered state (trace table,
    # TOD clock, serialization and checkpoint-synchronization) has no
    # modeled varnode, and the fetched word is consumed only by the trace
    # entry, so no p-code is emitted. CC unchanged. Opaque by design
    # (cf. :svc, :trap2, :diagnose).""")
    LINES.append("}")
    LINES.append("")


HEADER = """\
# =============================================================================
# s390x_gaps2.sinc — second-round gap fillers (6 mnemonics, 1281 constructors).
#
# GENERATED FILE — do not hand-edit. Produced by tools/gen_gaps2.py; re-run
# the generator to change.
#
# All opcodes, formats, and semantics verified against IBM z/Architecture
# Principles of Operation SA22-7832-14 (15th edition, April 2025).
#
# Inclusion: @include AFTER s390x_system.sinc in s390x.slaspec
# (recommended: immediately after s390x_gaps.sinc). Reuses: tokens
# RR/RXa/RSa (core), macro ea_D12 (core), registers r0-r15, a0-a15,
# pswm, pswia, and the unkval pcodeop (s390x_system.sinc).
#
# Conventions (inherited from the core spec):
#   - IBM bit numbering in comments is MSB=0; SLEIGH fields are LSB=0.
#   - PoP PSW bit p lives at pswm value-bit (63-p) (SSM convention).
#   - Token fields are zero-extended into pcode expressions.
#   - Size discipline: :1 = 1 byte, :4 = 4 bytes, :8 = 8 bytes.
#   - 12-bit displacements go through ea_D12 (unsigned).
#   - Display syntax matches HLASM operand order for the mnemonic.
#   - SLEIGH forbids constraining (=N) a field that also appears in the
#     display section, so field-constrained constructors print register
#     names as literals and hardcode them in p-code (as in gen_lmstm.py).
# =============================================================================

"""

def main():
    del LINES[:]
    emit_bsm_bassm("bsm", 0x0B)
    emit_bsm_bassm("bassm", 0x0C)
    emit_lae()
    emit_lam_stam("lam", 0x9A, True)
    emit_lam_stam("stam", 0x9B, False)
    emit_trace()
    with open(OUT, "w") as f:
        f.write(HEADER)
        f.write("\n".join(LINES))
    print("wrote %s (%d constructors)" % (OUT, sum(
        1 for l in LINES if l.startswith(":"))))

if __name__ == "__main__":
    main()
