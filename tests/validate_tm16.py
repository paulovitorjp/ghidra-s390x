#!/usr/bin/env python3
"""validate_tm16.py -- semantic validation of the TMHH/TMHL/TMLH/TMLL
condition-code fix.

PoP rule for the 16-bit TEST UNDER MASK forms: CC=0 if the selected bits
are all zero (or the mask is zero), CC=3 if the selected bits are all one,
otherwise "mixed": CC=1 if the tested field's leftmost bit is 0, CC=2 if
it is 1. (The byte forms TM/TMY have no CC=2 and are untouched.)

For each of the four instructions, 8 (field, mask) cases covering
CC=0/1/2/3:
  1. Decode the RIM encoding with tests/s390x_decode: require OK and the
     expected spec mnemonic.
  2. Dump p-code with tests/s390x_pcode.
  3. Concretely execute the p-code with the operand register set, using
     the tiny interpreter from validate_cond2 (intra-p-code labels are
     relative offsets: target = op index + const).
  4. Require the final cc value to equal the PoP rule above.

Also asserts at the source level that TM/TMY still call cc_tm (no CC=2),
since those need memory operands the interpreter cannot model.

Usage: python3 tests/validate_tm16.py [--sla PATH]
Exit 0 iff every check passes.
"""
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import validate_cond2 as v2

DEFAULT_SLA = os.path.join(HERE, "..", "data", "languages", "s390x.sla")

# name -> (M3, shift of the tested 16-bit field within the 64-bit register)
TM16 = {
    "TMHH": (2, 48),
    "TMHL": (3, 32),
    "TMLH": (0, 16),
    "TMLL": (1, 0),
}

# (field16, mask16, expected_cc)
CASES = [
    (0x0000, 0xFFFF, 0),  # selected bits all zero
    (0xFFFF, 0xFFFF, 3),  # selected bits all one
    (0x8000, 0x8000, 3),  # single selected bit, set -> all one
    (0x4000, 0x4000, 3),  # single selected bit, set -> all one
    (0x1234, 0x0000, 0),  # mask zero
    (0x00FF, 0xFF00, 0),  # disjoint mask -> selected zero
    (0xA000, 0xF000, 2),  # mixed, leftmost bit of field is 1
    (0x5000, 0xF000, 1),  # mixed, leftmost bit of field is 0
    (0x8000, 0xC000, 2),  # partial mask, mixed, leftmost 1
    (0x4000, 0x6000, 1),  # partial mask, mixed, leftmost 0
]


def encode_rim(m3, mask16):
    # RIM: A7 | (R1=5 << 4) | M3 | I2(16 bits, big-endian)
    return "a7%02x%04x" % ((5 << 4) | m3, mask16)


def check_source_tm_unchanged():
    """TM/TMY (byte forms) must still use cc_tm, never cc_tm16."""
    src = open(os.path.join(HERE, "..", "data", "languages",
                            "s390x_arith.sinc")).read()
    # find the :TM and :TMY constructor bodies
    for name in (":TM ", ":TMY "):
        m = re.search(r"^" + re.escape(name) + r".*?^}",
                      src, re.M | re.S)
        assert m, "constructor %s not found" % name.strip()
        body = m.group(0)
        assert "cc_tm(" in body, "%s lost cc_tm call" % name.strip()
        assert "cc_tm16(" not in body, "%s must not use cc_tm16" % name.strip()
    # and the four 16-bit forms must use cc_tm16
    for name in (":TMHH ", ":TMHL ", ":TMLH ", ":TMLL "):
        m = re.search(r"^" + re.escape(name) + r".*?^}",
                      src, re.M | re.S)
        assert m, "constructor %s not found" % name.strip()
        assert "cc_tm16(" in m.group(0), "%s must use cc_tm16" % name.strip()


def main():
    sla = sys.argv[sys.argv.index("--sla") + 1] if "--sla" in sys.argv \
        else DEFAULT_SLA
    sla = os.path.normpath(sla)
    check_source_tm_unchanged()
    print("source check: TM/TMY still cc_tm; TMHH/TMHL/TMLH/TMLL use cc_tm16")

    npass = nfail = 0
    failures = []
    for name, (m3, shift) in TM16.items():
        for field16, mask16, want_cc in CASES:
            tag = "%s field=0x%04x mask=0x%04x" % (name, field16, mask16)
            hx = encode_rim(m3, mask16)
            ok, why = True, ""
            # 1. decode
            r = subprocess.run([v2.DECODER, sla, hx], capture_output=True,
                               text=True, timeout=120)
            if not r.stdout.startswith("OK") or name not in r.stdout:
                ok, why = False, "decode: %s" % r.stdout.strip()[:80]
            else:
                # 2+3. dump p-code and execute with r5 = field << shift
                ptxt = v2.run_tool(v2.PCDUMP_BIN, sla, hx)
                ops = v2.parse_pcode(ptxt)
                if not ops:
                    ok, why = False, "no p-code dumped"
                else:
                    regs = {"r5": (field16 << shift) & 0xFFFFFFFFFFFFFFFF}
                    try:
                        (_res, state) = v2._simulate(ops, 0, regs)
                    except RuntimeError as e:
                        ok, why = False, "interpreter: %s" % e
                    else:
                        got_cc = state.get("cc")
                        if got_cc != want_cc:
                            ok, why = (False,
                                       "cc=%s want %d" % (got_cc, want_cc))
            if ok:
                npass += 1
            else:
                nfail += 1
                failures.append((tag, why))

    print("vectors checked : %d" % (npass + nfail))
    print("  passed        : %d" % npass)
    print("  failed        : %d" % nfail)
    for tag, why in failures:
        print("FAIL %s: %s" % (tag, why))
    sys.exit(1 if nfail else 0)


if __name__ == "__main__":
    main()
