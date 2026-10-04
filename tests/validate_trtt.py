#!/usr/bin/env python3
"""validate_trtt.py -- semantic validation of TRTT (TRANSLATE TWO TO TWO,
RRF-c, opcode 0xB990) against PoP 7-478.

The tiny interpreter in validate_cond2 now has a flat big-endian memory
model, so the register/memory/CC behavior can be executed concretely.

Checks per vector:
  1. Decode with tests/s390x_decode: require OK + mnemonic TRTT.
  2. Dump p-code, execute with the given registers and memory.
  3. Require the destination bytes, final CC, and the R1/R1+1/R2
     writeback to match the PoP rule.

PoP rules under test:
  - two-byte argument chars select two-byte function chars from the
    128K table at GR1 (index = 2 * argument);
  - each function char is compared to GR0 bits 48-63: equal -> CC=1,
    character NOT stored, registers not advanced past it;
  - exhausted second operand -> CC=0;
  - R1+1 decremented by processed bytes, R2/R1 incremented by the same;
  - odd R1 or odd length: specification exception, modeled as a no-op
    (state, including CC, unchanged).

Usage: python3 tests/validate_trtt.py [--sla PATH]
Exit 0 iff every check passes.
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import validate_cond2 as v2

DEFAULT_SLA = os.path.join(HERE, "..", "data", "languages", "s390x.sla")

DEST = 0x1000
SRC = 0x2000
TBL = 0x3000  # doubleword-aligned


def w16(mem, addr, val):
    mem[addr] = (val >> 8) & 0xFF
    mem[addr + 1] = val & 0xFF


def r16(mem, addr):
    return (mem.get(addr, 0) << 8) | mem.get(addr + 1, 0)


def base_regs(r1num, r2num, dest, src, length, testchar):
    """Register file for TRTT R1,R2 with R1 even."""
    regs = {"r1": TBL, "r0": testchar,
            "r%d" % r1num: dest, "r%d" % (r1num + 1): length,
            "r%d" % r2num: src}
    return regs


def run_trtt(sla, r1num, r2num, regs, mem):
    hx = "b990%02x%01x%01x" % (0, r1num, r2num)
    r = subprocess.run([v2.DECODER, sla, hx], capture_output=True,
                       text=True, timeout=120)
    if not r.stdout.startswith("OK") or "TRTT" not in r.stdout:
        raise AssertionError("decode failed: %s" % r.stdout.strip()[:80])
    ops = v2.parse_pcode(v2.run_tool(v2.PCDUMP_BIN, sla, hx))
    assert ops, "no p-code dumped"
    (_res, state) = v2._simulate(ops, 9, regs, mem)  # cc sentinel 9
    return state


def check(name, cond, detail=""):
    if not cond:
        raise AssertionError("%s: %s" % (name, detail))


def main():
    sla = sys.argv[sys.argv.index("--sla") + 1] if "--sla" in sys.argv \
        else DEFAULT_SLA
    sla = os.path.normpath(sla)
    npass = 0

    # --- vector 1: full translate, no match -> CC=0 ---------------------
    mem = {}
    for i, ch in enumerate([0x0041, 0x0042, 0x0043]):
        w16(mem, SRC + 2 * i, ch)
    for arg, fc in [(0x41, 0x0061), (0x42, 0x0062), (0x43, 0x0063)]:
        w16(mem, TBL + 2 * arg, fc)
    for i in range(3):
        w16(mem, DEST + 2 * i, 0xBBBB)
    regs = base_regs(2, 4, DEST, SRC, 6, 0xFFFF)
    st = run_trtt(sla, 2, 4, regs, mem)
    check("v1 dest", [r16(mem, DEST + 2 * i) for i in range(3)] ==
          [0x0061, 0x0062, 0x0063],
          "dest=%s" % [hex(r16(mem, DEST + 2 * i)) for i in range(3)])
    check("v1 cc", st["cc"] == 0, "cc=%s" % st["cc"])
    check("v1 r3", st["r3"] == 0, "r3=%s" % st.get("r3"))
    check("v1 r4", st["r4"] == SRC + 6, "r4=%s" % hex(st["r4"]))
    check("v1 r2", st["r2"] == DEST + 6, "r2=%s" % hex(st["r2"]))
    npass += 1

    # --- vector 2: match on 2nd char -> CC=1, no store, partial update --
    mem = {}
    for i, ch in enumerate([0x0041, 0x00FF, 0x0043]):
        w16(mem, SRC + 2 * i, ch)
    w16(mem, TBL + 2 * 0x41, 0x0061)
    w16(mem, TBL + 2 * 0xFF, 0x00AA)
    w16(mem, TBL + 2 * 0x43, 0x0063)
    for i in range(3):
        w16(mem, DEST + 2 * i, 0xBBBB)
    regs = base_regs(2, 4, DEST, SRC, 6, 0x00AA)
    st = run_trtt(sla, 2, 4, regs, mem)
    check("v2 dest0", r16(mem, DEST) == 0x0061, "dest0=%s" % hex(r16(mem, DEST)))
    check("v2 dest1 untouched", r16(mem, DEST + 2) == 0xBBBB,
          "dest1=%s" % hex(r16(mem, DEST + 2)))
    check("v2 cc", st["cc"] == 1, "cc=%s" % st["cc"])
    check("v2 r3", st["r3"] == 4, "r3=%s" % st.get("r3"))
    check("v2 r4", st["r4"] == SRC + 2, "r4=%s" % hex(st["r4"]))
    check("v2 r2", st["r2"] == DEST + 2, "r2=%s" % hex(st["r2"]))
    npass += 1

    # --- vector 3: odd length -> spec exception, no-op ------------------
    mem = {}
    w16(mem, SRC, 0x0041)
    w16(mem, TBL + 2 * 0x41, 0x0061)
    w16(mem, DEST, 0xBBBB)
    regs = base_regs(2, 4, DEST, SRC, 5, 0xFFFF)
    st = run_trtt(sla, 2, 4, regs, mem)
    check("v3 no-op cc", st["cc"] == 9, "cc=%s" % st["cc"])
    check("v3 no-op dest", r16(mem, DEST) == 0xBBBB, "dest changed")
    check("v3 no-op regs", st["r2"] == DEST and st["r3"] == 5 and
          st["r4"] == SRC, "regs=%s" % {k: st[k] for k in ("r2", "r3", "r4")})
    npass += 1

    # --- vector 4: odd R1 -> spec exception, no-op ----------------------
    hx = "b990%02x%01x%01x" % (0, 3, 4)
    r = subprocess.run([v2.DECODER, sla, hx], capture_output=True,
                       text=True, timeout=120)
    check("v4 decode", r.stdout.startswith("OK") and "TRTT" in r.stdout,
          r.stdout.strip()[:80])
    ops = v2.parse_pcode(v2.run_tool(v2.PCDUMP_BIN, sla, hx))
    mem = {}
    regs = {"r1": TBL, "r0": 0xFFFF, "r3": DEST, "r4": 6, "r5": SRC}
    (_res, st) = v2._simulate(ops, 9, regs, mem)
    check("v4 no-op cc", st["cc"] == 9, "cc=%s" % st["cc"])
    check("v4 no-op regs", st["r3"] == DEST and st["r4"] == 6,
          "regs changed")
    npass += 1

    # --- vector 5: zero length -> CC=0, nothing processed ----------------
    mem = {}
    regs = base_regs(6, 8, DEST, SRC, 0, 0xFFFF)
    st = run_trtt(sla, 6, 8, regs, mem)
    check("v5 cc", st["cc"] == 0, "cc=%s" % st["cc"])
    check("v5 regs", st["r6"] == DEST and st["r7"] == 0 and st["r8"] == SRC,
          "regs=%s" % {k: st[k] for k in ("r6", "r7", "r8")})
    npass += 1

    # --- vector 6: D9 encodings must NOT decode as TRTT (0xD9 = MVCK) ---
    for hx in ("d92010002000", "d9ff10002000"):
        r = subprocess.run([v2.DECODER, sla, hx], capture_output=True,
                           text=True, timeout=120)
        check("v6 %s not TRTT" % hx, "TRTT" not in r.stdout,
              r.stdout.strip()[:80])
    npass += 1

    print("vectors checked : %d" % npass)
    print("  passed        : %d" % npass)
    print("  failed        : 0")


if __name__ == "__main__":
    try:
        main()
    except AssertionError as e:
        print("FAIL %s" % e)
        sys.exit(1)
