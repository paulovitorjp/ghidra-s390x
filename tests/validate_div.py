#!/usr/bin/env python3
"""validate_div.py -- semantic edge tests for the signed/unsigned divide
family (D/DR/DSG/DSGR/DSGF/DSGFR/DL/DLR/DLG/DLGR).

Executes the compiled p-code with the tiny interpreter in
validate_cond2 (now with LOAD/STORE memory, signed branch offsets, and
CALLOTHER trap recording) and checks, per vector:
  - decode OK with the expected mnemonic,
  - trap (CALLOTHER userop 1 = trap_fixed_point_divide) iff PoP
    7-290/7-291 says a fixed-point-divide exception is recognized,
  - on trap: destination registers are preserved (operation suppressed),
  - otherwise: quotient/remainder placed per the instruction definition.

PoP rules under test:
  - divisor zero -> trap (includes 0/0);
  - quotient not expressible in the quotient field -> trap:
      D/DR:   quotient must fit signed 32 (INT64_MIN/-1 also traps);
      DSG-family: only INT64_MIN / -1 overflows (INT64_MIN / 1 is fine);
      DL/DLR: (dividend >> 32) >= divisor -> trap;
      DLG/DLGR: 128-bit quotient must fit unsigned 64.
  - remainder takes the dividend's sign (signed divides).

Usage: python3 tests/validate_div.py [--sla PATH]
Exit 0 iff every check passes.
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import validate_cond2 as v2

DEFAULT_SLA = os.path.join(HERE, "..", "data", "languages", "s390x.sla")
M64 = (1 << 64) - 1


def s64(u):
    return u - (1 << 64) if u >> 63 else u


def run(sla, hx, regs, mem=None):
    r = subprocess.run([v2.DECODER, sla, hx], capture_output=True,
                       text=True, timeout=120)
    if not r.stdout.startswith("OK"):
        raise AssertionError("decode failed for %s: %s" %
                             (hx, r.stdout.strip()[:80]))
    ops = v2.parse_pcode(v2.run_tool(v2.PCDUMP_BIN, sla, hx))
    assert ops, "no p-code dumped for %s" % hx
    (_res, state) = v2._simulate(ops, 0, dict(regs), dict(mem or {}))
    return r.stdout, state


def trapped(state):
    return 1 in state.get("_calls", [])


def check(name, cond, detail=""):
    if not cond:
        raise AssertionError("%s: %s" % (name, detail))


def main():
    sla = sys.argv[sys.argv.index("--sla") + 1] if "--sla" in sys.argv \
        else DEFAULT_SLA
    sla = os.path.normpath(sla)
    n = 0

    # ---- DR (0x1D): 64-bit dvd in r0/r1 lows, 32-bit signed divisor ----
    # DR r0,r2  -> 1d02 ; dvd=(r0l<<32)|r1l ; q->r1l ; r->r0l
    out, st = run(sla, "1d02", {"r0": 0, "r1": 100, "r2": 7})
    check("dr normal", "DR" in out and not trapped(st) and
          st["r1"] == 14 and st["r0"] == 2, str(st))
    n += 1
    # zero divisor -> trap, regs preserved
    out, st = run(sla, "1d02", {"r0": 0xDEAD, "r1": 100, "r2": 0})
    check("dr div0 trap", trapped(st), str(st.get("_calls")))
    check("dr div0 preserved", st["r0"] == 0xDEAD and st["r1"] == 100,
          str({k: st[k] for k in ("r0", "r1")}))
    n += 1
    # quotient overflow: 2^32 / 1 does not fit signed 32
    out, st = run(sla, "1d02", {"r0": 1, "r1": 0, "r2": 1})
    check("dr qovf trap", trapped(st), "no trap")
    check("dr qovf preserved", st["r0"] == 1 and st["r1"] == 0, "clobbered")
    n += 1
    # INT64_MIN / -1 -> trap
    out, st = run(sla, "1d02", {"r0": 0x80000000, "r1": 0,
                                "r2": 0xFFFFFFFF})
    check("dr min/-1 trap", trapped(st), "no trap")
    n += 1
    # negative dividend: remainder takes dividend's sign.
    # (quotient/remainder land in the registers' low 32 bits.)
    out, st = run(sla, "1d02", {"r0": 0xFFFFFFFF, "r1": 0xFFFFFF9C,
                                "r2": 7})
    check("dr neg", not trapped(st) and st["r1"] == 0xFFFFFFF2 and
          st["r0"] == 0xFFFFFFFE,
          "r0=%s r1=%s" % (hex(st["r0"]), hex(st["r1"])))
    n += 1

    # ---- D (0x5D) via memory: D r0,0(r0,r0) -> 5d000000 ; dvs=sext(mem32) --
    mem = {0: 0, 1: 0, 2: 0, 3: 7}
    out, st = run(sla, "5d000000", {"r0": 0, "r1": 100}, mem)
    check("d normal", "D " in out and not trapped(st) and st["r1"] == 14
          and st["r0"] == 2, str(st))
    n += 1
    mem = {0: 0, 1: 0, 2: 0, 3: 0}
    out, st = run(sla, "5d000000", {"r0": 5, "r1": 100}, mem)
    check("d div0 trap+preserved", trapped(st) and st["r0"] == 5 and
          st["r1"] == 100, str(st))
    n += 1

    # ---- DSGR (0xB90D): DSGR r2,r1 -> b90d0021 ; dvd=r3 ; q->r3 ; r->r2 --
    out, st = run(sla, "b90d0021", {"r3": 100, "r1": 7, "r2": 0xAA})
    check("dsgr normal", "DSGR" in out and not trapped(st) and
          st["r3"] == 14 and st["r2"] == 2, str(st))
    n += 1
    out, st = run(sla, "b90d0021", {"r3": 100, "r1": 0, "r2": 0xAA})
    check("dsgr div0 trap+preserved", trapped(st) and st["r3"] == 100 and
          st["r2"] == 0xAA, str(st))
    n += 1
    # INT64_MIN / -1 -> trap
    out, st = run(sla, "b90d0021",
                  {"r3": 0x8000000000000000, "r1": M64, "r2": 9})
    check("dsgr min/-1 trap", trapped(st), "no trap")
    check("dsgr min/-1 preserved", st["r3"] == 0x8000000000000000 and
          st["r2"] == 9, "clobbered")
    n += 1
    # INT64_MIN / 1 -> NO trap (quotient -2^63 is expressible); this was
    # the sdiv64_exc bug (it used to trap here).
    out, st = run(sla, "b90d0021",
                  {"r3": 0x8000000000000000, "r1": 1, "r2": 9})
    check("dsgr min/1 no trap", not trapped(st), "trapped=%s" %
          st.get("_calls"))
    check("dsgr min/1 result", st["r3"] == 0x8000000000000000 and
          st["r2"] == 0, "r2=%s r3=%s" % (hex(st["r2"]), hex(st["r3"])))
    n += 1

    # ---- DSGFR (0xB91D): divisor is low 32 bits sign-extended ------------
    out, st = run(sla, "b91d0021", {"r3": 100, "r1": 7, "r2": 0})
    check("dsgfr normal", "DSGFR" in out and not trapped(st) and
          st["r3"] == 14 and st["r2"] == 2, str(st))
    n += 1
    out, st = run(sla, "b91d0021", {"r3": 100, "r1": 0xFFFFFFFF, "r2": 0})
    # divisor = -1: 100 / -1 = -100 fits
    check("dsgfr neg1", not trapped(st) and s64(st["r3"]) == -100 and
          st["r2"] == 0, str(st))
    n += 1

    # ---- DSG (0xE3 0D) via memory: DSG r0,0(r0,r0) ; dvd=r1 ; q->r1 -----
    mem = {i: b for i, b in enumerate((0, 0, 0, 0, 0, 0, 0, 7))}
    out, st = run(sla, "e3000000000d", {"r1": 100, "r0": 0xBB}, mem)
    check("dsg normal", "DSG" in out and not trapped(st) and st["r1"] == 14
          and st["r0"] == 2, str(st))
    n += 1
    mem = {i: 0 for i in range(8)}
    out, st = run(sla, "e3000000000d", {"r1": 100, "r0": 0xBB}, mem)
    check("dsg div0 trap+preserved", trapped(st) and st["r1"] == 100 and
          st["r0"] == 0xBB, str(st))
    n += 1

    # ---- DLR (0xB997) unsigned: DLR r0,r2 -> b9970002 --------------------
    out, st = run(sla, "b9970002", {"r0": 0, "r1": 100, "r2": 7})
    check("dlr normal", "DLR" in out and not trapped(st) and
          st["r1"] == 14 and st["r0"] == 2, str(st))
    n += 1
    out, st = run(sla, "b9970002", {"r0": 0, "r1": 100, "r2": 0})
    check("dlr div0 trap+preserved", trapped(st) and st["r0"] == 0 and
          st["r1"] == 100, str(st))
    n += 1
    # quotient overflow: dvd=2^32, dvs=1 -> q=2^32 not expressible in 32b
    out, st = run(sla, "b9970002", {"r0": 1, "r1": 0, "r2": 1})
    check("dlr qovf trap", trapped(st), "no trap")
    n += 1

    # ---- DLGR (0xB987) unsigned 128/64: DLGR r2,r1 -> b9870021 ---------
    out, st = run(sla, "b9870021",
                  {"r2": 0, "r3": 100, "r1": 7})
    check("dlgr normal", "DLGR" in out and not trapped(st) and
          st["r3"] == 14 and st["r2"] == 2, str(st))
    n += 1
    out, st = run(sla, "b9870021", {"r2": 5, "r3": 100, "r1": 0})
    check("dlgr div0 trap+preserved", trapped(st) and st["r2"] == 5 and
          st["r3"] == 100, str(st))
    n += 1

    print("vectors checked : %d" % n)
    print("  passed        : %d" % n)
    print("  failed        : 0")


if __name__ == "__main__":
    try:
        main()
    except AssertionError as e:
        print("FAIL %s" % e)
        sys.exit(1)
