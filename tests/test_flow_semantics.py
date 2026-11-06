#!/usr/bin/env python3
"""Encoding-level checks for signed PC-relative targets, BALR/BASR, and BR.

Uses tests/s390x_decode and tests/s390x_pcode. Optional base address is the
tools' fourth argument (added for these cases). Exit 0 only when every case
matches.
"""
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, ".."))
SLA = os.path.join(ROOT, "data", "languages", "s390x.sla")
DECODE = os.path.join(HERE, "s390x_decode")
PCODE = os.path.join(HERE, "s390x_pcode")


def run(tool, hx, base=None):
    cmd = [tool, SLA, hx]
    if base is not None:
        cmd.append(hex(base))
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        raise RuntimeError("%s rc=%s\n%s" % (cmd, r.returncode, r.stderr))
    return r.stdout


def disasm(hx, base=None):
    line = run(DECODE, hx, base).strip().splitlines()[0]
    m = re.match(r"OK len=\d+ mnem=(\S+) body=(.*)$", line)
    if not m:
        raise AssertionError("decode failed for %s: %s" % (hx, line))
    return m.group(1), m.group(2), line


def target_values(body):
    """Signed integers printed as 0xN or -0xN in an operand string."""
    vals = []
    for tok in re.findall(r"-?0x[0-9a-fA-F]+|-?\d+", body):
        vals.append(int(tok, 0))
    return vals


def main():
    if not (os.path.exists(DECODE) and os.path.exists(PCODE)):
        sys.exit("missing s390x_decode/s390x_pcode; build them before this test")
    failures = []

    def check(name, cond, detail):
        if cond:
            print("PASS %s" % name)
        else:
            print("FAIL %s: %s" % (name, detail))
            failures.append(name)

    # BRASL r14 with RI2=0xfffffc03. At 0x101c0a the signed halfword count
    # -0x3fd * 2 lands on 0x101410. Treating the count as unsigned lands
    # on 0x200101410.
    mnem, body, line = disasm("c0e5fffffc03", 0x101C0A)
    vals = target_values(body)
    check("brasl signed target",
          mnem.lower() == "brasl" and 0x101410 in vals and 0x200101410 not in vals,
          line)
    # Same count at address 0 is a negative target, not a huge positive one.
    mnem, body, line = disasm("c0e5fffffc03", 0)
    vals = target_values(body)
    check("brasl signed at 0",
          -0x7FA in vals and all(v < 0x100000000 for v in vals),
          line)
    # BRCL mask 15, same immediate (shared 32-bit relative operand).
    mnem, body, line = disasm("c0f4fffffc03", 0x101C0A)
    vals = target_values(body)
    check("brcl signed target",
          0x101410 in vals and 0x200101410 not in vals,
          line)
    # 16-bit relative: j -4 halfwords from 0x1000 -> 0xff8.
    mnem, body, line = disasm("a7f4fffc", 0x1000)
    vals = target_values(body)
    check("brc signed 16-bit", 0xFF8 in vals, line)
    # Positive BRASL still adds.
    mnem, body, line = disasm("c0e500000004", 0x1000)
    vals = target_values(body)
    check("brasl positive", 0x1008 in vals, line)

    # LAY r15,-160(r15): e3 f0 ff 60 ff 71. Not +0xf60 and not a zero index.
    mnem, body, line = disasm("e3f0ff60ff71")
    low = (mnem + " " + body).lower()
    check("lay signed disp",
          "lay" in low and ("-0xa0" in low or "-160" in low)
          and "zero" not in low and "f60" not in low,
          line)
    # Index present: LAY r15,-160(r1,r15)
    mnem, body, line = disasm("e3f1ff60ff71")
    low = (mnem + " " + body).lower()
    check("lay with index",
          "lay" in low and ("-0xa0" in low or "-160" in low) and "r1" in low,
          line)
    # XY uses the same long displacement. e3 f0 ff 60 ff 57 = xy r15, mem.
    mnem, body, line = disasm("e3f0ff60ff57")
    low = (mnem + " " + body).lower()
    check("xy signed disp",
          low.startswith("xy") and ("-0xa0" in low or "-160" in low)
          and "zero" not in low and "f60" not in low,
          line)

    def ops(hx):
        text = run(PCODE, hx)
        return text, [ln for ln in text.splitlines() if ln.startswith("OP ")]

    text, ol = ops("05f0")  # balr r15,0
    names = " ".join(ol)
    check("balr r15,0 link only",
          any("r15" in ln for ln in ol)
          and "CALLIND" not in names and " CALL " not in (" " + names)
          and "BRANCH" not in names,
          text)
    text, ol = ops("05f1")  # balr r15,r1
    names = "\n".join(ol)
    check("balr indirect call",
          any(ln.startswith("OP CALLIND") and "r1" in ln for ln in ol)
          and not any(ln.startswith("OP CALL ") for ln in ol),
          text)
    text, ol = ops("0df0")  # basr r15,0
    names = " ".join(ol)
    check("basr r15,0 link only",
          "CALLIND" not in names and "BRANCH" not in names
          and any("r15" in ln for ln in ol),
          text)
    text, ol = ops("0df1")  # basr r15,r1
    check("basr indirect call",
          any(ln.startswith("OP CALLIND") and "r1" in ln for ln in ol),
          text)
    text, ol = ops("07f1")  # br r1
    check("br indirect",
          any(ln.startswith("OP BRANCHIND") and "r1" in ln for ln in ol)
          and not any(ln.startswith("OP BRANCH ") for ln in ol),
          text)
    # bhr r1: conditional form must indirect-branch, not branch to the register.
    text, ol = ops("0721")
    check("bhr indirect",
          any(ln.startswith("OP BRANCHIND") and "r1" in ln for ln in ol)
          and not any(re.search(r"OP CBRANCH in0=r\d", ln) for ln in ol)
          and not any(re.search(r"OP BRANCH in0=r\d", ln) for ln in ol),
          text)

    # LARL shares the 32-bit relative field. The stored value is computed
    # (sign-extend, scale, add); it is not a single folded constant.
    text, ol = ops_at("c010fffffc03", 0x101C0A)
    sys.path.insert(0, HERE)
    import validate_cond2 as vc
    _res, state = vc._simulate(vc.parse_pcode(text), 0, {})
    check("larl signed value",
          state.get("r1") == 0x101410,
          "r1=%s\n%s" % (state.get("r1"), text))

    if failures:
        print("%d failed" % len(failures))
        return 1
    print("all flow checks passed")
    return 0


def ops_at(hx, base):
    text = run(PCODE, hx, base)
    return text, [ln for ln in text.splitlines() if ln.startswith("OP ")]


if __name__ == "__main__":
    sys.exit(main())
