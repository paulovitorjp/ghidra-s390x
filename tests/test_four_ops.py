#!/usr/bin/env python3
"""Decode and p-code checks for LGFI, CLGFI, LHR, and LLH.

Each encoding is also checked against Capstone's mnemonic. Register
results come from executing the emitted p-code.
"""
import os
import sys

from capstone import CS_ARCH_SYSZ, CS_MODE_BIG_ENDIAN, Cs

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import validate_cond2 as vc  # noqa: E402

ROOT = os.path.normpath(os.path.join(HERE, ".."))
SLA = os.path.join(ROOT, "data", "languages", "s390x.sla")
DECODE = os.path.join(HERE, "s390x_decode")
MASK64 = 0xFFFFFFFFFFFFFFFF


def u64(v):
    return v & MASK64


def decode(hx):
    text = vc.run_tool(DECODE, SLA, hx).strip().splitlines()[0]
    parts = text.split(" body=", 1)
    if not parts[0].startswith("OK "):
        raise AssertionError(text)
    mnem = parts[0].split(" mnem=")[1]
    body = parts[1] if len(parts) == 2 else ""
    return mnem, body, text


def numbers(body):
    import re
    return [int(t, 0) for t in re.findall(r"-?0x[0-9a-fA-F]+|-?\d+", body)]


def run(hx, regs, mem=None, cc=3):
    if not os.path.exists(vc.PCDUMP_BIN):
        vc.build_pcode_dumper()
    text = vc.run_tool(vc.PCDUMP_BIN, SLA, hx)
    if "NODECODE" in text or "PCODE-ERROR" in text:
        raise RuntimeError(text)
    _res, state = vc._simulate(vc.parse_pcode(text), cc, regs, mem if mem is not None else {})
    return state, text


def main():
    if not os.path.exists(DECODE):
        sys.exit("missing decoder")
    md = Cs(CS_ARCH_SYSZ, CS_MODE_BIG_ENDIAN)
    failures = []

    def check(name, cond, detail):
        if cond:
            print("PASS %s" % name)
        else:
            print("FAIL %s: %s" % (name, detail))
            failures.append(name)

    def cap(hx, mnem):
        ins = list(md.disasm(bytes.fromhex(hx), 0))
        check("capstone " + mnem,
              len(ins) == 1 and ins[0].mnemonic == mnem and ins[0].size == len(hx) // 2,
              ins[0].mnemonic if ins else "none")

    cap("c011fffffffe", "lgfi")
    cap("c0f17fffffff", "lgfi")
    cap("c22effffffff", "clgfi")
    cap("c2ee00000010", "clgfi")
    cap("b9270012", "lhr")
    cap("b92700f0", "lhr")
    cap("e31020100095", "llh")
    cap("e3345ff8ff95", "llh")

    mnem, body, line = decode("c011fffffffe")
    check("lgfi -2 listing", mnem == "LGFI" and (-2 in numbers(body) or -0x2 in numbers(body)), line)
    state, text = run("c011fffffffe", {"r1": 0xFFFFFFFFFFFFFFFF}, cc=3)
    check("lgfi -2 value", u64(state.get("r1", 0)) == u64(-2) and state.get("cc") == 3, text)

    mnem, body, line = decode("c0f17fffffff")
    check("lgfi max listing", mnem == "LGFI" and 0x7FFFFFFF in numbers(body), line)
    state, text = run("c0f17fffffff", {"r15": 0xFFFFFFFF00000000}, cc=1)
    check("lgfi max value", state.get("r15") == 0x7FFFFFFF and state.get("cc") == 1, text)

    mnem, body, line = decode("c22effffffff")
    check("clgfi imm listing", mnem == "CLGFI" and 0xFFFFFFFF in numbers(body), line)
    before = 0xFFFFFFFF
    state, text = run("c22effffffff", {"r2": before}, cc=3)
    check("clgfi equal", state.get("cc") == 0 and state.get("r2") == before, text)
    state, text = run("c22effffffff", {"r2": 0}, cc=3)
    check("clgfi low", state.get("cc") == 1 and state.get("r2") == 0, text)
    state, text = run("c22effffffff", {"r2": 0x100000000}, cc=3)
    check("clgfi high", state.get("cc") == 2 and state.get("r2") == 0x100000000, text)

    mnem, body, line = decode("c2ee00000010")
    check("clgfi 0x10 listing", mnem == "CLGFI" and 0x10 in numbers(body), line)
    state, text = run("c2ee00000010", {"r14": 0x10}, cc=3)
    check("clgfi r14 equal", state.get("cc") == 0 and state.get("r14") == 0x10, text)
    state, text = run("c2ee00000010", {"r14": 0x0F}, cc=3)
    check("clgfi r14 low", state.get("cc") == 1 and state.get("r14") == 0x0F, text)
    state, text = run("c2ee00000010", {"r14": 0x11}, cc=3)
    check("clgfi r14 high", state.get("cc") == 2 and state.get("r14") == 0x11, text)

    mnem, body, line = decode("b9270012")
    low = (mnem + " " + body).lower()
    check("lhr listing", mnem == "LHR" and "r1" in low and "r2" in low, line)
    state, text = run("b9270012", {"r1": 0x11111111AAAAAAAA, "r2": 0x12348000}, cc=2)
    check("lhr sext low16",
          state.get("r1") == 0x11111111FFFF8000 and state.get("r2") == 0x12348000
          and state.get("cc") == 2, text)
    state, text = run("b9270012", {"r1": 0xABCDEF0100000000, "r2": 0x0002}, cc=2)
    check("lhr positive low16",
          state.get("r1") == 0xABCDEF0100000002 and state.get("cc") == 2, text)

    mnem, body, line = decode("b92700f0")
    low = (mnem + " " + body).lower()
    check("lhr r0 listing", mnem == "LHR" and "r15" in low and "r0" in low and "zero" not in low, line)
    state, text = run("b92700f0", {"r15": 0x2222222200000000, "r0": 0xABCDFFFF}, cc=1)
    check("lhr from r0",
          state.get("r15") == 0x22222222FFFFFFFF and state.get("r0") == 0xABCDFFFF
          and state.get("cc") == 1 and "zero" not in text.lower(), text)

    mnem, body, line = decode("e31020100095")
    low = (mnem + " " + body).lower()
    check("llh disp listing", mnem == "LLH" and 0x10 in numbers(body) and "r2" in low, line)
    mem = {0x1010: 0x00, 0x1011: 0xFF}
    state, text = run("e31020100095", {"r1": 0xAABBCCDDEEFF0011, "r2": 0x1000}, mem, cc=3)
    check("llh zext half",
          state.get("r1") == 0xAABBCCDD000000FF and state.get("cc") == 3, text)

    mnem, body, line = decode("e3345ff8ff95")
    low = (mnem + " " + body).lower()
    nums = numbers(body)
    check("llh indexed listing",
          mnem == "LLH" and (-8 in nums or -0x8 in nums) and "r4" in low and "r5" in low, line)
    mem = {0x2018: 0xFF, 0x2019: 0xFF}
    state, text = run("e3345ff8ff95",
                      {"r3": 0x1122334455667788, "r4": 0x20, "r5": 0x2000}, mem, cc=0)
    check("llh negative disp",
          state.get("r3") == 0x112233440000FFFF and state.get("cc") == 0, text)

    if failures:
        print("%d failed" % len(failures))
        return 1
    print("four-op checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
