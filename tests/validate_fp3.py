#!/usr/bin/env python3
"""validate_fp3.py — validate the extended/old HFP corpus (tests/corpus_fp3.json).

For every vector:
  1. Capstone (SystemZ, big-endian) must decode exactly one instruction whose
     mnemonic matches the corpus entry and whose size consumes ALL bytes.
  2. The project decoder (tests/s390x_decode) against the given .sla must
     decode exactly one instruction, consume ALL bytes, and print the
     expected (IBM) mnemonic.

Usage:
    python3 tests/validate_fp3.py [path/to/s390x.sla]
Default .sla is the W4 isolation build at /tmp/lang_W4/s390x.sla.

Exit status: 0 if all vectors pass, 1 otherwise. Prints exact pass/fail counts.
"""
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CORPUS = os.path.join(HERE, "corpus_fp3.json")
DECODER = os.path.join(HERE, "s390x_decode")
DEFAULT_SLA = "/tmp/lang_W4/s390x.sla"

from capstone import Cs, CS_ARCH_SYSZ, CS_MODE_BIG_ENDIAN

OK_RE = re.compile(r"^OK len=(\d+) mnem=([A-Za-z0-9]+)")


def check_capstone(md, vec):
    code = bytes.fromhex(vec["bytes_hex"])
    got = list(md.disasm(code, 0x1000))
    want = vec["capstone_mnemonic"].lower()
    if len(got) != 1:
        return False, f"capstone decoded {len(got)} insns (want 1)"
    ins = got[0]
    if ins.mnemonic.lower() != want:
        return False, f"capstone mnemonic {ins.mnemonic!r} != {want!r}"
    if ins.size != len(code):
        return False, f"capstone size {ins.size} != {len(code)} (partial decode)"
    return True, f"capstone {ins.mnemonic} {ins.op_str} size={ins.size}"


def check_decoder(sla, vec):
    code_hex = vec["bytes_hex"]
    want_mnem = vec["capstone_mnemonic"].upper()
    try:
        out = subprocess.run(
            [DECODER, sla, code_hex],
            capture_output=True, text=True, timeout=30,
        ).stdout.strip()
    except (OSError, subprocess.TimeoutExpired) as e:
        return False, f"decoder error: {e}"
    m = OK_RE.match(out)
    if not m:
        return False, f"decoder did not decode: {out[:100]}"
    length, mnem = int(m.group(1)), m.group(2).upper()
    if length != len(code_hex) // 2:
        return False, f"decoder consumed {length} of {len(code_hex)//2} bytes"
    if mnem != want_mnem:
        return False, f"decoder mnemonic {mnem} != {want_mnem}"
    return True, f"decoder {mnem} len={length}"


def main():
    sla = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_SLA
    if not os.path.exists(sla):
        print(f"FAIL: .sla not found: {sla}")
        return 1
    if not os.path.exists(DECODER):
        print(f"FAIL: decoder not found: {DECODER}")
        return 1
    with open(CORPUS) as f:
        vectors = json.load(f)
    md = Cs(CS_ARCH_SYSZ, CS_MODE_BIG_ENDIAN)
    passed = failed = 0
    for vec in vectors:
        hx = vec["bytes_hex"]
        ok1, msg1 = check_capstone(md, vec)
        ok2, msg2 = check_decoder(sla, vec)
        if ok1 and ok2:
            passed += 1
            print(f"ok   {vec['capstone_mnemonic']:6s} {hx:14s} {msg1} | {msg2}")
        else:
            failed += 1
            why = "; ".join(m for ok, m in ((ok1, msg1), (ok2, msg2)) if not ok)
            print(f"FAIL {vec['capstone_mnemonic']:6s} {hx:14s} {why}")
    print(f"\n{passed} passed, {failed} failed, {len(vectors)} total")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
