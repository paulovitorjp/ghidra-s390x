#!/usr/bin/env python3
"""validate_gaps2.py — differential validation for the W3 gap fillers.

For every vector in tests/corpus_gaps2.json:
  1. Disassemble with the compiled s390x.sla via tests/s390x_decode.
  2. Require exactly one constructor consuming exactly the vector bytes.
  3. Compare the effective mnemonic (first word of the display body)
     against Capstone's mnemonic, and the normalized operands against
     Capstone's op_str (same normalization as tests/sleigh_diff.py:
     lowercase, '%' stripped, parens/commas as separators, 'zero'
     dropped, numbers compared by value).

Usage:
  python3 tests/validate_gaps2.py [--sla PATH] [--corpus PATH]

Defaults: --sla /tmp/lang_W3/s390x.sla (the isolated W3 build),
          --corpus tests/corpus_gaps2.json.

Exit 0 iff every vector passes; exit 1 otherwise.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_SLA = "/tmp/lang_W3/s390x.sla"
DEFAULT_CORPUS = os.path.join(HERE, "corpus_gaps2.json")
DECODER = os.path.join(HERE, "s390x_decode")


def norm_num(tok):
    try:
        return ("num", int(tok, 0))
    except (ValueError, TypeError):
        return ("sym", tok)


def norm_operands(s):
    s = s.lower().replace("%", "")
    s = re.sub(r"[(),]", " ", s)
    toks = [t for t in s.split() if t not in ("zero",)]
    return [norm_num(t) for t in toks]


def run_decoder(sla, hexbytes, retries=3):
    last = ""
    for _ in range(retries):
        p = subprocess.run([DECODER, sla, hexbytes], capture_output=True,
                           text=True, timeout=120)
        last = p.stdout.strip().split("\n")[0] if p.stdout.strip() else ""
        if last:
            return last
        time.sleep(1)
    return last


def parse_out(line):
    if line.startswith("OK "):
        m = re.match(r"OK len=(\d+) mnem=(\S+) body=(.*)$", line)
        if m:
            return ("OK", int(m.group(1)), m.group(2), m.group(3))
    if line.startswith("PARTIAL "):
        return ("PARTIAL", 0, "", line)
    return ("NODECODE", 0, "", line)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sla", default=DEFAULT_SLA)
    ap.add_argument("--corpus", default=DEFAULT_CORPUS)
    args = ap.parse_args()

    for p, what in ((args.sla, ".sla"), (args.corpus, "corpus"),
                    (DECODER, "decoder")):
        if not os.path.exists(p):
            print("missing %s: %s" % (what, p))
            return 1

    corpus = json.load(open(args.corpus))
    passed, failed = [], []
    for v in corpus:
        hx = v["bytes_hex"]
        cm = v["capstone_mnemonic"].lower()
        co = v["capstone_op_str"]
        exp_len = len(bytes.fromhex(hx))
        line = run_decoder(args.sla, hx)
        status, ln, _label, body = parse_out(line)
        if status != "OK" or ln != exp_len:
            failed.append((hx, "decode: status=%s len=%s want=%d (%s)"
                           % (status, ln, exp_len, line)))
            continue
        eff_mnem = body.split()[0].lower() if body.split() else ""
        if eff_mnem != cm:
            failed.append((hx, "mnemonic: ours=%r capstone=%r" % (eff_mnem, cm)))
            continue
        b = body.split(None, 1)[1] if " " in body else ""
        if norm_operands(b) != norm_operands(co):
            failed.append((hx, "operands: ours=%r norm=%r capstone=%r norm=%r"
                           % (b, norm_operands(b), co, norm_operands(co))))
            continue
        passed.append(hx)

    print("vectors : %d" % len(corpus))
    print("  passed: %d" % len(passed))
    print("  failed: %d" % len(failed))
    for hx, why in failed:
        print("FAIL %s: %s" % (hx, why))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
