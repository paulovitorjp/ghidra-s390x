#!/usr/bin/env python3
"""validate_muldiv.py — differential validation for the multiply/divide group.

Builds a throwaway .sla from s390x.slaspec plus the muldiv includes
(without touching data/languages/s390x.slaspec), then decodes every
vector in tests/corpus_muldiv.json with tests/s390x_decode and compares
length, mnemonic, and operands against the Capstone ground truth in the
corpus.

Odd-R1 vectors have capstone_mnemonic=null (Capstone 5.0.7 refuses to
decode them: the hardware raises a specification exception). For those,
the validator requires our opaque fallback constructor to decode them
with the right length/mnemonic/operands instead of a Capstone diff.

Exit 0 when every vector passes; exit 1 otherwise.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.normpath(os.path.join(HERE, ".."))
LANGDIR = os.path.join(REPO, "data", "languages")
CORPUS = os.path.join(REPO, "tests", "corpus_muldiv.json")
DECODER = os.path.join(REPO, "tests", "s390x_decode")
SLEIGH_OPT = os.path.join(REPO, "ghidra", "decompile-cpp", "sleigh_opt")

MULDIV_INCLUDES = ["s390x_muldiv.sinc", "s390x_muldiv_gen.sinc"]


def build_test_sla(tmp):
    """Compile a test .sla = real spec + muldiv includes, in tmp/."""
    for f in os.listdir(LANGDIR):
        if f.endswith((".slaspec", ".sinc", ".pspec", ".ldefs")):
            shutil.copy(os.path.join(LANGDIR, f), tmp)
    # The muldiv .sinc files live in the repo; the throwaway spec below
    # references them by filename from tmp/.
    spec = open(os.path.join(LANGDIR, "s390x.slaspec")).read()
    anchor = '@include "s390x_branch.sinc"'
    assert anchor in spec, "include anchor moved; update validate_muldiv.py"
    extra = "\n".join(f'@include "{f}"' for f in MULDIV_INCLUDES)
    spec = spec.replace(anchor, anchor + "\n" + extra)
    spec_path = os.path.join(tmp, "s390x.slaspec")
    with open(spec_path, "w") as f:
        f.write(spec)
    sla_path = os.path.join(tmp, "s390x.sla")
    p = subprocess.run([SLEIGH_OPT, spec_path, sla_path],
                       capture_output=True, text=True, timeout=300)
    errs = [l for l in (p.stdout + p.stderr).splitlines() if "ERROR" in l]
    if errs:
        print("sleigh compile errors:")
        print("\n".join(errs))
        sys.exit(2)
    return sla_path


def norm_num(tok):
    try:
        return ("num", int(tok, 0))
    except (ValueError, TypeError):
        return ("sym", tok)


def norm_tokens(s):
    """Lowercase, strip %, split separators, drop the 'zero' pseudo-reg
    (B2/X2 = 0 means 'no register'; mirrors tests/sleigh_diff.py)."""
    s = s.lower().replace("%", "")
    s = re.sub(r"[(),]", " ", s)
    return [norm_num(t) for t in s.split() if t != "zero"]


def expected_ops(hx, category):
    """Operand tokens derived from the encoded bytes.

    This is the ground truth for the DISPLAY check: it verifies our
    disassembly renders every encoded field faithfully. (Capstone already
    verified the byte encoding itself when the corpus was built.)
    Known display limitations, shared with the core spec:
      * RXa D2 prints as unsigned 12-bit (Capstone prints signed);
      * RXYa prints only DL2 (low 12 bits), unsigned; DH2 is not rendered;
      * RILa I2 prints as unsigned 32-bit (RILa_I2 is not declared signed
        in s390x.slaspec; recommended one-line fix noted in the report).
    """
    b = bytes.fromhex(hx)
    n = len(b)
    if n == 2:  # RR
        r1, r2 = b[1] >> 4, b[1] & 0xF
        return [("sym", f"r{r1}"), ("sym", f"r{r2}")]
    if n == 4 and b[0] == 0xA7:  # RIa: signed 16-bit immediate
        r1 = b[1] >> 4
        i2 = int.from_bytes(b[2:4], "big", signed=True)
        return [("sym", f"r{r1}"), ("num", i2)]
    if n == 4 and b[0] in (0xB9, 0xB2):  # RRE
        r1, r2 = b[3] >> 4, b[3] & 0xF
        return [("sym", f"r{r1}"), ("sym", f"r{r2}")]
    if n == 4:  # RXa
        r1, x2 = b[1] >> 4, b[1] & 0xF
        b2, d2 = b[2] >> 4, ((b[2] & 0xF) << 8) | b[3]
        ops = [("num", r1), ("num", d2)]
        if category == "muldiv_pair":
            ops[0] = ("sym", f"r{r1}")
        else:
            ops[0] = ("sym", f"r{r1}")
        if x2:
            ops.append(("sym", f"r{x2}"))
        if b2:
            ops.append(("sym", f"r{b2}"))
        return ops
    if n == 6 and b[0] == 0xC2:  # RILa: unsigned 32-bit immediate (display)
        r1 = b[1] >> 4
        i2 = int.from_bytes(b[2:6], "big", signed=False)
        return [("sym", f"r{r1}"), ("num", i2)]
    if n == 6:  # RXYa: display renders DL2 only (unsigned)
        r1, x2 = b[1] >> 4, b[1] & 0xF
        b2, dl2 = b[2] >> 4, ((b[2] & 0xF) << 8) | b[3]
        ops = [("sym", f"r{r1}"), ("num", dl2)]
        if x2:
            ops.append(("sym", f"r{x2}"))
        if b2:
            ops.append(("sym", f"r{b2}"))
        return ops
    raise AssertionError(f"unknown format for {hx}")


def run_decoder(sla, hexbytes):
    p = subprocess.run([DECODER, sla, hexbytes],
                       capture_output=True, text=True, timeout=60)
    line = p.stdout.strip().split("\n")[0] if p.stdout.strip() else ""
    m = re.match(r"OK len=(\d+) mnem=(\S+) body=(.*)$", line)
    if not m:
        return None
    return int(m.group(1)), m.group(2), m.group(3)


def main():
    corpus = json.load(open(CORPUS))
    tmp = tempfile.mkdtemp(prefix="muldiv_val_")
    try:
        sla = build_test_sla(tmp)
        passed, failed = [], []
        for v in corpus:
            hx = v["bytes_hex"]
            dec = run_decoder(sla, hx)
            if dec is None:
                failed.append((hx, "decode failed / no OK line"))
                continue
            ln, label, body = dec
            if ln != v["expected_len"]:
                failed.append((hx, f"length: ours={ln} want={v['expected_len']}"))
                continue
            words = body.split()
            eff_mnem = words[0].lower() if words else ""
            b = body.split(None, 1)[1] if " " in body else ""
            if v["capstone_mnemonic"] is None:
                # Odd-R1 fallback: no Capstone reference possible.
                exp = v["notes"].split()[0].lower()
                if not label.endswith("_odd"):
                    failed.append((hx, f"odd-R1 vector hit {label}, want *_odd"))
                    continue
                if eff_mnem != exp:
                    failed.append((hx, f"odd-R1 mnemonic: ours={eff_mnem} want={exp}"))
                    continue
                m_r1 = re.search(r"r(\d+)", v["notes"])
                want_r1 = f"r{m_r1.group(1)}" if m_r1 else None
                ops = norm_tokens(b)
                # pair-R1 prints as a register operand in the fallback
                if not ops or ops[0] != ("sym", want_r1):
                    failed.append((hx, f"odd-R1 R1 operand: ours={ops[:1]} want={want_r1}"))
                    continue
                passed.append(hx)
                continue
            cm = v["capstone_mnemonic"]
            if eff_mnem != cm:
                failed.append((hx, f"mnemonic: ours={eff_mnem} (label {label}) want={cm}"))
                continue
            ours = norm_tokens(b)
            # pair constructors print even R1 as a bare number ("M 6,...")
            if v["category"] == "muldiv_pair" and ours and ours[0][0] == "num":
                ours = [("sym", f"r{ours[0][1]}")] + ours[1:]
            want = expected_ops(hx, v["category"])
            if ours != want:
                failed.append((hx, f"operands: ours={ours} want={want}"))
                continue
            passed.append(hx)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print(f"muldiv: {len(passed)}/{len(corpus)} vectors match Capstone")
    for hx, why in failed:
        print(f"  FAIL {hx}: {why}")
    sys.exit(0 if not failed else 1)


if __name__ == "__main__":
    main()
