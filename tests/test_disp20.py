#!/usr/bin/env python3
"""Signed 20-bit displacement listing for every long-displacement mnemonic.

Each mnemonic is decoded twice. The positive displacement is 0x1234, whose
low 12 bits are 0x234, so a listing that prints only those bits fails.
The negative displacement is -160 (-0xa0). Constructors that require the
high half to be zero are checked with a positive value only.
"""
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, ".."))
LANG = os.path.join(ROOT, "data", "languages")
SLA = os.path.join(LANG, "s390x.sla")
DECODE = os.path.join(HERE, "s390x_decode")

POS_DL, POS_DH, POS = 0x234, 0x01, 0x1234
NEG_DL, NEG_DH, NEG = 0xF60, 0xFF, -0xA0


def parse_tokens():
    fields = {}
    for name in os.listdir(LANG):
        if not name.endswith(".sinc") and name != "s390x.slaspec":
            continue
        text = open(os.path.join(LANG, name), encoding="utf-8").read()
        for m in re.finditer(
                r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\((\d+)\s*,\s*(\d+)\)",
                text, re.M):
            fields[m.group(1)] = (int(m.group(2)), int(m.group(3)))
    return fields


def find_is(line):
    in_q = False
    i = 0
    while i < len(line):
        if line[i] == '"':
            in_q = not in_q
        elif not in_q and line.startswith(" is ", i):
            return i
        i += 1
    return None


def constructors():
    out = []
    for name in os.listdir(LANG):
        if not name.endswith(".sinc"):
            continue
        for line in open(os.path.join(LANG, name), encoding="utf-8"):
            if not line.lstrip().startswith(":"):
                continue
            idx = find_is(line)
            if idx is None:
                continue
            disp, rest = line[:idx], line[idx:]
            if not any(s in disp for s in ("D20s", "layD", "xyD")):
                continue
            quoted = re.findall(r'"([^"]*)"', disp)
            mnem = quoted[0].split()[0] if quoted else ""
            out.append((mnem, rest))
    return out


def set_field(word, lo, hi, val):
    width = hi - lo + 1
    mask = ((1 << width) - 1) << lo
    return (word & ~mask) | ((val & ((1 << width) - 1)) << lo)


def build(rest, fields, dl, dh):
    """Return (hex, high_fixed) or None if a constraint blocks this displacement."""
    word = 0
    high_fixed = False
    for name, num in re.findall(
            r"\b([A-Za-z_][A-Za-z0-9_]*)=(-?0x[0-9a-fA-F]+|-?\d+)", rest):
        if name not in fields:
            continue
        val = int(num, 0)
        lo, hi = fields[name]
        word = set_field(word, lo, hi, val)
        if name.endswith(("DH2", "DH1", "DXH2")) and val != dh:
            high_fixed = True
    if high_fixed:
        return None
    for name, (lo, hi) in fields.items():
        if name not in rest:
            continue
        if name.endswith(("DL2", "DL1", "DXL2")):
            word = set_field(word, lo, hi, dl)
        elif name.endswith(("DH2", "DH1", "DXH2")):
            word = set_field(word, lo, hi, dh)
        elif name.endswith("_D20"):
            # Combined field: DL in the high 12 bits, DH in the low 8.
            word = set_field(word, lo, hi, (dl << 8) | dh)
    return "%012x" % word


def numbers(body):
    vals = []
    for tok in re.findall(r"-?0x[0-9a-fA-F]+|-?\d+", body):
        vals.append(int(tok, 0))
    return vals


def decode(hx):
    r = subprocess.run([DECODE, SLA, hx], capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        return None
    line = r.stdout.strip().splitlines()[0]
    m = re.match(r"OK len=\d+ mnem=\S+ body=(.*)$", line)
    if not m:
        return None
    return m.group(1)


def address_values(hx):
    """Every value written by the instruction's p-code, with registers at 0.

    The signed displacement is one of those values when the address is
    base + index + sign_extend_20(DH||DL). A low-12 address never writes it.
    """
    pcode = os.path.join(HERE, "s390x_pcode")
    r = subprocess.run([pcode, SLA, hx], capture_output=True, text=True, timeout=60)
    if r.returncode != 0 or "NODECODE" in r.stdout or "PCODE-ERROR" in r.stdout:
        return None
    sys.path.insert(0, HERE)
    import validate_cond2 as vc
    seen = []
    real = vc.set_vn

    def spy(vn, val, state):
        seen.append(val & 0xFFFFFFFFFFFFFFFF)
        return real(vn, val, state)

    vc.set_vn = spy
    try:
        vc._simulate(vc.parse_pcode(r.stdout), 0, {})
    except Exception:
        # Later floating-point ops are outside this check. The address
        # add is emitted before them, so values written so far still count.
        pass
    finally:
        vc.set_vn = real
    return seen


def main():
    if not os.path.exists(DECODE):
        sys.exit("missing decoder")
    fields = parse_tokens()
    seen = {}
    for mnem, rest in constructors():
        seen.setdefault(mnem, rest)
    failures = []
    checked = 0
    positive_only = 0
    for mnem in sorted(seen):
        rest = seen[mnem]
        pos = build(rest, fields, POS_DL, POS_DH)
        neg = build(rest, fields, NEG_DL, NEG_DH)
        if pos is None and neg is None:
            # High half is a constant other than both of our samples.
            # A zero high half still has to print that positive displacement.
            zero_high = build(rest, fields, POS_DL, 0)
            if zero_high is None:
                failures.append((mnem, "no encodable displacement"))
                continue
            body = decode(zero_high)
            nums = numbers(body or "")
            checked += 1
            positive_only += 1
            if body is None or POS_DL not in nums:
                failures.append((mnem, "fixed high: %s" % body))
            continue
        for label, hx, expect, false in (
                ("pos", pos, POS, POS_DL),
                ("neg", neg, NEG, NEG_DL),
        ):
            if hx is None:
                continue
            body = decode(hx)
            nums = numbers(body or "")
            checked += 1
            ok = body is not None and expect in nums and false not in nums
            if label == "neg":
                ok = ok and 0xFFF60 not in nums
            written = address_values(hx) if ok else None
            addr = expect & 0xFFFFFFFFFFFFFFFF
            # RXYF extraction writes the low 12 bits on the way to the
            # 20-bit value. The address itself is the signed result.
            if written is None or addr not in written:
                ok = False
            if not ok:
                failures.append((mnem, "%s %s -> %s addr=%s" % (
                    label, hx, body, "missing" if not written or addr not in (written or []) else "ok")))
    print("mnemonics %d  decodes %d  high-half-fixed %d  failed %d" % (
        len(seen), checked, positive_only, len(failures)))
    for item in failures[:40]:
        print("FAIL", item[0], item[1])
    if failures:
        return 1
    print("signed displacement listings passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
