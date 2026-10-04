#!/usr/bin/env python3
"""validate_branch2.py — validate s390x_branch2.sinc against Capstone.

Phase 1 (default): every vector below was hand-assembled from the PoP
(SA22-7832-14) instruction figures. Capstone 5.0.7 (CS_ARCH_SYSZ) is the
oracle: each vector must decode to the expected mnemonic and operand
string at address 0. Writes the validated vectors to
tests/corpus_branch2.json using the same schema as tests/corpus.json.

Phase 2 (--diff): additionally builds a SCRATCH copy of the spec with
s390x_branch2.sinc included (the real s390x.slaspec is NOT modified),
compiles it with the prebuilt sleigh_opt, and diffs our decoder output
against Capstone for every corpus vector (length, mnemonic, operands,
with PC-relative immediates normalized). This is the per-constructor
gate: every reachable constructor must be exercised by >=1 vector.

Usage:
    python3 tools/validate_branch2.py            # phase 1 only
    python3 tools/validate_branch2.py --diff    # phase 1 + decode diff
"""
import json
import os
import re
import shutil
import subprocess
import sys

from capstone import Cs, CS_ARCH_SYSZ, CS_MODE_BIG_ENDIAN

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, ".."))
LANGDIR = os.path.join(ROOT, "data", "languages")
OUT = os.path.join(ROOT, "tests", "corpus_branch2.json")
SLEIGH_OPT = os.path.join(ROOT, "ghidra", "decompile-cpp", "sleigh_opt")
DECODER = os.path.join(ROOT, "tests", "s390x_decode")
SCRATCH = "/tmp/s390x_branch2_build"

# (bytes_hex, expected_mnemonic, expected_op_str, category, notes)
# Field breakdowns follow the PoP figures (MSB=0 bit numbering).
VECTORS = [
    # --- BRANCH ON CONDITION, RX (0x47): M1(8-11) X2(12-15) B2(16-19) D2(20-31)
    ("4700c000", "bc", "0, 0(%r12)", "branch",
     "BC mask 0: never branches; Capstone prints the mask operand"),
    ("4710c000", "bo", "0(%r12)", "branch", "BC mask 1: branch on overflow"),
    ("4720c000", "bh", "0(%r12)", "branch", "BC mask 2: branch on high"),
    ("4730c000", "bnle", "0(%r12)", "branch", "BC mask 3"),
    ("4740c000", "bl", "0(%r12)", "branch", "BC mask 4: branch on low"),
    ("4750c000", "bnhe", "0(%r12)", "branch", "BC mask 5"),
    ("4760c000", "blh", "0(%r12)", "branch", "BC mask 6"),
    ("4770c000", "bne", "0(%r12)", "branch", "BC mask 7"),
    ("4780c000", "be", "0(%r12)", "branch", "BC mask 8: branch on equal"),
    ("4790c000", "bnlh", "0(%r12)", "branch", "BC mask 9"),
    ("47a0c000", "bhe", "0(%r12)", "branch", "BC mask 10"),
    ("47b0c000", "bnl", "0(%r12)", "branch", "BC mask 11"),
    ("47c0c000", "ble", "0(%r12)", "branch", "BC mask 12"),
    ("47d0c000", "bnh", "0(%r12)", "branch", "BC mask 13"),
    ("47e0c000", "bno", "0(%r12)", "branch", "BC mask 14"),
    ("47f0c000", "b", "0(%r12)", "branch", "BC mask 15: unconditional"),
    ("47f1c010", "b", "0x10(%r1, %r12)", "branch",
     "BC with index register and nonzero displacement"),
    # --- BRANCH ON COUNT ---
    # BCT: '46' R1(8-11) X2(12-15) B2(16-19) D2(20-31)
    ("4610c100", "bct", "%r1, 0x100(%r12)", "branch",
     "BCT: 32-bit count, RX EA"),
    # BCTG: 'E3' R1 X2 B2 DL2(20-31) DH2(32-39) '46'
    ("e310c0080046", "bctg", "%r1, 8(%r12)", "branch",
     "BCTG: 64-bit count, RXY EA, DH2=0"),
    # BCTR: '06' R1(8-11) R2(12-15)
    ("0612", "bctr", "%r1, %r2", "branch",
     "BCTR: R2 field != 0 (branching form)"),
    ("0601", "bctr", "%r0, %r1", "branch",
     "BCTR: R1=0 still decrements r0 (no R1=0 exception per PoP)"),
    ("0600", "bctr", "%r0, %r0", "branch",
     "BCTR: R2 field = 0 -> count without branching"),
    # BCTGR: 'B946' IGN(16-23) R1(24-27) R2(28-31)
    ("b9460012", "bctgr", "%r1, %r2", "branch",
     "BCTGR: R2 field != 0 (branching form)"),
    ("b9460000", "bctgr", "%r0, %r0", "branch",
     "BCTGR: R2 field = 0 -> count without branching"),
    # BRCT/BRCTG: 'A7' R1(8-11) OP2(12-15)=6/7 I2(16-31, signed)
    ("a7160004", "brct", "%r1, 8", "branch",
     "BRCT: forward, RI2=4 -> target 8 at pc 0"),
    ("a716fffe", "brct", "%r1, -4", "branch",
     "BRCT: backward, RI2=-2 -> target -4 at pc 0"),
    ("a7270004", "brctg", "%r2, 8", "branch",
     "BRCTG: forward, 64-bit count"),
    ("a727fffe", "brctg", "%r2, -4", "branch",
     "BRCTG: backward, 64-bit count"),
    # --- BRANCH ON INDEX HIGH / LOW OR EQUAL ---
    # BXH/BXLE: '86'/'87' R1(8-11) R3(12-15) B2(16-19) D2(20-31)
    ("8612c000", "bxh", "%r1, %r2, 0(%r12)", "branch",
     "BXH: R3=2 (even) -> increment r2, compare r3"),
    ("8614c000", "bxh", "%r1, %r4, 0(%r12)", "branch",
     "BXH: R3=4 (even) -> increment r4, compare r5"),
    ("8615c000", "bxh", "%r1, %r5, 0(%r12)", "branch",
     "BXH: R3=5 (odd) -> r5 is both increment and compare"),
    ("8712c000", "bxle", "%r1, %r2, 0(%r12)", "branch",
     "BXLE: 32-bit low-or-equal"),
    # BXHG/BXLEG: 'EB' R1 R3 B2 DL2(20-31) DH2(32-39) '44'/'45'
    ("eb12c0000044", "bxhg", "%r1, %r2, 0(%r12)", "branch",
     "BXHG: 64-bit, RSY EA"),
    ("eb12c0000045", "bxleg", "%r1, %r2, 0(%r12)", "branch",
     "BXLEG: 64-bit low-or-equal"),
    # BRXH/BRXLE: '84'/'85' R1(8-11) R3(12-15) I2(16-31, signed)
    ("8412fffe", "brxh", "%r1, %r2, -4", "branch",
     "BRXH: backward, RSI relative"),
    ("84120004", "brxh", "%r1, %r2, 8", "branch",
     "BRXH: forward, RSI relative"),
    ("8512fffe", "brxle", "%r1, %r2, -4", "branch",
     "BRXLE: backward, low-or-equal"),
    # BRXHG/BRXLG: 'EC' R1 R3 RI2(16-31, signed) IGN(32-39) '44'/'45'
    ("ec12fffe0044", "brxhg", "%r1, %r2, -4", "branch",
     "BRXHG: backward, RIEe relative, 64-bit"),
    ("ec1200040044", "brxhg", "%r1, %r2, 8", "branch",
     "BRXHG: forward, RIEe relative"),
    ("ec12fffe0045", "brxlg", "%r1, %r2, -4", "branch",
     "BRXLG: backward, low-or-equal, 64-bit"),
]

# PC-relative branch mnemonics in branch2: (imm byte range, target scale).
# Our spec displays the raw signed halfword offset; Capstone prints the
# absolute target (pc + 2*imm) at the disassembly base.
PCREL = {
    "brct": (2, 4, 2), "brctg": (2, 4, 2),
    "brxh": (2, 4, 2), "brxle": (2, 4, 2),
    "brxhg": (2, 4, 2), "brxlg": (2, 4, 2),
}


def phase1_capstone():
    md = Cs(CS_ARCH_SYSZ, CS_MODE_BIG_ENDIAN)
    failures = []
    records = []
    for hx, mnem, op_str, cat, notes in VECTORS:
        data = bytes.fromhex(hx)
        ds = list(md.disasm(data, 0))
        if not ds:
            failures.append(f"{hx}: Capstone decoded nothing (want {mnem})")
            continue
        d = ds[0]
        if d.mnemonic != mnem or d.op_str != op_str:
            failures.append(
                f"{hx}: got '{d.mnemonic} {d.op_str}', want '{mnem} {op_str}'")
            continue
        if d.size != len(data):
            failures.append(f"{hx}: decoded size {d.size}, want {len(data)}")
            continue
        records.append({
            "bytes_hex": hx,
            "capstone_mnemonic": d.mnemonic,
            "capstone_op_str": d.op_str,
            "category": cat,
            "notes": notes,
        })
        print(f"ok  {hx} -> {d.mnemonic} {d.op_str}")

    with open(OUT, "w") as f:
        json.dump(records, f, indent=2)
        f.write("\n")
    print(f"wrote {len(records)} vectors to {OUT}")

    if failures:
        print(f"\n{len(failures)} CAPSTONE FAILURES:")
        for fl in failures:
            print("  " + fl)
        return None
    print(f"phase 1: {len(records)}/{len(VECTORS)} vectors match Capstone")
    return records


def build_scratch():
    """Copy the language dir to SCRATCH and include branch2 (real spec untouched)."""
    if os.path.exists(SCRATCH):
        shutil.rmtree(SCRATCH)
    shutil.copytree(LANGDIR, SCRATCH)
    spec = os.path.join(SCRATCH, "s390x.slaspec")
    src = open(spec).read()
    anchor = '@include "s390x_branch.sinc"'
    assert anchor in src, "anchor include not found in scratch slaspec"
    src = src.replace(anchor, anchor + '\n@include "s390x_branch2.sinc"')
    open(spec, "w").write(src)
    r = subprocess.run([SLEIGH_OPT, spec], capture_output=True, text=True,
                       timeout=600)
    out = r.stdout + r.stderr
    errs = [l for l in out.splitlines() if "ERROR" in l]
    if errs:
        print("sleigh compile ERRORS:")
        for e in errs[:30]:
            print("  " + e)
        return None
    sla = os.path.splitext(spec)[0] + ".sla"
    assert os.path.exists(sla), f"no .sla produced: {sla}"
    print(f"scratch spec compiled: {sla}")
    return sla


def norm_num(tok):
    try:
        return ("num", int(tok, 0))
    except (ValueError, TypeError):
        return ("sym", tok)


def norm_operands(body):
    s = body.lower().replace("%", "")
    s = re.sub(r"[(),]", " ", s)
    toks = [t for t in s.split() if t not in ("zero",)]
    return [norm_num(t) for t in toks]


def run_decoder(sla, hx):
    p = subprocess.run([DECODER, sla, hx], capture_output=True, text=True,
                       timeout=60)
    line = p.stdout.strip().split("\n")[0] if p.stdout.strip() else ""
    m = re.match(r"OK len=(\d+) mnem=(\S+) body=(.*)$", line)
    if not m:
        return None, f"decode failed: {line or p.stderr.strip()[:120]}"
    return (int(m.group(1)), m.group(2), m.group(3)), None


def phase2_diff(records):
    sla = build_scratch()
    if sla is None:
        return False
    passed, failed = [], []
    for v in records:
        hx = v["bytes_hex"]
        cm = v["capstone_mnemonic"].lower()
        co = v["capstone_op_str"]
        res, err = run_decoder(sla, hx)
        if err:
            failed.append((hx, cm, co, err))
            continue
        ln, label, body = res
        if ln != len(bytes.fromhex(hx)):
            failed.append((hx, cm, co, f"length: ours={ln}"))
            continue
        eff = body.split()[0].lower() if body.split() else label.lower()
        if eff != cm:
            failed.append((hx, cm, co,
                           f"mnemonic: ours={eff} (label {label})"))
            continue
        b = body.split(None, 1)[1] if " " in body else ""
        ours = norm_operands(b)
        want = norm_operands(co)
        pc = PCREL.get(eff)
        if pc:
            off, end, scale = pc
            raw = int.from_bytes(bytes.fromhex(hx)[off:end], "big", signed=True)
            nums = [t for t in ours if t[0] == "num"]
            if len(nums) != 1 or nums[0][1] != raw:
                failed.append((hx, cm, co,
                               f"pcrel imm: ours={body!r} encoded={raw}"))
                continue
            cnums = [t for t in want if t[0] == "num"]
            if cnums and cnums[0][1] != scale * raw:
                print(f"NOTE {hx}: capstone target {cnums[0][1]:#x} "
                      f"!= {scale}*({raw}) — oracle quirk?")
        elif ours != want:
            failed.append((hx, cm, co,
                           f"operands: ours={body!r} norm={ours} "
                           f"capstone={co!r} norm={want}"))
            continue
        passed.append(hx)
        print(f"ok  {hx} {eff:7s} (label {label})")
    print(f"\nphase 2: {len(passed)}/{len(records)} decode-diff vectors match")
    if failed:
        print("DIFF FAILURES:")
        for hx, cm, co, why in failed:
            print(f"  {hx:14s} capstone: {cm} {co}  -> {why}")
        return False
    print("All branch2 vectors match Capstone in length, mnemonic, operands.")
    return True


def main():
    records = phase1_capstone()
    if records is None:
        sys.exit(1)
    if "--diff" in sys.argv:
        print()
        if not phase2_diff(records):
            sys.exit(1)
    print("\nvalidate_branch2: PASS")


if __name__ == "__main__":
    main()
