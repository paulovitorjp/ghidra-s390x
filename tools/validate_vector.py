#!/usr/bin/env python3
"""Validate vector instruction constructors against Capstone 5.0.7.

For each vector in tests/corpus_vector.json:
  1. Decode with our SLEIGH (s390x_decode on temp-compiled .sla)
  2. Decode with Capstone (CS_ARCH_SYSZ)
  3. Check mnemonics match expected and each other.

Fails loudly on mismatch. Does not edit s390x.slaspec; compiles a temp copy.
"""
import json, subprocess, sys, os, tempfile, shutil
from capstone import Cs, CS_ARCH_SYSZ, CS_MODE_BIG_ENDIAN

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LANG = os.path.join(ROOT, "data", "languages")
SLEIGH_OPT = os.path.join(ROOT, "ghidra", "decompile-cpp", "sleigh_opt")
DECODE = os.path.join(ROOT, "tests", "s390x_decode")
CORPUS = os.path.join(ROOT, "tests", "corpus_vector.json")

def build_sla():
    tmpd = tempfile.mkdtemp(prefix="vecval_")
    # Copy language dir files needed for includes
    for fn in os.listdir(LANG):
        if fn.endswith(".sinc") or fn == "s390x.slaspec":
            shutil.copy(os.path.join(LANG, fn), tmpd)
    slaspec = os.path.join(tmpd, "s390x.slaspec")
    with open(slaspec, "a") as f:
        f.write('\n@include "s390x_vector.sinc"\n')
    sla = os.path.join(tmpd, "s390x.sla")
    r = subprocess.run([SLEIGH_OPT, slaspec, sla],
                       capture_output=True, text=True, cwd=tmpd)
    if r.returncode != 0 or not os.path.exists(sla):
        print("SLEIGH compile failed:", file=sys.stderr)
        print(r.stdout[-2000:], file=sys.stderr)
        print(r.stderr[-2000:], file=sys.stderr)
        sys.exit(1)
    return tmpd, sla

def sleigh_decode(sla, hx):
    r = subprocess.run([DECODE, sla, hx], capture_output=True, text=True)
    out = r.stdout.strip()
    # Expected: "OK len=6 mnem=vl body=..."
    if not out.startswith("OK"):
        return None, out
    parts = out.split()
    mnem = None
    for i, p in enumerate(parts):
        if p.startswith("mnem="):
            mnem = p.split("=",1)[1]
            break
    return mnem, out

def main():
    with open(CORPUS) as f:
        vectors = json.load(f)
    tmpd, sla = build_sla()
    try:
        md = Cs(CS_ARCH_SYSZ, CS_MODE_BIG_ENDIAN)
        fails = 0
        for v in vectors:
            name, hx, want = v["name"], v["hex"], v["mnemonic"]
            smnem, sraw = sleigh_decode(sla, hx)
            cres = list(md.disasm(bytes.fromhex(hx), 0x1000))
            cmnem = cres[0].mnemonic if len(cres)==1 else None
            ok = (smnem == want) and (cmnem == want)
            status = "ok" if ok else "FAIL"
            if not ok:
                fails += 1
            print(f"{status:4s} {name:10s} {hx} want={want} sleigh={smnem} capstone={cmnem}")
            if not ok:
                print(f"       sleigh raw: {sraw}")
        print(f"\n{len(vectors)-fails}/{len(vectors)} passed")
        return 1 if fails else 0
    finally:
        shutil.rmtree(tmpd, ignore_errors=True)

if __name__ == "__main__":
    sys.exit(main())
