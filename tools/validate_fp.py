#!/usr/bin/env python3
"""validate_fp.py — differential validation of the FP extension (s390x_fp.sinc).

Does NOT modify the project: it copies data/languages/*.sinc and
s390x.slaspec into a temp dir, appends `@include "s390x_fp.sinc"` to the
*temp* slaspec only, compiles a temp SLA, then for every vector in
tests/corpus_fp.json:

  1. Decodes with the temp SLA via tests/s390x_decode.
  2. Requires exactly one constructor consuming exactly the vector bytes.
  3. Compares mnemonic and operands against Capstone 5.0.7 (CS_ARCH_SYSZ),
     normalized (case, '%', separators; numbers by value; 'fNh' high-half
     aliases -> 'fN').

Also runs a no-regression check: every vector in tests/corpus.json must
decode identically under the base SLA and the FP-enabled SLA.

Exit 0 if every FP vector matches and nothing regressed; exit 1 otherwise.
"""
import json, os, re, shutil, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, '..'))
LANGDIR = os.path.join(ROOT, 'data', 'languages')
BASE_SLA = os.path.join(LANGDIR, 's390x.sla')
DECODER = os.path.join(ROOT, 'tests', 's390x_decode')
CORPUS_FP = os.path.join(ROOT, 'tests', 'corpus_fp.json')
CORPUS = os.path.join(ROOT, 'tests', 'corpus.json')
SLEIGH_OPT_CANDIDATES = [
    os.path.join(ROOT, 'ghidra', 'decompile-cpp', 'sleigh_opt'),
    shutil.which('sleigh_opt'),
]

INCLUDE_LINE = '@include "s390x_fp.sinc"'


def find_sleigh_opt():
    for c in SLEIGH_OPT_CANDIDATES:
        if c and os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    print("FATAL: sleigh_opt not found", file=sys.stderr)
    sys.exit(2)


def build_fp_sla(tmp):
    """Copy language sources to tmp, add the FP include to the temp slaspec,
    compile. Returns path to the temp SLA."""
    for name in os.listdir(LANGDIR):
        if name.endswith(('.sinc', '.slaspec', '.ldefs', '.pspec', '.cspec')):
            shutil.copy(os.path.join(LANGDIR, name), tmp)
    spec = os.path.join(tmp, 's390x.slaspec')
    with open(spec, 'a') as f:
        f.write(INCLUDE_LINE + '\n')
    sla = os.path.join(tmp, 's390x_fp.sla')
    p = subprocess.run([find_sleigh_opt(), '-l', spec, sla],
                       capture_output=True, text=True, timeout=300)
    if p.returncode != 0 or not os.path.isfile(sla):
        print("FATAL: sleigh compile failed:\n" + p.stdout + p.stderr,
              file=sys.stderr)
        sys.exit(2)
    # Surface only NEW warnings (from s390x_fp.sinc); pre-existing ones are OK.
    new_warn = [l for l in (p.stdout + p.stderr).splitlines()
                if 'WARN' in l and 's390x_fp.sinc' in l]
    for l in new_warn:
        print("WARNING (fp): " + l)
    return sla


def norm_num(tok):
    try:
        return ('num', int(tok, 0))
    except (ValueError, TypeError):
        return ('sym', tok)


def norm_operands(body):
    s = body.lower().replace('%', '')
    # fNh = high-half alias of fN: strip the 'h' for Capstone comparison
    s = re.sub(r'\bf(\d+)h\b', r'f\1', s)
    s = re.sub(r'[(),]', ' ', s)
    toks = [t for t in s.split() if t not in ('zero',)]
    return [norm_num(t) for t in toks]


def run_decoder(sla, hexbytes):
    p = subprocess.run([DECODER, sla, hexbytes], capture_output=True,
                       text=True, timeout=60)
    line = p.stdout.strip().split('\n')[0] if p.stdout.strip() else ''
    return line


def main():
    with tempfile.TemporaryDirectory(prefix='s390x_fp_') as tmp:
        fp_sla = build_fp_sla(tmp)

        corpus = json.load(open(CORPUS_FP))
        fails, passed = [], 0
        for v in corpus:
            hx = v['bytes_hex']
            line = run_decoder(fp_sla, hx)
            m = re.match(r'OK len=(\d+) mnem=(\S+) body=(.*)$', line)
            want_len = len(bytes.fromhex(hx))
            if not m or int(m.group(1)) != want_len:
                fails.append((hx, 'decode/length', line, v))
                continue
            got_mnem = m.group(2).lower()
            want_mnem = v['capstone_mnemonic'].lower()
            if got_mnem != want_mnem:
                fails.append((hx, 'mnemonic', line, v))
                continue
            # strip the leading mnemonic word from the body, like sleigh_diff.py
            body = m.group(3)
            body = body.split(None, 1)[1] if ' ' in body else ''
            if norm_operands(body) != norm_operands(v['capstone_op_str']):
                fails.append((hx, 'operands', line, v))
                continue
            passed += 1

        # No-regression: a core vector that decoded under the base SLA must
        # decode identically under the FP SLA. (NODECODE -> OK is expected:
        # FP vectors in corpus.json were unimplemented before this extension.)
        regress = []
        if os.path.isfile(BASE_SLA):
            for v in json.load(open(CORPUS)):
                hx = v['bytes_hex']
                a, b = run_decoder(BASE_SLA, hx), run_decoder(fp_sla, hx)
                if a.startswith('OK ') and a != b:
                    regress.append((hx, a, b))

    total = len(corpus)
    print(f"FP vectors: {passed}/{total} matched Capstone")
    for hx, kind, line, v in fails:
        print(f"  FAIL [{kind}] {hx}: got {line!r} want "
              f"{v['capstone_mnemonic']} {v['capstone_op_str']}")
    if regress:
        print(f"REGRESSION: {len(regress)} core vectors changed")
        for hx, a, b in regress[:10]:
            print(f"  {hx}: base={a!r} fp={b!r}")
    if fails or regress:
        sys.exit(1)
    print("no regressions in core corpus")
    print("OK")


if __name__ == '__main__':
    main()
