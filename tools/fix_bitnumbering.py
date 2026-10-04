#!/usr/bin/env python3
"""Fix SLEIGH field bit-numbering: spec used PoP numbering (bit 0 = MSB);
SLEIGH requires bit 0 = LSB regardless of endianness.

For a token of N bits, PoP range (s,e) -> SLEIGH (N-1-e, N-1-s).
Only transforms lines inside 'define token NAME(N) ... ;' blocks.
"""
import re, sys, shutil
import os

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

FILES = [
    os.path.join(REPO_ROOT, 'data/languages/s390x.slaspec'),
    os.path.join(REPO_ROOT, 'data/languages/s390x_branch.sinc'),
    os.path.join(REPO_ROOT, 'data/languages/s390x_loadstore.sinc'),
    os.path.join(REPO_ROOT, 'data/languages/s390x_arith.sinc'),
]

tok_re = re.compile(r'^\s*define token\s+(\w+)\((\d+)\)')
field_re = re.compile(r'^(\s*[A-Za-z0-9_]+ = )\((\d+),(\d+)\)(.*)$')

for path in FILES:
    shutil.copy(path, path + '.prebitfix')
    out = []
    cur_n = None
    cur_tok = None
    n_fixed = 0
    for line in open(path):
        m = tok_re.match(line)
        if m:
            cur_tok, cur_n = m.group(1), int(m.group(2))
            out.append(line)
            continue
        if cur_n is not None:
            if line.strip() == ';':
                cur_n, cur_tok = None, None
                out.append(line)
                continue
            fm = field_re.match(line)
            if fm:
                pre, s, e, post = fm.group(1), int(fm.group(2)), int(fm.group(3)), fm.group(4)
                ns, ne = cur_n - 1 - e, cur_n - 1 - s
                assert 0 <= ns <= ne < cur_n, f'{path}: bad range ({s},{e}) in {cur_n}-bit {cur_tok}'
                out.append(f'{pre}({ns},{ne}){post}\n')
                n_fixed += 1
                continue
        out.append(line)
    open(path, 'w').write(''.join(out))
    print(f'{path}: fixed {n_fixed} fields')
print('backups saved as *.prebitfix')
