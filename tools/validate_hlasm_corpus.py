#!/usr/bin/env python3
"""Validate HLASM-extracted machine code against the SLEIGH decoder.

Usage:
  python3 validate_hlasm_corpus.py --manifest /tmp/hlasm_probe/manifest.json \
      --extracted extracted.json --out corpus_new.json --report report.txt

- manifest: label -> {mnemonic (as written to HLASM), operands, spec_mnemonic, srcfile}
- extracted: label -> hex bytes (from zos_asm.py output)
- Checks: decoder OK, decoded mnemonic matches the HLASM mnemonic
  (allowing spec display-name variants like br_ret for BR).
- Writes corpus JSON in the corpus_zos_hlasm.json schema + a text report.
"""
import argparse
import json
import re
import subprocess
import sys

DECODE = 'tests/s390x_decode'
SLA = 'data/languages/s390x.sla'


def decode(hexbytes):
    p = subprocess.run([DECODE, SLA, hexbytes], capture_output=True, text=True)
    return p.stdout.strip(), p.returncode


def mnem_match(decoded, hlasm, spec):
    d = decoded.lower()
    cand = {hlasm.lower(), spec.lower(), spec.split('_')[0].lower()}
    # Constructor names carry operand-range suffixes (DR_6, LM_1_5, br_ret);
    # the base token identifies the mnemonic family.
    return d in cand or d.split('_')[0] in cand


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--manifest', required=True)
    ap.add_argument('--extracted', required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--report', required=True)
    args = ap.parse_args()

    manifest = json.load(open(args.manifest))
    extracted = json.load(open(args.extracted))

    cases, passes, fails, mismatches, nodecodes = [], 0, 0, [], []
    for label in sorted(manifest):
        m = manifest[label]
        entry = {'label': label, 'hlasm': m['hlasm_mnemonic'] + ' ' + m['operands'],
                 'spec_mnemonic': m['spec_mnemonic'],
                 'srcfile': m.get('srcfile', '')}
        hx = extracted.get(label)
        if not hx:
            entry['status'] = 'MISSING'
            fails += 1
            cases.append(entry)
            continue
        entry['bytes'] = hx
        out, rc = decode(hx)
        dm = re.search(r'mnem=(\S+)', out)
        dec_mnem = dm.group(1) if dm else ''
        if rc != 0 or 'NODECODE' in out:
            entry['status'] = 'NODECODE'
            entry['decode_out'] = out
            nodecodes.append(label)
            fails += 1
        else:
            entry['decoded'] = out
            if mnem_match(dec_mnem, m['hlasm_mnemonic'], m['spec_mnemonic']):
                entry['status'] = 'PASS'
                passes += 1
            else:
                entry['status'] = 'MNEM_MISMATCH'
                mismatches.append((label, m['hlasm_mnemonic'], dec_mnem, hx))
                fails += 1
        cases.append(entry)

    json.dump({'cases': cases,
               'summary': {'total': len(cases), 'pass': passes,
                           'fail': fails, 'nodecode': len(nodecodes),
                           'mnem_mismatch': len(mismatches)}},
              open(args.out, 'w'), indent=1)

    with open(args.report, 'w') as f:
        f.write('total=%d pass=%d fail=%d nodecode=%d mnem_mismatch=%d\n'
                % (len(cases), passes, fails, len(nodecodes), len(mismatches)))
        if mismatches:
            f.write('\nMNEMONIC MISMATCHES (triage):\n')
            for label, h, d, hx in mismatches:
                f.write('  %s HLASM=%s decoded=%s bytes=%s\n' % (label, h, d, hx))
        if nodecodes:
            f.write('\nNODECODE labels:\n  %s\n' % ' '.join(nodecodes[:50]))
    print('total=%d pass=%d fail=%d nodecode=%d mismatches=%d'
          % (len(cases), passes, fails, len(nodecodes), len(mismatches)))


if __name__ == '__main__':
    main()
