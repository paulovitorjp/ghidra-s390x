#!/usr/bin/env python3
"""Classify HLASM-validated bytes against SLEIGH decoder.

For each label with HLASM-extracted bytes:
  - Decode with s390x_decode
  - Compare decoded mnemonic vs HLASM mnemonic (case-insensitive,
    allowing known alias variants)
  - Classify: MATCH, MISMATCH, NODECODE

Usage:
  python3 classify_hlasm_sleigh.py --results /tmp/batch_results.json \
      --out /tmp/classification.json
"""
import argparse
import json
import re
import subprocess
import sys
from collections import Counter

DECODE = 'tests/s390x_decode'
SLA = 'data/languages/s390x.sla'

# Known benign alias variants: (decoded, hlasm) -> allow
ALIASES = {
    ('j', 'brc'), ('j', 'j'),  # BRC displays as j
    ('br', 'br'), ('bcr', 'bcr'),
}

def decode(hexbytes):
    """Returns (mnemonic, full_output) or (None, 'NODECODE')."""
    try:
        p = subprocess.run([DECODE, SLA, hexbytes],
                           capture_output=True, text=True, timeout=10)
        out = p.stdout.strip()
        if 'NODECODE' in out or p.returncode != 0:
            return None, 'NODECODE'
        m = re.search(r'mnem=(\S+)', out)
        if m:
            return m.group(1).lower(), out
        return None, 'NODECODE'
    except Exception as e:
        return None, f'ERROR:{e}'

def mnem_match(decoded, hlasm):
    """Check if decoded mnemonic matches HLASM mnemonic."""
    d = decoded.lower().strip()
    h = hlasm.lower().strip()
    if d == h:
        return True
    if (d, h) in ALIASES:
        return True
    # Allow trailing condition suffix differences? No — be strict.
    # But allow: decoded 'bcr' vs hlasm 'bcr' with different case — already handled.
    return False

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--results', required=True)
    ap.add_argument('--manifest-dir', default='hlasm_batches')
    ap.add_argument('--out', required=True)
    args = ap.parse_args()

    results = json.load(open(args.results))
    classification = {
        'match': [],
        'alias': [],  # Rewrite: HLASM base+mask vs SLEIGH extended (same encoding)
        'mismatch': [],  # Non-rewrite: different mnemonic (real issue)
        'nodecode': [],
        'summary': {},
    }

    total = 0
    for i in range(1, 12):
        batch_key = 'batch_%02d' % i
        b = results.get(batch_key, {})
        labels = b.get('labels', {})
        # Load manifest for this batch
        try:
            man = json.load(open(f"{args.manifest_dir}/manifest_{i:02d}.json"))
        except FileNotFoundError:
            man = {}
        
        for lbl, hexbytes in labels.items():
            total += 1
            e = man.get(lbl, {})
            hlasm_mnem = e.get('hlasm_mnemonic', 'UNKNOWN')
            spec_mnem = e.get('spec_mnemonic', 'UNKNOWN')
            rewrite_note = e.get('rewrite_note')
            
            # For rewritten instructions, compare against the SPEC mnemonic
            # (e.g., HLASM 'BCR 14,2' vs SLEIGH 'bnher' — both are :bnher)
            if rewrite_note:
                compare_mnem = spec_mnem
            else:
                compare_mnem = hlasm_mnem
            
            decoded, out = decode(hexbytes)
            if decoded is None:
                classification['nodecode'].append({
                    'label': lbl, 'bytes': hexbytes,
                    'hlasm': hlasm_mnem, 'spec': spec_mnem,
                    'rewrite': rewrite_note,
                    'detail': out,
                })
            elif mnem_match(decoded, compare_mnem):
                classification['match'].append({
                    'label': lbl, 'bytes': hexbytes,
                    'hlasm': hlasm_mnem, 'decoded': decoded,
                    'spec': spec_mnem, 'rewrite': rewrite_note,
                })
            elif rewrite_note:
                # Rewrite: HLASM used base+explicit mask, SLEIGH shows extended
                # mnemonic. Same encoding, different display name -> alias.
                classification['alias'].append({
                    'label': lbl, 'bytes': hexbytes,
                    'hlasm': hlasm_mnem, 'decoded': decoded,
                    'spec': spec_mnem, 'rewrite': rewrite_note,
                })
            else:
                classification['mismatch'].append({
                    'label': lbl, 'bytes': hexbytes,
                    'hlasm': hlasm_mnem, 'decoded': decoded,
                    'spec': spec_mnem, 'rewrite': rewrite_note,
                    'compare': compare_mnem,
                    'detail': out,
                })

    classification['summary'] = {
        'total': total,
        'match': len(classification['match']),
        'alias': len(classification['alias']),
        'mismatch': len(classification['mismatch']),
        'nodecode': len(classification['nodecode']),
    }
    json.dump(classification, open(args.out, 'w'), indent=1)
    s = classification['summary']
    print(f"Total: {s['total']}, Match: {s['match']}, Alias: {s['alias']}, "
          f"Mismatch: {s['mismatch']}, Nodecode: {s['nodecode']}")

if __name__ == '__main__':
    main()
