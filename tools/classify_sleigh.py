#!/usr/bin/env python3
"""Classify HLASM-assembled bytes against SLEIGH decode.

For each label in batch results:
  - HLASM assembled + SLEIGH decodes with matching mnemonic -> PASS
  - HLASM assembled + SLEIGH decodes with different mnemonic -> MISMATCH
  - HLASM assembled + SLEIGH NODECODE -> SLEIGH_GAP
  - HLASM rejected (undefined opcode etc.) -> HLASM_REJECT

Usage: python3 tools/classify_sleigh.py /tmp/batch_results.json
Outputs: /tmp/sleigh_classification.json
"""
import json, os, re, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
SLA = os.path.normpath(os.path.join(HERE, '..', 'data', 'languages', 's390x.sla'))
DECODER = os.path.join(HERE, 's390x_decode')
BATCH_DIR = os.path.normpath(os.path.join(HERE, '..', 'hlasm_batches'))

def load_sources():
    """label -> (mnemonic, operands) from batch .asm files."""
    src = {}
    for fn in sorted(os.listdir(BATCH_DIR)):
        if not fn.endswith('.asm'):
            continue
        for line in open(os.path.join(BATCH_DIR, fn)):
            m = re.match(r'^([TEG]\d{4})\s+([A-Z][A-Z0-9]*)\s*(.*)$', line.rstrip())
            if m:
                label, mnem, operands = m.groups()
                src[label] = (mnem, operands.strip())
    return src

def sleigh_decode(hexbytes):
    """Return (status, mnemonic, body) or (NODECODE, None, None)."""
    try:
        p = subprocess.run([DECODER, SLA, hexbytes],
                           capture_output=True, text=True, timeout=30)
        out = p.stdout.strip()
        # Format: "OK len=N mnem=XXX body=..." or "NODECODE ..."
        m = re.match(r'OK len=(\d+) mnem=(\S+) body=(.*)', out)
        if m:
            return ('OK', m.group(2), m.group(3))
        if 'NODECODE' in out:
            return ('NODECODE', None, None)
        return ('ERROR', None, out[:100])
    except Exception as e:
        return ('ERROR', None, str(e)[:100])

def main():
    results = json.load(open(sys.argv[1]))
    sources = load_sources()
    print(f"loaded {len(sources)} source statements", flush=True)

    classification = {
        'PASS': [], 'MISMATCH': [], 'SLEIGH_GAP': [],
        'HLASM_REJECT': [], 'DECODE_ERROR': [],
    }
    details = {}

    for batch_key, batch in sorted(results.items()):
        if not batch_key.startswith('batch_'):
            continue
        labels = batch.get('labels', {})
        errors = batch.get('errors', [])
        # Build set of labels HLASM rejected (from error messages mentioning label?)
        # Actually errors don't reference labels; missing = expected - found
        missing = set(batch.get('batch_missing', []))

        for label, hexbytes in labels.items():
            src_mnem, src_ops = sources.get(label, ('?', '?'))
            status, dec_mnem, dec_body = sleigh_decode(hexbytes)
            if status == 'OK':
                # Compare mnemonics (case-insensitive)
                if dec_mnem.lower() == src_mnem.lower():
                    classification['PASS'].append(label)
                else:
                    classification['MISMATCH'].append(label)
                    details[label] = {
                        'hlasm_mnem': src_mnem, 'hlasm_bytes': hexbytes,
                        'sleigh_mnem': dec_mnem, 'sleigh_body': dec_body,
                    }
            elif status == 'NODECODE':
                classification['SLEIGH_GAP'].append(label)
                details[label] = {
                    'hlasm_mnem': src_mnem, 'hlasm_bytes': hexbytes,
                }
            else:
                classification['DECODE_ERROR'].append(label)
                details[label] = {'hlasm_bytes': hexbytes, 'error': dec_body}

        # HLASM_REJECT: labels expected but not in labels dict
        for label in missing:
            src_mnem, _ = sources.get(label, ('?', '?'))
            classification['HLASM_REJECT'].append(label)
            details[label] = {'hlasm_mnem': src_mnem, 'reason': 'HLASM did not assemble'}

    # Summary
    print("\n=== CLASSIFICATION SUMMARY ===")
    for k, v in classification.items():
        print(f"{k}: {len(v)}")
    print(f"\nDetails for {len(details)} non-PASS cases")

    with open('/tmp/sleigh_classification.json', 'w') as f:
        json.dump({'summary': {k: len(v) for k, v in classification.items()},
                   'classification': classification,
                   'details': details}, f, indent=1)
    print("wrote /tmp/sleigh_classification.json")

if __name__ == '__main__':
    main()
