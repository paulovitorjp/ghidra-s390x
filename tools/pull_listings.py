#!/usr/bin/env python3
"""Pull existing HLASM listings from z/OS without re-assembling.

Reads MUSE.ASM.LIST01..LIST11 (permanent cataloged datasets from the
earlier batch runs) via 3270 EDIT/LIST, parses labels->bytes using the
batch manifests, and writes the combined results to a PERSISTENT path
(~/workspace/zarch-sleigh/tests/batch_results_pulled.json).

Usage:
  MUSE_PASSWORD='...' python3 tools/pull_listings.py 1 11
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
from zos_asm import read_listing, parse_listing

OUT = os.path.expanduser('~/workspace/zarch-sleigh/tests/batch_results_pulled.json')
MANIFEST_DIR = os.path.expanduser('~/workspace/zarch-sleigh/hlasm_batches')


def main():
    lo, hi = int(sys.argv[1]), int(sys.argv[2])
    all_results = {}
    for n in range(lo, hi + 1):
        dsname = 'MUSE.ASM.LIST%02d' % n
        man_path = os.path.join(MANIFEST_DIR, 'manifest_%02d.json' % n)
        manifest = json.load(open(man_path)) if os.path.exists(man_path) else {}
        expect = len(manifest) or 400
        print(f"=== {dsname}: reading listing ({expect} expected) ===", flush=True)
        try:
            lines = read_listing(dsname, expect)
        except Exception as e:
            print(f"  ERROR reading {dsname}: {e}", flush=True)
            all_results['batch_%02d' % n] = {'error': str(e)}
            continue
        found, errors, missing = parse_listing(lines, manifest)
        key = 'batch_%02d' % n
        all_results[key] = {
            'listdsn': dsname,
            'labels': found,
            'errors': errors,
            'missing': missing,
            'batch_found': len(found),
            'batch_expected': len(manifest),
        }
        print(f"  {key}: found {len(found)}/{len(manifest)}, "
              f"errors={len(errors)}, missing={len(missing)}", flush=True)
        # Incremental save after each batch (survives interruption)
        json.dump(all_results, open(OUT, 'w'), indent=1)
    print(f"\nwrote {OUT}")


if __name__ == '__main__':
    main()
