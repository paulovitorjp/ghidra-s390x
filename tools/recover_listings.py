#!/usr/bin/env python3
"""Recover HLASM batch extraction results from cataloged listing datasets.

The 11 assembly batches cataloged their listings as permanent datasets
(MUSE.ASM.LIST01..LIST11, DISP=(NEW,CATLG)) at submit time, so after the
2026-10-01 agent-VM restart wiped /tmp, the 4,080/4,350 extraction results
can be recovered WITHOUT re-running the ~25-min assembly jobs.

Per batch:
  1. Verify MUSE.ASM.LISTnn is still cataloged (LISTDS fast-fail).
  2. EDIT + LIST the dataset, page to the end, capture the screens.
  3. Re-parse labels with zos_asm.parse_listing using the per-batch manifest
     (hlasm_batches/manifest_NN.json).

Writes hlasm_batches/recovered_results.json:
  {"LIST01": {"labels": {...}, "errors": [...], "missing": [...], "status": "ok"},
   ...}

Usage (password transient via env, never stored or written anywhere):
  MUSE_PASSWORD=... python3 recover_listings.py [--batches 1,3] [--check]

--check only verifies which LIST datasets are cataloged (no page-through).
"""
import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import zos_asm  # noqa: E402  (imports register the atexit trace-shredder)

BASE = os.path.dirname(os.path.abspath(__file__))
BATCH_DIR = os.path.join(BASE, '..', 'hlasm_batches')
OUT = os.path.join(BATCH_DIR, 'recovered_results.json')


def dataset_exists(dsname):
    screens = zos_asm.tso_session(["LISTDS '%s'" % dsname])
    text = ' '.join(' '.join(s) for s in screens)
    return 'NOT IN CATALOG' not in text.upper()


def recover_batch(n):
    dsname = 'MUSE.ASM.LIST%02d' % n
    if not os.environ.get('MUSE_PASSWORD'):
        raise RuntimeError('MUSE_PASSWORD env var not set')
    manifest_path = os.path.join(BATCH_DIR, 'manifest_%02d.json' % n)
    manifest = json.load(open(manifest_path))
    result = {'dsname': dsname, 'expect': len(manifest)}
    if not dataset_exists(dsname):
        result['status'] = 'missing-dataset'
        return result
    # give the spool writer a beat (cheap safety for race at submit time)
    time.sleep(5)
    lines = zos_asm.read_listing(dsname, len(manifest))
    found, errors, missing = zos_asm.parse_listing(lines, manifest)
    result.update({'status': 'ok', 'labels': found,
                   'errors': errors, 'missing': missing,
                   'found_count': len(found)})
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--batches', default='1,2,3,4,5,6,7,8,9,10,11',
                    help='comma-separated batch numbers')
    ap.add_argument('--check', action='store_true',
                    help='only verify datasets are cataloged')
    args = ap.parse_args()

    batches = [int(x) for x in args.batches.split(',') if x.strip()]
    if not os.environ.get('MUSE_PASSWORD'):
        print(json.dumps({'error': 'MUSE_PASSWORD env var not set'}))
        return

    results = {}
    for n in batches:
        key = 'LIST%02d' % n
        dsname = 'MUSE.ASM.LIST%02d' % n
        try:
            if args.check:
                ok = dataset_exists(dsname)
                results[key] = {'status': 'cataloged' if ok else 'missing-dataset',
                                'dsname': dsname}
            else:
                results[key] = recover_batch(n)
        except Exception as e:  # per-batch failure must not kill the run
            results[key] = {'status': 'error', 'dsname': dsname,
                            'error': '%s: %s' % (type(e).__name__, e)}
        print('batch %d: %s' % (n, results[key]['status']), flush=True)

    if not args.check:
        json.dump(results, open(OUT, 'w'), indent=1)
        total = sum(r.get('found_count', 0) for r in results.values())
        print('wrote %s, total labels=%d' % (OUT, total))
    else:
        ok = sum(1 for r in results.values()
                 if r['status'] == 'cataloged')
        print('%d/%d datasets cataloged' % (ok, len(results)))


if __name__ == '__main__':
    main()
