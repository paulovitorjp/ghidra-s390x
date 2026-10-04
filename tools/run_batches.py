#!/usr/bin/env python3
"""Run all 11 HLASM batches through zos_asm.py and collect results.

Usage: MUSE_PASSWORD=... python3 run_batches.py [start] [end]
Outputs: /tmp/batch_results.json with per-batch {labels, errors, missing}
"""
import json
import os
import subprocess
import sys

BATCH_DIR = 'hlasm_batches'
N_BATCHES = 11
RESULTS_PATH = '/tmp/batch_results.json'


def batch_labels(n):
    """Expected labels from the batch manifest (not a formula)."""
    manifest = '%s/manifest_%02d.json' % (BATCH_DIR, n)
    with open(manifest) as f:
        return sorted(json.load(f).keys())


def main():
    start = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    end = int(sys.argv[2]) if len(sys.argv) > 2 else N_BATCHES
    # Merge with prior results so batches can be run incrementally.
    results = {}
    if os.path.exists(RESULTS_PATH):
        try:
            with open(RESULTS_PATH) as f:
                results = json.load(f)
        except Exception:
            results = {}
    for n in range(start, end + 1):
        batch = '%s/batch_%02d.asm' % (BATCH_DIR, n)
        manifest = '%s/manifest_%02d.json' % (BATCH_DIR, n)
        print('=== batch %02d: %s ===' % (n, batch), flush=True)
        p = subprocess.run(
            [sys.executable, 'tools/zos_asm.py', '--batch', batch,
             '--n', str(n), '--manifest', manifest],
            capture_output=True, text=True, timeout=3600,
            cwd=os.path.dirname(os.path.abspath(__file__)) + '/..')
        try:
            r = json.loads(p.stdout[p.stdout.index('{'):p.stdout.rindex('}') + 1])
        except Exception as e:
            r = {'error': 'bad json: %s; stderr=%s' % (e, p.stderr[-500:])}
        expected = set(batch_labels(n))
        found = set((r.get('labels') or {}).keys())
        r['batch_expected'] = len(expected)
        r['batch_found'] = len(found & expected)
        r['batch_missing'] = sorted(expected - found)
        # labels from other batches shouldn't appear, but note them
        r['unexpected'] = sorted(found - expected)
        results['batch_%02d' % n] = r
        print('batch %02d: found %d/%d expected, errors=%d' % (
            n, r['batch_found'], r['batch_expected'], len(r.get('errors', []))), flush=True)
        with open(RESULTS_PATH, 'w') as f:
            json.dump(results, f, indent=1)
    print('wrote %s' % RESULTS_PATH)


if __name__ == '__main__':
    main()
