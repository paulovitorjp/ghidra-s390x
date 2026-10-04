#!/usr/bin/env python3
"""Assemble HLASM batches on z/OS via 3270 and extract machine code.

Pipeline per batch:
  1. 3270 login -> TSO: allocate + EDIT-write HLASM source to MUSE.ASM.SRC
  2. EDIT-write JCL to MUSE.ASM.JCL, SUBMIT -> jobid
  3. Poll LISTDS for MUSE.ASM.LISTnn until cataloged
  4. EDIT listing + LIST, page through, capture trace
  5. Parse listing lines -> {label: hexbytes}, flag assembly errors

Usage:
  MUSE_PASSWORD=... python3 zos_asm.py --batch /tmp/hlasm_probe/batch_01.asm --n 1
  MUSE_PASSWORD=... python3 zos_asm.py --probe   # small ARCH/feature probe

Outputs JSON to stdout: {"labels": {label: bytes}, "errors": [...], "jobid": ...}
"""
import argparse
import atexit
import json
import os
import re
import subprocess
import sys
import time

RELAY = '127.0.0.1:13271'
# Traces contain the TSO password (typed via String()). Keep them on the
# RAM tmpfs so they never hit disk; they are shredded after use and the
# atexit handler cleans up leftovers from killed runs.
TRACE_BASE = '/dev/shm/zos_asm'
SCR = '/tmp/zos_asm.scr'
_trace_n = [0]


def _trace_file():
    _trace_n[0] += 1
    return '%s_%02d.log' % (TRACE_BASE, _trace_n[0])


def run_script(actions, timeout=600):
    """Run s3270 actions via in-memory stdin (no credential-bearing script file).
    Returns (stdout, trace_path). The trace is shredded even if the run
    raises (timeout/kill), so a crashed session cannot leave a
    credential-bearing trace behind."""
    trace = _trace_file()
    cmd = ['s3270', '-trace', '-tracefile', trace]
    try:
        # errors='replace': s3270 can emit raw EBCDIC/3270-data bytes on
        # stdout; stdout is unused (screens come from the trace file).
        p = subprocess.run(cmd, input='\n'.join(actions) + '\n',
                           capture_output=True, text=True, timeout=timeout,
                           errors='replace')
        return p.stdout, trace
    except BaseException:
        shred(trace)
        raise


def _cleanup_leftover_traces():
    """Shred any credential-bearing trace files left by killed runs."""
    import glob
    for path in glob.glob(TRACE_BASE + '*') + glob.glob('/tmp/*s3270*') + glob.glob('/tmp/zos_asm*'):
        shred(path)


atexit.register(_cleanup_leftover_traces)


def shred(path):
    """Securely delete a credential-bearing file."""
    if path and os.path.exists(path):
        # Overwrite with zeros then unlink
        try:
            with open(path, 'r+b') as f:
                f.seek(0, os.SEEK_END)
                size = f.tell()
                f.seek(0)
                f.write(b'\x00' * size)
                f.flush()
                os.fsync(f.fileno())
        except:
            pass
        try:
            os.unlink(path)
        except:
            pass


def trace_screens(trace):
    if not os.path.exists(trace):
        return []
    log = open(trace, errors='replace').read()
    return [m.group(1) for m in
            re.finditer(r'RCVD TN3270E\(3270-DATA.*?\n(.*?)(?=\n2026)', log, re.S)]


def screen_text(s):
    # Screen fields are single-quoted, but a field's text may itself
    # contain apostrophes (HLASM C'...'/X'...' operands, as in the EBCDIC
    # batch).  Pair an opening quote with the first quote that cannot
    # close an in-field '...' pair, so one apostrophe can't desynchronize
    # every later field on the screen (which dropped all 18 EBCDIC labels:
    # the old pairing consumed each next row's opening quote as the
    # previous row's close).
    texts = re.findall(r"'((?:[^']|'[^'\n]*')+)'", s)
    out = []
    for t in texts:
        t = t.strip()
        if t and not any(k in t for k in ('SetBufferAddress', 'StartField',
                                          'InsertCursor', 'EraseUnprotected')):
            out.append(t)
    return out


def login_actions():
    pwd = os.environ.get('MUSE_PASSWORD', '')
    if not pwd:
        raise RuntimeError('MUSE_PASSWORD env var not set')
    return [
        'Connect(%s)' % RELAY,
        'Wait(30, Output)',
        'String("LOGON MUSE")', 'Enter',
        'Wait(30, Output)',
        'String("%s")' % pwd, 'Enter',
        'Wait(12, Output)',
    ]


def tso_session(commands):
    """Run TSO commands in one logged-in session. commands: list of
    command strings. Returns list of screen-text lists."""
    actions = login_actions()
    for cmd in commands:
        actions.append('String("%s")' % cmd.replace('"', ''))
        actions.append('Enter')
        actions.append('Wait(12, Output)')
    actions.append('String("LOGOFF")')
    actions.append('Enter')
    actions.append('Wait(10, Output)')
    actions.append('Quit')
    _, trace = run_script(actions)
    screens = [screen_text(s) for s in trace_screens(trace)]
    shred(trace)
    return screens


def edit_write(dsname, lines):
    """Allocate (fresh) + EDIT-write lines to a sequential dataset.

    Uses TEXT type (avoids the 'ENTER DATA SET TYPE' prompt). A freshly
    allocated dataset is empty, so EDIT auto-enters INPUT mode: lines are
    typed directly with no explicit INPUT subcommand.
    """
    actions = login_actions()
    actions += [
        'String("DELETE \'%s\'")' % dsname, 'Enter', 'Wait(10, Output)',
        'String("ALLOC DA(\'%s\') NEW CATALOG TRACKS SPACE(5,5) DSORG(PS) RECFM(F,B) LRECL(80) BLKSIZE(3120)")' % dsname,
        'Enter', 'Wait(10, Output)',
        # Verify allocation settled before EDIT (EDIT on a not-yet-cataloged
        # dataset creates it with VB/255 defaults). LISTDS forces a catalog read.
        'String("LISTDS \'%s\'")' % dsname, 'Enter', 'Wait(12, Output)',
        'String("EDIT \'%s\' TEXT NONUM")' % dsname, 'Enter', 'Wait(12, Output)',
    ]
    for ln in lines:
        if not ln.strip():
            continue  # skip blanks: a blank line would exit INPUT early
        actions.append('String("%s")' % ln.replace('"', "'"))
        actions.append('Enter')
        actions.append('Wait(8, Output)')
    actions += ['Enter', 'Wait(8, Output)',  # empty line ends INPUT
                'String("SAVE")', 'Enter', 'Wait(10, Output)',
                'String("END")', 'Enter', 'Wait(10, Output)',
                'String("LOGOFF")', 'Enter', 'Wait(10, Output)', 'Quit']
    _, trace = run_script(actions, timeout=1200)
    shred(trace)


JCL_INLINE_TEMPLATE = """//%(job)s JOB ,'HLASM',CLASS=A,MSGCLASS=X
//ASM      EXEC PGM=ASMA90,PARM='LIST,NOOBJECT'
//SYSIN    DD *
%(src)s
/*
//SYSPRINT DD DSN=MUSE.ASM.LIST%(n)02d,DISP=(NEW,CATLG,DELETE),
//             DCB=(RECFM=FBA,LRECL=133,BLKSIZE=1330),
//             SPACE=(TRK,(15,5))
//SYSUT1   DD UNIT=SYSDA,SPACE=(CYL,(2,1))
"""


def submit_inline(jcl_lines):
    """SUBMIT * with inline JCL. Returns jobid like JOB00123 or None."""
    actions = login_actions()
    actions += ['String("SUBMIT *")', 'Enter', 'Wait(10, Output)']
    # Send lines in batches without per-line Wait for speed;
    # single Wait at end lets 3270 catch up
    for ln in jcl_lines:
        if not ln.strip():
            continue
        # escape for s3270 String(): no double quotes in JCL
        actions.append('String("%s")' % ln.replace('"', "'"))
        actions.append('Enter')
    actions += ['Wait(30, Output)',  # let input catch up
                'Enter', 'Wait(15, Output)',  # empty line ends job stream input
                'String("LOGOFF")', 'Enter', 'Wait(10, Output)', 'Quit']
    _, trace = run_script(actions, timeout=600)
    # Read trace for the SUBMITTED job id, then shred (contains credential).
    # TSO reports: IKJ56250I JOB TASM0001(JOB00123) SUBMITTED
    # The trace may split the message across lines; try several patterns.
    jobid = None
    if os.path.exists(trace):
        log = open(trace, errors='replace').read()
        for pat in (r'IKJ56250I\s+JOB\s+\S*?\(?(JOB\d+)\)?\s+SUBMITTED',
                    r'\((JOB\d+)\)\s*SUBMITTED',
                    r'SUBMITTED.*?\((JOB\d+)\)',
                    r'IKJ56250I.{0,80}?\(?(JOB\d+)\)?'):
            m = re.search(pat, log, re.S)
            if m:
                jobid = m.group(1)
                break
    shred(trace)
    return jobid


def wait_for_dataset(dsname, tries=30, wait=20):
    for _ in range(tries):
        screens = tso_session(["LISTDS '%s'" % dsname])
        text = ' '.join(' '.join(s) for s in screens)
        if 'NOT IN CATALOG' not in text.upper():
            return True
        time.sleep(wait)
    return False


def read_listing(dsname, expect_labels):
    """EDIT the listing, LIST it, page to the end. Returns raw text lines."""
    actions = login_actions()
    actions += ['String("EDIT \'%s\' TEXT NONUM")' % dsname, 'Enter', 'Wait(12, Output)',
                'String("LIST")', 'Enter', 'Wait(12, Output)']
    # Page: enough Enters for expect_labels lines (~20/screen) + margin
    pages = max(10, expect_labels // 15 + 12)
    for _ in range(pages):
        actions += ['Enter', 'Wait(3, Output)']
    actions += ['String("END")', 'Enter', 'Wait(10, Output)',
                'String("LOGOFF")', 'Enter', 'Wait(10, Output)', 'Quit']
    _, trace = run_script(actions, timeout=1200)
    lines = []
    for s in trace_screens(trace):
        lines.extend(screen_text(s))
    shred(trace)
    return lines


LISTING_RE = re.compile(r'^\s*([0-9A-F]{6})\s+([0-9A-F][0-9A-F\s]*?)\s+(?:[0-9A-F]{5,6}\s+)?\d+\s+(\S+)')
ERROR_RE = re.compile(r'\*\*.*ERROR|ASMA\d+E', re.I)


def parse_listing(lines, manifest, diag=None):
    """Return (labels->{bytes}, errors[]). manifest: label->{...} for check.
    If manifest is empty, auto-detect labels matching T#### pattern.
    If diag is a dict, it is filled with label -> outcome for every manifest
    label: 'extracted' on success, otherwise the drop reason
    ('assembler-error line', 'error-flagged line', 'invalid LOC',
    'no hex after label', 'all-zero bytes rejected',
    'label not present on any line')."""
    found = {}
    errors = []
    hexset = set('0123456789ABCDEF')
    if diag is not None:
        diag.clear()
    # Auto-detect: if no manifest, find all T####/E####/G#### labels in lines
    if not manifest:
        label_pat = re.compile(r'\b([TEG]\d{4})\b')
        detected = set()
        for raw in lines:
            detected.update(label_pat.findall(raw))
        manifest = {l: 1 for l in detected}
    for raw in lines:
        # Normalize: screen extraction embeds newlines and '...' artifacts
        ln = raw.replace('...', '').replace('\n', ' ')
        ln = re.sub(r'\s+', ' ', ln)
        if ERROR_RE.search(ln):
            errors.append(ln[:120])
            if diag is not None:
                for label in manifest:
                    if label in ln.split() and label not in diag:
                        diag[label] = 'assembler-error line: %s' % ln[:80]
            continue
        # Skip lines that are part of an error report (assembler flags the
        # statement; the machine-code field may be zeros or garbage).
        if '**' in ln:
            if diag is not None:
                for label in manifest:
                    if label in ln.split() and label not in diag:
                        diag[label] = 'error-flagged (**) line: %s' % ln[:80]
            continue
        tokens = ln.split()
        if not tokens:
            continue
        # Reassemble split LOC: screen-wrapping may split the 6-digit LOC
        # across tokens (e.g., '00' + '00DE' -> '0000DE'). Merge leading
        # hex tokens until we have 6 chars or hit non-hex.
        loc = ''
        idx = 0
        while idx < len(tokens) and len(loc) < 6:
            tok = tokens[idx]
            if tok and all(c in hexset for c in tok) and len(loc) + len(tok) <= 6:
                loc += tok
                idx += 1
            else:
                break
        # Validate LOC: must be exactly 6 hex digits. If not, the line
        # is too corrupted to parse safely; skip it.
        if len(loc) != 6:
            if diag is not None:
                for label in manifest:
                    if label in tokens and label not in diag:
                        diag[label] = ('invalid LOC (fragments=%r): %s'
                                       % (tokens[:3], ln[:80]))
            continue
        # Rebuild tokens with merged LOC
        tokens = [loc] + tokens[idx:]
        # Find a manifest label as a token
        for label in manifest:
            if label in tokens and label not in found:
                idx = tokens.index(label)
                # Accumulate hex tokens after location (tokens[0]),
                # stopping before stmt number (tokens[idx-1])
                hex_chars = ''
                for tok in tokens[1:idx-1]:
                    if tok and all(c in hexset for c in tok):
                        # 5-6 char token after some hex = NEXTLOC, not machine code
                        if len(tok) >= 5 and len(hex_chars) >= 4:
                            break
                        hex_chars += tok
                    else:
                        break
                    if len(hex_chars) >= 12:
                        break
                # Machine code is 4, 8, or 12 hex digits; trim NEXTLOC overflow.
                # Reject all-zero fields: HLASM emits zeros (or nothing) for
                # statements that failed assembly; those are missing, not data.
                if len(hex_chars) >= 4 and set(hex_chars) != {'0'}:
                    # Take longest valid length (12, 8, or 4)
                    for L in (12, 8, 4):
                        if len(hex_chars) >= L:
                            hex_chars = hex_chars[:L]
                            break
                    found[label] = hex_chars
                    if diag is not None:
                        diag[label] = 'extracted'
                elif diag is not None and label not in diag:
                    if len(hex_chars) < 4:
                        diag[label] = ('no hex after label '
                                       '(tokens=%r)' % (tokens[:idx + 2],))
                    else:
                        diag[label] = 'all-zero bytes rejected'
                break
    missing = [l for l in manifest if l not in found]
    if diag is not None:
        for label in manifest:
            if label not in diag:
                diag[label] = ('label not present on any line'
                               if label not in found else 'extracted')
    return found, errors, missing


PROBE_SRC = """*
PROBE    CSECT
BT1      NOPR  0
T0001    AR     1,2
T0002    VL     1,16(2,3)
T0003    ADTR   1,2,3
T0004    LOCFH  1,2
T0005    VLR    1,2
T0006    J      BT2
BT2      NOPR  0
         END
""".split('\n')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--batch', help='HLASM source file')
    ap.add_argument('--n', type=int, default=1, help='batch number -> LISTnn')
    ap.add_argument('--probe', action='store_true')
    ap.add_argument('--manifest', help='manifest.json for label check')
    ap.add_argument('--diag', action='store_true',
                    help='print per-label extraction diagnostics as JSON')
    args = ap.parse_args()

    if args.probe:
        src_lines = [l for l in PROBE_SRC if l.strip()]
        n = 99
        manifest = {'T0001': 1, 'T0002': 1, 'T0003': 1,
                    'T0004': 1, 'T0005': 1, 'T0006': 1}
    else:
        src_lines = open(args.batch).read().split('\n')
        n = args.n
        manifest = json.load(open(args.manifest)) if args.manifest else {}

    job = 'TASM%04d' % n
    src_text = '\n'.join(l for l in src_lines if l.rstrip())
    jcl = (JCL_INLINE_TEMPLATE % {'job': job, 'n': n, 'src': src_text}).split('\n')
    # Remove stale listing from a previous run so wait_for_dataset sees the new one
    tso_session(["DELETE 'MUSE.ASM.LIST%02d'" % n])
    jobid = submit_inline(jcl)
    result = {'job': job, 'jobid': jobid, 'listdsn': 'MUSE.ASM.LIST%02d' % n}
    if not wait_for_dataset(result['listdsn']):
        result['error'] = 'listing dataset never appeared'
        print(json.dumps(result, indent=1))
        return
    # Give the writer a beat to finish
    time.sleep(15)
    lines = read_listing(result['listdsn'], len(manifest))
    diag = {} if args.diag else None
    found, errors, missing = parse_listing(lines, manifest, diag)
    result['labels'] = found
    result['errors'] = errors
    result['missing'] = missing
    if args.diag:
        result['diag'] = diag
    result['found_count'] = len(found)
    print(json.dumps(result, indent=1))


if __name__ == '__main__':
    main()
