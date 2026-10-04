#!/usr/bin/env python3
"""Generate HLASM test sources covering every spec constructor.

Parses the display templates in data/languages/*.sinc and emits one HLASM
statement per constructor with canonical operands. HLASM (IBM's assembler)
is the independent encoding oracle: whatever bytes it produces for a
mnemonic are ground truth for the SLEIGH decoder test.

Usage:
  gen_hlasm_corpus.py [--batch-size N] [--out DIR]

Output: DIR/batch_01.asm ... each a complete HLASM program, plus
        DIR/manifest.json mapping label -> {spec_mnemonic, hlasm_mnemonic,
        operands, file}.
"""
import argparse
import json
import os
import re
import sys

LANGDIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       '..', 'data', 'languages')

# ---------------------------------------------------------------------------
# .sinc parsing
# ---------------------------------------------------------------------------

HEADER_RE = re.compile(r'^:(\S+)\s+(.*?)\s+is\s+(.*)$')
TOKENIZER_RE = re.compile(r'"([^"]*)"|([A-Za-z][A-Za-z0-9_]*_[A-Za-z][A-Za-z0-9]*)')


def parse_sinc(path):
    """Yield (spec_mnemonic, display_template, is_pattern)."""
    with open(path, errors='replace') as f:
        buf = ''
        for raw in f:
            line = raw.rstrip('\n')
            if line.startswith(':'):
                if buf:
                    yield parse_header(buf)
                buf = line
            elif buf and ' is ' not in buf:
                buf += ' ' + line.strip()
            # else: inside constructor body, ignore
        if buf:
            yield parse_header(buf)


def parse_header(buf):
    m = HEADER_RE.match(buf)
    if not m:
        raise ValueError('unparseable header: %r' % buf[:120])
    return m.group(1), m.group(2), m.group(3)


def render_display(template):
    """Split display template into (mnemonic_literal, [tokens]) where each
    token is ('lit', text) or ('field', token, name)."""
    parts = []
    for m in TOKENIZER_RE.finditer(template):
        if m.group(1) is not None:
            parts.append(('lit', m.group(1)))
        else:
            tok, name = m.group(2).rsplit('_', 1)
            parts.append(('field', tok, name))
    return parts


# ---------------------------------------------------------------------------
# Field -> canonical HLASM operand fragment
# ---------------------------------------------------------------------------

def imm_for_token(token):
    t = token.upper()
    if 'RIL' in t:
        return '305419896'      # 0x12345678, 32-bit
    if 'MII' in t:
        return '1193046'       # 0x123456, 24-bit
    if t.startswith('SI') or t == 'SI':
        return '171'           # 0xAB, 8-bit
    if 'SIL' in t:
        return '4660'          # 0x1234, 16-bit
    if 'RI' in t:
        return '4660'          # 0x1234, 16-bit
    return '171'


def field_fragment(token, name, vec_variant):
    """Return HLASM text for a field, or None to skip (display-only)."""
    if 'TARGET' in name.upper():
        return None  # handled by caller (needs label alternation state)
    # Vector registers: Vn[a|b] -- a=low bank, b=high bank (extension bit)
    mv = re.match(r'V([123])', name)
    if mv:
        n = int(mv.group(1))
        if name.endswith('b'):
            return str(n + 16)
        return str(n)
    if name in ('R1',):
        return '1'
    if name == 'R2':
        return '2'
    if name == 'R3':
        return '3'
    if name == 'R4':
        return '4'
    if name == 'X2':
        return '2'
    if name == 'X3':
        return '3'
    if name == 'B1':
        return '4'
    if name == 'B2':
        return '3'
    if name == 'B3':
        return '5'
    if name == 'B4':
        return '6'
    if name == 'D1':
        return '0'
    if name == 'D2':
        return '16'
    if name == 'D3':
        return '32'
    if name == 'D4':
        return '48'
    if name in ('DL1',):
        return '0'
    if name in ('DL2',):
        # Long-displacement forms (token contains Y): exercise high bits.
        return '74565' if 'Y' in token.upper() else '16'
    if name.startswith('DH'):
        return ''  # never in display; defensive
    if name.startswith('I'):
        return imm_for_token(token)
    if name.startswith('M'):
        return '7'
    if name.startswith('L'):
        return '8'
    # Unknown field kind: record and use 0 so generation never blocks.
    return '0'


UNKNOWN_FIELDS = {}


# ---------------------------------------------------------------------------
# HLASM rewrite rules for extended mnemonics it does not define.
# ---------------------------------------------------------------------------
# IBM HLASM defines extended condition mnemonics only for simple masks.
# Compound masks (3,5,6,9,10,11,12,13,14) exist in the spec as Capstone
# spellings for decode parity (see data/languages/s390x_cond.sinc) but
# HLASM rejects them with ASMA057E (proven: 127 rejections in batch 1).
# The same holds for compare-and-trap LH/HE/LE (masks 6,10,12) and the
# immediate-trap H form (mask 2; CITH rejected while CITL/CITE assemble).
# Rewrite those to the base mnemonic with an explicit mask operand so the
# encoding is still tested. DIAGNOSE has no HLASM mnemonic at all
# (PoP: "DIAGNOSE has no mnemonic") and is skipped.
COMPOUND_MASKS = {3, 5, 6, 9, 10, 11, 12, 13, 14}
FIXED_MASK_RE = re.compile(r'[A-Za-z0-9_]*_M\d+\s*=\s*(0x[0-9a-fA-F]+|\d+)')
MFIELD_RE = re.compile(r'[A-Za-z][A-Za-z0-9_]*_M\d+')

# (family prefix, base mnemonic); mask operand goes last for all of these.
# ORDERED LONGEST-FIRST: 'LOCG' is a prefix of 'LOCGHI', so the longer
# name must be tried first or LOCHI/LOCGHI compounds get the wrong base.
COND_FAMILIES_LAST = ('LOCFHR', 'LOCHHI', 'LOCGHI', 'STOCFH', 'SELFHR',
                      'LOCGR', 'LOCFH', 'STOCG', 'LOCHI', 'SELGR',
                      'LOCR', 'LOCG', 'STOC', 'SELR', 'LOC')
TRAP_REG = ('CLGRT', 'CGRT', 'CLRT', 'CRT')          # rewrite masks 6,10,12
TRAP_IMM = ('CLGIT', 'CLFIT', 'CGIT', 'CLGT', 'CLT', 'CIT')  # rewrite 2,6,10,12


def fixed_mask(ispat):
    """Return the fixed mask value from a constructor constraint, or None."""
    m = FIXED_MASK_RE.search(ispat)
    if not m:
        return None
    v = m.group(1)
    return int(v, 16) if v.startswith('0x') else int(v)


def rewrite_extended(spec_mnem, hmnem, operands, template, ispat):
    """Rewrite an HLASM-rejected extended mnemonic to base+explicit mask.

    Returns (hmnem, operands, note). note is None when no rewrite applies,
    'skip' for DIAGNOSE, else a string describing the rewrite.
    """
    name = spec_mnem.upper()
    if name == 'DIAGNOSE' or name == 'DIAG':
        return hmnem, operands, 'skip'
    # Only extended mnemonics: fixed mask in constraint, no mask field.
    mask = fixed_mask(ispat)
    if mask is None or MFIELD_RE.search(template):
        return hmnem, operands, None
    base = None
    pos = None
    if mask in COMPOUND_MASKS:
        if re.match(r'^B[A-Z]{2,3}R$', name):
            base, pos = 'BCR', 'first'
        elif re.match(r'^B[A-Z]{2,3}$', name):
            base, pos = 'BC', 'first'
        elif re.match(r'^J[A-Z]+$', name):
            base, pos = 'BRC', 'first'
        else:
            for fam in COND_FAMILIES_LAST:
                if name.startswith(fam) and len(name) > len(fam):
                    base, pos = fam, 'last'
                    break
    if base is None:
        for fam in TRAP_REG:
            if name.startswith(fam) and len(name) > len(fam) and mask in (6, 10, 12):
                base, pos = fam, 'last'
                break
    if base is None:
        for fam in TRAP_IMM:
            if name.startswith(fam) and len(name) > len(fam) and mask in (2, 6, 10, 12):
                # CLT/CLGT are RSY format: HLASM syntax is R1,M3,D2(B2),
                # so the mask goes after R1, not at the end.
                if fam in ('CLT', 'CLGT'):
                    base, pos = fam, 'middle'
                else:
                    base, pos = fam, 'last'
                break
    if base is None:
        return hmnem, operands, None
    if pos == 'first':
        new_operands = '%d,%s' % (mask, operands)
    elif pos == 'middle':
        # Insert mask after first operand (R1): "1,74565(3)" -> "1,2,74565(3)"
        parts = operands.split(',', 1)
        if len(parts) == 2:
            new_operands = '%s,%d,%s' % (parts[0], mask, parts[1])
        else:
            new_operands = '%s,%d' % (operands, mask)
    else:
        new_operands = '%s,%d' % (operands, mask)
    note = '%s->%s mask=%d' % (hmnem, base, mask)
    return base, new_operands, note


def build_operands(template, label_state):
    """Render display template -> (hlasm_mnemonic, operand_text)."""
    parts = render_display(template)
    out = []
    for kind, a, b in [(p[0], p[1], p[2] if len(p) > 2 else None) for p in parts]:
        if kind == 'lit':
            out.append(a)
        else:
            token, name = a, b
            if 'TARGET' in name.upper():
                lbl = 'BT1' if label_state[0] % 2 == 0 else 'BT2'
                label_state[0] += 1
                out.append(lbl)
                continue
            frag = field_fragment(token, name, None)
            if frag is None:
                continue
            if frag == '0' and not (name.startswith(('R', 'X', 'B', 'D', 'I', 'M', 'L', 'V'))):
                UNKNOWN_FIELDS.setdefault('%s_%s' % (token, name), 0)
                UNKNOWN_FIELDS['%s_%s' % (token, name)] += 1
            out.append(frag)
    text = ''.join(out)
    m = re.match(r'\s*(\S+)\s*(.*)$', text, re.S)
    if not m:
        raise ValueError('empty render: %r' % template)
    # Some displays hardcode register operands as literals, e.g. "MVCL r0,r0".
    # HLASM wants bare numbers; apply to operands only, never the mnemonic.
    # Includes access registers (a0-a15) used by LAM/STAM etc., and the
    # literal word "zero" used by some templates (e.g. LAE).
    operands = re.sub(r'\b[ra](\d+)\b', r'\1', m.group(2).strip())
    operands = re.sub(r'\bzero\b', '0', operands)
    return m.group(1).upper(), operands


# ---------------------------------------------------------------------------
# Main generation
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--batch-size', type=int, default=400)
    ap.add_argument('--out', default='hlasm_batches')
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)

    entries = []  # (spec_mnemonic, hlasm_mnemonic, operands, srcfile, note)
    seen = set()
    dupes = 0
    dupe_list = []
    rewrites = 0
    skips = []
    label_state = [0]
    for fname in sorted(os.listdir(LANGDIR)):
        if not fname.endswith('.sinc'):
            continue
        for spec_mnem, template, _is in parse_sinc(os.path.join(LANGDIR, fname)):
            try:
                hmnem, operands = build_operands(template, label_state)
            except ValueError as e:
                print('SKIP %s: %s' % (spec_mnem, e), file=sys.stderr)
                continue
            hmnem, operands, note = rewrite_extended(
                spec_mnem, hmnem, operands, template, _is)
            if note == 'skip':
                skips.append((spec_mnem, hmnem, fname))
                continue
            if note:
                rewrites += 1
            key = (hmnem, operands)
            if key in seen:
                dupes += 1
                dupe_list.append((spec_mnem, hmnem, operands, fname, note))
                continue
            seen.add(key)
            entries.append((spec_mnem, hmnem, operands, fname, note))

    print('constructors parsed -> %d unique HLASM statements (%d exact dupes)'
          % (len(entries), dupes))
    print('rewrites (extended->base+mask): %d' % rewrites)
    print('skips (no HLASM mnemonic): %d' % len(skips))
    for spec_mnem, hmnem, fname in skips:
        print('   SKIP %s (%s) [%s]' % (spec_mnem, hmnem, fname))
    with open(os.path.join(args.out, 'dupes.json'), 'w') as f:
        json.dump([{'spec_mnemonic': s, 'hlasm_mnemonic': h, 'operands': o,
                    'srcfile': fn, 'rewrite_note': n}
                   for s, h, o, fn, n in dupe_list], f, indent=1)
    with open(os.path.join(args.out, 'skips.json'), 'w') as f:
        json.dump([{'spec_mnemonic': s, 'hlasm_mnemonic': h, 'srcfile': fn}
                   for s, h, fn in skips], f, indent=1)
    if UNKNOWN_FIELDS:
        print('unknown field kinds encountered:')
        for k, v in sorted(UNKNOWN_FIELDS.items()):
            print('   %-24s x%d' % (k, v))

    manifest = {}
    batch_idx = 0
    for start in range(0, len(entries), args.batch_size):
        batch_idx += 1
        chunk = entries[start:start + args.batch_size]
        lines = []
        # NOTE: no *PROCESS ARCH(n) line. IBM HLASM R6.0 (PTF UI30594)
        # rejects ARCH(10/11/12/13) with ASMA420N; the default ARCH level
        # already assembles vector (VL/VLR) and DFP (ADTR) encodings.
        lines.append('PROG     CSECT')
        lines.append('BT1      NOPR  0')
        batch_manifest = {}
        for i, (spec_mnem, hmnem, operands, srcfile, note) in enumerate(chunk):
            label = 'T%04d' % (start + i + 1)
            lines.append('%-8s %-6s %s' % (label, hmnem, operands))
            entry = {
                'spec_mnemonic': spec_mnem,
                'hlasm_mnemonic': hmnem,
                'operands': operands,
                'srcfile': srcfile,
            }
            if note:
                entry['rewrite_note'] = note
            manifest[label] = entry
            batch_manifest[label] = entry
        lines.append('BT2      NOPR  0')
        lines.append('         END')
        path = os.path.join(args.out, 'batch_%02d.asm' % batch_idx)
        with open(path, 'w') as f:
            f.write('\n'.join(lines) + '\n')
        mpath = os.path.join(args.out, 'manifest_%02d.json' % batch_idx)
        with open(mpath, 'w') as f:
            json.dump(batch_manifest, f, indent=1)
        print('wrote %s (%d instructions) + %s' % (path, len(chunk), mpath))

    with open(os.path.join(args.out, 'manifest.json'), 'w') as f:
        json.dump(manifest, f, indent=1)
    print('manifest: %d labels' % len(manifest))


if __name__ == '__main__':
    main()
