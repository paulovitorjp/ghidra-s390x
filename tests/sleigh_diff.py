#!/usr/bin/env python3
"""sleigh_diff.py — differential test: our SLEIGH disassembly vs Capstone.

For every vector in tests/corpus.json:
  1. Disassemble with the compiled s390x.sla via tests/s390x_decode.
  2. Require exactly one constructor consuming exactly the vector bytes.
  3. Compare mnemonic (with IBM-vs-Capstone alias map) and operands
     (normalized: case, '%', separators; numbers compared by value).

Vectors whose instructions have no spec constructor are classified
EXPECTED_UNIMPL (computed statically from the .sinc sources) and reported
separately — they are complete-set phase work, not validation failures.

Exit 0 if every *implemented* vector matches; exit 1 otherwise.
"""
import json, os, re, subprocess, sys
import glob

HERE = os.path.dirname(os.path.abspath(__file__))
SLA = os.path.normpath(os.path.join(HERE, '..', 'data', 'languages', 's390x.sla'))
DECODER = os.path.join(HERE, 's390x_decode')
CORPUS = os.path.join(HERE, 'corpus.json')
if len(sys.argv) > 1:
    # Allow running the differential harness against any corpus file,
    # e.g. `python3 tests/sleigh_diff.py tests/corpus_fp3.json`.
    arg = sys.argv[1]
    if os.path.isabs(arg):
        CORPUS = arg
    elif arg.startswith('tests/'):
        CORPUS = os.path.normpath(os.path.join(HERE, '..', arg))
    else:
        CORPUS = os.path.normpath(os.path.join(HERE, arg))
LANGDIR = os.path.normpath(os.path.join(HERE, '..', 'data', 'languages'))

# Capstone mnemonic -> our IBM PoP mnemonic (spec follows IBM Appendix J).
# Only for same-mask different-name pairs (verified against the spec's
# M1 constraints): Capstone uses 'jg*' for BRCL, IBM uses 'jl*'.
MNEM_ALIAS = {
    'jge': 'jle', 'jgne': 'jlne', 'jgl': 'jll', 'jgh': 'jlh',
    'jg': 'jlu',
}
# Spec BCR extended mnemonics -> mask (from s390x_branch.sinc RRb_M1).
BCR_MASKS = {'nopr':0,'bor':1,'bhr':2,'bnler':3,'blr':4,'bnher':5,'blhr':6,
             'bner':7,'ber':8,'bnlhr':9,'bher':10,'bnlr':11,'bler':12,
             'bnhr':13,'bnor':14,'br':15}
# SS-format string ops: our display prints the raw L field (length-1);
# IBM/Capstone syntax prints the actual length. Add 1 when comparing.
SS_LEN_MNEMS = {'mvc','xc','nc','oc','clc','mvcin'}

def normalize_corpus(corpus):
    """Accept the two legacy corpus schemas and normalize to the
    canonical one (bytes_hex, capstone_mnemonic, capstone_op_str,
    expected_len)."""
    out = []
    for v in corpus:
        if "hex" in v and "bytes_hex" not in v:
            # tests/corpus_vector.json schema
            v = dict(v)
            v["bytes_hex"] = v.pop("hex")
            v["capstone_mnemonic"] = v.pop("mnemonic", None)
            v["capstone_op_str"] = v.pop("capstone_op", None)
            v["expected_len"] = v.pop("size", None)
        out.append(v)
    return out

def spec_mnemonics():
    """Display mnemonics present in the spec (lowercased).

    Besides constructor labels and full display strings, also record the
    first whitespace-delimited token of each display string. Generated
    constructors hardcode registers (e.g. :MVCL_0_0 "MVCL r0,r0"), so the
    bare mnemonic (e.g. 'mvcl') only appears as the display's first word.
    Without this, corpus vectors for those instructions are misclassified
    as expected-unimplemented instead of being tested.
    """
    out = set()
    for f in glob.glob(os.path.join(LANGDIR, '*.sinc')):
        for m in re.finditer(r'^:(\w+)\s+"([^"]*)"', open(f).read(), re.M):
            out.add(m.group(1).lower())
            disp = m.group(2).strip().lower()
            out.add(disp)
            if disp:
                out.add(disp.split()[0])
    return out

def norm_num(tok):
    """Canonicalize a numeric token to int, else return the token."""
    try:
        return ('num', int(tok, 0))
    except (ValueError, TypeError):
        return ('sym', tok)

def norm_operands(body):
    """Normalize an operand string to a token list."""
    s = body.lower().replace('%', '')
    s = re.sub(r'[(),]', ' ', s)
    toks = [t for t in s.split() if t not in ('zero',)]
    return [norm_num(t) for t in toks]

def capstone_operands(op_str):
    return norm_operands(op_str)

def run_decoder(hexbytes):
    p = subprocess.run([DECODER, SLA, hexbytes], capture_output=True,
                       text=True, timeout=60)
    line = p.stdout.strip().split('\n')[0] if p.stdout.strip() else ''
    return line

def parse_out(line):
    # "OK len=4 mnem=lr body=r1,r15" | "PARTIAL ..." | "NODECODE ..."
    if line.startswith('OK '):
        m = re.match(r'OK len=(\d+) mnem=(\S+) body=(.*)$', line)
        return ('OK', int(m.group(1)), m.group(2), m.group(3))
    if line.startswith('PARTIAL '):
        m = re.match(r'PARTIAL len=(-?\d+) mnem=(\S*) body=(.*)$', line)
        return ('PARTIAL', int(m.group(1)), m.group(2), m.group(3))
    return ('NODECODE', 0, '', line)

def pcrel_info(mnem):
    """(imm_bytes, scale, base) for PC-relative branch immediates, or None."""
    # BRC: RIc 16-bit @ bytes 2..3, target = pc + 2*imm
    # BRCL/BRASL: RIL 32-bit @ bytes 2..5, target = pc + 2*imm
    # BRAS: RIb 16-bit @ bytes 2..3, target = pc + 2*imm
    if mnem in ('je', 'jne', 'jh', 'jl', 'jo', 'jno', 'jnh', 'jnl', 'j',
                'jnop'):
        return (2, 4, 2)
    if mnem in ('jle', 'jlne', 'jlh', 'jll', 'jlo', 'jlno', 'jlnh',
                'jlnl', 'jlu', 'jlnop', 'brasl'):
        return (2, 6, 2)
    if mnem == 'bras':
        return (2, 4, 2)
    # BRCT/BRCTG/BRXH/BRXLE/BRXHG/BRXLG: 16-bit signed halfword imm
    # at bytes 2..3, target = pc + 2*imm
    if mnem in ('brct', 'brctg', 'brxh', 'brxle', 'brxhg', 'brxlg'):
        return (2, 4, 2)
    return None

# Mul/div pair instructions whose generated constructors print the even R1
# as a plain number ("M 6,..."); map the first numeric operand back to rN.
# Also covers the double-shift pair constructors (SRDL/SLDL/SRDA/SLDA).
PAIR_LIT_R1 = {'m','mr','mg','mfy','ml','mlr','mlg','mlgr',
               'd','dr','dl','dlr','dlg','dlgr','dsg','dsgr','dsgf','dsgfr',
               'srdl','sldl','srda','slda'}

def norm_fp_alias(tok):
    """Map our short-FP fNh aliases to Capstone's fN register names."""
    if tok[0] == 'sym':
        m = re.fullmatch(r'f(\d+)h', tok[1])
        if m:
            return ('sym', f'f{m.group(1)}')
    return tok

# Decimal SS: our display prints the raw L field (length-1) and B=0 as
# 'zero'; Capstone/IBM print the actual length and omit B=0. Compare
# structurally: parse both sides into (D, parts) operand groups.
# Group shapes per mnemonic, as (our_parts, cap_parts) where each part
# is 'D' (displacement), 'L' (length), 'B' (base reg), and cap parts may
# be missing B when B=0.
DEC_SHAPES = {
    # SSb: D1(L1,B1),D2(L2,B2)
    'ap': ([('D','L','B'),('D','L','B')], [('D','L','B?'),('D','L','B?')]),
    'sp': ([('D','L','B'),('D','L','B')], [('D','L','B?'),('D','L','B?')]),
    'mp': ([('D','L','B'),('D','L','B')], [('D','L','B?'),('D','L','B?')]),
    'dp': ([('D','L','B'),('D','L','B')], [('D','L','B?'),('D','L','B?')]),
    'cp': ([('D','L','B'),('D','L','B')], [('D','L','B?'),('D','L','B?')]),
    'zap': ([('D','L','B'),('D','L','B')], [('D','L','B?'),('D','L','B?')]),
    'pack': ([('D','L','B'),('D','L','B')], [('D','L','B?'),('D','L','B?')]),
    'unpk': ([('D','L','B'),('D','L','B')], [('D','L','B?'),('D','L','B?')]),
    'mvo': ([('D','L','B'),('D','L','B')], [('D','L','B?'),('D','L','B?')]),
    # SSf: D1(B1),D2(L2,B2)
    'pka': ([('D','B'),('D','L','B')], [('D','B?'),('D','L','B?')]),
    'pku': ([('D','B'),('D','L','B')], [('D','B?'),('D','L','B?')]),
    # SSa: D1(L1,B1),D2(B2)
    'tr': ([('D','L','B'),('D','B')], [('D','L','B?'),('D','B?')]),
    'trt': ([('D','L','B'),('D','B')], [('D','L','B?'),('D','B?')]),
    'trtr': ([('D','L','B'),('D','B')], [('D','L','B?'),('D','B?')]),
    'mvn': ([('D','L','B'),('D','B')], [('D','L','B?'),('D','B?')]),
    'mvz': ([('D','L','B'),('D','B')], [('D','L','B?'),('D','B?')]),
    'unpka': ([('D','L','B'),('D','B')], [('D','L','B?'),('D','B?')]),
    'ed': ([('D','L','B'),('D','B')], [('D','L','B?'),('D','B?')]),
    'edmk': ([('D','L','B'),('D','B')], [('D','L','B?'),('D','B?')]),
    # SSc: D1(L1,B1),D2(B2),I3
    'srp': ([('D','L','B'),('D','B')], [('D','L'),('D','B?')]),
    # RSLa: D1(L1,B1)
    'tp': ([('D','L','B')], [('D','L')]),
}

def parse_groups(s):
    """Parse 'D ( X , Y ), D2 ( Z )' into [ (D, [X, Y]), (D2, [Z]) ]
    plus any trailing comma-separated tokens."""
    groups = []
    spans = []
    for m in re.finditer(r'(\S+?)\s*\(\s*([^)]*?)\)', s):
        d = m.group(1)
        inner = [p.strip() for p in m.group(2).split(',') if p.strip()]
        groups.append((d, inner))
        spans.append(m.span())
    rest = s
    for st, en in sorted(spans, reverse=True):
        rest = rest[:st] + rest[en:]
    trailing = [t for t in re.split(r'[,\s]+', rest) if t]
    return groups, trailing

def dec_val(tok):
    """Numeric value of a token string, or None."""
    try:
        return int(tok.replace('%', ''), 0)
    except (ValueError, AttributeError):
        return None

def decimal_operands_ok(body, co, mnem):
    """Structural operand comparison for decimal SS instructions."""
    o_shapes, c_shapes = DEC_SHAPES[mnem]
    o_groups, o_trail = parse_groups(body)
    c_groups, c_trail = parse_groups(co)
    if len(o_groups) != len(o_shapes) or len(c_groups) != len(c_shapes):
        return f'group count: ours={o_groups} capstone={c_groups}'
    for (od, oparts), oshape, (cd, cparts), cshape in zip(
            o_groups, o_shapes, c_groups, c_shapes):
        # Ours always has all parts; Capstone may omit trailing optional
        # (B?) parts when B=0. 'D' is the group head, compared separately.
        o_roles = [p for p in oshape if p != 'D']
        c_roles = [p for p in cshape if p != 'D']
        if len(oparts) != len(o_roles):
            return f'ours group shape: ({od},{oparts})'
        if len(cparts) > len(c_roles):
            return f'capstone group shape: ({cd},{cparts})'
        if any(not p.endswith('?') for p in c_roles[len(cparts):]):
            return f'capstone group shape: ({cd},{cparts}) vs {cshape}'
        omap = dict(zip(o_roles, oparts))
        cmap = dict(zip([p.rstrip('?') for p in c_roles[:len(cparts)]],
                        cparts))
        if dec_val(od) != dec_val(cd):
            return f'D: ours={od} capstone={cd}'
        if 'L' in omap and 'L' in cmap:
            if dec_val(omap['L']) + 1 != dec_val(cmap['L']):
                return f'L: ours={omap["L"]} capstone={cmap["L"]}'
        ob = omap.get('B', omap.get('B?'))
        cb = cmap.get('B', cmap.get('B?'))
        ob_zero = (ob is None) or (ob.lower() == 'zero')
        if ob_zero != (cb is None):
            return f'B presence: ours={ob} capstone={cb}'
        if not ob_zero and ob.lower().replace('%', '') != cb.lower().replace('%', ''):
            return f'B: ours={ob} capstone={cb}'
    # trailing tokens (SRP's I3 shift amount)
    if len(o_trail) != len(c_trail):
        return f'trailing: ours={o_trail} capstone={c_trail}'
    for ot, ct in zip(o_trail, c_trail):
        if dec_val(ot) != dec_val(ct) and ot != ct:
            return f'trailing: ours={ot} capstone={ct}'
    return None

# RXY-form mul/div mnemonics (display shows DL2 only; Capstone shows the
# full signed 20-bit displacement).
MULDIV_DISP20 = {'dl','dlg','dsg','dsgf','mfy','mg','ml','mlg','msy'}

def disp20_from_encoding(hx):
    """Signed 20-bit displacement for 6-byte E3/EB (RXY/RSY/SIY) encodings.

    Our display follows the core convention of printing only the low 12
    bits (DL2); Capstone prints the full signed 20-bit displacement.
    Returns (dl2_unsigned, full_signed)."""
    b = bytes.fromhex(hx)
    dl2 = ((b[2] & 0xF) << 8) | b[3]
    dh2 = b[4]
    raw = (dh2 << 12) | dl2
    full = raw - 0x100000 if raw & 0x80000 else raw
    return dl2, full

def is_disp20_form(hx):
    b = bytes.fromhex(hx)
    return len(b) == 6 and b[0] in (0xE3, 0xEB)

def main():
    corpus = normalize_corpus(json.load(open(CORPUS)))
    spec = spec_mnemonics()
    # statically expected-unimplemented: no spec mnemonic (after aliasing)
    unimpl = set()
    for v in corpus:
        cm = v['capstone_mnemonic']
        if cm is None:
            # decode-only vector (oracle can't decode it); never unimpl
            continue
        cm = cm.lower()
        mapped = MNEM_ALIAS.get(cm, cm)
        if mapped not in spec and cm not in spec:
            # Capstone BRCL extended spelling with no IBM counterpart
            # (e.g. jghe = mask 0xA): covered by generic :brcl
            if cm.startswith('jg') and 'brcl' in spec:
                continue
            unimpl.add(v['bytes_hex'])

    passed, failed, skipped = [], [], []
    details = []
    for v in corpus:
        hx = v['bytes_hex']
        cm = v['capstone_mnemonic']
        co = v.get('capstone_op_str')
        if hx in unimpl:
            skipped.append((hx, cm, 'no spec constructor'))
            continue
        line = run_decoder(hx)
        status, ln, mnem, body = parse_out(line)
        if status != 'OK':
            failed.append((hx, cm, co, f'decode {status}: {line}'))
            continue
        if cm is None:
            # Decode-only vector (no oracle mnemonic): require the
            # expected length and a non-empty mnemonic.
            exp_len = v.get('expected_len')
            if exp_len is not None and ln != exp_len:
                failed.append((hx, cm, co,
                               f'decode-only length: ours={ln} want={exp_len}'))
                continue
            if not mnem:
                failed.append((hx, cm, co, 'decode-only: empty mnemonic'))
                continue
            passed.append(hx)
            details.append(f'DECODE-ONLY {hx}: {body}')
            continue
        cm = cm.lower()
        # Effective mnemonic: SLEIGH's printMnemonic emits the constructor
        # LABEL (e.g. LM_3_7 for generated LM/STM); the real mnemonic is the
        # display's first word (e.g. LM). Use that for comparison.
        eff_mnem = body.split()[0].lower() if body.split() else mnem.lower()
        exp_mnem = MNEM_ALIAS.get(cm, cm)
        if eff_mnem != exp_mnem and eff_mnem != cm:
            # BCR: Capstone prints base 'bcr M,R2'; we print the extended
            # mnemonic. Verify the mask matches and compare the rest.
            if cm == 'bcr' and eff_mnem in BCR_MASKS:
                want_ops = capstone_operands(co)
                mask_ok = (want_ops and want_ops[0] == ('num', BCR_MASKS[eff_mnem]))
                rest_ok = norm_operands(body.split(None,1)[1]
                                        if ' ' in body else '') == want_ops[1:]
                if mask_ok and rest_ok:
                    passed.append(hx)
                    continue
            # Generic BRCL: mask has no IBM extended mnemonic (e.g. mask
            # 0xA which Capstone calls 'jghe'). Verify our mask operand
            # against the encoded M1 nibble and the target via pcrel.
            if eff_mnem == 'brcl' and cm.startswith('j'):
                m1 = (bytes.fromhex(hx)[1] >> 4) & 0xF
                bparts = norm_operands(body.split(None,1)[1]
                                       if ' ' in body else '')
                raw = int.from_bytes(bytes.fromhex(hx)[2:6], 'big', signed=True)
                if (bparts[:1] == [('num', m1)] and
                        [t for t in bparts if t[0]=='num'][1:] == [('num', raw)]):
                    passed.append(hx)
                    continue
            failed.append((hx, cm, co,
                           f'mnemonic: ours={eff_mnem} (label {mnem})'))
            continue
        # operand comparison (strip the leading mnemonic word from the body)
        if co is None:
            # Mnemonic-only vector (oracle gave no operand string): the
            # mnemonic already matched above; nothing further to check.
            passed.append(hx)
            details.append(f'MNEM-ONLY {hx}: {body}')
            continue
        b = body.split(None,1)[1] if ' ' in body else ''
        ours = [norm_fp_alias(t) for t in norm_operands(b)]
        want = capstone_operands(co)
        if eff_mnem in SS_LEN_MNEMS and len(ours) > 1 and ours[1][0] == 'num':
            # IBM length syntax: our raw L field is length-1
            ours = ours[:1] + [('num', ours[1][1] + 1)] + ours[2:]
        if eff_mnem in ('lm','lmg','lmh','stm','stmg','stmh','stmy'):
            # Generated LM/STM display hardcodes R1,R3 as plain numbers
            # ("LM 3,7,..."); Capstone prints registers. The decode matched
            # the R1/R3-constrained constructor, so map them to r-names.
            ours = [('sym', f'r{t[1]}') if i < 2 and t[0] == 'num' else t
                    for i, t in enumerate(ours)]
        if eff_mnem in PAIR_LIT_R1 and ours and ours[0][0] == 'num':
            # Generated mul/div pair display prints even R1 as a plain
            # number ("M 6,..."); Capstone prints %r6.
            ours = [('sym', f'r{ours[0][1]}')] + ours[1:]
        if eff_mnem in DEC_SHAPES:
            # Decimal SS: compare structurally (raw L vs length, B=0
            # printed as 'zero' vs omitted).
            derr = decimal_operands_ok(b, co, eff_mnem)
            if derr:
                failed.append((hx, cm, co, f'decimal: {derr}'))
            else:
                passed.append(hx)
            continue
        if eff_mnem == 'clclu' and is_disp20_form(hx):
            # CLCLU displays only DL2 (core RSY convention); Capstone
            # prints the full 20-bit displacement.
            dl2, full = disp20_from_encoding(hx)
            ours = [('num', full) if t == ('num', dl2) else t for t in ours]
        if eff_mnem in MULDIV_DISP20 and is_disp20_form(hx):
            # RXY-form mul/div displays only DL2; Capstone prints the
            # full signed 20-bit displacement.
            dl2, full = disp20_from_encoding(hx)
            if full != dl2:
                ours = [('num', full) if t == ('num', dl2) else t
                        for t in ours]
        pc = pcrel_info(eff_mnem)
        if pc:
            # Our spec prints the absolute target (like Capstone).
            # At decode pc=0, target = scale*raw.
            off, end, scale = pc
            raw = int.from_bytes(bytes.fromhex(hx)[off:end], 'big', signed=True)
            expected = scale * raw
            nums = [t for t in ours if t[0] == 'num']
            if len(nums) != 1 or nums[0][1] != expected:
                failed.append((hx, cm, co,
                               f'pcrel target: ours={body!r} expected={expected:#x}'))
                continue
            # sanity: capstone target should be pc(0) + scale*raw
            cnums = [t for t in want if t[0] == 'num']
            if cnums and cnums[0][1] != expected:
                details.append(f'NOTE {hx}: capstone target {cnums[0][1]:#x} '
                               f'!= {scale}*({raw}) — oracle quirk?')
        else:
            if ours != want:
                failed.append((hx, cm, co,
                               f'operands: ours={body!r} norm={ours} '
                               f'capstone={co!r} norm={want}'))
                continue
        passed.append(hx)

    print(f'implemented vectors : {len(corpus) - len(unimpl)}')
    print(f'  passed            : {len(passed)}')
    print(f'  failed            : {len(failed)}')
    print(f'expected-unimpl     : {len(skipped)} (no spec constructor)')
    for d in details:
        print(d)
    if failed:
        print('\nFAILURES:')
        for hx, cm, co, why in failed:
            print(f'  {hx:14s} capstone: {cm} {co}  -> {why}')
        return 1
    print('\nAll implemented vectors match.')
    return 0

if __name__ == '__main__':
    sys.exit(main())
