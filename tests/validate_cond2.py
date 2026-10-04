#!/usr/bin/env python3
"""validate_cond2.py -- semantic validation of the conditional-BCR p-code fix.

For every vector in tests/corpus_cond2.json (all 16 BCR masks x R2 fields
0/1/3/14):
  1. Decode with tests/s390x_decode: require OK and the expected spec mnemonic.
  2. Dump p-code with tests/s390x_pcode (built on demand from the repo's
     ghidra/decompile-cpp sources using the same minimal file set CI uses
     for tests/s390x_decode).
  3. Symbolically execute the emitted p-code for cc in {0,1,2,3} with a tiny
     interpreter covering exactly the op subset these constructors emit.
  4. Require: indirect branch taken  <=>  (mask & (8>>cc)) != 0 AND the R2
     field != 0, targeting exactly the R2 register; mask-15/R2=14 must
     RETURN; mask 0 and any R2=0 case must emit no control-flow op at all.

This fails on the pre-fix spec (which tested the target register's contents
instead of mask-vs-cc) and passes on the fixed spec.

Usage:
    python3 tests/validate_cond2.py [--sla PATH] [--no-build]
Default .sla: data/languages/s390x.sla. Exit 0 iff every check passes.
"""
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, ".."))
CORPUS = os.path.join(HERE, "corpus_cond2.json")
DECODER = os.path.join(HERE, "s390x_decode")
PCDUMP_SRC = os.path.join(HERE, "s390x_pcode.cc")
PCDUMP_BIN = os.path.join(HERE, "s390x_pcode")
CPP = os.path.join(ROOT, "ghidra", "decompile-cpp")
DEFAULT_SLA = os.path.join(ROOT, "data", "languages", "s390x.sla")

# Minimal SLEIGH decoder file set, kept in sync with .github/workflows/ci.yml.
CI_SRCS = ("xml marshal space float address pcoderaw translate opcodes "
           "globalcontext sleigh pcodeparse pcodecompile sleighbase slghsymbol "
           "slghpatexpress slghpattern semantics context slaformat compression "
           "filemanage loadimage").split()

BCR_NAMES = {0: 'nopr', 1: 'bor', 2: 'bhr', 3: 'bnler', 4: 'blr', 5: 'bnher',
             6: 'blhr', 7: 'bner', 8: 'ber', 9: 'bnlhr', 10: 'bher',
             11: 'bnlr', 12: 'bler', 13: 'bnhr', 14: 'bnor', 15: 'br'}


def build_pcode_dumper():
    srcs = [os.path.join(CPP, f + ".cc") for f in CI_SRCS]
    missing = [s for s in srcs + [PCDUMP_SRC] if not os.path.exists(s)]
    if missing:
        raise RuntimeError("missing sources for pcode dumper: %s" % missing[:3])
    cmd = (["g++", "-O2", "-std=c++17", "-I", CPP] + srcs +
           [PCDUMP_SRC, "-lz", "-o", PCDUMP_BIN])
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if r.returncode != 0:
        raise RuntimeError("pcode dumper build failed:\n" + r.stderr[-3000:])


def run_tool(binary, sla, hx):
    r = subprocess.run([binary, sla, hx], capture_output=True, text=True,
                       timeout=120)
    return r.stdout


# --------------------------------------------------------------------------
# P-code parser + tiny interpreter (op subset emitted by BCR constructors).
# --------------------------------------------------------------------------
OP_RE = re.compile(r"^OP (\S+)((?: \S+=\S+)*)$")
VN_RE = re.compile(r"(in\d+|out)=(\S+)")


def parse_vn(tok):
    if tok.startswith("const:"):
        parts = tok.split(":")
        # const:<value>[:<size>] (dumper prints the size; older dumps omit it)
        val = int(parts[1])
        size = int(parts[2]) if len(parts) > 2 else 8
        return ("const", val, size)
    if re.fullmatch(r"[a-z][a-z0-9]*", tok):
        return ("reg", tok)
    return ("tmp", tok)  # unique:/ram:/... space:off:size


def parse_pcode(text):
    ops = []
    for line in text.splitlines():
        m = OP_RE.match(line.strip())
        if not m:
            continue
        name, rest = m.group(1), m.group(2)
        out, ins = None, []
        for vm in VN_RE.finditer(rest):
            kind, tok = vm.group(1), vm.group(2)
            if kind == "out":
                out = parse_vn(tok)
            else:
                ins.append(parse_vn(tok))
        ops.append((name, out, ins))
    return ops


def vn_size(vn):
    """Byte size of a parsed varnode (regs are 8; tmps carry :size)."""
    if vn[0] == "tmp":
        try:
            return int(vn[1].rsplit(":", 1)[1])
        except (ValueError, IndexError):
            return 8
    return 8


def mask_for(vn, state):
    # (size-aware value mask, value)
    kind = vn[0]
    if kind == "const":
        return 0xFFFFFFFFFFFFFFFF, vn[1]
    key = vn[1] if kind == "reg" else vn[1]
    size = 8
    if kind == "tmp":
        parts = vn[1].rsplit(":", 1)
        try:
            size = int(parts[1])
        except (ValueError, IndexError):
            size = 8
    m = (1 << (8 * size)) - 1
    return m, state.get(key, 0)


def set_vn(vn, val, state):
    kind = vn[0]
    key = vn[1]
    if kind == "const":
        raise RuntimeError("write to const")
    size = 8
    if kind == "tmp":
        parts = vn[1].rsplit(":", 1)
        try:
            size = int(parts[1])
        except (ValueError, IndexError):
            size = 8
    state[key] = val & ((1 << (8 * size)) - 1)


def const_val(vn):
    assert vn[0] == "const", vn
    return vn[1]


def branch_offset(vn):
    """Signed intra-p-code branch offset: target op = this op + offset."""
    assert vn[0] == "const", vn
    val, size = vn[1], vn[2] if len(vn) > 2 else 8
    if val >= 1 << (8 * size - 1):
        val -= 1 << (8 * size)
    return val


def _simulate(ops, cc_val, regs, mem=None):
    """Execute ops; return (result, final_state).
    result is ('fallthrough', None) | ('branchind', regname) |
    ('return', regname-or-None). regs maps regname -> int (cc overridden).
    mem is an optional dict modeling flat big-endian memory for LOAD/STORE
    (all address spaces share one flat model); reads default to 0."""
    state = dict(regs)
    state["cc"] = cc_val
    if mem is None:
        mem = {}

    def mem_read(addr, size):
        val = 0
        for k in range(size):
            val = (val << 8) | (mem.get(addr + k, 0) & 0xFF)
        return val

    def mem_write(addr, size, val):
        for k in range(size - 1, -1, -1):
            mem[addr + k] = val & 0xFF
            val >>= 8
    pc = 0
    steps = 0
    while 0 <= pc < len(ops):
        steps += 1
        if steps > 10000:
            raise RuntimeError("p-code did not terminate")
        name, out, ins = ops[pc]
        vals = [mask_for(v, state) for v in ins]

        def v(i):
            return vals[i][1]

        if name == "COPY":
            set_vn(out, v(0), state)
        elif name == "LOAD":
            # ins[0] = address-space id const, ins[1] = address.
            # Flat memory model shared across spaces.
            set_vn(out, mem_read(v(1), vn_size(out)), state)
        elif name == "STORE":
            # ins[0] = space id, ins[1] = address, ins[2] = value.
            mem_write(v(1), vn_size(ins[2]), v(2))
        elif name == "CALLOTHER":
            # User-defined p-code op (e.g. trap_fixed_point_divide()).
            # in0 = userop index const. Record the call and continue;
            # the p-code after the call models the architectural effect
            # (for divide traps: register preservation).
            uop = ins[0]
            calls = state.setdefault("_calls", [])
            calls.append(v(0))
            if out is not None:
                set_vn(out, 0, state)
        elif name == "INT_AND":
            set_vn(out, v(0) & v(1), state)
        elif name == "INT_OR":
            set_vn(out, v(0) | v(1), state)
        elif name == "INT_XOR":
            set_vn(out, v(0) ^ v(1), state)
        elif name == "INT_LEFT":
            set_vn(out, v(0) << v(1), state)
        elif name == "INT_RIGHT":
            set_vn(out, v(0) >> v(1), state)
        elif name == "INT_SRIGHT":
            m0, a = vals[0]
            bits = m0.bit_length()
            if a & (1 << (bits - 1)):
                a -= (1 << bits)
            set_vn(out, a >> v(1), state)
        elif name == "INT_ADD":
            set_vn(out, v(0) + v(1), state)
        elif name == "INT_SUB":
            set_vn(out, v(0) - v(1), state)
        elif name == "INT_MULT":
            set_vn(out, v(0) * v(1), state)
        elif name == "INT_NEGATE":
            set_vn(out, -v(0), state)
        elif name in ("INT_DIV", "INT_REM", "INT_SDIV", "INT_SREM"):
            # Division. The interpreter works on Python ints; emulate the
            # p-code width from the output size. INT_DIV/INT_REM are
            # unsigned; INT_SDIV/INT_SREM are signed (truncation toward
            # zero, remainder taking the dividend's sign). Division by
            # zero raises like the hardware trap would abort execution.
            size = vn_size(out)
            bits = 8 * size
            a, b = v(0), v(1)
            if name in ("INT_SDIV", "INT_SREM"):
                sa = a - (1 << bits) if a >> (bits - 1) else a
                sb = b - (1 << bits) if b >> (bits - 1) else b
                if sb == 0:
                    raise ZeroDivisionError("INT_SDIV by zero")
                q = abs(sa) // abs(sb)
                if (sa < 0) != (sb < 0):
                    q = -q
                r = sa - q * sb
                res = q if name == "INT_SDIV" else r
            else:
                if b == 0:
                    raise ZeroDivisionError("INT_DIV by zero")
                res = (a // b) if name == "INT_DIV" else (a % b)
            set_vn(out, res, state)
        elif name == "INT_2COMP":
            set_vn(out, (~v(0)) + 1, state)
        elif name == "INT_ZEXT":
            set_vn(out, v(0), state)
        elif name == "INT_SEXT":
            m0, a = vals[0]
            bits = m0.bit_length()
            if a & (1 << (bits - 1)):
                a -= (1 << bits)
            set_vn(out, a, state)
        elif name in ("INT_EQUAL", "INT_NOTEQUAL", "INT_LESS", "INT_SLESS",
                      "INT_LESSEQUAL", "INT_SLESSEQUAL"):
            a, b = v(0), v(1)
            sa = sb = None
            if "S" in name.split("_", 1)[1]:
                for val, m in ((a, vals[0][0]), (b, vals[1][0])):
                    bits = m.bit_length()
                    if val & (1 << (bits - 1)):
                        val -= (1 << bits)
                    if sa is None:
                        sa = val
                    else:
                        sb = val
                a, b = sa, sb
            r = {"INT_EQUAL": a == b, "INT_NOTEQUAL": a != b,
                 "INT_LESS": a < b, "INT_SLESS": a < b,
                 "INT_LESSEQUAL": a <= b, "INT_SLESSEQUAL": a <= b}[name]
            set_vn(out, 1 if r else 0, state)
        elif name in ("BOOL_AND", "BOOL_OR", "BOOL_XOR"):
            r = {"BOOL_AND": (v(0) and v(1)), "BOOL_OR": (v(0) or v(1)),
                 "BOOL_XOR": ((v(0) != 0) ^ (v(1) != 0))}[name]
            set_vn(out, 1 if r else 0, state)
        elif name == "BOOL_NEGATE":
            set_vn(out, 0 if v(0) else 1, state)
        elif name == "CBRANCH":
            # SLEIGH CBRANCH: in0 = target, in1 = condition.
            # Intra-p-code labels print as a SIGNED relative const offset:
            # target op index = index of this op + offset.
            if v(1) != 0:
                tgt = ins[0]
                if tgt[0] == "const":
                    pc = pc + branch_offset(tgt)
                    continue
                return (("branchind", tgt[1] if tgt[0] == "reg" else repr(tgt)), state)
        elif name == "BRANCH":
            # 'goto <register>' compiles to BRANCH with a register destination
            # (indirect branch); a const destination is a signed relative
            # intra-p-code label: target op index = this op index + offset.
            tgt = ins[0]
            if tgt[0] == "const":
                pc = pc + branch_offset(tgt)
                continue
            return (("branchind", tgt[1] if tgt[0] == "reg" else repr(tgt)), state)
        elif name == "BRANCHIND":
            tgt = ins[0]
            return (("branchind", tgt[1] if tgt[0] == "reg" else repr(tgt)), state)
        elif name == "RETURN":
            if ins and ins[0][0] == "reg":
                return (("return", ins[0][1]), state)
            return (("return", None), state)
        elif name in ("CALL", "CALLIND", "CALLOTHER"):
            pass  # no BCR constructor emits these; ignore if present
        else:
            raise RuntimeError("unsupported p-code op in interpreter: " + name)
        pc += 1
    return (("fallthrough", None), state)


def simulate(ops, cc_val, regs):
    """Execute ops; return ('fallthrough', None) | ('branchind', regname) |
    ('return', regname-or-None). regs maps regname -> int (cc overridden)."""
    result, _state = _simulate(ops, cc_val, regs)
    return result


# --------------------------------------------------------------------------
def main():
    sla = DEFAULT_SLA
    do_build = True
    args = sys.argv[1:]
    while args:
        a = args.pop(0)
        if a == "--sla":
            sla = args.pop(0)
        elif a == "--no-build":
            do_build = False
        else:
            sys.exit("unknown arg: " + a)
    if not os.path.exists(sla):
        sys.exit("no such .sla: " + sla)
    if do_build or not os.path.exists(PCDUMP_BIN):
        print("building p-code dumper ...", flush=True)
        build_pcode_dumper()
    if not os.path.exists(DECODER):
        sys.exit("missing decoder binary: " + DECODER + " (build it first)")

    corpus = json.load(open(CORPUS))
    regs = {"r%d" % i: 0x1000 + i for i in range(16)}  # nonzero sentinels
    regs["r0"] = 0x2000  # r0 contents nonzero: old bug would branch on it

    npass = nfail = 0
    failures = []
    for vec in corpus:
        hx = vec["bytes_hex"]
        b = bytes.fromhex(hx)
        mask = (b[1] >> 4) & 0xF
        r2 = b[1] & 0xF
        tag = "%s mask=%d r2=%d" % (hx, mask, r2)

        # --- 1. decode check ---
        dline = run_tool(DECODER, sla, hx).strip().splitlines()
        dline = dline[0] if dline else ""
        m = re.match(r"OK len=(\d+) mnem=(\S+) body=(.*)", dline)
        if not m:
            nfail += 1
            failures.append((tag, "decode failed: " + dline))
            continue
        want_mnem = BCR_NAMES[mask]
        got_mnem = m.group(2).lower()
        # mask 15 splits into three constructors by R2 field value
        mnem_ok = (got_mnem == want_mnem or
                   (mask == 15 and got_mnem in ("br", "br_ret", "br_nop")))
        if not mnem_ok:
            nfail += 1
            failures.append((tag, "mnemonic: got %s want %s" %
                             (m.group(2), want_mnem)))
            continue

        # --- 2/3. p-code dump + symbolic execution over cc=0..3 ---
        plines = run_tool(PCDUMP_BIN, sla, hx)
        if "NODECODE" in plines or "PCODE-ERROR" in plines:
            nfail += 1
            failures.append((tag, "pcode dump failed"))
            continue
        ops = parse_pcode(plines)
        try:
            results = [simulate(ops, cc, regs) for cc in range(4)]
        except RuntimeError as e:
            nfail += 1
            failures.append((tag, "interpreter: %s" % e))
            continue

        # --- 4. expected semantics ---
        ok = True
        why = ""
        rname = "r%d" % r2
        if mask == 0 or r2 == 0:
            # architectural no-op: mask 0, or R2 field zero (PoP: BCR with
            # R2=0 never branches regardless of mask). No control-flow op
            # may fire for any cc value.
            if any(r[0] != "fallthrough" for r in results):
                ok, why = False, "no-op case took control flow: %s" % (results,)
        elif mask == 15 and r2 == 14:
            if any(r != ("return", "r14") for r in results):
                ok, why = False, "br_ret must RETURN r14: %s" % (results,)
        elif mask == 15:
            if any(r != ("branchind", rname) for r in results):
                ok, why = False, "mask-15 must always branch to %s: %s" % (rname, results)
        else:
            for cc, r in enumerate(results):
                taken = (mask & (8 >> cc)) != 0
                if taken:
                    if r != ("branchind", rname):
                        ok, why = False, ("cc=%d: expected branch to %s, got %s"
                                           % (cc, rname, r))
                        break
                else:
                    if r[0] != "fallthrough":
                        ok, why = False, ("cc=%d: expected fallthrough, got %s"
                                           % (cc, r))
                        break
            # structural: the taken/not-taken decision must read cc
            if ok and not any("cc" in line for line in plines.splitlines()
                              if line.startswith("OP")):
                ok, why = False, "p-code never references cc"
        if ok:
            npass += 1
        else:
            nfail += 1
            failures.append((tag, why))

    print("vectors checked : %d" % (npass + nfail))
    print("  passed        : %d" % npass)
    print("  failed        : %d" % nfail)
    for tag, why in failures:
        print("FAIL %s: %s" % (tag, why))
    sys.exit(1 if nfail else 0)


if __name__ == "__main__":
    main()
