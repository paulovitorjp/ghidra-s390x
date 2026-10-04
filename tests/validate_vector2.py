#!/usr/bin/env python3
"""validate_vector2.py — W7 workstream validation.

Validates the vector-facility p-code semantics (s390x_vector.sinc) and the
D-family divide-exception modeling (s390x_muldiv.sinc):

  1. Decode check: every vector in tests/corpus_vector2.json must decode OK
     with the expected mnemonic (Capstone cross-check; the vzero/vone
     extended mnemonics alias to our vgbm constructor).
  2. Semantic check: a tiny p-code interpreter executes the dumped p-code
     of VA/VS, VGBM and DL/DLR/DLGR and compares against Python reference
     models, including the fixed-point-divide trap paths.
  3. Structural check: the trap_fixed_point_divide user p-code op is
     defined in the source and the signed-divide helper macros exist.

Usage:
    python3 tests/validate_vector2.py [--sla PATH] [--no-build]

The p-code dumper (tests/s390x_pcode.cc) is built on demand with the same
minimal Ghidra decompile-cpp file set CI uses; the binary is written to
/tmp/s390x_pcode so the real tree is untouched.
"""
import json
import os
import random
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, ".."))
CORPUS = os.path.join(HERE, "corpus_vector2.json")
DECODER = os.path.join(HERE, "s390x_decode")
PCDUMP_SRC = os.path.join(HERE, "s390x_pcode.cc")
# Prefer a /tmp build (keeps the real tree untouched); fall back to the
# in-tree binary if present.
PCDUMP_BIN = ("/tmp/s390x_pcode" if os.path.exists("/tmp/s390x_pcode")
              else os.path.join(HERE, "s390x_pcode"))
CPP = os.path.join(ROOT, "ghidra", "decompile-cpp")
DEFAULT_SLA = os.path.join(ROOT, "data", "languages", "s390x.sla")

CI_SRCS = ("xml marshal space float address pcoderaw translate opcodes "
           "globalcontext sleigh pcodeparse pcodecompile sleighbase slghsymbol "
           "slghpatexpress slghpattern semantics context slaformat compression "
           "filemanage loadimage").split()

# Capstone extended mnemonics -> our constructor mnemonic.
MNEM_ALIAS = {"vzero": "vgbm", "vone": "vgbm"}
# Mul/div pair constructors print the even R1 as a literal ("DR 2 , r4").
PAIR_R1 = {"dr", "dlr", "dlgr", "dsgr", "dsgfr", "d", "dlg", "dsg"}

REG_SIZE = {}
REG_SIZE.update({f"r{i}": 8 for i in range(16)})
REG_SIZE.update({f"v{i}": 16 for i in range(32)})
REG_SIZE["cc"] = 8
REG_SIZE["zero"] = 8


def build_pcode_dumper():
    srcs = [os.path.join(CPP, f + ".cc") for f in CI_SRCS]
    missing = [s for s in srcs + [PCDUMP_SRC] if not os.path.exists(s)]
    if missing:
        raise RuntimeError("missing sources for pcode dumper: %s" % missing[:3])
    cmd = (["g++", "-O2", "-std=c++17", "-I", CPP] + srcs +
           [PCDUMP_SRC, "-lz", "-o", PCDUMP_BIN])
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
    if r.returncode != 0:
        raise RuntimeError("pcode dumper build failed:\n" + r.stderr[-3000:])


def run_decoder(sla, hexbytes):
    p = subprocess.run([DECODER, sla, hexbytes], capture_output=True,
                       text=True, timeout=120)
    return p.stdout.strip().split("\n")[0] if p.stdout.strip() else ""


def run_pcdump(sla, hexbytes):
    p = subprocess.run([PCDUMP_BIN, sla, hexbytes], capture_output=True,
                       text=True, timeout=120)
    if p.returncode != 0:
        raise RuntimeError("pcode dump failed for %s:\n%s" % (hexbytes, p.stderr[-2000:]))
    return p.stdout


# ---------------------------------------------------------------------------
# Tiny p-code interpreter (register/unique/const only; no memory, no floats).
# ---------------------------------------------------------------------------

def parse_varnode(tok):
    if tok.startswith("const:"):
        return ("const", int(tok.split(":")[1]), 0)
    m = re.fullmatch(r"([a-z]+):0x([0-9a-fA-F]+):(\d+)", tok)
    if m:
        return (m.group(1), int(m.group(2), 16), int(m.group(3)))
    if tok in REG_SIZE:
        return ("reg", tok, REG_SIZE[tok])
    raise ValueError("unparseable varnode: %r" % tok)


def parse_dump(text):
    """Parse dumper output -> (disasm_line, [(opname, out, [ins])])."""
    disasm = None
    ops = []
    for line in text.split("\n"):
        line = line.strip()
        if line.startswith("DISASM"):
            disasm = line
        elif line.startswith("OP "):
            parts = line.split()
            opname = parts[1]
            out, ins = None, []
            for p in parts[2:]:
                k, v = p.split("=", 1)
                if k == "out":
                    out = parse_varnode(v)
                elif k.startswith("in"):
                    ins.append(parse_varnode(v))
            ops.append((opname, out, ins))
        elif line.startswith("NODECODE") or line.startswith("PARTIAL"):
            raise RuntimeError("cannot interpret: %s" % line)
    if disasm is None or not ops:
        raise RuntimeError("empty p-code dump")
    return disasm, ops


class Interp:
    UNKNOWN = None  # unkval() / propagated unknown

    def __init__(self, ops):
        self.ops = ops
        self.state = {}
        self.traps = []      # userop CALLOTHERs with no output (traps taken)
        self.steps = 0

    def key(self, v):
        kind, off, size = v
        return (kind, off, size)

    def get(self, v, size):
        kind, off, vsize = v
        if kind == "const":
            return off & ((1 << (8 * size)) - 1)
        # Look up by the varnode's own size: an 8-byte temporary read by
        # a 1-byte-result comparison is still stored under its 8-byte key.
        return self.state.get((kind, off, vsize), 0)

    def put(self, v, val):
        kind, off, size = v
        assert kind != "const"
        self.state[(kind, off, size)] = val

    def mask(self, size):
        return (1 << (8 * size)) - 1

    def run(self, init, max_steps=200000):
        for name, val in init.items():
            self.state[("reg", name, REG_SIZE[name])] = val
        pc = 0
        while 0 <= pc < len(self.ops):
            if self.steps > max_steps:
                raise RuntimeError("interpreter step limit exceeded")
            self.steps += 1
            opname, out, ins = self.ops[pc]
            # osize: result width; isize: operand width (comparisons have
            # 1-byte results but N-byte operands; consts size to isize).
            osize = out[2] if out else 0
            isize = max([v[2] for v in ins if v[0] != "const"] or [osize or 8])
            vals = [self.get(v, isize) for v in ins]

            def u(i):
                return vals[i]

            m = self.mask(osize or isize)
            mi = self.mask(isize)
            nxt = pc + 1
            if opname == "COPY":
                res = u(0)
            elif opname == "INT_ADD":
                res = (u(0) + u(1)) & m if None not in (u(0), u(1)) else None
            elif opname == "INT_SUB":
                res = (u(0) - u(1)) & m if None not in (u(0), u(1)) else None
            elif opname == "INT_MULT":
                res = (u(0) * u(1)) & m if None not in (u(0), u(1)) else None
            elif opname == "INT_DIV":
                res = (u(0) // u(1)) & m if None not in (u(0), u(1)) and u(1) != 0 else None
            elif opname == "INT_LEFT":
                # Ghidra OpBehaviorIntLeft: shift >= width yields 0 (not wrapped).
                a, b = u(0), u(1)
                res = ((a << b) & m) if None not in (a, b) and b < 8 * isize else (0 if None not in (a, b) else None)
            elif opname == "INT_RIGHT":
                a, b = u(0), u(1)
                res = ((a >> b) & m) if None not in (a, b) and b < 8 * isize else (0 if None not in (a, b) else None)
            elif opname == "INT_SRIGHT":
                a = u(0)
                if a is None or u(1) is None:
                    res = None
                elif u(1) >= 8 * isize:
                    # Oversized arithmetic shift: sign-fill (Ghidra masks via
                    # in1 >= sizeout*8 check in practice; match INT_RIGHT).
                    res = m if a >> (8 * isize - 1) else 0
                else:
                    sh = u(1)
                    res = ((a - (1 << (8 * isize)) if a >> (8 * isize - 1) else a) >> sh) & m
            elif opname == "INT_AND":
                res = (u(0) & u(1)) if None not in (u(0), u(1)) else None
            elif opname == "INT_OR":
                res = (u(0) | u(1)) if None not in (u(0), u(1)) else None
            elif opname == "INT_XOR":
                res = (u(0) ^ u(1)) if None not in (u(0), u(1)) else None
            elif opname == "INT_NEGATE":
                res = (-u(0)) & m if u(0) is not None else None
            elif opname == "INT_NOTEQUAL":
                res = None if None in (u(0), u(1)) else (1 if u(0) != u(1) else 0)
            elif opname == "INT_EQUAL":
                res = None if None in (u(0), u(1)) else (1 if u(0) == u(1) else 0)
            elif opname == "INT_LESS":
                res = None if None in (u(0), u(1)) else (1 if u(0) < u(1) else 0)
            elif opname == "INT_LESSEQUAL":
                res = None if None in (u(0), u(1)) else (1 if u(0) <= u(1) else 0)
            elif opname == "INT_SLESS":
                def s(x):
                    return x - (1 << (8 * isize)) if x >> (8 * isize - 1) else x
                res = None if None in (u(0), u(1)) else (1 if s(u(0)) < s(u(1)) else 0)
            elif opname == "INT_ZEXT":
                res = u(0) & m if u(0) is not None else None
            elif opname == "INT_SEXT":
                a = u(0)
                if a is None:
                    res = None
                else:
                    inbits = 8 * ins[0][2]
                    res = (a - (1 << inbits) if a >> (inbits - 1) else a) & m
            elif opname == "SUBPIECE":
                a = u(0)
                res = (a >> (8 * u(1))) & m if None not in (a, u(1)) else None
            elif opname == "CBRANCH":
                # Branch targets print as const:<op-index> relative to the
                # branch op itself (signed 32-bit).
                off = ins[0][1]
                if off >= 0x80000000:
                    off -= 0x100000000
                cond = u(1)
                if cond is None:
                    raise RuntimeError("branch on unknown at op %d" % pc)
                if cond:
                    nxt = pc + off
                res = "nojump"
            elif opname == "BRANCH":
                off = ins[0][1]
                if off >= 0x80000000:
                    off -= 0x100000000
                nxt = pc + off
                res = "nojump"
            elif opname == "CALLOTHER":
                # in0 is the raw userop id; a missing output means the
                # op is used as a trap statement (cf. trap_compare_data).
                if out is None:
                    self.traps.append(ins[0][1])
                res = "callother"
                if out is not None:
                    self.put(out, None)  # unkval()
            else:
                raise RuntimeError("unsupported op %r at %d" % (opname, pc))
            if res == "nojump":
                pass
            elif res == "callother":
                pass
            else:
                self.put(out, res)
            pc = nxt
        return self

    def reg(self, name):
        return self.state.get(("reg", name, REG_SIZE[name]), 0)


# ---------------------------------------------------------------------------
# Reference models.
# ---------------------------------------------------------------------------

def ref_va_vs(a, b, esz, sub):
    n = 16 // esz
    ebits = 8 * esz
    mm = (1 << ebits) - 1
    acc = 0
    for i in range(n):
        ea = (a >> (i * ebits)) & mm
        eb = (b >> (i * ebits)) & mm
        er = (ea - eb if sub else ea + eb) & mm
        acc |= er << (i * ebits)
    return acc


def ref_vgbm(i2):
    acc = 0
    for i in range(16):
        if (i2 >> i) & 1:
            acc |= 0xFF << (8 * i)
    return acc


# ---------------------------------------------------------------------------
# Checks.
# ---------------------------------------------------------------------------

def check_decode(sla):
    corpus = json.load(open(CORPUS))
    passed, failed = 0, []
    for v in corpus:
        hx = v["bytes_hex"]
        line = run_decoder(sla, hx)
        m = re.match(r"OK len=(\d+) mnem=(\S+) body=(.*)$", line)
        if not m:
            failed.append((hx, "decode failed: %s" % line))
            continue
        mnem = m.group(2).lower()
        body = m.group(3)
        want = MNEM_ALIAS.get(v["capstone_mnemonic"], v["capstone_mnemonic"])
        # Generated pair constructors use labels like DR_2; the real
        # mnemonic is the display's first word.
        eff = body.strip().split()[0].lower() if body.strip() else mnem
        if eff != want and mnem != want:
            failed.append((hx, "mnemonic: ours=%s/%s want=%s" % (mnem, eff, want)))
            continue
        # Operand sanity: every v-register number Capstone names must
        # appear in our body, and vice versa.
        cap_regs = sorted(int(x) for x in re.findall(r"%v(\d+)", v["capstone_op_str"]))
        our_regs = sorted(int(x) for x in re.findall(r"\bv(\d+)\b", body))
        if v["capstone_mnemonic"] in ("vzero", "vone"):
            if our_regs != cap_regs:
                failed.append((hx, "v-regs: ours=%s cap=%s" % (our_regs, cap_regs)))
                continue
            imm = int(v["bytes_hex"][4:8], 16)
            if ("0x%x" % imm) not in body.replace("0x0", "0x0"):
                # body prints the immediate in hex (0x0 for 0, 0xffff)
                if not re.search(r"\b0x0\b", body) if imm == 0 else \
                   not re.search(r"\b0xffff\b", body):
                    failed.append((hx, "vzero/vone immediate missing: %s" % body))
                    continue
        elif cap_regs != our_regs:
            failed.append((hx, "v-regs: ours=%s cap=%s" % (our_regs, cap_regs)))
            continue
        if v["category"] == "muldiv":
            cap_gprs = sorted(int(x) for x in re.findall(r"%r(\d+)", v["capstone_op_str"]))
            our_gprs = sorted(int(x) for x in re.findall(r"\br(\d+)\b", body))
            # Our pair constructors print even R1 as a literal number.
            lits = [int(x) for x in re.findall(r"(?:^|\s)(\d+)\s*,", body)]
            if sorted(our_gprs + lits) != cap_gprs:
                failed.append((hx, "gprs: ours=%s+%s cap=%s body=%s" %
                               (our_gprs, lits, cap_gprs, body)))
                continue
        passed += 1
    return passed, failed


def get_pcode(sla, hx):
    text = run_pcdump(sla, hx)
    return parse_dump(text)


VEC_CASES = [
    # (hex, esz, sub)
    ("e71230000ef3", 1, 0),  # vab v17,v18,v19
    ("e71230000ef7", 1, 1),  # vsb v17,v18,v19
    ("e702300018f3", 2, 0),  # vah v16,v2,v3
    ("e712300004f7", 1, 1),  # vsb v1,v18,v3
    ("e70130002cf7", 4, 1),  # vsf v16,v17,v3
    ("e712300030f7", 8, 1),  # vsg v1,v2,v3
    ("e712300020f3", 4, 0),  # vaf v1,v2,v3
    ("e712300030f3", 8, 0),  # vag v1,v2,v3
]

VEC_REGS = {
    "e71230000ef3": ("v17", "v18", "v19"),
    "e71230000ef7": ("v17", "v18", "v19"),
    "e702300018f3": ("v16", "v2", "v3"),
    "e712300004f7": ("v1", "v18", "v3"),
    "e70130002cf7": ("v16", "v17", "v3"),
    "e712300030f7": ("v1", "v2", "v3"),
    "e712300020f3": ("v1", "v2", "v3"),
    "e712300030f3": ("v1", "v2", "v3"),
}

VGBM_CASES = ["e71000000044", "e710ffff0044", "e71000ff0044", "e710ff000044",
              "e71055550044", "e700a5a50844", "e71012340044"]
VGBM_REGS = {"e71000000044": "v1", "e710ffff0044": "v1", "e71000ff0044": "v1",
             "e710ff000044": "v1", "e71055550044": "v1", "e700a5a50844": "v16",
             "e71012340044": "v1"}


def check_vector_semantics(sla):
    """Execute VA/VS p-code on random inputs; compare against lane model."""
    rng = random.Random(0x5eed)
    passed, failed = 0, []
    for hx, esz, sub in VEC_CASES:
        vd, va, vb = VEC_REGS[hx]
        disasm, ops = get_pcode(sla, hx)
        for trial in range(6):
            a = rng.getrandbits(128)
            b = rng.getrandbits(128)
            if trial == 0:
                a, b = 0, 0
            if trial == 1:
                a, b = (1 << 128) - 1, (1 << 128) - 1  # wrap-around case
            st = Interp(ops).run({va: a, vb: b})
            got = st.reg(vd)
            want = ref_va_vs(a, b, esz, sub)
            if got != want:
                failed.append((hx, "trial %d: got %032x want %032x" % (trial, got, want)))
                break
            # CC must be untouched by VA/VS.
            if st.reg("cc") != 0:
                failed.append((hx, "cc clobbered: %d" % st.reg("cc")))
                break
        else:
            passed += 1
    return passed, failed


def check_vgbm_semantics(sla):
    passed, failed = 0, []
    for hx in VGBM_CASES:
        vd = VGBM_REGS[hx]
        i2 = int(hx[4:8], 16)
        disasm, ops = get_pcode(sla, hx)
        # The I2 field arrives as a constant in the dump; make sure the
        # value matches the encoding before trusting execution.
        st = Interp(ops).run({})
        got = st.reg(vd)
        want = ref_vgbm(i2)
        if got != want:
            failed.append((hx, "got %032x want %032x" % (got, want)))
            continue
        passed += 1
    return passed, failed


def check_divide(sla):
    """DLR/DLGR: random unsigned divisions + trap paths.

    Uses the R2=r2 encodings (b9970002/b9870002) for the general case so
    the divisor is independent of the dividend; the degenerate R2=r0
    forms exercise the trap paths deterministically.
    """
    rng = random.Random(0xd17)
    passed, failed = 0, []
    # DLR_0, R2=r2: dvs = r2[31:0]; dvd = r0[31:0]:r1[31:0] (64-bit);
    # r0[31:0] = rem, r1[31:0] = quot (low halves only).
    disasm, ops = get_pcode(sla, "b9970002")
    if not any(o == "CALLOTHER" and out is None for o, out, _ in ops):
        return 0, [("b9970002", "no trap CALLOTHER in p-code")]
    for trial in range(40):
        dvd = rng.getrandbits(64)
        dvs = rng.getrandbits(32)
        if trial == 0:
            dvs = 0  # divisor zero -> trap
        elif trial == 1:
            dvd, dvs = 0x100000000, 1  # quotient = 2^32 -> overflow trap
        st = Interp(ops).run({"r0": dvd >> 32, "r1": dvd & 0xFFFFFFFF,
                              "r2": dvs})
        # DLR traps on divisor zero and when the quotient does not fit
        # 32 bits, i.e. (dvd >> 32) >= dvs.
        if dvs == 0 or (dvd >> 32) >= dvs:
            if not st.traps:
                failed.append(("b9970002", "trial %d: expected trap" % trial))
                break
        else:
            if st.traps:
                failed.append(("b9970002", "spurious trap"))
                break
            q, r = dvd // dvs, dvd % dvs
            if (st.reg("r1") & 0xFFFFFFFF) != q or (st.reg("r0") & 0xFFFFFFFF) != r:
                failed.append(("b9970002", "trial %d: q/r mismatch" % trial))
                break
    else:
        passed += 1
    # DLR_0 degenerate (R2=r0): dvs = r0[31:0] = 0 -> must trap, and the
    # suppressed operation must leave r0/r1 unchanged.
    disasm, ops = get_pcode(sla, "b9970000")
    st = Interp(ops).run({"r0": 0, "r1": 12345})
    if not st.traps:
        failed.append(("b9970000", "divisor=0 did not trap"))
    elif st.reg("r0") != 0 or st.reg("r1") != 12345:
        failed.append(("b9970000", "trap did not preserve r0/r1"))
    else:
        passed += 1
    # DLGR_0, R2=r2: d = r2 (64-bit); dvd = r0:r1 (128-bit);
    # r0 = rem, r1 = quot.
    disasm, ops = get_pcode(sla, "b9870002")
    if not any(o == "CALLOTHER" and out is None for o, out, _ in ops):
        return passed, failed + [("b9870002", "no trap CALLOTHER in p-code")]
    for trial in range(24):
        hi = rng.getrandbits(64)
        lo = rng.getrandbits(64)
        d = rng.getrandbits(64)
        if trial == 0:
            d = 0  # divisor zero -> trap
        elif trial == 1:
            d, hi = 3, 4  # hi >= d -> quotient overflow -> trap
        st = Interp(ops).run({"r0": hi, "r1": lo, "r2": d})
        if d == 0 or hi >= d:
            if not st.traps:
                failed.append(("b9870002", "trial %d: expected trap" % trial))
                break
        else:
            if st.traps:
                failed.append(("b9870002", "spurious trap"))
                break
            dvd = (hi << 64) | lo
            if st.reg("r1") != dvd // d or st.reg("r0") != dvd % d:
                failed.append(("b9870002", "trial %d: q/r mismatch" % trial))
                break
    else:
        passed += 1
    # DLGR_0 degenerate (R2=r0): d = r0 = hi -> hi >= d overflow trap,
    # and the suppressed operation must leave r0/r1 unchanged.
    disasm, ops = get_pcode(sla, "b9870000")
    st = Interp(ops).run({"r0": 5, "r1": 99})
    if not st.traps:
        failed.append(("b9870000", "hi>=d did not trap"))
    elif st.reg("r0") != 5 or st.reg("r1") != 99:
        failed.append(("b9870000", "trap did not preserve r0/r1"))
    else:
        passed += 1
    return passed, failed


def check_structural():
    """Source-level invariants for the exception modeling."""
    langdir = os.path.join(ROOT, "data", "languages")
    muldiv = open(os.path.join(langdir, "s390x_muldiv.sinc")).read()
    checks = [
        ("define pcodeop trap_fixed_point_divide;" in muldiv,
         "trap_fixed_point_divide userop defined"),
        ("trap_fixed_point_divide();" in muldiv, "trap call sites present"),
        ("macro sdiv32_exc" in muldiv, "sdiv32_exc helper defined"),
        ("macro sdiv64_exc" in muldiv, "sdiv64_exc helper defined"),
        ("if (d == 0) goto <udiv64_trap>;" in muldiv, "udiv64 zero-divisor check"),
        ("if (hi >= d) goto <udiv128_trap>;" in muldiv, "udiv128 overflow check"),
    ]
    passed = sum(1 for ok, _ in checks if ok)
    failed = [("structural", name) for ok, name in checks if not ok]
    return passed, failed


def main():
    sla = DEFAULT_SLA
    build = True
    args = sys.argv[1:]
    while args:
        a = args.pop(0)
        if a == "--sla":
            sla = args.pop(0)
        elif a == "--no-build":
            build = False
    if build and not os.path.exists(PCDUMP_BIN):
        print("building p-code dumper ...")
        build_pcode_dumper()
    total_pass, total_fail = 0, []
    for name, fn in [("decode", lambda: check_decode(sla)),
                     ("vector-semantics", lambda: check_vector_semantics(sla)),
                     ("vgbm-semantics", lambda: check_vgbm_semantics(sla)),
                     ("divide-exceptions", lambda: check_divide(sla)),
                     ("structural", check_structural)]:
        try:
            p, f = fn()
        except Exception as e:
            p, f = 0, [(name, "EXCEPTION: %r" % e)]
        total_pass += p
        for hx, msg in f:
            total_fail.append((name, hx, msg))
        print("%-18s pass=%d fail=%d" % (name, p, len(f)))
        for hx, msg in f:
            print("  FAIL %s: %s" % (hx, msg))
    print("TOTAL pass=%d fail=%d" % (total_pass, len(total_fail)))
    return 1 if total_fail else 0


if __name__ == "__main__":
    sys.exit(main())
