#!/usr/bin/env python3
"""Check PACK, UNPK, AP, and CP p-code against known packed-decimal results.

The constructors are not rewritten here. A tiny interpreter executes the
emitted p-code on a few hand-computed inputs from the operation definitions:
zone nibbles become packed digits, the rightmost zone is the sign, AP adds
magnitudes, and CP orders signed packed values.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import validate_cond2 as vc  # noqa: E402

ROOT = os.path.normpath(os.path.join(HERE, ".."))
SLA = os.path.join(ROOT, "data", "languages", "s390x.sla")


def mem_bytes(mem, addr, n):
    return bytes(mem.get(addr + i, 0) & 0xFF for i in range(n))


def run_op(hx, regs, mem, cc=0):
    if not os.path.exists(vc.PCDUMP_BIN):
        vc.build_pcode_dumper()
    text = vc.run_tool(vc.PCDUMP_BIN, SLA, hx)
    if "NODECODE" in text or "PCODE-ERROR" in text:
        raise RuntimeError(text)
    ops = vc.parse_pcode(text)

    def drive():
        state = dict(regs)
        state["cc"] = cc
        pc = 0
        steps = 0
        while 0 <= pc < len(ops):
            steps += 1
            if steps > 200000:
                raise RuntimeError("p-code did not terminate after %d" % steps)
            name, out, ins = ops[pc]
            vals = [vc.mask_for(v, state) for v in ins]

            def v(i, vals=vals):
                return vals[i][1]

            if name == "CBRANCH":
                if v(1) != 0:
                    pc = pc + vc.branch_offset(ins[0])
                    continue
            elif name == "BRANCH":
                pc = pc + vc.branch_offset(ins[0])
                continue
            elif name == "COPY":
                vc.set_vn(out, v(0), state)
            elif name == "LOAD":
                vc.set_vn(out, mem_read(mem, v(1), vc.vn_size(out)), state)
            elif name == "STORE":
                mem_write(mem, v(1), vc.vn_size(ins[2]), v(2))
            elif name == "INT_ADD":
                vc.set_vn(out, v(0) + v(1), state)
            elif name == "INT_SUB":
                vc.set_vn(out, v(0) - v(1), state)
            elif name == "INT_MULT":
                vc.set_vn(out, v(0) * v(1), state)
            elif name == "INT_DIV":
                if v(1) == 0:
                    raise RuntimeError("division by zero")
                vc.set_vn(out, v(0) // v(1), state)
            elif name == "INT_AND":
                vc.set_vn(out, v(0) & v(1), state)
            elif name == "INT_OR":
                vc.set_vn(out, v(0) | v(1), state)
            elif name == "INT_XOR":
                vc.set_vn(out, v(0) ^ v(1), state)
            elif name == "INT_LEFT":
                vc.set_vn(out, v(0) << v(1), state)
            elif name == "INT_RIGHT":
                vc.set_vn(out, v(0) >> v(1), state)
            elif name == "INT_ZEXT":
                vc.set_vn(out, v(0), state)
            elif name == "INT_SEXT":
                m0, a = vals[0]
                bits = m0.bit_length()
                if a & (1 << (bits - 1)):
                    a -= 1 << bits
                vc.set_vn(out, a, state)
            elif name == "INT_2COMP":
                vc.set_vn(out, (~v(0)) + 1, state)
            elif name == "INT_NEGATE":
                vc.set_vn(out, -v(0), state)
            elif name in ("INT_EQUAL", "INT_NOTEQUAL", "INT_LESS", "INT_SLESS",
                          "INT_LESSEQUAL", "INT_SLESSEQUAL"):
                a, b = v(0), v(1)
                if "S" in name.split("_", 1)[1]:
                    sa = sb = None
                    for val, msk in ((a, vals[0][0]), (b, vals[1][0])):
                        bits = msk.bit_length()
                        if val & (1 << (bits - 1)):
                            val -= 1 << bits
                        if sa is None:
                            sa = val
                        else:
                            sb = val
                    a, b = sa, sb
                rel = {
                    "INT_EQUAL": a == b, "INT_NOTEQUAL": a != b,
                    "INT_LESS": a < b, "INT_SLESS": a < b,
                    "INT_LESSEQUAL": a <= b, "INT_SLESSEQUAL": a <= b,
                }[name]
                vc.set_vn(out, 1 if rel else 0, state)
            elif name in ("BOOL_AND", "BOOL_OR", "BOOL_XOR"):
                rel = {
                    "BOOL_AND": (v(0) and v(1)),
                    "BOOL_OR": (v(0) or v(1)),
                    "BOOL_XOR": ((v(0) != 0) ^ (v(1) != 0)),
                }[name]
                vc.set_vn(out, 1 if rel else 0, state)
            elif name == "BOOL_NEGATE":
                vc.set_vn(out, 0 if v(0) else 1, state)
            elif name == "CALLOTHER":
                if out is not None:
                    vc.set_vn(out, 0, state)
            else:
                raise RuntimeError("unsupported op %s" % name)
            pc += 1
        return state

    return drive()


def mem_read(mem, addr, size):
    val = 0
    for k in range(size):
        val = (val << 8) | (mem.get(addr + k, 0) & 0xFF)
    return val


def mem_write(mem, addr, size, val):
    for k in range(size - 1, -1, -1):
        mem[addr + k] = val & 0xFF
        val >>= 8


def main():
    failures = []

    def check(name, cond, detail):
        if cond:
            print("PASS %s" % name)
        else:
            print("FAIL %s: %s" % (name, detail))
            failures.append(name)

    # PACK 0(3,r1),0(5,r2): zoned +12345 -> packed 12345C
    mem = {}
    for i, b in enumerate(bytes.fromhex("f1f2f3f4c5")):
        mem[0x3000 + i] = b
    st = run_op("f22410002000", {"r1": 0x2000, "r2": 0x3000, "zero": 0}, mem)
    got = mem_bytes(mem, 0x2000, 3)
    check("pack +12345", got == bytes.fromhex("12345c"), got.hex())

    # UNPK 0(5,r1),0(3,r2): packed 12345C -> zoned F1F2F3F4C5
    mem = {}
    for i, b in enumerate(bytes.fromhex("12345c")):
        mem[0x3000 + i] = b
    st = run_op("f34210002000", {"r1": 0x2000, "r2": 0x3000, "zero": 0}, mem)
    got = mem_bytes(mem, 0x2000, 5)
    check("unpk 12345C", got == bytes.fromhex("f1f2f3f4c5"), got.hex())

    # AP 0(1,r1),0(1,r2): 1C + 1C = 2C, cc = 2 (positive nonzero)
    mem = {0x2000: 0x1C, 0x3000: 0x1C}
    st = run_op("fa0010002000", {"r1": 0x2000, "r2": 0x3000, "zero": 0}, mem)
    check("ap 1+1", mem.get(0x2000) == 0x2C and st.get("cc") == 2,
          "byte=%s cc=%s" % (mem.get(0x2000), st.get("cc")))

    # CP 0(1,r1),0(1,r2): 2C ? 1C -> cc = 2 (first operand high)
    mem = {0x2000: 0x2C, 0x3000: 0x1C}
    st = run_op("f90010002000", {"r1": 0x2000, "r2": 0x3000, "zero": 0}, mem)
    check("cp 2>1", st.get("cc") == 2 and mem.get(0x2000) == 0x2C,
          "cc=%s stored=%s" % (st.get("cc"), mem.get(0x2000)))

    # CP equal positives, and a negative versus positive (1D < 1C) -> cc = 1.
    # Opposite signs on zeros still compare equal. 100C vs 010C is a
    # multi-digit order check (100 > 10).
    mem = {0x2000: 0x1C, 0x3000: 0x1C}
    st = run_op("f90010002000", {"r1": 0x2000, "r2": 0x3000, "zero": 0}, mem)
    check("cp equal", st.get("cc") == 0, "cc=%s" % st.get("cc"))
    mem = {0x2000: 0x1D, 0x3000: 0x1C}
    st = run_op("f90010002000", {"r1": 0x2000, "r2": 0x3000, "zero": 0}, mem)
    check("cp neg<pos", st.get("cc") == 1, "cc=%s" % st.get("cc"))
    mem = {0x2000: 0x0C, 0x3000: 0x0D}
    st = run_op("f90010002000", {"r1": 0x2000, "r2": 0x3000, "zero": 0}, mem)
    check("cp zero signs", st.get("cc") == 0, "cc=%s" % st.get("cc"))
    # CP 0(2,r1),0(2,r2): L1=L2=1. 10 0C ? 01 0C.
    mem = {0x2000: 0x10, 0x2001: 0x0C, 0x3000: 0x01, 0x3001: 0x0C}
    st = run_op("f91110002000", {"r1": 0x2000, "r2": 0x3000, "zero": 0}, mem)
    check("cp 100>10", st.get("cc") == 2, "cc=%s" % st.get("cc"))
    # AP 0(2,r1),0(1,r2): 01 2C + 1C = 01 3C.
    mem = {0x2000: 0x01, 0x2001: 0x2C, 0x3000: 0x1C}
    st = run_op("fa1010002000", {"r1": 0x2000, "r2": 0x3000, "zero": 0}, mem)
    got = mem_bytes(mem, 0x2000, 2)
    check("ap 12+1", got == bytes.fromhex("013c") and st.get("cc") == 2,
          "bytes=%s cc=%s" % (got.hex(), st.get("cc")))

    if failures:
        print("%d failed" % len(failures))
        return 1
    print("decimal checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
