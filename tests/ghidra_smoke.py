# ghidra_smoke.py — Ghidra Jython postScript for s390x smoke test.
# Run via: analyzeHeadless <projdir> smoke -import ghidra_smoke.bin \
#   -processor s390x:BE:64:default -postScript ghidra_smoke.py -scriptPath tests
from ghidra.app.decompiler import DecompInterface
from ghidra.program.flatapi import FlatProgramAPI
import os

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

OUTDIR = os.path.join(REPO_ROOT, "tests/")
lines = []
def log(s):
    lines.append(s)
    print(s)

try:
    prog = currentProgram
    log("program: %s" % prog.getName())
    log("language: %s" % prog.getLanguage().getLanguageID())
    lo = prog.getMinAddress()
    hi = prog.getMaxAddress()
    log("address range: %s .. %s" % (lo, hi))

    flat = FlatProgramAPI(prog, monitor)
    listing = prog.getListing()

    # disassemble the whole block
    addr = lo
    guard = 0
    while addr is not None and addr.compareTo(hi) <= 0 and guard < 128:
        guard += 1
        flat.disassemble(addr)
        inst = listing.getInstructionAt(addr)
        if inst is None:
            log("NO DECODE at %s" % addr)
            addr = addr.add(1)
            continue
        addr = addr.add(inst.getLength())

    # dump disassembly + pcode
    log("=== DISASSEMBLY ===")
    inst = listing.getInstructionAt(lo)
    count = 0
    while inst is not None and count < 128:
        count += 1
        log("%s  %-28s" % (inst.getAddress(), inst.toString()))
        try:
            for op in inst.getPcode():
                log("    pcode: %s" % op.toString())
        except Exception as e:
            log("    pcode ERROR: %s" % e)
        inst = inst.getNext()
    log("instruction count: %d" % count)

    # functions
    f_main = flat.createFunction(toAddr(0), "main")
    f_sum = flat.createFunction(toAddr(0xc), "sum_fn")
    log("created functions: %s @ %s, %s @ %s" % (
        f_main.getName(), f_main.getEntryPoint(),
        f_sum.getName(), f_sum.getEntryPoint()))

    # decompile sum_fn
    log("=== DECOMPILE sum_fn ===")
    decomp = DecompInterface()
    decomp.openProgram(prog)
    res = decomp.decompileFunction(f_sum, 120, monitor)
    if res is not None and res.decompileCompleted():
        c = res.getDecompiledFunction().getC()
        log(c)
        open(OUTDIR + "ghidra_smoke_decompile.c", "w").write(c)
        log("decompile: OK")
    else:
        msg = res.getErrorMessage() if res is not None else "null result"
        log("decompile FAILED: %s" % msg)
    decomp.dispose()
except Exception as e:
    import traceback
    log("SCRIPT EXCEPTION: %s" % e)
    log(traceback.format_exc())

open(OUTDIR + "ghidra_smoke_disasm.txt", "w").write("\n".join(lines) + "\n")
print("smoke script done")
