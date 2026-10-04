# elf_smoke_test.py -- Ghidra Jython postScript: validate stock ELF loader + s390x module.
# Run via: analyzeHeadless <projdir> loader_test -import tests/elf_smoke.elf \
#   -postScript elf_smoke_test.py -scriptPath tests
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
    log("compiler: %s" % prog.getCompilerSpec().getCompilerSpecID())
    log("image base: %s" % prog.getImageBase())
    log("min/max: %s .. %s" % (prog.getMinAddress(), prog.getMaxAddress()))

    flat = FlatProgramAPI(prog, monitor)
    listing = prog.getListing()
    symtab = prog.getSymbolTable()

    # entry point
    entry = None
    for sym in symtab.getSymbols("entry"):
        entry = sym.getAddress()
    log("entry symbol(s): %s" % [str(s.getAddress()) for s in symtab.getSymbols("entry")])

    # our function symbols
    for name in ("_start", "main", "sum"):
        syms = symtab.getSymbols(name)
        addrs = [str(s.getAddress()) for s in syms]
        log("symbol %-8s -> %s" % (name, addrs if addrs else "MISSING"))

    # disassemble everything in .text-ish range from entry
    addr = toAddr(0x10078)
    hi = prog.getMaxAddress()
    guard = 0
    while addr is not None and addr.compareTo(hi) <= 0 and guard < 64:
        guard += 1
        flat.disassemble(addr)
        inst = listing.getInstructionAt(addr)
        if inst is None:
            log("NO DECODE at %s" % addr)
            addr = addr.add(1)
            continue
        addr = addr.add(inst.getLength())

    log("=== DISASSEMBLY ===")
    inst = listing.getInstructionAt(toAddr(0x10078))
    count = 0
    while inst is not None and count < 64:
        count += 1
        log("%s  %-30s" % (inst.getAddress(), inst.toString()))
        inst = inst.getNext()
    log("instruction count: %d" % count)

    # functions known?
    fm = prog.getFunctionManager()
    log("=== FUNCTIONS ===")
    for f in fm.getFunctions(True):
        log("fn %-10s @ %s" % (f.getName(), f.getEntryPoint()))

    # decompile main
    log("=== DECOMPILE main ===")
    f_main = fm.getFunctionAt(toAddr(0x10080))
    if f_main is None:
        # fall back: create it
        f_main = flat.createFunction(toAddr(0x10080), "main")
        log("created main manually")
    decomp = DecompInterface()
    decomp.openProgram(prog)
    res = decomp.decompileFunction(f_main, 120, monitor)
    if res is not None and res.decompileCompleted():
        c = res.getDecompiledFunction().getC()
        log(c)
        open(OUTDIR + "elf_smoke_decompile.c", "w").write(c)
        log("decompile: OK")
    else:
        msg = res.getErrorMessage() if res is not None else "null result"
        log("decompile FAILED: %s" % msg)
    decomp.dispose()

    # also decompile sum
    log("=== DECOMPILE sum ===")
    f_sum = fm.getFunctionAt(toAddr(0x100b6))
    if f_sum is None:
        f_sum = flat.createFunction(toAddr(0x100b6), "sum")
    decomp2 = DecompInterface()
    decomp2.openProgram(prog)
    res2 = decomp2.decompileFunction(f_sum, 120, monitor)
    if res2 is not None and res2.decompileCompleted():
        log(res2.getDecompiledFunction().getC())
        log("decompile sum: OK")
    else:
        log("decompile sum FAILED: %s" % (res2.getErrorMessage() if res2 else "null"))
    decomp2.dispose()
except Exception as e:
    import traceback
    log("SCRIPT EXCEPTION: %s" % e)
    log(traceback.format_exc())

open(OUTDIR + "elf_smoke_test.txt", "w").write("\n".join(lines) + "\n")
print("elf smoke script done")
