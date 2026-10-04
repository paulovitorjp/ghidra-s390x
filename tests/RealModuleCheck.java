// RealModuleCheck.java -- headless verification of the z/OS MVS Load Module
// loader against a genuine IFOX00/IEWL-produced load module (PROG1/SUBR/DATAC).
// Run via: analyzeHeadless <projdir> <projname> -import <file>
//   -loader "z/OS MVS Load Module" -postScript RealModuleCheck.java
//   -noanalysis -scriptPath <tests dir>
// The module: PROG1@0 len 0x74, SUBR@0x78 len 0x64, DATAC@0xE0 len 0x10,
// entry 0, RLDs: A(0x70->SUBR) V(0xE0->SUBR) A(0xE4->SUBR). Base defaults 0x10000.
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;

public class RealModuleCheck extends GhidraScript {

    private int failures = 0;
    private static final long BASE = 0x10000L;

    private void check(boolean cond, String what) {
        println((cond ? "PASS " : "FAIL ") + what);
        if (!cond) failures++;
    }

    @Override
    public void run() throws Exception {
        println("== real IFOX00/IEWL module check ==");
        println("program: " + currentProgram.getName());
        println("language: " + currentProgram.getLanguageID().getIdAsString());
        println("compiler: " +
            currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString());

        println("-- memory blocks --");
        for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
            println("  " + b.getName() + " " + b.getStart() + " len=" + b.getSize());
        }
        check(hasBlock("PROG1", BASE + 0x00, 0x74), "block PROG1 @0x10000 len 0x74");
        check(hasBlock("SUBR", BASE + 0x78, 0x64), "block SUBR @0x10078 len 0x64");
        check(hasBlock("DATAC", BASE + 0xE0, 0x10), "block DATAC @0x100e0 len 0x10");

        println("-- imported symbols --");
        SymbolTable st = currentProgram.getSymbolTable();
        SymbolIterator it = st.getAllSymbols(false);
        while (it.hasNext()) {
            Symbol s = it.next();
            if (s.getSource() == SourceType.IMPORTED) {
                println("  " + s.getName() + " @ " + s.getAddress());
            }
        }

        // relocation checks: all three adcons must point at SUBR (base+0x78)
        long a1 = readU32(BASE + 0x70);
        long a2 = readU32(BASE + 0xE0);
        long a3 = readU32(BASE + 0xE4);
        println("adcon @0x10070 (A PROG1->SUBR) = 0x" + Long.toHexString(a1));
        println("adcon @0x100e0 (V DATAC->SUBR) = 0x" + Long.toHexString(a2));
        println("adcon @0x100e4 (A DATAC->SUBR) = 0x" + Long.toHexString(a3));
        check(a1 == BASE + 0x78, "A-type adcon in PROG1 relocated to SUBR");
        check(a2 == BASE + 0x78, "V-type adcon in DATAC relocated to SUBR");
        check(a3 == BASE + 0x78, "A-type adcon in DATAC relocated to SUBR");

        // entry point
        Address entry = null;
        AddressIterator eit = st.getExternalEntryPointIterator();
        if (eit.hasNext()) entry = eit.next();
        println("entry point: " + entry);
        check(entry != null && entry.getOffset() == BASE, "entry point at 0x10000");

        // disassemble all three blocks
        ghidra.program.disassemble.Disassembler dis =
            ghidra.program.disassemble.Disassembler.getDisassembler(
                currentProgram, monitor, null);
        for (String bn : new String[]{"PROG1", "SUBR"}) {
            MemoryBlock b = currentProgram.getMemory().getBlock(bn);
            dis.disassemble(b.getStart(),
                new ghidra.program.model.address.AddressSet(b.getStart(), b.getEnd()),
                true);
            println("-- disassembly of " + bn + " --");
            ghidra.program.model.listing.InstructionIterator insns =
                currentProgram.getListing().getInstructions(b.getStart(), true);
            int n = 0;
            while (insns.hasNext() && n++ < 24) {
                ghidra.program.model.listing.Instruction ix = insns.next();
                if (ix.getAddress().compareTo(b.getEnd()) > 0) break;
                println("  " + ix.getAddress() + ": " + ix);
            }
        }

        // decompile entry (PROG1) and SUBR
        Function f = getFunctionAt(entry);
        if (f == null) f = createFunction(entry, "PROG1_entry");
        check(f != null, "function at entry");
        Address subrAddr = currentProgram.getAddressFactory().getDefaultAddressSpace()
            .getAddress(BASE + 0x78);
        Function fs = getFunctionAt(subrAddr);
        if (fs == null) fs = createFunction(subrAddr, "SUBR");
        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        DecompileResults res = di.decompileFunction(f, 120, monitor);
        println("entry decompile ok=" + res.decompileCompleted());
        String c = res.getDecompiledFunction().getC();
        println("-- decompiled PROG1 --");
        println(c);
        check(res.decompileCompleted(), "entry decompiles");
        DecompileResults rs = di.decompileFunction(fs, 120, monitor);
        String cs = rs.getDecompiledFunction().getC();
        println("-- decompiled SUBR --");
        println(cs);
        // The z/OS cspec save-area dance defeats constant propagation for r2,
        // so assert on the disassembly (LA r2,0x2a) rather than the decompiler.
        boolean hasLa42 = false;
        ghidra.program.model.listing.InstructionIterator si =
            currentProgram.getListing().getInstructions(subrAddr, true);
        while (si.hasNext()) {
            String s = si.next().toString();
            if (s.contains("0x2a")) { hasLa42 = true; break; }
        }
        check(hasLa42, "SUBR contains LA r2,0x2a (returns 42)");

        println(failures == 0 ? "ALL CHECKS PASSED" : failures + " CHECKS FAILED");
        if (failures > 0) throw new RuntimeException(failures + " real-module checks failed");
    }

    private boolean hasBlock(String name, long start, long len) {
        MemoryBlock b = currentProgram.getMemory().getBlock(name);
        return b != null && b.getStart().getOffset() == start && b.getSize() == len;
    }

    private long readU32(long off) throws Exception {
        Address a = currentProgram.getAddressFactory().getDefaultAddressSpace()
            .getAddress(off);
        byte[] b = new byte[4];
        currentProgram.getMemory().getBytes(a, b);
        return ((b[0] & 0xffL) << 24) | ((b[1] & 0xffL) << 16) |
               ((b[2] & 0xffL) << 8) | (b[3] & 0xffL);
    }
}
