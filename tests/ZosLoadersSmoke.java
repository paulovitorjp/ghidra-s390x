// ZosLoadersSmoke.java -- headless validation for the z/OS loaders.
// Run via: analyzeHeadless <projdir> <projname> -import <file>
//   -loader "<loader name>" -postScript ZosLoadersSmoke.java <lmod|goff>
//   -noanalysis -scriptPath <tests dir>
// Prints blocks, symbols, entry, adcon values, disassembly and the
// decompiled entry function (which must use the "zos" compiler spec).
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;

import java.io.PrintWriter;

public class ZosLoadersSmoke extends GhidraScript {

    private int failures = 0;

    private void check(boolean cond, String what) {
        println((cond ? "PASS " : "FAIL ") + what);
        if (!cond) failures++;
    }

    private String hex(long v) {
        return "0x" + Long.toHexString(v);
    }

    @Override
    public void run() throws Exception {
        String mode = getScriptArgs().length > 0 ? getScriptArgs()[0] : "lmod";
        println("== z/OS loader smoke test: mode=" + mode + " ==");
        println("program: " + currentProgram.getName());
        println("language: " + currentProgram.getLanguageID().getIdAsString());
        String cspec = currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString();
        println("compiler: " + cspec);
        check(cspec.equals("zos"), "compiler spec is zos (z/OS LE ABI)");

        println("-- memory blocks --");
        int blockCount = 0;
        for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
            println("  " + b.getName() + " " + b.getStart() + " len=" + b.getSize());
            blockCount++;
        }
        // The synthetic lmod also carries SYM (X'40') and scatter/translation
        // (X'10') records, which the loader must skip via their count fields.
        // Exactly 3 blocks (MAIN, DATA, EXTERNAL) proves the record scan
        // stayed aligned through them; a mis-skip would throw or misalign.
        // Mode "pds" uses the same member bytes behind a ZOSPDS21 raw-PDS-
        // directory-entry header, so the same checks apply.
        if (mode.equals("lmod") || mode.equals("pds")) {
            check(blockCount == 3, "exactly 3 blocks (SYM/scatter records skipped)");
        }

        println("-- symbols --");
        SymbolTable st = currentProgram.getSymbolTable();
        SymbolIterator it = st.getAllSymbols(false);
        while (it.hasNext()) {
            Symbol s = it.next();
            if (s.getSource() == SourceType.IMPORTED) {
                println("  " + s.getName() + " @ " +
                    (s.getAddress() == Address.NO_ADDRESS ? "EXTERNAL" : s.getAddress()));
            }
        }

        long base = 0x10000L;
        int subrOff = 28;

        if (mode.equals("lmod") || mode.equals("pds")) {
            check(findBlock("MAIN") != null, "block MAIN exists");
            check(findBlock("DATA") != null, "block DATA exists");
            Symbol subr = findSymbol("SUBR");
            check(subr != null && subr.getAddress().getOffset() == base + subrOff,
                "SUBR label at " + hex(base + subrOff));
            long adcon1 = readU32(base + 40);
            check(adcon1 == base + subrOff, "A-type adcon relocated to " + hex(adcon1));
            long adcon2 = readU32(base + 44);
            check(adcon2 == 0, "Q-type adcon left unresolved (0)");
        } else if (mode.equals("goffcont")) {
            // continued-record GOFF: TXT split 56+44, RLD split 74+10
            // (item 3 straddles the boundary), ESD long name split 8+9
            check(findBlock("C_CODE") != null, "block C_CODE exists");
            Symbol entry = findSymbol("ENTRY");
            check(entry != null && entry.getAddress().getOffset() == base,
                "ENTRY label at " + hex(base));
            Symbol subr = findSymbol("SUBR");
            check(subr != null && subr.getAddress().getOffset() == base + subrOff,
                "SUBR label at " + hex(base + subrOff));
            Symbol longName = findSymbol("VERYLONGENTRYNAME");
            check(longName != null && longName.getAddress().getOffset() == base,
                "continued-ESD long name VERYLONGENTRYNAME at " + hex(base));
            int padByte = readU8(base + 60);
            check(padByte == 0xAA,
                "TXT continuation payload byte at " + hex(base + 60) + " is 0xAA");
            long adcon1 = readU32(base + 92);
            check(adcon1 == base + subrOff,
                "A-type adcon via continued RLD relocated to " + hex(adcon1));
            long adcon2 = readU32(base + 96);
            check(adcon2 == 0, "Q-type adcon left unresolved (0)");
            long splitWord = readU32(base + 40);
            // fetch mode adds to the stored value: 0xAAAAAAAA (pad) + base
            check(splitWord == 0xAAAAAAAAL + base,
                "split RLD item 3 (across boundary) relocated to " + hex(splitWord));
        } else {
            check(findBlock("C_CODE") != null, "block C_CODE exists");
            Symbol entry = findSymbol("ENTRY");
            check(entry != null && entry.getAddress().getOffset() == base,
                "ENTRY label at " + hex(base));
            Symbol subr = findSymbol("SUBR");
            check(subr != null && subr.getAddress().getOffset() == base + subrOff,
                "SUBR label at " + hex(base + subrOff));
            long adcon1 = readU32(base + 34);
            check(adcon1 == base + subrOff, "A-type adcon relocated to " + hex(adcon1));
            long adcon2 = readU32(base + 38);
            check(adcon2 == 0, "Q-type adcon left unresolved (0)");
        }
        boolean foundExt = false;
        ghidra.program.model.symbol.SymbolIterator all =
            currentProgram.getSymbolTable().getAllSymbols(false);
        while (all.hasNext()) {
            if (all.next().getName().equals("EXTFN")) { foundExt = true; break; }
        }
        check(foundExt, "EXTFN external symbol recorded");

        Address entry = null;
        AddressIterator eit = st.getExternalEntryPointIterator();
        if (eit.hasNext()) entry = eit.next();
        println("entry point: " + entry);
        check(entry != null && entry.getOffset() == base, "entry point at " + hex(base));

        // disassemble the code block, then create the entry function
        MemoryBlock codeBlock = (mode.equals("lmod") || mode.equals("pds"))
            ? findBlock("MAIN") : findBlock("C_CODE");
        ghidra.program.disassemble.Disassembler dis =
            ghidra.program.disassemble.Disassembler.getDisassembler(
                currentProgram, monitor, null);
        dis.disassemble(codeBlock.getStart(),
            new ghidra.program.model.address.AddressSet(
                codeBlock.getStart(), codeBlock.getEnd()),
            true);
        println("-- disassembly of code block --");
        ghidra.program.model.listing.InstructionIterator insns =
            currentProgram.getListing().getInstructions(codeBlock.getStart(), true);
        int n = 0;
        while (insns.hasNext() && n++ < 20) {
            ghidra.program.model.listing.Instruction ix = insns.next();
            println("  " + ix.getAddress() + ": " + ix);
            if (ix.getAddress().compareTo(codeBlock.getEnd()) > 0) break;
        }
        Function f = getFunctionAt(entry);
        if (f == null) {
            f = createFunction(entry, "entry");
        }
        println("function body: " + (f != null ? f.getBody() : "null"));
        check(f != null, "function at entry (" + (f != null ? f.getName() : "?") + ")");
        Address subrAddr =
            currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(base + 28);
        if (getFunctionAt(subrAddr) == null) {
            createFunction(subrAddr, "subr");
        }
        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        DecompileResults res = di.decompileFunction(f, 120, monitor);
        println("decompile completed=" + res.decompileCompleted() +
            " error=" + res.getErrorMessage());
        String c = res.getDecompiledFunction().getC();
        println("-- decompiled entry --");
        println(c);
        check(c.contains("if"), "decompiled output contains if/else");
        check(c.contains("SUBR") || c.contains("subr") || c.contains("0x1001c"),
            "decompiled output references subr call");

        println("-- decompiled SUBR --");
        Function fs = getFunctionAt(subrAddr);
        DecompileResults rs = di.decompileFunction(fs, 120, monitor);
        println(rs.getDecompiledFunction().getC());
        println("entry body at decompile time: " + f.getBody());
        String outPath = "/home/hatch/workspace/zarch-sleigh/tests/zos_smoke_" +
            mode + "_decompile.c";
        try (PrintWriter pw = new PrintWriter(outPath)) {
            pw.println("/* decompiled with compiler spec: " + cspec + " */");
            pw.println(c);
        }
        println("wrote " + outPath);

        println(failures == 0 ? "ALL CHECKS PASSED" : failures + " CHECKS FAILED");
        if (failures > 0) throw new RuntimeException(failures + " smoke checks failed");
    }

    private MemoryBlock findBlock(String name) {
        return currentProgram.getMemory().getBlock(name);
    }

    private Symbol findSymbol(String name) {
        SymbolIterator it = currentProgram.getSymbolTable().getSymbolIterator(name, true);
        return it.hasNext() ? it.next() : null;
    }

    private long readU32(long off) throws Exception {
        Address a = currentProgram.getAddressFactory().getDefaultAddressSpace()
            .getAddress(off);
        byte[] b = new byte[4];
        currentProgram.getMemory().getBytes(a, b);
        return ((b[0] & 0xffL) << 24) | ((b[1] & 0xffL) << 16) |
               ((b[2] & 0xffL) << 8) | (b[3] & 0xffL);
    }

    private int readU8(long off) throws Exception {
        Address a = currentProgram.getAddressFactory().getDefaultAddressSpace()
            .getAddress(off);
        byte[] b = new byte[1];
        currentProgram.getMemory().getBytes(a, b);
        return b[0] & 0xff;
    }
}
