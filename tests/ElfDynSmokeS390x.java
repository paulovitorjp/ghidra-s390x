// ElfDynSmokeS390x.java -- Ghidra Java postScript: validate S390_ElfRelocationHandler
// against the handcrafted ET_DYN s390x binary (tests/elf_dyn_smoke.elf).
// The ELF is linked at vaddr 0, so load bias B = loaded(func) - 0x1000.
// Every expectation is derived from actual loaded addresses (robust to any
// image base Ghidra chooses for the ET_DYN). Output: tests/elf_dyn_smoke_test.txt
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.listing.BookmarkType;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class ElfDynSmokeS390x extends GhidraScript {

    private static final String OUTDIR = "/home/hatch/workspace/zarch-sleigh/tests/";
    private StringBuilder sb = new StringBuilder();
    private int failures = 0;

    private void log(String s) {
        sb.append(s).append("\n");
        println(s);
    }

    private void check(String name, long got, long want) {
        boolean ok = (got == want);
        if (!ok) failures++;
        log(String.format("%s %-22s got=0x%x want=0x%x", ok ? "PASS" : "FAIL", name, got, want));
    }

    private long symaddr(String name) throws Exception {
        SymbolIterator it = currentProgram.getSymbolTable().getSymbols(name);
        if (!it.hasNext()) throw new Exception("missing symbol " + name);
        return it.next().getAddress().getOffset();
    }

    // _GLOBAL_OFFSET_TABLE_ created by the handler's synthesized-GOT path lives
    // in the default address space; the UNDEF dynsym entry may also have left
    // an EXTERNAL-space symbol with the same name.
    private long gotBase() throws Exception {
        ghidra.program.model.address.AddressSpace defSpace =
            currentProgram.getAddressFactory().getDefaultAddressSpace();
        SymbolIterator it = currentProgram.getSymbolTable().getSymbols("_GLOBAL_OFFSET_TABLE_");
        while (it.hasNext()) {
            Symbol s = it.next();
            if (s.getAddress().getAddressSpace().equals(defSpace)) {
                return s.getAddress().getOffset();
            }
        }
        throw new Exception("no default-space _GLOBAL_OFFSET_TABLE_");
    }

    @Override
    public void run() throws Exception {
        try {
            Memory mem = currentProgram.getMemory();
            log("program: " + currentProgram.getName());
            log("language: " + currentProgram.getLanguage().getLanguageID());
            log("image base: " + currentProgram.getImageBase());

            long func = symaddr("func");
            long target2 = symaddr("target2");
            long dAbs64 = symaddr("d_abs64");
            long dTarget = dAbs64 + 8;
            long bias = func - 0x1000L;
            long got = gotBase();
            log(String.format("func=0x%x target2=0x%x dAbs64=0x%x bias=0x%x got=0x%x",
                func, target2, dAbs64, bias, got));

            // GOT entries are allocated in first-use order:
            // d_abs64->got+0, d_target->got+8, func->got+16, target2->got+24
            long gAbs64 = 0, gTarget = 8, gFunc = 16, gT2 = 24;

            // ---- original vectors (unchanged) ----
            // R_390_64 d_abs64 = S(d_target) + 0
            check("R_390_64", mem.getLong(toAddr(0x2000 + bias)), (0x2008 + bias));
            // R_390_RELATIVE d_rel = B + 0x500
            check("R_390_RELATIVE", mem.getLong(toAddr(0x2010 + bias)), bias + 0x500);
            // R_390_GLOB_DAT d_gd = S(func) + 16
            check("R_390_GLOB_DAT", mem.getLong(toAddr(0x2018 + bias)), func + 16);
            // R_390_PC32 d_pc32 = S(target2) - P
            check("R_390_PC32", mem.getInt(toAddr(0x2020 + bias)) & 0xffffffffL,
                (target2 - (0x2020 + bias)) & 0xffffffffL);
            // R_390_32 d_abs32 = S(d_abs64) + 4
            check("R_390_32", mem.getInt(toAddr(0x2024 + bias)) & 0xffffffffL,
                (dAbs64 + 4) & 0xffffffffL);
            // R_390_16 d_abs16 = S(func) + 2
            check("R_390_16", mem.getShort(toAddr(0x2028 + bias)) & 0xffff, (func + 2) & 0xffff);
            // R_390_8 d_abs8 = S(func) + 3
            check("R_390_8", mem.getByte(toAddr(0x202a + bias)) & 0xff, (func + 3) & 0xff);
            // R_390_PC16 d_pc16 = S(func) - P
            check("R_390_PC16", mem.getShort(toAddr(0x202b + bias)) & 0xffff,
                (func - (0x202b + bias)) & 0xffff);
            // R_390_TLS_TPOFF d_tls: warned+skipped, must be untouched
            check("R_390_TLS_TPOFF_skip", mem.getLong(toAddr(0x2030 + bias)), 0L);
            // R_390_PC32DBL on brasl field: ((S(target2) + 2 - P) >> 1), P = field addr
            long p = 0x1002 + bias;
            check("R_390_PC32DBL", mem.getInt(toAddr(p)) & 0xffffffffL,
                ((target2 + 2 - p) >> 1) & 0xffffffffL);

            // ---- extended absolute / PC-relative vectors ----
            // R_390_12: 12-bit field, top nibble preserved (preset 0xA000)
            check("R_390_12", mem.getShort(toAddr(0x2040 + bias)) & 0xffff,
                (0xA000 | (target2 & 0xfff)) & 0xffff);
            // R_390_20: 20-bit field, top 12 bits preserved (preset 0xABC00000)
            check("R_390_20", mem.getInt(toAddr(0x2042 + bias)) & 0xffffffffL,
                (0xABC00000L | ((func + 0x12345) & 0xfffff)) & 0xffffffffL);
            // R_390_PC16DBL: ((S + A - P) >> 1), 16-bit
            p = 0x2046 + bias;
            int d16 = (int) (target2 + 2 - p);
            check("R_390_PC16DBL", mem.getShort(toAddr(p)) & 0xffff,
                ((short) (((short) d16) >> 1)) & 0xffff);
            // R_390_PC12DBL: low 12 of ((S + A - P) >> 1), top nibble preserved
            p = 0x2048 + bias;
            d16 = (int) (target2 + 2 - p);
            check("R_390_PC12DBL", mem.getShort(toAddr(p)) & 0xffff,
                (0xB000 | ((d16 >> 1) & 0xfff)) & 0xffff);
            // R_390_PC24DBL: low 24 of ((S + A - P) >> 1), top byte preserved
            p = 0x204a + bias;
            d16 = (int) (target2 + 2 - p);
            check("R_390_PC24DBL", mem.getInt(toAddr(p)) & 0xffffffffL,
                (0xCD000000L | ((d16 >> 1) & 0xffffff)) & 0xffffffffL);
            // R_390_PC64: S + A - P, 64-bit
            p = 0x204e + bias;
            check("R_390_PC64", mem.getLong(toAddr(p)), func - p);

            // ---- GOT-relative vectors (G = entry - GOT) ----
            // R_390_GOT12: preset nibble 0xD000, G(d_abs64) = 0
            check("R_390_GOT12", mem.getShort(toAddr(0x2056 + bias)) & 0xffff,
                (0xD000 | ((gAbs64) & 0xfff)) & 0xffff);
            // R_390_GOT16: G(d_target) = 8
            check("R_390_GOT16", mem.getShort(toAddr(0x2058 + bias)) & 0xffff, gTarget & 0xffff);
            // R_390_GOT20: preset 0xE1200000, G(func) = 16
            check("R_390_GOT20", mem.getInt(toAddr(0x205a + bias)) & 0xffffffffL,
                (0xE1200000L | (gFunc & 0xfffff)) & 0xffffffffL);
            // R_390_GOT32: G(target2) + 4 = 28
            check("R_390_GOT32", mem.getInt(toAddr(0x205e + bias)) & 0xffffffffL,
                (gT2 + 4) & 0xffffffffL);
            // R_390_GOT64: G(d_abs64) + 8 = 8
            check("R_390_GOT64", mem.getLong(toAddr(0x2062 + bias)), gAbs64 + 8);
            // R_390_GOTPLT12: preset 0xF000, G(d_abs64) = 0
            check("R_390_GOTPLT12", mem.getShort(toAddr(0x206a + bias)) & 0xffff, 0xF000);
            // R_390_GOTPLT16: G(d_target) = 8
            check("R_390_GOTPLT16", mem.getShort(toAddr(0x206c + bias)) & 0xffff,
                gTarget & 0xffff);
            // R_390_GOTPLT20: preset 0xE2200000, G(func) = 16
            check("R_390_GOTPLT20", mem.getInt(toAddr(0x206e + bias)) & 0xffffffffL,
                (0xE2200000L | (gFunc & 0xfffff)) & 0xffffffffL);
            // R_390_GOTPLT32: G(target2) = 24
            check("R_390_GOTPLT32", mem.getInt(toAddr(0x2072 + bias)) & 0xffffffffL,
                gT2 & 0xffffffffL);
            // R_390_GOTPLT64: G(d_abs64) = 0
            check("R_390_GOTPLT64", mem.getLong(toAddr(0x2076 + bias)), gAbs64);
            // R_390_GOTENT: ((G(func) + 2 - P) >> 1)
            p = 0x207e + bias;
            int de = (int) (gFunc + 2 - p);
            check("R_390_GOTENT", mem.getInt(toAddr(p)) & 0xffffffffL,
                (de >> 1) & 0xffffffffL);
            // R_390_GOTPLTENT: ((G(target2) + 2 - P) >> 1)
            p = 0x2082 + bias;
            de = (int) (gT2 + 2 - p);
            check("R_390_GOTPLTENT", mem.getInt(toAddr(p)) & 0xffffffffL,
                (de >> 1) & 0xffffffffL);

            // ---- GOT-base vectors ----
            // R_390_GOTPC: GOT + A - P
            p = 0x2086 + bias;
            check("R_390_GOTPC", mem.getInt(toAddr(p)) & 0xffffffffL,
                ((int) (got - p)) & 0xffffffffL);
            // R_390_GOTPCDBL: ((GOT + A - P) >> 1)
            p = 0x208a + bias;
            de = (int) (got + 2 - p);
            check("R_390_GOTPCDBL", mem.getInt(toAddr(p)) & 0xffffffffL,
                (de >> 1) & 0xffffffffL);
            // R_390_GOTOFF16: S(d_target) - GOT, 16-bit
            check("R_390_GOTOFF16", mem.getShort(toAddr(0x208e + bias)) & 0xffff,
                ((short) (dTarget - got)) & 0xffff);
            // R_390_GOTOFF32: S(d_target) - GOT
            check("R_390_GOTOFF32", mem.getInt(toAddr(0x2090 + bias)) & 0xffffffffL,
                ((int) (dTarget - got)) & 0xffffffffL);
            // R_390_GOTOFF64: S(func) - GOT
            check("R_390_GOTOFF64", mem.getLong(toAddr(0x2094 + bias)), func - got);

            // ---- PLT-relative vectors (L = defined symbol address) ----
            // R_390_PLT16DBL: ((L(target2) + 2 - P) >> 1)
            p = 0x209c + bias;
            d16 = (int) (target2 + 2 - p);
            check("R_390_PLT16DBL", mem.getShort(toAddr(p)) & 0xffff,
                ((short) (d16 >> 1)) & 0xffff);
            // R_390_PLT12DBL: preset 0xC000
            p = 0x209e + bias;
            d16 = (int) (target2 + 2 - p);
            check("R_390_PLT12DBL", mem.getShort(toAddr(p)) & 0xffff,
                (0xC000 | ((d16 >> 1) & 0xfff)) & 0xffff);
            // R_390_PLT32DBL: ((L(func) + 2 - P) >> 1)
            p = 0x20a0 + bias;
            d16 = (int) (func + 2 - p);
            check("R_390_PLT32DBL", mem.getInt(toAddr(p)) & 0xffffffffL,
                (d16 >> 1) & 0xffffffffL);
            // R_390_PLT24DBL: preset 0xDD000000
            p = 0x20a4 + bias;
            d16 = (int) (func + 2 - p);
            check("R_390_PLT24DBL", mem.getInt(toAddr(p)) & 0xffffffffL,
                (0xDD000000L | ((d16 >> 1) & 0xffffff)) & 0xffffffffL);
            // R_390_PLT32: L(target2) - P
            p = 0x20a8 + bias;
            check("R_390_PLT32", mem.getInt(toAddr(p)) & 0xffffffffL,
                ((int) (target2 - p)) & 0xffffffffL);
            // R_390_PLT64: L(func) - P
            p = 0x20ac + bias;
            check("R_390_PLT64", mem.getLong(toAddr(p)), func - p);
            // R_390_PLTOFF16: L(target2) - GOT, 16-bit
            check("R_390_PLTOFF16", mem.getShort(toAddr(0x20b4 + bias)) & 0xffff,
                ((short) (target2 - got)) & 0xffff);
            // R_390_PLTOFF32: L(target2) - GOT
            check("R_390_PLTOFF32", mem.getInt(toAddr(0x20b6 + bias)) & 0xffffffffL,
                ((int) (target2 - got)) & 0xffffffffL);
            // R_390_PLTOFF64: L(func) - GOT
            check("R_390_PLTOFF64", mem.getLong(toAddr(0x20ba + bias)), func - got);

            // ---- dynamic-linking edge cases ----
            // R_390_IRELATIVE: warned, but B + A recorded (resolver not invoked)
            check("R_390_IRELATIVE", mem.getLong(toAddr(0x20c2 + bias)), bias + 0x1008);
            // R_390_COPY: warned+skipped, memory untouched
            check("R_390_COPY_skip", mem.getLong(toAddr(0x20ca + bias)), 0x1122334455667788L);
            // R_390_GNU_VTINHERIT / VTENTRY: no-op skips, memory untouched
            check("R_390_GNU_VTINHERIT_skip", mem.getByte(toAddr(0x20d2 + bias)) & 0xff, 0xAA);
            check("R_390_GNU_VTENTRY_skip", mem.getByte(toAddr(0x20d3 + bias)) & 0xff, 0xBB);

            // synthesized GOT contents: each entry holds its symbol's value
            check("GOT[0]=d_abs64", mem.getLong(toAddr(got)), dAbs64);
            check("GOT[1]=d_target", mem.getLong(toAddr(got + 8)), dTarget);
            check("GOT[2]=func", mem.getLong(toAddr(got + 16)), func);
            check("GOT[3]=target2", mem.getLong(toAddr(got + 24)), target2);

            // disassembly: brasl must decode and flow to target2
            disassemble(toAddr(func));
            Instruction inst = getInstructionAt(toAddr(func));
            if (inst == null || !inst.getMnemonicString().equals("brasl")) {
                failures++;
                log("FAIL brasl decode: " + (inst == null ? "NONE" : inst.toString()));
            } else {
                log("disasm @func: " + inst.toString());
                boolean found = false;
                for (Address f : inst.getFlows()) {
                    log("  flow: " + f);
                    if (f.getOffset() == target2) found = true;
                }
                if (found) {
                    log("PASS brasl target");
                } else {
                    failures++;
                    log("FAIL brasl target");
                }
            }

            // R_390_JMP_SLOT: slot written + thunk linkage created.
            // NOTE: the IMPORTED symbol lives in the EXTERNAL address space
            // (EXTERNAL:00000001), so its default-space address is found via
            // the thunk function the handler created, not via getOffset().
            Function extThunk = null;
            for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
                if (f.getName().equals("extfunc")) {
                    extThunk = f;
                    break;
                }
            }
            if (extThunk == null) {
                failures++;
                log("FAIL extfunc thunk missing");
            } else {
                long extAddr = extThunk.getEntryPoint().getOffset();
                log(String.format("extfunc thunk @ 0x%x isThunk=%b isExternal=%b",
                    extAddr, extThunk.isThunk(), extThunk.isExternal()));
                check("R_390_JMP_SLOT", mem.getLong(toAddr(0x3010 + bias)), extAddr);
                if (extThunk.isThunk()) {
                    log("PASS extfunc linkage");
                } else {
                    failures++;
                    log("FAIL extfunc not a thunk");
                }
            }

            // relocation bookmarks: no ERROR expected.
            // WARNING expected exactly 3x: TLS_TPOFF (not modeled), IRELATIVE
            // (resolver not invoked), COPY (runtime copy unsupported).
            int nerr = currentProgram.getBookmarkManager().getBookmarkCount(BookmarkType.ERROR);
            int nwarn = currentProgram.getBookmarkManager().getBookmarkCount(BookmarkType.WARNING);
            log("bookmarks: ERROR=" + nerr + " WARNING=" + nwarn);
            List<String> warns = new ArrayList<>();
            Iterator<Bookmark> wit =
                currentProgram.getBookmarkManager().getBookmarksIterator(BookmarkType.WARNING);
            while (wit.hasNext()) {
                Bookmark bm = wit.next();
                warns.add(bm.toString());
                log("  warn: " + bm);
            }
            if (nerr != 0) {
                failures++;
                log("FAIL unexpected ERROR bookmarks");
            } else {
                log("PASS no ERROR bookmarks");
            }
            boolean tlsWarn = false, ifuncWarn = false, copyWarn = false;
            for (String w : warns) {
                if (w.contains("TLS relocation not modeled")) tlsWarn = true;
                if (w.contains("IFUNC resolver not invoked")) ifuncWarn = true;
                if (w.contains("Runtime copy not supported")) copyWarn = true;
            }
            if (nwarn == 3 && tlsWarn && ifuncWarn && copyWarn) {
                log("PASS expected WARNING bookmarks (TLS/IRELATIVE/COPY)");
            } else {
                failures++;
                log(String.format(
                    "FAIL warnings: count=%d tls=%b ifunc=%b copy=%b", nwarn,
                    tlsWarn, ifuncWarn, copyWarn));
            }

            log("RESULT: " + (failures == 0 ? "ALL PASS" : "FAILURES") +
                " (" + failures + " failures)");
        } catch (Exception e) {
            log("SCRIPT EXCEPTION: " + e);
            for (StackTraceElement st : e.getStackTrace()) log("  at " + st);
            failures++;
        }
        try (FileWriter w = new FileWriter(OUTDIR + "elf_dyn_smoke_test.txt")) {
            w.write(sb.toString());
        }
        println("elf dyn smoke script done, failures=" + failures);
    }
}
