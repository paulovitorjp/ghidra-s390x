// ElfSmokeS390x.java — Ghidra Java postScript validating the stock ELF loader
// against an EM_S390 test binary. Reports language selection, entry point,
// symbols, functions, disassembly, and decompiles main() and sum().
// Output: tests/elf_smoke_test.txt, tests/elf_smoke_decompile.c
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.util.task.TaskMonitor;
import java.io.FileWriter;

public class ElfSmokeS390x extends GhidraScript {

    private static final String OUTDIR = "/home/hatch/workspace/zarch-sleigh/tests/";

    @Override
    public void run() throws Exception {
        StringBuilder sb = new StringBuilder();
        sb.append("program: ").append(currentProgram.getName()).append("\n");
        sb.append("language: ").append(currentProgram.getLanguage().getLanguageID()).append("\n");
        sb.append("compiler: ").append(currentProgram.getCompilerSpec().getCompilerSpecID()).append("\n");
        sb.append("image base: ").append(currentProgram.getImageBase()).append("\n");
        Address lo = currentProgram.getMinAddress();
        Address hi = currentProgram.getMaxAddress();
        sb.append("range: ").append(lo).append(" .. ").append(hi).append("\n");

        // entry point symbol
        sb.append("entry symbols: ");
        SymbolIterator entries = currentProgram.getSymbolTable().getSymbols("entry");
        while (entries.hasNext()) {
            sb.append(entries.next().getAddress()).append(" ");
        }
        sb.append("\n");

        // our function symbols from .symtab
        for (String name : new String[] { "_start", "main", "sum" }) {
            SymbolIterator it = currentProgram.getSymbolTable().getSymbols(name);
            sb.append("symbol ").append(name).append(" -> ");
            if (!it.hasNext()) {
                sb.append("MISSING");
            }
            while (it.hasNext()) {
                Symbol s = it.next();
                sb.append(s.getAddress()).append(" ");
            }
            sb.append("\n");
        }

        // disassemble from entry across the .text range
        Address addr = toAddr(0x10078L);
        int guard = 0;
        while (addr.compareTo(hi) <= 0 && guard++ < 64) {
            disassemble(addr);
            Instruction inst = getInstructionAt(addr);
            if (inst == null) {
                sb.append("NO DECODE at ").append(addr).append("\n");
                addr = addr.add(1);
                continue;
            }
            addr = addr.add(inst.getLength());
        }

        sb.append("=== DISASSEMBLY ===\n");
        Instruction inst = getInstructionAt(toAddr(0x10078L));
        int count = 0;
        while (inst != null && count < 64) {
            count++;
            sb.append(inst.getAddress()).append("  ")
              .append(inst.getMnemonicString()).append("  ")
              .append(inst.toString()).append("\n");
            inst = inst.getNext();
        }
        sb.append("instruction count: ").append(count).append("\n");

        sb.append("=== FUNCTIONS ===\n");
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            sb.append("fn ").append(f.getName()).append(" @ ").append(f.getEntryPoint()).append("\n");
        }

        // decompile main @ 0x10080 and sum @ 0x100b6
        // Both are saved to elf_smoke_decompile.c (main first, then sum appended).
        decompileAt(sb, 0x10080L, "main", "elf_smoke_decompile.c", false);
        decompileAt(sb, 0x100b6L, "sum", "elf_smoke_decompile.c", true);

        try (FileWriter w = new FileWriter(OUTDIR + "elf_smoke_test.txt")) {
            w.write(sb.toString());
        }
    }

    private void decompileAt(StringBuilder sb, long off, String label, String saveFile,
            boolean append)
            throws Exception {
        Address a = toAddr(off);
        Function f = getFunctionAt(a);
        if (f == null) {
            f = createFunction(a, label);
            sb.append("(created function ").append(label).append(" manually)\n");
        }
        sb.append("=== DECOMPILE ").append(f.getName()).append(" ===\n");
        DecompInterface decomp = new DecompInterface();
        if (!decomp.openProgram(currentProgram)) {
            sb.append("openProgram FAILED\n");
            return;
        }
        DecompileResults res = decomp.decompileFunction(f, 120, TaskMonitor.DUMMY);
        if (res.decompileCompleted()) {
            String cCode = res.getDecompiledFunction().getC();
            sb.append(cCode).append("\ndecompile ").append(label).append(": OK\n");
            if (saveFile != null) {
                try (FileWriter w = new FileWriter(OUTDIR + saveFile, append)) {
                    w.write(cCode);
                    w.write("\n");
                }
            }
        } else {
            sb.append("decompile ").append(label).append(" FAILED: errmsg='")
              .append(res.getErrorMessage()).append("'\n");
        }
        decomp.dispose();
    }
}
