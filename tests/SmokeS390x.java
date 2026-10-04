// SmokeS390x.java — Ghidra Java postScript for the s390x smoke test.
// Imports a raw binary, disassembles it, dumps p-code, creates functions,
// and runs the decompiler. Output goes to tests/ghidra_smoke_disasm.txt
// and tests/ghidra_smoke_decompile.c.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.task.TaskMonitor;
import java.io.FileWriter;

public class SmokeS390x extends GhidraScript {

    private static final String OUTDIR = "/home/hatch/workspace/zarch-sleigh/tests/";

    @Override
    public void run() throws Exception {
        StringBuilder sb = new StringBuilder();
        sb.append("program: ").append(currentProgram.getName()).append("\n");
        sb.append("language: ").append(currentProgram.getLanguage().getLanguageID()).append("\n");
        Address lo = currentProgram.getMinAddress();
        Address hi = currentProgram.getMaxAddress();
        sb.append("range: ").append(lo).append(" .. ").append(hi).append("\n");

        // Disassemble the whole image.
        Address addr = lo;
        int guard = 0;
        while (addr.compareTo(hi) <= 0 && guard++ < 256) {
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
        Instruction inst = getInstructionAt(lo);
        int count = 0;
        while (inst != null && count < 256) {
            count++;
            sb.append(inst.getAddress()).append("  ")
              .append(inst.getMnemonicString()).append("  ")
              .append(inst.toString()).append("\n");
            for (PcodeOp op : inst.getPcode()) {
                sb.append("    pcode: ").append(op.toString()).append("\n");
            }
            inst = inst.getNext();
        }
        sb.append("instruction count: ").append(count).append("\n");

        // Create functions. For the 28-byte smoke binary, main @ 0 and sum_fn @ 0xc.
        // For smaller binaries, decompile the single function at 0.
        String funcAddrProp = System.getProperty("smoke.funcaddr",
                hi.getOffset() >= 0x1b ? "c" : "0");
        Address funcAddr = toAddr(new java.math.BigInteger(funcAddrProp, 16).longValue());
        Function fTarget = getFunctionAt(funcAddr);
        if (fTarget == null) {
            fTarget = createFunction(funcAddr, "target_fn");
        }
        if (hi.getOffset() >= 0x1b) {
            if (getFunctionAt(toAddr(0)) == null) {
                createFunction(toAddr(0), "main");
            }
            if (getFunctionAt(toAddr(0xc)) == null) {
                createFunction(toAddr(0xc), "sum_fn");
            }
        }
        sb.append("decompile target: ").append(fTarget.getName()).append(" @ ")
          .append(fTarget.getEntryPoint()).append("\n");

        // Run the decompiler.
        sb.append("=== DECOMPILE ===\n");
        DecompInterface decomp = new DecompInterface();
        if (!decomp.openProgram(currentProgram)) {
            sb.append("openProgram FAILED\n");
        } else {
            DecompileResults res = decomp.decompileFunction(fTarget, 120, TaskMonitor.DUMMY);
            if (res.decompileCompleted()) {
                String cCode = res.getDecompiledFunction().getC();
                sb.append(cCode).append("\ndecompile: OK\n");
                try (FileWriter w = new FileWriter(OUTDIR + "ghidra_smoke_decompile.c")) {
                    w.write(cCode);
                }
            } else {
                sb.append("decompile FAILED: completed=").append(res.decompileCompleted())
                  .append(" cancelled=").append(res.isCancelled())
                  .append(" errmsg='").append(res.getErrorMessage()).append("'\n");
            }
            decomp.dispose();
        }

        try (FileWriter w = new FileWriter(OUTDIR + "ghidra_smoke_disasm.txt")) {
            w.write(sb.toString());
        }
    }
}
