// RawBaseCheck.java -- minimal check: prints address range and first instruction
// of a raw-binary import, proving -loader-baseAddr took effect.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.address.Address;
import java.io.FileWriter;

public class RawBaseCheck extends GhidraScript {
    @Override
    public void run() throws Exception {
        StringBuilder sb = new StringBuilder();
        sb.append("program: ").append(currentProgram.getName()).append("\n");
        sb.append("language: ").append(currentProgram.getLanguage().getLanguageID()).append("\n");
        Address lo = currentProgram.getMinAddress();
        Address hi = currentProgram.getMaxAddress();
        sb.append("range: ").append(lo).append(" .. ").append(hi).append("\n");
        disassemble(lo);
        Instruction inst = getInstructionAt(lo);
        sb.append("first: ").append(inst == null ? "NO DECODE" : inst.toString()).append("\n");
        try (FileWriter w = new FileWriter("/home/hatch/workspace/zarch-sleigh/tests/raw_base_check.txt")) {
            w.write(sb.toString());
        }
    }
}
