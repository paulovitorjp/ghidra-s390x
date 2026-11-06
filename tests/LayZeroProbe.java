// LayZeroProbe.java
// Raw image:
//   la  r1,5(0,0)
//   lay r2,-160(r1)     ; encoding e3 20 1f 60 ff 71
//   ar  r2,r1
//   br  r14
// The long displacement must print as the signed value -160 (-0xa0),
// with no zero index. Decompiled text must not invent an in_zero input.
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.PcodeOp;
import java.util.Arrays;

public class LayZeroProbe extends GhidraScript {

    private static final byte[] EXPECT = new byte[] {
        0x41, 0x10, 0x00, 0x05,
        (byte) 0xE3, 0x20, 0x1F, 0x60, (byte) 0xFF, 0x71,
        0x1A, 0x21,
        0x07, (byte) 0xFE
    };

    @Override
    public void run() throws Exception {
        Address lo = currentProgram.getMinAddress();
        byte[] got = new byte[EXPECT.length];
        currentProgram.getMemory().getBytes(lo, got);
        if (!Arrays.equals(EXPECT, got)) {
            throw new RuntimeException("image bytes are not the lay/zero fixture");
        }
        disassemble(lo);
        StringBuilder listing = new StringBuilder();
        Instruction ins = getInstructionAt(lo);
        boolean sawLay = false;
        boolean sawBranchInd = false;
        while (ins != null) {
            String text = ins.toString();
            listing.append(text).append("\n");
            println("insn " + ins.getAddress() + " " + text);
            for (PcodeOp op : ins.getPcode()) {
                println("  pcode " + op);
            }
            if (text.toLowerCase().contains("lay")) {
                sawLay = true;
                String low = text.toLowerCase();
                if (low.contains("zero")) {
                    throw new RuntimeException("lay still prints a zero index: " + text);
                }
                if (low.contains("f60") || low.contains("3936")) {
                    throw new RuntimeException("lay still prints the unsigned low 12 bits: " + text);
                }
                if (!low.contains("-0xa0") && !low.contains("-160")) {
                    throw new RuntimeException("lay displacement is not -160: " + text);
                }
            }
            if (text.toLowerCase().contains("br")) {
                for (PcodeOp op : ins.getPcode()) {
                    if (op.getOpcode() == PcodeOp.BRANCHIND || op.getOpcode() == PcodeOp.RETURN) {
                        sawBranchInd = true;
                    }
                }
            }
            ins = ins.getNext();
        }
        if (!sawLay) {
            throw new RuntimeException("lay did not decode:\n" + listing);
        }
        if (!sawBranchInd) {
            throw new RuntimeException("br r14 was not an indirect return");
        }
        Function f = getFunctionAt(lo);
        if (f == null) {
            f = createFunction(lo, "entry");
        }
        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        DecompileResults res = di.decompileFunction(f, 60, monitor);
        if (res.getDecompiledFunction() == null) {
            throw new RuntimeException("decompile produced no function: " + res.getErrorMessage());
        }
        String c = res.getDecompiledFunction().getC();
        println("decomp completed=" + res.decompileCompleted());
        println(c);
        if (c.contains("in_zero")) {
            throw new RuntimeException("decompiler invented in_zero");
        }
        for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
            println("block " + b.getName() + " x=" + b.isExecute());
        }
        println("LAY ZERO CHECK PASSED");
    }
}
