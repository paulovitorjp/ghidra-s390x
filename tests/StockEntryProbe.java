// StockEntryProbe.java
// After auto-analysis of tests/entry_stub.lmod, report instruction and
// function counts and whether the code section is executable.
// Pass "measure" to print only. The default mode fails the script when
// the entry was not recovered.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;

public class StockEntryProbe extends GhidraScript {

    @Override
    public void run() throws Exception {
        boolean measure = false;
        for (String a : getScriptArgs()) {
            if ("measure".equals(a)) {
                measure = true;
            }
        }
        int instructions = 0;
        InstructionIterator ii = currentProgram.getListing().getInstructions(true);
        Instruction first = null;
        while (ii.hasNext()) {
            Instruction ins = ii.next();
            if (first == null) {
                first = ins;
            }
            instructions++;
            if (instructions <= 12) {
                println("insn " + ins.getAddress() + " " + ins);
            }
        }
        int functions = 0;
        FunctionIterator fi = currentProgram.getFunctionManager().getFunctions(true);
        while (fi.hasNext()) {
            Function f = fi.next();
            functions++;
            println("func " + f.getName() + " " + f.getEntryPoint()
                + " body=" + f.getBody().getNumAddresses());
        }
        int execBlocks = 0;
        int plainBlocks = 0;
        for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
            boolean ext = "EXTERNAL".equals(b.getName());
            println("block " + b.getName() + " start=" + b.getStart()
                + " len=" + b.getSize()
                + " r=" + b.isRead() + " w=" + b.isWrite() + " x=" + b.isExecute()
                + " ext=" + ext);
            if (!ext) {
                plainBlocks++;
                if (b.isExecute()) {
                    execBlocks++;
                }
            }
        }
        Address entry = null;
        var eit = currentProgram.getSymbolTable().getExternalEntryPointIterator();
        if (eit.hasNext()) {
            entry = eit.next();
        }
        println("entry=" + entry);
        println("instructions=" + instructions);
        println("functions=" + functions);
        println("exec_blocks=" + execBlocks);
        println("plain_blocks=" + plainBlocks);
        SymbolIterator syms = currentProgram.getSymbolTable().getAllSymbols(false);
        while (syms.hasNext()) {
            Symbol s = syms.next();
            if (s.isExternal() || s.getSource().toString().contains("IMPORTED")) {
                println("symbol " + s.getName() + " " + s.getAddress());
            }
        }
        if (measure) {
            println("MODE measure");
            return;
        }
        if (execBlocks < 1) {
            throw new RuntimeException("code section is not executable");
        }
        if (instructions < 6) {
            throw new RuntimeException("expected the entry stub to disassemble, instructions="
                + instructions);
        }
        if (functions < 1) {
            throw new RuntimeException("expected a function at the entry, functions=" + functions);
        }
        println("STOCK ENTRY CHECK PASSED");
    }
}
