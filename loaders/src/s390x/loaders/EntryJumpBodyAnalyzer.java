// A branch through r15 that only skips a header is still the same routine.
// Body repair otherwise records that branch as a thunk and starts the
// landed code as its own function, so r15 would no longer be the entry
// address. This runs after that repair and puts the landed instructions
// back in the entry function.
package s390x.loaders;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class EntryJumpBodyAnalyzer extends AbstractAnalyzer {

    public EntryJumpBodyAnalyzer() {
        super("Entry jump body",
            "Keep a header-skipping branch in the same function as the code it reaches.",
            AnalyzerType.BYTE_ANALYZER);
        setPriority(AnalysisPriority.DATA_ANALYSIS.after());
        setDefaultEnablement(true);
    }

    @Override
    public boolean canAnalyze(Program program) {
        if (!"s390x".equals(program.getLanguage().getProcessor().toString())) {
            return false;
        }
        String id = program.getCompilerSpec().getCompilerSpecID().getIdAsString();
        return "zos".equals(id);
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
            throws CancelledException {
        AddressIterator entries = program.getSymbolTable().getExternalEntryPointIterator();
        while (entries.hasNext()) {
            monitor.checkCancelled();
            Address entry = entries.next();
            if (!set.contains(entry)) {
                continue;
            }
            includeLandedCode(program, entry, log);
        }
        return true;
    }

    private void includeLandedCode(Program program, Address entry, MessageLog log) {
        Instruction entryIns = program.getListing().getInstructionAt(entry);
        if (entryIns == null || !entryIns.getFlowType().isJump()) {
            return;
        }
        AddressSet body = new AddressSet();
        body.add(entryIns.getMinAddress(), entryIns.getMaxAddress());
        Function func = program.getFunctionManager().getFunctionAt(entry);
        if (func != null && func.isThunk()) {
            Function thunked = func.getThunkedFunction(false);
            if (thunked != null) {
                addFallthrough(program, body, thunked.getEntryPoint());
                try {
                    func.setThunkedFunction(null);
                } catch (IllegalArgumentException e) {
                    log.appendMsg("entry thunk at " + entry + " stayed: " + e.getMessage());
                }
                if (program.getFunctionManager().getFunctionAt(thunked.getEntryPoint()) != null) {
                    program.getFunctionManager().removeFunction(thunked.getEntryPoint());
                }
            }
        }
        for (Reference ref : entryIns.getReferencesFrom()) {
            if (ref.getReferenceType().isJump()) {
                addFallthrough(program, body, ref.getToAddress());
            }
        }
        if (body.getNumAddresses() <= entryIns.getLength()) {
            return;
        }
        try {
            if (func == null) {
                if (program.getFunctionManager().getFunctionContaining(entry) != null) {
                    return;
                }
                program.getListing().createFunction(null, entry, body, SourceType.DEFAULT);
            } else {
                AddressSet merged = new AddressSet(func.getBody());
                merged.add(body);
                func.setBody(merged);
            }
        } catch (InvalidInputException | OverlappingFunctionException e) {
            log.appendMsg("entry body at " + entry + " was not extended: " + e.getMessage());
        }
    }

    private static void addFallthrough(Program program, AddressSet body, Address start) {
        Instruction ins = program.getListing().getInstructionAt(start);
        while (ins != null && !body.contains(ins.getMinAddress())) {
            body.add(ins.getMinAddress(), ins.getMaxAddress());
            Address fall = ins.getFallThrough();
            ins = fall == null ? null : program.getListing().getInstructionAt(fall);
        }
    }
}
