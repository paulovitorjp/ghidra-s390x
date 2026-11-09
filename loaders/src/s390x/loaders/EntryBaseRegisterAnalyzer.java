// At a function entry, r15 holds that entry address. A branch through r15
// (the usual way to skip a short header) can then be followed without a
// manually seeded register.
//
// The value is stored in the program context at the entry address, which is
// what constant propagation already reads when it starts at that address.
// The resolved target is disassembled here when it is not already an
// instruction. Stopping after the entry instruction alone is the failure
// this analyzer exists to prevent.
package s390x.loaders;

import java.math.BigInteger;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.RefType;
import ghidra.program.util.ContextEvaluatorAdapter;
import ghidra.program.util.SymbolicPropogator;
import ghidra.program.util.VarnodeContext;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class EntryBaseRegisterAnalyzer extends AbstractAnalyzer {

    public EntryBaseRegisterAnalyzer() {
        super("Entry base register",
            "Record r15 as the entry address so a branch through r15 is followed.",
            AnalyzerType.BYTE_ANALYZER);
        setPriority(AnalysisPriority.BLOCK_ANALYSIS.after());
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
        Register r15 = program.getLanguage().getRegister("r15");
        if (r15 == null) {
            return false;
        }
        AddressIterator entries = program.getSymbolTable().getExternalEntryPointIterator();
        while (entries.hasNext()) {
            monitor.checkCancelled();
            Address entry = entries.next();
            if (!set.contains(entry)) {
                continue;
            }
            followEntry(program, entry, r15, monitor, log);
        }
        return true;
    }

    private void followEntry(Program program, Address entry, Register r15, TaskMonitor monitor,
            MessageLog log) throws CancelledException {
        try {
            RegisterValue existing = program.getProgramContext().getRegisterValue(r15, entry);
            if (existing == null || !existing.hasValue()) {
                RegisterValue seeded = new RegisterValue(r15, BigInteger.valueOf(entry.getOffset()));
                program.getProgramContext().setRegisterValue(entry, entry, seeded);
            }
        } catch (ContextChangeException e) {
            log.appendMsg("r15 at " + entry + " was not recorded: " + e.getMessage());
            return;
        }

        Disassembler dis = Disassembler.getDisassembler(program, monitor, null);
        if (program.getListing().getInstructionAt(entry) == null) {
            AddressSet done = dis.disassemble(new AddressSet(entry, entry), null, true);
            if (done != null && !done.isEmpty()) {
                ghidra.app.plugin.core.analysis.AutoAnalysisManager.getAnalysisManager(program)
                    .codeDefined(done);
            }
        }
        if (program.getListing().getInstructionAt(entry) == null) {
            return;
        }

        SymbolicPropogator prop = new SymbolicPropogator(program);
        AddressSet onlyEntry = new AddressSet(entry, entry);
        prop.flowConstants(entry, onlyEntry, new FollowTarget(program, dis, monitor), false, monitor);
    }

    /** Disassemble a resolved branch target. Computed jumps are not disassembled by default. */
    private static final class FollowTarget extends ContextEvaluatorAdapter {
        private final Program program;
        private final Disassembler dis;
        private final TaskMonitor monitor;

        FollowTarget(Program program, Disassembler dis, TaskMonitor monitor) {
            this.program = program;
            this.dis = dis;
            this.monitor = monitor;
        }

        @Override
        public Address evaluateConstant(VarnodeContext context, Instruction instr, int pcodeop,
                Address constant, int size, DataType dataType, RefType refType) {
            if (refType != null && refType.isFlow()) {
                return constant;
            }
            return null;
        }

        @Override
        public boolean evaluateReference(VarnodeContext context, Instruction instr, int pcodeop,
                Address address, int size, DataType dataType, RefType refType) {
            if (!refType.isFlow() || address == null || !address.isMemoryAddress()) {
                return true;
            }
            MemoryBlock block = program.getMemory().getBlock(address);
            if (block == null || !block.isExecute() || !block.isInitialized()) {
                return true;
            }
            if (program.getListing().getInstructionContaining(address) != null) {
                return true;
            }
            if (program.getListing().getDefinedDataContaining(address) != null) {
                return true;
            }
            AddressSet done = dis.disassemble(address, null, true);
            if (done != null && !done.isEmpty()) {
                ghidra.app.plugin.core.analysis.AutoAnalysisManager.getAnalysisManager(program)
                    .codeDefined(done);
            }
            return true;
        }
    }
}
