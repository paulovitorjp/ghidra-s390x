// ZosProgramObjectLoader.java -- Ghidra loader stub for modern z/OS
// program objects (PM1 through PM5, as produced by the binder for PDSE
// and USS executables).
//
// This loader DETECTS program objects (EBCDIC "IEWPLMH " eyecatcher) and
// then fails with a descriptive error. Full loading is not implemented:
// program objects are binder-managed block/section/class structures whose
// stored byte layout is not specified at a parseable level by the
// authoritative IBM documentation. IBM "z/OS MVS Program Management:
// Advanced Facilities" (ieab200) documents program objects only through
// the binder APIs -- IEWBIND (Chapter 3), the fast data access API
// IEWBFDAT (Chapter 4), and the IEWBUFF API buffer formats (Appendix D,
// incl. the PMAR conduit whose mapping lives in the separate "z/OS MVS
// Data Areas" IEWPMAR macro). None of these specify the portable on-disk
// byte layout of a program object as stored in a PDSE or USS file; the
// PM-level markers (PO1..PO5 / PM1..PM5) appear only in API return buffers
// (e.g. CUI_TYPE in the compile-unit information buffer), not in the
// stored file. Without an authoritative stored-format specification (or
// binder APIs on a live z/OS system, or real program-object samples to
// validate a reverse-engineered parser against), any parser would be
// guesswork. See LOADERS.md ("Program objects (PM1-PM5): not supported")
// for the precise blocker and what would unblock it. Workaround: use the
// z/OS binder (IEWL/IEWBLINK) to convert the program object to a classic
// load module or a GOFF object first.
package s390x.loaders;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.*;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class ZosProgramObjectLoader extends AbstractLibrarySupportLoader {

    public static final String LOADER_NAME = "z/OS Program Object (unsupported)";

    @Override
    public String getName() {
        return LOADER_NAME;
    }

    @Override
    public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
        if (provider.length() < 8) {
            return Collections.emptyList();
        }
        byte[] head = provider.readBytes(0, 8);
        // EBCDIC "IEWPLMH " eyecatcher (Cp037: C9 C5 E6 D7 D3 D4 C8 40)
        byte[] eye = { (byte) 0xC9, (byte) 0xC5, (byte) 0xE6, (byte) 0xD7,
                       (byte) 0xD3, (byte) 0xD4, (byte) 0xC8, (byte) 0x40 };
        if (!Arrays.equals(head, eye)) {
            return Collections.emptyList();
        }
        List<LoadSpec> specs = new ArrayList<>();
        // A language/compiler pair is required so the importer can get as far
        // as load(), where the descriptive error below is raised.
        specs.add(new LoadSpec(this, 0,
            new LanguageCompilerSpecPair("s390x:BE:64:default", "zos"), false));
        return specs;
    }

    @Override
    protected void load(Program program, Loader.ImporterSettings settings)
            throws IOException, LoadException, CancelledException {
        throw new LoadException(
            "z/OS program objects (PM1-PM5) are not supported by this loader. " +
            "The stored byte layout of a program object is not specified by " +
            "the authoritative IBM documentation: \"z/OS MVS Program " +
            "Management: Advanced Facilities\" documents program objects only " +
            "through the binder APIs (IEWBIND, IEWBFDAT fast data access, " +
            "IEWBUFF buffer formats) -- see LOADERS.md section 6 for the " +
            "chapter-by-chapter analysis. Without the stored-format " +
            "specification, binder APIs on a live z/OS system, or real " +
            "program-object samples to validate against, a parser would be " +
            "guesswork. " +
            "Use the z/OS binder (IEWL/IEWBLINK) to convert the program object to a " +
            "classic load module or a GOFF object, then load it with the " +
            "\"z/OS MVS Load Module\" or \"z/OS GOFF Object File\" loader. " +
            "See LOADERS.md for details.");
    }
}
