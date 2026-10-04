// ZosPdsDirCheck.java -- standalone regression for s390x.loaders.PdsDirectory.
//
// Compiles the loader sources WITHOUT Ghidra jars (PdsDirectory and ZosUtil
// are dependency-free) and checks valid + malformed PDS directories from
// tests/zos_pds*.dir. Run: javac -d /tmp/pdscheck loaders/src/s390x/loaders/
//   PdsDirectory.java loaders/src/s390x/loaders/ZosUtil.java
//   tests/ZosPdsDirCheck.java && java -cp /tmp/pdscheck ZosPdsDirCheck
import java.nio.file.*;
import s390x.loaders.PdsDirectory;

public class ZosPdsDirCheck {
    static int pass = 0, fail = 0;
    static void check(boolean cond, String what) {
        if (cond) { pass++; System.out.println("ok   " + what); }
        else { fail++; System.out.println("FAIL " + what); }
    }

    /** Build a minimal on-disk entry: 8B name + 3B TTRP + indicator +
     *  24 bytes user data (basic section + 3 pad) with the given FTB2.
     *  User-data offsets: ATR1=8, ATR2=9, FTB1=18, FTB2=19, FTB3=20. */
    static PdsDirectory.PdsEntry craftEntry(byte ftb2) throws Exception {
        byte[] e = new byte[12 + 24];
        byte[] nm = "TST".getBytes("Cp037");
        System.arraycopy(nm, 0, e, 0, nm.length);
        for (int i = nm.length; i < 8; i++) e[i] = 0x40;
        e[11] = 0x0C;                       // NTTR=0, LUSR=12
        e[12 + 8] = 0x00; e[12 + 9] = 0x00; // ATR1/ATR2
        e[12 + 18] = 0x00;                  // FTB1
        e[12 + 19] = ftb2;                  // FTB2
        e[12 + 20] = 0x00;                  // FTB3
        return PdsDirectory.parseEntry(e, 0, e.length);
    }

    public static void main(String[] args) throws Exception {
        byte[] img = Files.readAllBytes(Paths.get(
            "/home/hatch/workspace/zarch-sleigh/tests/zos_pds.dir"));

        // ---- valid directory: 2 blocks, 6 entries ----
        java.util.List<PdsDirectory.PdsEntry> entries = PdsDirectory.parse(img);
        check(entries.size() == 6, "6 entries in zos_pds.dir (got " + entries.size() + ")");

        PdsDirectory.PdsEntry prog1 = PdsDirectory.find(entries, "PROG1");
        check(prog1 != null, "find PROG1");
        check(!prog1.alias, "PROG1 is not an alias");
        check(prog1.lm != null, "PROG1 has basic section");
        PdsDirectory.LoadModuleInfo lm = prog1.lm;
        check(lm.epa == 0, "PROG1 EPA=0");
        check(lm.isReentrant() && lm.isReusable() && lm.isExecutable(),
            "PROG1 RENT+REUS+EXEC");
        check(!lm.isOverlay() && !lm.isScatter(), "PROG1 not overlay/scatter");
        check(!lm.isProgramObject(), "PROG1 not program-object format");
        check(lm.amode(false).equals("31"), "PROG1 AMODE 31 (got " + lm.amode(false) + ")");
        check(lm.rmode().equals("ANY"), "PROG1 RMODE ANY (got " + lm.rmode() + ")");
        check(lm.stor == 0x1000 && lm.ftbl == 0x100, "PROG1 STOR/FTBL");
        check(lm.ttrn[2] == 0, "PROG1 TTRN");

        // ---- alias entry ----
        PdsDirectory.PdsEntry a1 = PdsDirectory.find(entries, "ALIAS1");
        check(a1 != null, "find ALIAS1");
        check(a1.alias, "ALIAS1 marked alias");
        check(a1.lm != null && a1.lm.hasAlias, "ALIAS1 has alias section");
        check(a1.lm.epm == 0, "ALIAS1 EPM=0");
        check(a1.lm.memberName.equals("PROG1"), "ALIAS1 MNM=PROG1");
        check(a1.lm.amode(true).equals("31"), "alias AMODE 31 (got " + a1.lm.amode(true) + ")");

        // ---- scatter entry ----
        PdsDirectory.PdsEntry p2 = PdsDirectory.find(entries, "PROG2");
        check(p2 != null && p2.lm != null, "find PROG2");
        check(p2.lm.isScatter(), "PROG2 SCTR bit");
        check(p2.lm.hasScatter, "PROG2 has scatter section");
        check(p2.lm.slsz == 16 && p2.lm.ttsz == 32, "PROG2 SLSZ/TTSZ");
        check(p2.lm.esdt == 1 && p2.lm.esdc == 3, "PROG2 ESDT/ESDC");

        // ---- program-object-format entry ----
        PdsDirectory.PdsEntry p3 = PdsDirectory.find(entries, "PROG3");
        check(p3 != null && p3.lm != null, "find PROG3");
        check(p3.lm.isProgramObject(), "PROG3 PDS2LFMT bit detected");

        // ---- entry in second block (packing: entry never spans blocks) ----
        PdsDirectory.PdsEntry pad = PdsDirectory.find(entries, "PAD1");
        check(pad != null, "find PAD1 in block 2");
        check(pad != null && pad.userData.length == 62, "PAD1 62 user-data bytes");

        check(PdsDirectory.find(entries, "NOSUCH") == null, "missing member -> null");

        // ---- AMODE mask edges: craft entries with each PDSMAMOD/PDSAAMOD ----
        // main AMODE: 00=24, 10=31, 01=64, 11=ANY (mask 0x03)
        String[] mainModes = {"24", "64", "31", "ANY"};
        for (int i = 0; i < 4; i++) {
            PdsDirectory.PdsEntry e = craftEntry((byte) i);
            check(e.lm.amode(false).equals(mainModes[i]),
                "main AMODE bits " + i + " -> " + mainModes[i]);
        }
        // alias AMODE: 00=24, 10=31, 01=64, 11=ANY (mask 0x0C)
        for (int i = 0; i < 4; i++) {
            PdsDirectory.PdsEntry e = craftEntry((byte) (i << 2));
            check(e.lm.amode(true).equals(mainModes[i]),
                "alias AMODE bits " + i + " -> " + mainModes[i]);
        }
        // RMODE edges
        check(craftEntry((byte) 0x00).lm.rmode().equals("24"), "RMODE 24 default");
        check(craftEntry((byte) 0x10).lm.rmode().equals("ANY"), "RMODE ANY");
        check(craftEntry((byte) 0x30).lm.rmode().equals("64"), "RMODE 64");

        // ---- malformed: claimed scatter section does not fit ----
        byte[] badTrunc = Files.readAllBytes(Paths.get(
            "/home/hatch/workspace/zarch-sleigh/tests/zos_pds_bad_trunc.dir"));
        try {
            PdsDirectory.parse(badTrunc);
            check(false, "truncated scatter section must throw");
        } catch (PdsDirectory.PdsFormatException e) {
            check(true, "truncated scatter section throws: " + e.getMessage());
        }

        // ---- malformed: alias bit set but alias section does not fit ----
        byte[] badAlias = new byte[256];
        byte[] anm = "ALX".getBytes("Cp037");
        System.arraycopy(anm, 0, badAlias, 0, anm.length);
        for (int i = anm.length; i < 8; i++) badAlias[i] = 0x40;
        badAlias[11] = (byte) 0x8C;   // alias, LUSR=12 -> 24 user-data bytes
        try {
            PdsDirectory.parse(badAlias);
            check(false, "truncated alias section must throw");
        } catch (PdsDirectory.PdsFormatException e) {
            check(true, "truncated alias section throws");
        }

        // ---- malformed: image not a multiple of 256 ----
        byte[] badLen = Files.readAllBytes(Paths.get(
            "/home/hatch/workspace/zarch-sleigh/tests/zos_pds_bad_len.dir"));
        try {
            PdsDirectory.parse(badLen);
            check(false, "non-256-byte image must throw");
        } catch (PdsDirectory.PdsFormatException e) {
            check(true, "non-256-byte image throws");
        }

        // ---- malformed: entry overruns its block ----
        // three 74-byte entries (LUSR=31) fill offsets 0..221; a fourth
        // entry header at 222 claims 74 more bytes -> overrun.
        byte[] crafted = new byte[256];
        for (int base : new int[]{0, 74, 148, 222}) {
            crafted[base] = (byte) 'E';
            crafted[base + 11] = 0x1F;      // NTTR=0, LUSR=31 -> 74 bytes
        }
        try {
            PdsDirectory.parse(crafted);
            check(false, "overrun in fourth entry must throw");
        } catch (PdsDirectory.PdsFormatException e) {
            check(true, "overrun in fourth entry throws");
        }

        System.out.println(pass + " passed, " + fail + " failed");
        if (fail > 0) System.exit(1);
    }
}
