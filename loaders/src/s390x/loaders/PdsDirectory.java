// PdsDirectory.java -- parser for raw PDS directory blocks.
//
// A PDS directory is a sequence of 256-byte blocks holding variable-length
// member entries packed back to back. Each on-disk entry (PDS2 format,
// mapped by the IHAPDS macro; see IBM "z/OS MVS Program Management:
// Advanced Facilities", Appendix E "PDS directory entry format on entry to
// STOW", and the MVS 3.8 IHAPDS macro source):
//
//   off  len  field
//     0    8  PDS2NAME  member name or alias (EBCDIC, blank-padded)
//     8    3  PDS2TTRP  TTR of first block of the member
//    11    1  PDS2INDC  indicator byte:
//                   bit 0 (0x80) PDS2ALIS: name is an alias
//                   bits 1-2     PDS2NTTR: number of TTRs in the user data
//                   bits 3-7     PDS2LUSR: user-data length in halfwords
//    12  2*LUSR  user data; for load modules the basic section is:
//
//    12    3  PDS2TTRT  TTR of first block of text
//    15    1  PDS2ZERO  zero
//    16    3  PDS2TTRN  TTR of note list (overlay) or scatter/translation
//                       table (scatter); zero otherwise
//    19    1  PDS2NL    number of note-list entries (overlay), else zero
//    20    1  PDS2ATR1  RENT/REUS/OVLY/TEST/LOAD/SCTR/EXEC/1BLK (bits 0-7)
//    21    1  PDS2ATR2  FLVL/ORG0/EP0/NRLD/NREP/TSTN/LEF/REFR (bits 0-7)
//    22    3  PDS2STOR  total contiguous storage requirement
//    25    2  PDS2FTBL  length of first block of text
//    27    3  PDS2EPA   entry-point address (LE-assigned, module-relative;
//                       associated with the alias when PDS2ALIS is set)
//    30    3  PDS2FTBO  AOS flag bytes PDS2FTB1/2/3, incl. PDS2LFMT
//                       ("module is in program object format"), AMODE/RMODE
//                       bits (PDSLRM64, PDSLRMOD, PDSAAMOD, PDSMAMOD)
//    33  --  PDSBCEND  end of basic section
//
// Optional sections may follow the basic section in order: scatter-load
// (8 bytes: PDS2SLSZ/PDS2TTSZ/PDS2ESDT/PDS2ESDC), alias (11 bytes:
// PDS2EPM entry point for the member name + PDS2MNM member name), SSI,
// APF. This parser reads the basic section and the scatter/alias sections
// and exposes any further user-data bytes raw.
//
// Packing rules implemented here: entries never span a block boundary; if
// an entry does not fit in the remainder of a block it starts the next
// block (leftover bytes are zero padding). An all-X'FF' name field marks
// the end of the directory; an all-X'00' name field ends the current
// block's entries. Anything else that does not parse (entry overrunning
// its block, truncated entry, claimed section not fitting the user data,
// bad lengths) is refused with a PdsFormatException.
//
// This class is intentionally free of Ghidra imports so it can be unit
// tested standalone (see tests/ZosPdsDirCheck.java).
package s390x.loaders;

import java.util.ArrayList;
import java.util.List;

public class PdsDirectory {

    public static final int BLOCK_SIZE = 256;

    /** Thrown for any malformed directory data. */
    public static class PdsFormatException extends Exception {
        public PdsFormatException(String msg) { super(msg); }
    }

    /** One parsed directory entry. */
    public static class PdsEntry {
        public String name;       // decoded EBCDIC member/alias name
        public byte[] ttrp = new byte[3]; // TTR of first block of member
        public boolean alias;     // PDS2ALIS
        public int nttr;          // PDS2NTTR
        public byte[] userData;   // raw user data (2 * PDS2LUSR bytes)
        public LoadModuleInfo lm; // non-null when userData covers the basic section
    }

    /** Interpreted load-module user data (basic + scatter + alias sections). */
    public static class LoadModuleInfo {
        public byte[] ttrt = new byte[3]; // TTR of first block of text
        public byte[] ttrn = new byte[3]; // TTR of note list / scatter table
        public int nl;                    // note-list entries (overlay)
        public int atr1, atr2;            // attribute bytes
        public long stor;                 // PDS2STOR
        public int ftbl;                  // PDS2FTBL
        public int epa;                   // PDS2EPA entry-point address (module-relative)
        public int ftb1, ftb2, ftb3;       // PDS2FTB1/2/3 AOS flag bytes
        // scatter-load section (present iff PDS2SCTR; refused if truncated)
        public boolean hasScatter;
        public int slsz, ttsz, esdt, esdc;
        // alias section (present iff PDS2ALIS; refused if truncated)
        public boolean hasAlias;
        public int epm;                   // PDS2EPM entry point for member name
        public String memberName;         // PDS2MNM

        public boolean isOverlay()       { return (atr1 & 0x20) != 0; } // PDS2OVLY
        public boolean isScatter()       { return (atr1 & 0x04) != 0; } // PDS2SCTR
        public boolean isReentrant()     { return (atr1 & 0x80) != 0; } // PDS2RENT
        public boolean isReusable()      { return (atr1 & 0x40) != 0; } // PDS2REUS
        public boolean isExecutable()    { return (atr1 & 0x02) != 0; } // PDS2EXEC
        /** PDS2LFMT: member is stored in program object format. */
        public boolean isProgramObject() { return (ftb1 & 0x04) != 0; }

        /** Decoded RMODE: "24", "ANY", or "64". */
        public String rmode() {
            if ((ftb2 & 0x20) != 0) return "64";   // PDSLRM64
            if ((ftb2 & 0x10) != 0) return "ANY";  // PDSLRMOD
            return "24";
        }

        /** Decoded AMODE for the entry point: "24", "31", "64", or "ANY".
         *  PDSMAMOD (main entry) and PDSAAMOD (alias entry) both encode
         *  00=24, 10=31, 01=64, 11=ANY (IBM "PDS directory entry format on
         *  entry to STOW"); the two fields just sit in different bit
         *  positions of PDS2FTB2 (mask 0x03 vs 0x0C). */
        public String amode(boolean forAlias) {
            int bits = forAlias ? (ftb2 & 0x0C) >> 2 : (ftb2 & 0x03);
            // 00=24, 10=31, 01=64, 11=ANY
            if (bits == 0x02) return "31";
            if (bits == 0x01) return "64";
            if (bits == 0x03) return "ANY";
            return "24";
        }
    }

    /**
     * Parse one on-disk directory entry at {@code off} in {@code buf}.
     * Returns the entry; the caller advances by {@code entryLength(...)}.
     */
    public static PdsEntry parseEntry(byte[] buf, int off, int limit)
            throws PdsFormatException {
        if (off + 12 > limit) {
            throw new PdsFormatException(
                "truncated directory entry at offset 0x" + Integer.toHexString(off));
        }
        int indc = buf[off + 11] & 0xff;
        int lusr = indc & 0x1f; // user-data length in halfwords
        int entryLen = 12 + 2 * lusr;
        if (off + entryLen > limit) {
            throw new PdsFormatException(
                "directory entry at offset 0x" + Integer.toHexString(off) +
                " overruns its block (indicator byte 0x" + Integer.toHexString(indc) + ")");
        }
        PdsEntry e = new PdsEntry();
        e.name = ZosUtil.ebcdicName(buf, off, 8);
        System.arraycopy(buf, off + 8, e.ttrp, 0, 3);
        e.alias = (indc & 0x80) != 0;
        e.nttr = (indc >> 5) & 0x03;
        e.userData = new byte[2 * lusr];
        System.arraycopy(buf, off + 12, e.userData, 0, e.userData.length);
        if (e.userData.length >= 21) {
            e.lm = interpretLoadModule(e.userData, e.alias);
        }
        return e;
    }

    /** Throw if {@code need} bytes at {@code o} do not fit in {@code ud}. */
    private static void need(byte[] ud, int o, int need, String section)
            throws PdsFormatException {
        if (o < 0 || need < 0 || o + need > ud.length) {
            throw new PdsFormatException(
                "directory entry user data too short for " + section +
                " (need " + (o + need) + " bytes, have " + ud.length + ")");
        }
    }

    /** Length of the entry starting at {@code off} (12 + 2 * PDS2LUSR). */
    public static int entryLength(byte[] buf, int off, int limit)
            throws PdsFormatException {
        if (off + 12 > limit) {
            throw new PdsFormatException(
                "truncated directory entry at offset 0x" + Integer.toHexString(off));
        }
        int lusr = buf[off + 11] & 0x1f;
        int len = 12 + 2 * lusr;
        if (off + len > limit) {
            throw new PdsFormatException(
                "directory entry at offset 0x" + Integer.toHexString(off) +
                " overruns its block");
        }
        return len;
    }

    private static boolean allByte(byte[] buf, int off, int len, int v) {
        for (int i = 0; i < len; i++) {
            if ((buf[off + i] & 0xff) != v) return false;
        }
        return true;
    }

    /**
     * Parse a raw PDS directory image (multiple of 256 bytes) into entries.
     * An all-X'FF' name field ends the directory; an all-X'00' name field
     * ends the current block's entries (entries never span blocks, so a
     * zero-filled tail followed by more blocks is normal packing).
     * Malformed entries are refused.
     */
    public static List<PdsEntry> parse(byte[] img) throws PdsFormatException {
        if (img.length == 0 || img.length % BLOCK_SIZE != 0) {
            throw new PdsFormatException(
                "PDS directory image must be a non-empty multiple of 256 bytes, got " +
                img.length);
        }
        List<PdsEntry> out = new ArrayList<>();
        for (int b = 0; b < img.length; b += BLOCK_SIZE) {
            int blockEnd = b + BLOCK_SIZE;
            int o = b;
            while (o + 12 <= blockEnd) {
                if (allByte(img, o, 8, 0xFF)) {
                    return out; // end of directory
                }
                if (allByte(img, o, 8, 0x00)) {
                    break; // zero-filled tail of this block; entries may follow
                           // in later blocks
                }
                PdsEntry e = parseEntry(img, o, blockEnd);
                out.add(e);
                int len = entryLength(img, o, blockEnd);
                if (len <= 0) {
                    throw new PdsFormatException(
                        "zero-length directory entry at offset 0x" +
                        Integer.toHexString(o));
                }
                o += len;
            }
            // Fewer than 12 bytes left in the block: padding to block end.
            // (Entries never span blocks; a short tail of padding is normal.)
        }
        return out;
    }

    /** Find an entry by member/alias name (case-sensitive, trimmed). */
    public static PdsEntry find(List<PdsEntry> entries, String name) {
        for (PdsEntry e : entries) {
            if (e.name.equals(name)) return e;
        }
        return null;
    }

    /**
     * Interpret load-module user data (on-disk offsets: basic section is
     * userData[0..20]; scatter section follows if PDS2SCTR; SSI section
     * follows if PDS2SSI; alias section follows if PDS2ALIS). A claimed
     * section that does not fit the user data is refused, never silently
     * skipped.
     */
    static LoadModuleInfo interpretLoadModule(byte[] ud, boolean isAlias)
            throws PdsFormatException {
        LoadModuleInfo m = new LoadModuleInfo();
        need(ud, 0, 21, "load-module basic section");
        System.arraycopy(ud, 0, m.ttrt, 0, 3);
        // ud[3] is PDS2ZERO
        System.arraycopy(ud, 4, m.ttrn, 0, 3);
        m.nl = ud[7] & 0xff;
        m.atr1 = ud[8] & 0xff;
        m.atr2 = ud[9] & 0xff;
        m.stor = ZosUtil.u24(ud, 10);
        m.ftbl = ZosUtil.u16(ud, 13);
        m.epa = ZosUtil.u24(ud, 15);
        m.ftb1 = ud[18] & 0xff;
        m.ftb2 = ud[19] & 0xff;
        m.ftb3 = ud[20] & 0xff;
        int o = 21;
        if (m.isScatter()) {
            need(ud, o, 8, "scatter section (PDS2SCTR set)");
            m.hasScatter = true;
            m.slsz = ZosUtil.u16(ud, o);
            m.ttsz = ZosUtil.u16(ud, o + 2);
            m.esdt = ZosUtil.u16(ud, o + 4);
            m.esdc = ZosUtil.u16(ud, o + 6);
            o += 8;
        }
        // SSI section (when PDS2SSI in FTB1) sits between scatter and alias
        // and starts on a halfword boundary; its length is variable. We do
        // not interpret SSI contents, but we must skip it to find a
        // following alias section. The SSI section layout (PDSS03) is:
        // optional 1 pad byte for halfword alignment, then 4-byte SSI word
        // + 2-byte member serial = 6 bytes.
        if ((m.ftb1 & 0x08) != 0) { // PDS2SSI
            if ((o & 1) != 0) o++; // halfword alignment pad
            need(ud, o, 6, "SSI section (PDS2SSI set)");
            o += 6;
        }
        if (isAlias) {
            need(ud, o, 11, "alias section (entry marked alias)");
            m.hasAlias = true;
            m.epm = ZosUtil.u24(ud, o);
            m.memberName = ZosUtil.ebcdicName(ud, o + 3, 8);
        }
        return m;
    }
}
