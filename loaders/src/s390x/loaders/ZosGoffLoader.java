// ZosGoffLoader.java -- Ghidra loader for z/OS GOFF object files.
//
// Parses the documented subset of SA22-7644 Appendix C ("Generalized
// object file format"): 80-byte fixed records, HDR (X'03F000'), ESD
// (X'030000'), TXT (X'031000'), RLD (X'032000') and END (X'034000').
// Supported ESD symbol types: SD (section definition), ED (element
// definition), LD (label definition), PR (part reference), ER/WX (external
// reference/weak external). RLD items support reference type 0 (R-address)
// with referent types 0 (label) and 1 (element), action 0/1 (+/-), fetch
// (add to stored value) and store (overwrite) modes, and target lengths
// 2/4/8. External references are recorded as external symbols and left
// unresolved. Continued records are chained per the PTV continuation bits
// (byte 1, low two bits: 01 = initial continued, 10/11 = continuation;
// continuation records carry 77 payload bytes after the 3-byte PTV) before
// parsing, so logical ESD/TXT/RLD/END records may span several physical
// records. Record formats outside this subset are rejected with a clear
// error, as are malformed continuation chains.
//
// The loaded program uses the "zos" compiler spec (z/OS Language
// Environment ABI); see data/languages/s390x-zos.cspec.
package s390x.loaders;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.*;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.*;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class ZosGoffLoader extends AbstractLibrarySupportLoader {

    public static final String LOADER_NAME = "z/OS GOFF Object File";
    public static final String IMAGE_BASE_OPTION = "Image Base (hex)";
    public static final String DEFAULT_IMAGE_BASE = "0x10000";
    private static final int REC = 80;

    // ESD symbol types
    private static final int T_SD = 0, T_ED = 1, T_LD = 2, T_PR = 3, T_ER = 4, T_WX = 4;

    private static class Esd {
        int type, id, parent; long offset, length; String name;
    }

    private static class Txt {
        int esdId; long offset; byte[] data;
    }

    private static class Rld {
        byte[] flags = new byte[6];
        long rPtr, pPtr, off;
    }

    /** A logical GOFF record: one initial physical record plus any chained
     *  continuation records, flattened to PTV + fixed header + concatenated
     *  payload so the record parsers below see a single byte array. */
    private static class LogicalRec {
        byte[] data;
        int firstPhys; // index of the first physical record (for diagnostics)
    }

    // PTV byte 1, low two bits (SA22-7644 Appendix C; "MVS Program
    // Management: Advanced Facilities"):
    //   00 = initial record, not continued
    //   01 = initial record, continued on the next physical record
    //   10 = continuation record, not continued further
    //   11 = continuation record, continued on the next physical record
    private static int contBits(int ptv1) {
        return ptv1 & 0x03;
    }

    /** Offset in the initial record where the variable-length payload starts. */
    private static int goffDataIndex(int rectype) {
        switch (rectype) {
            case 0x00: return 72; // ESD name
            case 0x10: return 24; // TXT data
            case 0x20: return 6;  // RLD items
            case 0x30: return 8;  // LEN data
            case 0x40: return 26; // END name
            case 0xF0: return 60; // HDR module properties
            default:   return -1;
        }
    }

    /** Offset of the u16 field holding the total payload length. */
    private static int goffDataLenOff(int rectype) {
        switch (rectype) {
            case 0x00: return 70; // ESD name length
            case 0x10: return 22; // TXT data length
            case 0x20: return 4;  // RLD data length
            case 0x30: return 6;  // LEN data length
            case 0x40: return 24; // END name length
            case 0xF0: return 52; // HDR properties length
            default:   return -1;
        }
    }

    /**
     * Chain continued physical records into logical records.
     *
     * Each continuation record must have its continuation bit (bit 1 of PTV
     * byte 1) set, must match the initial record's type, and contributes 77
     * payload bytes after its 3-byte PTV. Malformed chains (dangling
     * continuation, type mismatch, truncation, stray continued bit) are
     * refused with a LoadException rather than mis-parsed.
     */
    private static List<LogicalRec> flattenRecords(byte[] img, int nrec)
            throws LoadException {
        List<LogicalRec> out = new ArrayList<>();
        int r = 0;
        while (r < nrec) {
            int o = r * REC;
            int ptv0 = img[o] & 0xff, ptv1 = img[o + 1] & 0xff;
            if (ptv0 != 0x03) {
                throw new LoadException("record " + r + ": bad PTV X'" +
                    Integer.toHexString(ptv0) + "'");
            }
            int rectype = ptv1 & 0xF0;
            int cb = contBits(ptv1);
            if ((cb & 0x02) != 0) {
                throw new LoadException("record " + r +
                    ": continuation record with no continued record before it");
            }
            int di = goffDataIndex(rectype);
            if (di < 0) {
                throw new LoadException("record " + r + ": unsupported PTV X'" +
                    Integer.toHexString(ptv1) + "'");
            }
            int total = ZosUtil.u16(img, o + goffDataLenOff(rectype));
            int firstPhys = r;
            int have = Math.min(total, REC - di);
            byte[] flat = new byte[di + total];
            System.arraycopy(img, o, flat, 0, di);
            System.arraycopy(img, o + di, flat, di, have);
            int need = total - have;
            r++;
            if (need == 0 && cb == 0x01) {
                throw new LoadException("record " + firstPhys +
                    ": continued bit set but payload length is 0");
            }
            while (need > 0) {
                if (r >= nrec) {
                    throw new LoadException("record " + firstPhys +
                        ": truncated continued record (missing continuation record)");
                }
                int co = r * REC;
                int cptv0 = img[co] & 0xff, cptv1 = img[co + 1] & 0xff;
                if (cptv0 != 0x03) {
                    throw new LoadException("record " + r + ": bad PTV X'" +
                        Integer.toHexString(cptv0) + "'");
                }
                if ((cptv1 & 0xF0) != rectype) {
                    throw new LoadException("record " + r +
                        ": continuation record type X'" +
                        Integer.toHexString(cptv1 & 0xF0) +
                        "' does not match continued record " + firstPhys +
                        " type X'" + Integer.toHexString(rectype) + "'");
                }
                int ccb = contBits(cptv1);
                if ((ccb & 0x02) == 0) {
                    throw new LoadException("record " + r +
                        ": expected continuation record for continued record " +
                        firstPhys);
                }
                int chunk = Math.min(need, REC - 3);
                System.arraycopy(img, co + 3, flat, di + have, chunk);
                have += chunk;
                need -= chunk;
                boolean cExpectMore = (ccb & 0x01) != 0;
                if (need == 0 && cExpectMore) {
                    throw new LoadException("record " + r +
                        ": continued bit set on final continuation record");
                }
                if (need > 0 && !cExpectMore) {
                    throw new LoadException("record " + firstPhys +
                        ": truncated continued record (" + need +
                        " payload bytes missing)");
                }
                r++;
            }
            LogicalRec lr = new LogicalRec();
            lr.data = flat;
            lr.firstPhys = firstPhys;
            out.add(lr);
        }
        return out;
    }

    private int extCounter = 0;
    private Address extBase = null;

    @Override
    public String getName() {
        return LOADER_NAME;
    }

    @Override
    public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
        if (provider.length() < REC) {
            return Collections.emptyList();
        }
        byte[] head = provider.readBytes(0, 3);
        if ((head[0] & 0xff) != 0x03 || (head[1] & 0xff) != 0xF0 || (head[2] & 0xff) != 0x00) {
            return Collections.emptyList();
        }
        LanguageCompilerSpecPair pair =
            new LanguageCompilerSpecPair("s390x:BE:64:default", "zos");
        List<LoadSpec> specs = new ArrayList<>();
        specs.add(new LoadSpec(this, 0x10000L, pair, true));
        return specs;
    }

    @Override
    public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
            DomainObject domainObject, boolean isLoadInto, boolean isNewProgram) {
        List<Option> list =
            new ArrayList<>(super.getDefaultOptions(provider, loadSpec, domainObject,
                isLoadInto, isNewProgram));
        list.add(new Option(IMAGE_BASE_OPTION, DEFAULT_IMAGE_BASE));
        return list;
    }

    private static String optValue(List<Option> options, String name, String dflt) {
        for (Option o : options) {
            if (o.getName().equals(name)) {
                Object v = o.getValue();
                return v == null ? dflt : v.toString();
            }
        }
        return dflt;
    }

    @Override
    protected void load(Program program, Loader.ImporterSettings settings)
            throws IOException, LoadException, CancelledException {
        ByteProvider provider = settings.provider();
        MessageLog log = settings.log();
        TaskMonitor monitor = settings.monitor();
        List<Option> options = settings.options();

        long imageBase = ZosUtil.parseBase(
            optValue(options, IMAGE_BASE_OPTION, DEFAULT_IMAGE_BASE), 0x10000L);

        long fileLen = provider.length();
        if (fileLen % REC != 0) {
            throw new LoadException("GOFF file length " + fileLen +
                " is not a multiple of the 80-byte record length");
        }
        byte[] img = provider.readBytes(0, fileLen);
        int nrec = (int) (fileLen / REC);

        Map<Integer, Esd> esdById = new HashMap<>();
        List<Txt> texts = new ArrayList<>();
        List<Rld> rlds = new ArrayList<>();
        long entryEsd = -1, entryOff = 0;
        String entryName = null;

        List<LogicalRec> records = flattenRecords(img, nrec);

        for (LogicalRec lr : records) {
            byte[] rec = lr.data;
            int r = lr.firstPhys; // physical index, for diagnostics
            int ptv1 = rec[1] & 0xff;
            int rectype = ptv1 & 0xF0;
            switch (rectype) {
                case 0xF0: // HDR
                    if (r != 0) {
                        log.appendMsg("HDR record not first (record " + r + ")");
                    }
                    break;
                case 0x00: { // ESD
                    Esd e = new Esd();
                    e.type = rec[3] & 0xff;
                    e.id = (int) ZosUtil.u32(rec, 4);
                    e.parent = (int) ZosUtil.u32(rec, 8);
                    e.offset = ZosUtil.u32(rec, 16);
                    e.length = ZosUtil.u32(rec, 24);
                    int nl = ZosUtil.u16(rec, 70);
                    if (nl > 0) {
                        if (72 + nl > rec.length) {
                            throw new LoadException("record " + r + ": truncated ESD name");
                        }
                        e.name = ZosUtil.ebcdicName(rec, 72, nl);
                    } else {
                        e.name = "ESD" + e.id;
                    }
                    esdById.put(e.id, e);
                    break;
                }
                case 0x10: { // TXT
                    Txt t = new Txt();
                    t.esdId = (int) ZosUtil.u32(rec, 4);
                    t.offset = ZosUtil.u32(rec, 12);
                    int dlen = ZosUtil.u16(rec, 22);
                    if (dlen > rec.length - 24) {
                        throw new LoadException("record " + r + ": TXT length " + dlen +
                            " exceeds record");
                    }
                    t.data = Arrays.copyOfRange(rec, 24, 24 + dlen);
                    texts.add(t);
                    break;
                }
                case 0x20: { // RLD
                    int dlen = ZosUtil.u16(rec, 4);
                    if (6 + dlen > rec.length) {
                        throw new LoadException("record " + r + ": RLD length " + dlen +
                            " exceeds record");
                    }
                    int p = 6, end = 6 + dlen;
                    long prevR = 0, prevP = 0, prevOff = 0;
                    boolean firstItem = true;
                    while (p < end) {
                        if (p + 6 > end) {
                            throw new LoadException("record " + r + ": truncated RLD item");
                        }
                        Rld ri = new Rld();
                        System.arraycopy(rec, p, ri.flags, 0, 6);
                        int sameR = (ri.flags[0] >> 7) & 1;
                        int sameP = (ri.flags[0] >> 6) & 1;
                        int sameO = (ri.flags[0] >> 5) & 1;
                        int offLen = (((ri.flags[0] >> 4) & 1) == 1) ? 2 : 4;
                        if (firstItem && (sameR == 1 || sameP == 1 || sameO == 1)) {
                            throw new LoadException("record " + r +
                                ": first RLD item uses same-R/P/offset compression " +
                                "with no previous item");
                        }
                        firstItem = false;
                        p += 8; // flags(6) + reserved(2)
                        if (sameR == 0) {
                            if (p + 4 > end) throw new LoadException(
                                "record " + r + ": truncated RLD R-pointer");
                            ri.rPtr = ZosUtil.u32(rec, p); p += 4;
                        } else {
                            ri.rPtr = prevR;
                        }
                        if (sameP == 0) {
                            if (p + 4 > end) throw new LoadException(
                                "record " + r + ": truncated RLD P-pointer");
                            ri.pPtr = ZosUtil.u32(rec, p); p += 4;
                        } else {
                            ri.pPtr = prevP;
                        }
                        if (sameO == 0) {
                            if (p + offLen > end) throw new LoadException(
                                "record " + r + ": truncated RLD offset");
                            ri.off = offLen == 4 ? ZosUtil.u32(rec, p)
                                : ZosUtil.u16(rec, p);
                            p += offLen;
                        } else {
                            ri.off = prevOff;
                        }
                        p += 8; // reserved
                        prevR = ri.rPtr; prevP = ri.pPtr; prevOff = ri.off;
                        rlds.add(ri);
                    }
                    break;
                }
                case 0x30: // LEN
                    break;
                case 0x40: { // END
                    int mode = rec[3] & 0x3;
                    if (mode == 1) {
                        entryEsd = ZosUtil.u32(rec, 12);
                        entryOff = ZosUtil.u32(rec, 20);
                    } else if (mode == 2) {
                        int nl = ZosUtil.u16(rec, 24);
                        if (26 + nl > rec.length) {
                            throw new LoadException("record " + r + ": truncated END name");
                        }
                        entryName = nl > 0 ? ZosUtil.ebcdicName(rec, 26, nl) : null;
                    } else {
                        log.appendMsg("END record: no entry point specified");
                    }
                    break;
                }
                default:
                    throw new LoadException("record " + r + ": unsupported PTV X'" +
                        Integer.toHexString(ptv1) + "'");
            }
            monitor.checkCancelled();
        }

        // ---- assign addresses: one block per ED with nonzero length ----
        Memory mem = program.getMemory();
        Map<Integer, Long> baseByEsd = new HashMap<>();
        long cursor = imageBase;
        List<Esd> eds = new ArrayList<>();
        for (Esd e : esdById.values()) {
            if (e.type == T_ED) {
                eds.add(e);
            }
        }
        eds.sort(Comparator.comparingInt(e -> e.id));
        Set<String> usedNames = new HashSet<>();
        for (Esd e : eds) {
            if (e.length <= 0) {
                continue;
            }
            String bn = ZosUtil.sanitize(e.name, "ED" + e.id);
            int k = 2;
            while (!usedNames.add(bn)) bn = ZosUtil.sanitize(e.name, "E") + "_" + (k++);
            Address start = program.getAddressFactory().getDefaultAddressSpace()
                .getAddress(cursor);
            try {
                mem.createInitializedBlock(bn, start, e.length, (byte) 0, monitor, false);
                baseByEsd.put(e.id, cursor);
            } catch (Exception ex) {
                log.appendMsg("could not create block " + bn + ": " + ex.getMessage());
            }
            cursor += (e.length + 7) & ~7L;
        }

        // ---- write TXT data ----
        for (Txt t : texts) {
            Esd e = esdById.get(t.esdId);
            if (e == null || e.type != T_ED) {
                log.appendMsg("TXT for unknown/non-element ESD " + t.esdId);
                continue;
            }
            Long base = baseByEsd.get(t.esdId);
            if (base == null) {
                continue;
            }
            Address a = program.getAddressFactory().getDefaultAddressSpace()
                .getAddress(base + t.offset);
            try {
                mem.setBytes(a, t.data);
            } catch (Exception ex) {
                log.appendMsg("TXT write failed at 0x" +
                    Long.toHexString(base + t.offset) + ": " + ex.getMessage());
            }
        }

        // ---- external block for unresolved imports ----
        try {
            extBase = MemoryBlockUtils.addExternalBlock(program, 0x1000, log);
        } catch (Exception e) {
            log.appendMsg("could not create EXTERNAL block: " + e.getMessage());
        }

        // ---- symbols: LD/PR labels, ER externals ----
        SymbolTable st = program.getSymbolTable();
        for (Esd e : esdById.values()) {
            try {
                if (e.type == T_LD || e.type == T_PR) {
                    Esd pe = esdById.get(e.parent);
                    Long pb = pe != null ? baseByEsd.get(pe.id) : null;
                    if (pb != null) {
                        Address a = program.getAddressFactory().getDefaultAddressSpace()
                            .getAddress(pb + e.offset);
                        st.createLabel(a, ZosUtil.sanitize(e.name, "LD" + e.id),
                            SourceType.IMPORTED);
                    }
                } else if (e.type == T_ER || e.type == T_WX) {
                    addExternal(program, e.name);
                }
            } catch (Exception ex) {
                log.appendMsg("symbol " + e.name + ": " + ex.getMessage());
            }
        }

        // ---- relocations ----
        int applied = 0, skipped = 0;
        for (Rld ri : rlds) {
            int refType = (ri.flags[1] >> 4) & 0xF;
            int referentType = ri.flags[1] & 0xF;
            int action = (ri.flags[2] >> 1) & 0x7F;
            boolean fetch = (ri.flags[2] & 1) == 0;
            int tlen = ri.flags[4] & 0xFF;
            Esd pEsd = esdById.get((int) ri.pPtr);
            Esd rEsd = esdById.get((int) ri.rPtr);
            if (pEsd == null || rEsd == null || refType != 0) {
                log.appendMsg("RLD skipped: bad P/R pointer or refType=" + refType);
                skipped++;
                continue;
            }
            Long pb = baseByEsd.get(pEsd.id);
            if (pb == null) {
                log.appendMsg("RLD skipped: P-element " + pEsd.id + " has no block");
                skipped++;
                continue;
            }
            Address adconAddr = program.getAddressFactory().getDefaultAddressSpace()
                .getAddress(pb + ri.off);
            try {
                if (rEsd.type == T_ER || rEsd.type == T_WX) {
                    addExternal(program, rEsd.name);
                    skipped++; // unresolved external: value left alone
                    continue;
                }
                long second;
                if (referentType == 1) {
                    Long rb = baseByEsd.get(rEsd.id);
                    if (rb == null) { skipped++; continue; }
                    second = rb;
                } else if (referentType == 0) {
                    Esd pe = esdById.get(rEsd.parent);
                    Long rb = pe != null ? baseByEsd.get(pe.id) : null;
                    if (rb == null) { skipped++; continue; }
                    second = rb + rEsd.offset;
                } else {
                    log.appendMsg("RLD skipped: referentType=" + referentType);
                    skipped++;
                    continue;
                }
                if (tlen != 2 && tlen != 4 && tlen != 8) {
                    log.appendMsg("RLD skipped: target length " + tlen);
                    skipped++;
                    continue;
                }
                long first = fetch ? readMem(mem, adconAddr, tlen) : 0;
                long result = (action == 1) ? first - second : first + second;
                writeMem(mem, adconAddr, tlen, result);
                applied++;
            } catch (Exception ex) {
                log.appendMsg("RLD apply failed at 0x" +
                    Long.toHexString(pb + ri.off) + ": " + ex.getMessage());
                skipped++;
            }
        }
        log.appendMsg("relocations: applied=" + applied + " skipped/unresolved=" + skipped);

        // ---- entry point ----
        Address entryAddr = null;
        if (entryEsd >= 0) {
            Long b = baseByEsd.get((int) entryEsd);
            if (b != null) {
                entryAddr = program.getAddressFactory().getDefaultAddressSpace()
                    .getAddress(b + entryOff);
            }
        } else if (entryName != null) {
            for (Esd e : esdById.values()) {
                if ((e.type == T_LD || e.type == T_PR) && e.name.equals(entryName)) {
                    Esd pe = esdById.get(e.parent);
                    Long b = pe != null ? baseByEsd.get(pe.id) : null;
                    if (b != null) {
                        entryAddr = program.getAddressFactory().getDefaultAddressSpace()
                            .getAddress(b + e.offset);
                    }
                    break;
                }
            }
        }
        if (entryAddr == null && !baseByEsd.isEmpty()) {
            entryAddr = program.getAddressFactory().getDefaultAddressSpace()
                .getAddress(Collections.min(baseByEsd.values()));
            log.appendMsg("no entry in END record; defaulting to first element");
        }
        if (entryAddr != null) {
            st.addExternalEntryPoint(entryAddr);
            // NOTE: no function is created here; auto-analysis (or the caller)
            // disassembles the entry region and creates functions from the flow.
            log.appendMsg("entry point: " + entryAddr);
        }
    }

    private static long readMem(Memory mem, Address a, int len) throws Exception {
        byte[] b = new byte[len];
        mem.getBytes(a, b);
        long v = 0;
        for (byte x : b) {
            v = (v << 8) | (x & 0xff);
        }
        return v;
    }

    private static void writeMem(Memory mem, Address a, int len, long v) throws Exception {
        byte[] b = new byte[len];
        for (int i = len - 1; i >= 0; i--) {
            b[i] = (byte) (v & 0xff);
            v >>= 8;
        }
        mem.setBytes(a, b);
    }

    private void addExternal(Program program, String name) {
        if (extBase == null) {
            return; // no EXTERNAL block; already logged
        }
        try {
            program.getExternalManager().addExtLocation(
                "ZOS_IMPORTS", ZosUtil.sanitize(name, "EXT"),
                extBase.add(extCounter++), SourceType.IMPORTED);
        } catch (Exception e) {
            // best effort; duplicate externals are fine to ignore
        }
    }
}
