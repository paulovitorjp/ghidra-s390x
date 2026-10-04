// ZosLoadModuleLoader.java -- Ghidra loader for classic MVS/z/OS load modules.
//
// Parses the documented subset of SA22-7644 Appendix B ("Load module
// formats"), cross-checked against IBM MVS/XA Loader Logic LY26-3901-1
// (record layouts) and Service Aids Logic LY28-1189-2 (RLD flag byte):
// CESD records (X'20'), control/text records (X'01'/X'05'/X'0D'),
// RLD records (X'02'/X'06'/X'0E'), combined CTL+RLD (X'03'/X'07'/X'0F'),
// plus SYM (X'40'), IDR (X'80') and scatter/translation (X'10') records
// which the MVS loader itself ignores and are skipped here.
// Supported RLD item types: A-type (non-branch) and V-type (branch)
// 2/3/4-byte adcons (relocated by the image load bias),
// Q-type (unresolved external: symbol recorded, value left alone).
// CTL+RLD record X'0B' is rejected with a clear error: X'0B' is not a
// defined load-module record ID (IBM "z/OS MVS Program Management:
// Advanced Facilities" Appendix B, Figs. 15-17, enumerates control IDs
// X'01'/X'05'/X'0D', RLD IDs X'02'/X'06'/X'0E' and CTL+RLD IDs
// X'03'/X'07'/X'0F' only; public-domain linkage-editor source agrees), so it
// is refused rather than guessed at.
//
// Entry point: a real load module member does NOT carry its entry point;
// it lives in the PDS directory entry (PDS2EPA/PDS2EPM). This loader
// accepts an optional raw PDS directory entry prepended to the member
// bytes (see tools/gen_zos_pds.py and LOADERS.md):
//   "ZOSPDS21" u16BE version u16BE entryLen u8[entryLen] raw PDS2 entry
// (on-disk format: 8B name + 3B TTRP + 1B indicator + user data, as parsed
// by PdsDirectory). The entry point comes from PDS2EPA (or PDS2EPM for
// alias entries with an alias section); module attributes (overlay,
// scatter, AMODE/RMODE, program-object-format flag PDS2LFMT) are honored:
// a PDS2LFMT entry is refused as a program object, and overlay/scatter
// modules get an explicit warning that relocation is applied flat.
// The older "ZOSLMOD1" test header is still accepted as a fallback.
// Without any header the whole file is parsed as the member and the entry
// defaults to the first LR item (else offset 0).
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
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class ZosLoadModuleLoader extends AbstractLibrarySupportLoader {

    public static final String LOADER_NAME = "z/OS MVS Load Module";
    public static final String IMAGE_BASE_OPTION = "Image Base (hex)";
    public static final String DEFAULT_IMAGE_BASE = "0x10000";
    public static final String DIR_MAGIC = "ZOSLMOD1";
    /** Magic for the raw-PDS-directory-entry header (see class javadoc). */
    public static final String PDS_MAGIC = "ZOSPDS21";

    // CESD item types (Figure 13)
    private static final int T_SD = 0x00, T_LR = 0x03, T_PC = 0x04, T_ER = 0x02, T_WX = 0x0A;

    private static class CesdItem {
        String name; int type; int addr; int len; int esdId;
    }

    private static class TextChunk {
        int addr; byte[] data;
    }

    private static class RldItem {
        int flag, p, r, addr;
    }

    /**
     * Parse RLD items from a record's RLD data area. Each item is
     * R-pointer(2) + P-pointer(2) + flag(1) + address(3); when the previous
     * item's flag has bit 0x01 (SAMERP) set, the next item is a 4-byte
     * continuation (flag + address) reusing the same R and P pointers.
     */
    private static void parseRldItems(byte[] img, int off, int rldLen,
            List<RldItem> rlds, MessageLog log) throws LoadException {
        int end = off + rldLen;
        if (end > img.length) {
            throw new LoadException("RLD data overruns image");
        }
        int p = 0, r = 0; // carried across continuation items
        boolean sameRP = false;
        int o = off;
        while (o < end) {
            if (!sameRP) {
                if (o + 8 > end) {
                    throw new LoadException("truncated RLD item at offset 0x" +
                        Integer.toHexString(o));
                }
                r = ZosUtil.u16(img, o);
                p = ZosUtil.u16(img, o + 2);
                o += 4;
            } else {
                if (o + 4 > end) {
                    throw new LoadException("truncated RLD continuation at offset 0x" +
                        Integer.toHexString(o));
                }
            }
            RldItem it = new RldItem();
            it.flag = img[o] & 0xff;
            it.p = p;
            it.r = r;
            it.addr = ZosUtil.u24(img, o + 1);
            rlds.add(it);
            sameRP = (it.flag & 0x01) != 0;
            o += 4;
        }
    }

    private int extCounter = 0;
    private Address extBase = null;

    @Override
    public String getName() {
        return LOADER_NAME;
    }

    @Override
    public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
        if (provider.length() < 16) {
            return Collections.emptyList();
        }
        byte[] head = provider.readBytes(0, 16);
        boolean magic = true;
        for (int i = 0; i < 8; i++) {
            if (head[i] != (byte) DIR_MAGIC.charAt(i)) { magic = false; break; }
        }
        boolean pdsMagic = true;
        for (int i = 0; i < 8; i++) {
            if (head[i] != (byte) PDS_MAGIC.charAt(i)) { pdsMagic = false; break; }
        }
        boolean looksLikeCesd = (head[0] & 0xff) == 0x20;
        if (!magic && !pdsMagic && !looksLikeCesd) {
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

        byte[] img = provider.readBytes(0, provider.length());
        int pos = 0;

        // ---- optional directory header ----
        String memberName = null;
        long entryOff = -1;
        List<String> aliases = new ArrayList<>();
        String asciiHead = img.length >= 8
            ? new String(img, 0, 8, java.nio.charset.StandardCharsets.US_ASCII) : "";
        if (img.length >= 12 && asciiHead.equals(PDS_MAGIC)) {
            // Raw PDS directory entry header: "ZOSPDS21" u16BE version
            // u16BE entryLen u8[entryLen] on-disk PDS2 entry, then member.
            int version = ZosUtil.u16(img, 8);
            int entryLen = ZosUtil.u16(img, 10);
            if (version != 1) {
                throw new LoadException("unsupported " + PDS_MAGIC +
                    " header version " + version);
            }
            if (12 + entryLen > img.length) {
                throw new LoadException(PDS_MAGIC +
                    " header entry overruns file");
            }
            PdsDirectory.PdsEntry de;
            try {
                de = PdsDirectory.parseEntry(img, 12, 12 + entryLen);
            } catch (PdsDirectory.PdsFormatException e) {
                throw new LoadException("bad PDS directory entry in " +
                    PDS_MAGIC + " header: " + e.getMessage());
            }
            pos = 12 + entryLen;
            memberName = de.name;
            if (de.lm == null) {
                throw new LoadException("PDS directory entry for '" + de.name +
                    "' has no load-module basic section (" + de.userData.length +
                    " user-data bytes)");
            }
            PdsDirectory.LoadModuleInfo lm = de.lm;
            if (lm.isProgramObject()) {
                // PDS2LFMT: the member is stored in program object format,
                // not as a classic load module.
                throw new LoadException("PDS member '" + de.name +
                    "' is stored in program object format (PDS2LFMT set); " +
                    "classic load-module parsing does not apply. " +
                    "See LOADERS.md section 6.");
            }
            entryOff = (de.alias && lm.hasAlias) ? lm.epm : lm.epa;
            if (de.alias) {
                aliases.add(lm.memberName != null ? lm.memberName : "?");
            }
            log.appendMsg("PDS directory entry: member=" + de.name +
                (de.alias ? " (alias of " + aliases + ")" : "") +
                " entryOff=0x" + Long.toHexString(entryOff) +
                " amode=" + lm.amode(de.alias) + " rmode=" + lm.rmode() +
                " attrs=" + pdsAttrs(lm));
            if (lm.isOverlay()) {
                log.appendMsg("WARNING: module is in overlay structure " +
                    "(PDS2OVLY); RLD relocation is applied flat against the " +
                    "image base, not per overlay-segment origin. " +
                    "Segment-aware relocation is not implemented.");
            }
            if (lm.isScatter()) {
                log.appendMsg("WARNING: module is in scatter format " +
                    "(PDS2SCTR); scatter/translation tables are skipped and " +
                    "text is loaded flat. Scatter loading is not implemented.");
            }
        } else if (img.length >= 26 && asciiHead.equals(DIR_MAGIC)) {
            memberName = ZosUtil.ebcdicName(img, 10, 8);
            entryOff = ZosUtil.u32(img, 18);
            int nalias = ZosUtil.u16(img, 24);
            pos = 26;
            if (nalias < 0 || pos + 8L * nalias > img.length) {
                throw new LoadException(DIR_MAGIC +
                    " header claims " + nalias + " aliases but the file is too short");
            }
            for (int i = 0; i < nalias; i++) {
                aliases.add(ZosUtil.ebcdicName(img, pos, 8));
                pos += 8;
            }
            log.appendMsg("PDS directory header: member=" + memberName +
                " entryOff=0x" + Long.toHexString(entryOff) + " aliases=" + aliases);
        }

        // ---- record scan ----
        List<CesdItem> cesd = new ArrayList<>();
        List<TextChunk> texts = new ArrayList<>();
        List<RldItem> rlds = new ArrayList<>();
        int esdIdBase = 1;

        while (pos < img.length) {
            int id = img[pos] & 0xff;
            switch (id) {
                case 0x20: case 0x28: { // CESD (0x28 = last CESD of module)
                    int count = ZosUtil.u16(img, pos + 6);
                    int firstId = ZosUtil.u16(img, pos + 4);
                    int n = count / 16;
                    for (int i = 0; i < n; i++) {
                        int o = pos + 8 + i * 16;
                        if (o + 16 > img.length) break;
                        CesdItem it = new CesdItem();
                        it.name = ZosUtil.ebcdicName(img, o, 8);
                        it.type = img[o + 8] & 0x0f;
                        it.addr = ZosUtil.u24(img, o + 9);
                        it.len = ZosUtil.u24(img, o + 13);
                        it.esdId = firstId + i;
                        cesd.add(it);
                    }
                    esdIdBase = firstId;
                    pos += 8 + count;
                    break;
                }
                case 0x01: case 0x05: case 0x0D: { // control (+EOS/+EOM)
                    int ctlLen = ZosUtil.u16(img, pos + 4);
                    int ccwAddr = ZosUtil.u24(img, pos + 9);
                    int ccwCount = ZosUtil.u16(img, pos + 14);
                    int hdrLen = 16 + ctlLen;
                    pos += hdrLen;
                    if (ccwCount > 0) {
                        if (pos + ccwCount > img.length) {
                            throw new LoadException("truncated text record at 0x" +
                                Integer.toHexString(pos));
                        }
                        TextChunk t = new TextChunk();
                        t.addr = ccwAddr;
                        t.data = Arrays.copyOfRange(img, pos, pos + ccwCount);
                        texts.add(t);
                        pos += ccwCount;
                    }
                    if (id == 0x0D) {
                        pos = img.length; // EOM
                    }
                    break;
                }
                case 0x02: case 0x06: case 0x0E: { // RLD-only record
                    // 16-byte control header: RLD byte count at off 6-7, RLD data at off 16.
                    // Item: R-ptr(2) P-ptr(2) flag(1) addr(3); a 4-byte continuation
                    // (flag+addr, same R&P) follows when the previous flag has 0x01 set.
                    int rldLen = ZosUtil.u16(img, pos + 6);
                    parseRldItems(img, pos + 16, rldLen, rlds, log);
                    pos += 16 + rldLen;
                    break;
                }
                case 0x03: case 0x07: case 0x0F: { // combined CTL+RLD: RLD info first,
                    // then the ID/length list, then the text record follows
                    int rldLen = ZosUtil.u16(img, pos + 6);
                    int idLen = ZosUtil.u16(img, pos + 4);
                    parseRldItems(img, pos + 16, rldLen, rlds, log);
                    int ccwAddr = ZosUtil.u24(img, pos + 9);
                    int ccwCount = ZosUtil.u16(img, pos + 14);
                    pos += 16 + rldLen + idLen;
                    if (ccwCount > 0) {
                        if (pos + ccwCount > img.length) {
                            throw new LoadException("combined CTL+RLD text overruns image");
                        }
                        TextChunk t = new TextChunk();
                        t.addr = ccwAddr;
                        t.data = Arrays.copyOfRange(img, pos, pos + ccwCount);
                        texts.add(t);
                        pos += ccwCount;
                    }
                    if (id == 0x0F) {
                        pos = img.length; // EOM
                    }
                    break;
                }
                case 0x0B:
                    // Refused: X'0B' is not a defined load-module record ID.
                    // IBM "z/OS MVS Program Management: Advanced Facilities",
                    // Appendix B, Figs. 15-17, enumerates the record
                    // identification bytes exhaustively: control X'01'/X'05'/
                    // X'0D', RLD X'02'/X'06'/X'0E', CTL+RLD X'03'/X'07'/X'0F'.
                    // The public-domain linkage-editor source likewise
                    // defines only 01/02/03/05/06/07/0D/0E/0F. There is no
                    // authoritative definition of an X'0B' record's layout or
                    // relocation semantics, so it is refused rather than
                    // guessed at. (Overlay modules use the defined X'05'/X'06'/
                    // X'07' "last of segment" IDs; correct overlay relocation
                    // additionally needs per-segment origins from the overlay
                    // note list, which this loader does not implement.)
                    throw new LoadException(
                        "load-module record ID 0x0B at offset 0x" +
                        Integer.toHexString(pos) + " is not a defined " +
                        "load-module record ID (see LOADERS.md); refusing");
                case 0x10: { // scatter/translation (overlay programs)
                    // The MVS loader itself ignores these records (LY26-3901-1
                    // Fig.54 "Scatter/Translation Record--Ignored by the
                    // Loader"): they carry the loader's translation/scatter
                    // tables, not program text. Layout: ID(1)=0x10,
                    // zero(1), count(2), data(count bytes); skip via count.
                    if (pos + 4 > img.length) {
                        throw new LoadException(
                            "truncated scatter/translation record at 0x" +
                            Integer.toHexString(pos));
                    }
                    if ((img[pos + 1] & 0xff) != 0) {
                        log.appendMsg("0x10 record with nonzero byte 1 " +
                            "(not a documented scatter/translation record); " +
                            "skipping via count field");
                    }
                    int skip = 4 + ZosUtil.u16(img, pos + 2);
                    if (pos + skip > img.length) {
                        throw new LoadException(
                            "scatter/translation record overruns image at 0x" +
                            Integer.toHexString(pos));
                    }
                    log.appendMsg("skipped scatter/translation record (" +
                        (skip - 4) + " data bytes)");
                    pos += skip;
                    break;
                }
                case 0x40: { // SYM (TEST symbol table)
                    // Likewise ignored by the MVS loader (LY26-3901-1 Fig.52
                    // "SYM Record--Ignored by the Loader"). Layout:
                    // ID(1)=0x40, subtype(1), count(2), data(count bytes).
                    if (pos + 4 > img.length) {
                        throw new LoadException("truncated SYM record at 0x" +
                            Integer.toHexString(pos));
                    }
                    int skip = 4 + ZosUtil.u16(img, pos + 2);
                    if (pos + skip > img.length) {
                        throw new LoadException("SYM record overruns image at 0x" +
                            Integer.toHexString(pos));
                    }
                    pos += skip;
                    break;
                }
                case 0x80: { // IDR: byte 1 is record length minus 1
                    if (pos + 2 > img.length) {
                        throw new LoadException("truncated IDR record at 0x" +
                            Integer.toHexString(pos));
                    }
                    int skip = 1 + (img[pos + 1] & 0xff);
                    if (pos + skip > img.length) {
                        throw new LoadException("IDR record overruns image at 0x" +
                            Integer.toHexString(pos));
                    }
                    pos += skip;
                    break;
                }
                default:
                    throw new LoadException("unknown load-module record ID 0x" +
                        Integer.toHexString(id) + " at offset 0x" + Integer.toHexString(pos));
            }
            monitor.checkCancelled();
        }

        Map<Integer, CesdItem> byId = new HashMap<>();
        for (CesdItem it : cesd) {
            byId.put(it.esdId, it);
        }

        // ---- memory blocks, one per SD/PC csect ----
        Memory mem = program.getMemory();
        Set<String> usedNames = new HashSet<>();
        for (CesdItem it : cesd) {
            if ((it.type == T_SD || it.type == T_PC) && it.len > 0) {
                String bn = ZosUtil.sanitize(it.name, "CSECT" + it.esdId);
                int k = 2;
                while (!usedNames.add(bn)) bn = ZosUtil.sanitize(it.name, "C") + "_" + (k++);
                Address start = program.getAddressFactory().getDefaultAddressSpace()
                    .getAddress(imageBase + it.addr);
                try {
                    mem.createInitializedBlock(bn, start, it.len, (byte) 0, monitor, false);
                } catch (Exception e) {
                    log.appendMsg("could not create block " + bn + ": " + e.getMessage());
                }
            }
        }

        // ---- write text ----
        // Text chunks are module-contiguous but CSECT blocks may have gaps
        // (alignment padding); clip each chunk to the created blocks.
        for (TextChunk t : texts) {
            long tStart = imageBase + t.addr;
            long tEnd = tStart + t.data.length;
            for (MemoryBlock b : mem.getBlocks()) {
                long bStart = b.getStart().getOffset();
                long bEnd = bStart + b.getSize();
                long s = Math.max(tStart, bStart);
                long e = Math.min(tEnd, bEnd);
                if (s < e) {
                    try {
                        mem.setBytes(
                            program.getAddressFactory().getDefaultAddressSpace()
                                .getAddress(s),
                            t.data, (int) (s - tStart), (int) (e - s));
                    } catch (Exception ex) {
                        log.appendMsg("could not write text at 0x" +
                            Long.toHexString(s) + ": " + ex.getMessage());
                    }
                }
            }
        }

        // ---- external block for unresolved imports ----
        try {
            extBase = MemoryBlockUtils.addExternalBlock(program, 0x1000, log);
        } catch (Exception e) {
            log.appendMsg("could not create EXTERNAL block: " + e.getMessage());
        }

        // ---- symbols ----
        SymbolTable st = program.getSymbolTable();
        for (CesdItem it : cesd) {
            try {
                Address a = program.getAddressFactory().getDefaultAddressSpace()
                    .getAddress(imageBase + it.addr);
                if (it.type == T_LR) {
                    st.createLabel(a, ZosUtil.sanitize(it.name, "LR" + it.esdId),
                        SourceType.IMPORTED);
                } else if (it.type == T_ER || it.type == T_WX) {
                    addExternal(program, log, it.name);
                }
            } catch (Exception e) {
                log.appendMsg("symbol " + it.name + ": " + e.getMessage());
            }
        }

        // ---- relocations ----
        int applied = 0, skipped = 0;
        for (RldItem r : rlds) {
            // Flag byte is xxxx LL S T, bit 0 = MSB (LY28-1189-2 RLDTAB):
            //   xxxx = 0000 A-type (DC A), 0001 V-type (DC V): relocate by
            //          adding/subtracting R's load bias;
            //   xxxx = 0010/0011 pseudo-register, 1000/1001 unresolved (Q-type):
            //          do NOT replace the adcon value (record the external).
            //   LL = 01/10/11 -> 2/3/4 bytes; S = 0 add, 1 subtract;
            //   T = 1 -> next item reuses this item's R and P (continuation).
            boolean noReloc = (r.flag & 0xe0) != 0;
            CesdItem pItem = byId.get(r.p);
            CesdItem rItem = byId.get(r.r);
            if (pItem == null || rItem == null) {
                log.appendMsg("RLD with bad P/R pointers: P=" + r.p + " R=" + r.r);
                skipped++;
                continue;
            }
            // The RLD address is the adcon's offset within the module
            // (module-relative, not P-relative: IEWL assigns final offsets).
            Address adconAddr = program.getAddressFactory().getDefaultAddressSpace()
                .getAddress(imageBase + r.addr);
            int ll = (r.flag >> 2) & 0x3;
            int len = ll + 1; // LL encodes length-1
            if (ll == 0) {
                log.appendMsg("RLD with unsupported length code 0 at P=" + r.p);
                skipped++;
                continue;
            }
            try {
                if (noReloc || rItem.type == T_ER || rItem.type == T_WX) {
                    addExternal(program, log, rItem.name);
                    skipped++; // value left unresolved, external recorded
                    continue;
                }
                long oldVal = readMem(mem, adconAddr, len);
                long newVal = (((r.flag >> 1) & 1) == 1) ? oldVal - imageBase : oldVal + imageBase;
                writeMem(mem, adconAddr, len, newVal);
                applied++;
            } catch (Exception e) {
                log.appendMsg("RLD apply failed at 0x" +
                    Long.toHexString(imageBase + r.addr) + ": " + e.getMessage());
                skipped++;
            }
        }
        log.appendMsg("relocations: applied=" + applied + " skipped/unresolved=" + skipped);

        // ---- entry point ----
        long entry = imageBase + (entryOff >= 0 ? entryOff : 0);
        if (entryOff < 0) {
            for (CesdItem it : cesd) {
                if (it.type == T_LR) { entry = imageBase + it.addr; break; }
            }
        }
        Address entryAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(entry);
        st.addExternalEntryPoint(entryAddr);
        // NOTE: no function is created here; auto-analysis (or the caller)
        // disassembles the entry region and creates functions from the flow.
        log.appendMsg("entry point: 0x" + Long.toHexString(entry) +
            (memberName != null ? " member=" + memberName : ""));
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

    /** Human-readable PDS2ATR1/ATR2 attribute flags for the log. */
    private static String pdsAttrs(PdsDirectory.LoadModuleInfo lm) {
        StringBuilder sb = new StringBuilder();
        if (lm.isReentrant()) sb.append("RENT,");
        if (lm.isReusable()) sb.append("REUS,");
        if (lm.isOverlay()) sb.append("OVLY,");
        if (lm.isScatter()) sb.append("SCTR,");
        if (lm.isExecutable()) sb.append("EXEC,");
        if ((lm.atr1 & 0x10) != 0) sb.append("TEST,");
        if ((lm.atr1 & 0x08) != 0) sb.append("LOADONLY,");
        if ((lm.atr2 & 0x10) != 0) sb.append("NORLD,");
        if (sb.length() > 0) sb.setLength(sb.length() - 1);
        return sb.toString();
    }

    private void addExternal(Program program, MessageLog log, String name) {        if (extBase == null) {
            log.appendMsg("external " + name + ": no EXTERNAL block, skipped");
            return;
        }
        try {
            program.getExternalManager().addExtLocation(
                "ZOS_IMPORTS", ZosUtil.sanitize(name, "EXT"),
                extBase.add(extCounter++), SourceType.IMPORTED);
        } catch (Exception e) {
            log.appendMsg("external " + name + ": " + e.getMessage());
        }
    }
}
