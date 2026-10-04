#!/usr/bin/env python3
"""gen_zos_pds.py -- build synthetic PDS directory + member files for loader testing.

Outputs (all under tests/):
  zos_pds.dir           raw PDS directory image: 256-byte blocks, entries:
                          PROG1  load module, basic section (RENT/REUS/EXEC,
                                 AMODE 31, RMODE ANY, EPA=0)
                          ALIAS1 alias of PROG1 (alias section: EPM=0, MNM=PROG1)
                          PROG2  scatter-format load module (scatter section)
                          PROG3  program-object-format entry (PDS2LFMT set)
                          PAD1   large entry placed in block 1 (tests the
                                 "entry never spans blocks" packing rule)
  zos_pds.lmod          "ZOSPDS21" header (PROG1's raw PDS2 entry) + a real
                        load-module member (same shape as gen_zos_loadmod.py:
                        CESD, control/text, RLD, SYM, scatter/translation, EOM)
  zos_pds_progobj.lmod  "ZOSPDS21" header (PROG3's PDS2LFMT entry) + dummy
                        member -> the loader must refuse it as a program object
  zos_pds_nobs.lmod     "ZOSPDS21" header whose entry has no basic section
                        (LUSR=0) -> the loader must refuse it
  zos_pds_0b.lmod       "ZOSPDS21" header (PROG1) + member containing an X'0B'
                        record -> the loader must refuse the record ID
  zos_pds_bad_trunc.dir malformed: entry claims more user data than fits in
                        the block -> PdsDirectory must refuse
  zos_pds_bad_len.dir   malformed: image not a multiple of 256 bytes

PDS2 entry layout follows the IHAPDS macro / IBM "z/OS MVS Program
Management: Advanced Facilities" Appendix E ("PDS directory entry format
on entry to STOW"): on-disk entry = 8B name + 3B TTRP + 1B indicator +
user data (2 * PDS2LUSR bytes). Load-module basic section = 21 bytes of
user data (TTRT/ZERO/TTRN/NL/ATR1/ATR2/STOR/FTBL/EPA/FTBO).
"""
import struct, sys
import os

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

T = os.path.join(REPO_ROOT, 'tests/')

# --- tiny assembler (same idiom as gen_zos_loadmod.py) -------------------------
code = bytearray(); labels = {}; fixups = []
def emit(*bs): code.extend(bs)
def label(n): labels[n] = len(code)
def brasl_r14(t):
    o = len(code); emit(0xC0,0xE5,0,0,0,0); fixups.append((o,'i32',t))
def jh(t):
    o = len(code); emit(0xA7,0x24,0,0); fixups.append((o,'i16',t))
def j(t):
    o = len(code); emit(0xA7,0xF4,0,0); fixups.append((o,'i16',t))
def assemble():
    label('main')
    brasl_r14('subr')
    emit(0xA7,0xFF,0x00,0x2A)   # cghi %r15,42
    jh('Lbig')
    emit(0xA7,0xF8,0x00,0x00)   # lhi %r15,0
    j('Lend')
    label('Lbig')
    emit(0xA7,0xF8,0x00,0x01)   # lhi %r15,1
    label('Lend')
    emit(0x07,0xFE)             # br %r14
    label('subr')
    emit(0xA7,0xF8,0x00,0x2B)   # lhi %r15,43
    emit(0x07,0xFE)             # br %r14
def apply_fixups():
    for off,kind,name in fixups:
        v = (labels[name]-off)//2
        if kind=='i32':
            assert -(2**31) <= v < 2**31; code[off+2:off+6]=struct.pack('>i',v)
        else:
            assert -(2**15) <= v < 2**15; code[off+2:off+4]=struct.pack('>h',v)
EXPECTED = ["brasl","cghi","jh","lhi","j","lhi","br","lhi","br"]
def capstone_check():
    from capstone import Cs, CS_ARCH_SYSZ, CS_MODE_BIG_ENDIAN
    md = Cs(CS_ARCH_SYSZ, CS_MODE_BIG_ENDIAN)
    insns = list(md.disasm(bytes(code),0))
    for i in insns: print("  0x%x:\t%s\t%s"%(i.address,i.mnemonic,i.op_str))
    got=[i.mnemonic for i in insns]; ok=True
    if got!=EXPECTED: print("MISMATCH:\n got:%s\n exp:%s"%(got,EXPECTED)); ok=False
    return ok

# --- load-module member builders (same record shapes as gen_zos_loadmod.py) ----
def cesd_item(name, typ, addr, length_or_id, flags13=0x38):
    item = bytearray(16)
    item[0:8] = name.encode('cp037').ljust(8, b'\x40')
    item[8] = typ
    item[9:12] = struct.pack('>I', addr)[1:4]
    item[12] = flags13
    item[13:16] = struct.pack('>I', length_or_id)[1:4]
    return bytes(item)

def cesd_record(items, last=False):
    rec = bytearray()
    rec.append(0x28 if last else 0x20)
    rec.append(0x80); rec += b'\x00\x00'
    rec += struct.pack('>H', 1)
    rec += struct.pack('>H', len(items)*16)
    for it in items: rec += it
    return bytes(rec)

def control_record(rld_count, cesd_id, text_len, text_addr, ident=0x01):
    rec = bytearray()
    rec.append(ident); rec += b'\x00\x00'
    rec.append(rld_count)
    rec += struct.pack('>H', 4); rec += b'\x00\x00'
    rec.append(0x02)
    rec += struct.pack('>I', text_addr)[1:4]
    rec += b'\x00\x00'
    rec += struct.pack('>H', text_len)
    rec += struct.pack('>H', cesd_id)
    rec += struct.pack('>H', text_len)
    return bytes(rec)

def rld_record(items):
    rec = bytearray()
    rec.append(0x02); rec += b'\x00\x00\x00'
    rec += struct.pack('>H', 0)
    rec += struct.pack('>H', len(items)*8)
    rec += b'\x00'*8
    for (r,p,flag,addr) in items:
        rec += struct.pack('>H', r); rec += struct.pack('>H', p)
        rec.append(flag); rec += struct.pack('>I', addr)[1:4]
    return bytes(rec)

def sym_record(data): return b'\x40\x80' + struct.pack('>H', len(data)) + data
def scatter_record(data): return b'\x10\x00' + struct.pack('>H', len(data)) + data

def build_member(with_0b=False):
    SD, LR, ER = 0x00, 0x03, 0x02
    Lc = len(code); subr_off = labels['subr']
    data_off = (Lc + 7) & ~7
    items = [
        cesd_item('MAIN', SD, 0, Lc),
        cesd_item('MAIN', LR, 0, 0),
        cesd_item('SUBR', LR, subr_off, 0),
        cesd_item('DATA', SD, data_off, 8),
        cesd_item('EXTFN', ER, 0, 0),
    ]
    out = bytearray()
    out += cesd_record(items)
    out += control_record(0, 1, Lc, 0)
    out += bytes(code)
    data = struct.pack('>II', subr_off, 0)
    out += control_record(1, 4, len(data), data_off)
    out += data
    out += rld_record([(3,4,0x0C,data_off),(5,4,0x8C,data_off+4)])
    if with_0b:
        # An X'0B' record: shaped like a CTL+RLD header; the loader must
        # refuse it on the record ID before interpreting the body.
        rec = bytearray(b'\x0b' + b'\x00'*15)
        out += bytes(rec)
    out += sym_record(b'\x00'*32)
    out += scatter_record(b'\x00'*24)
    out += control_record(0, 0, 0, 0, ident=0x0D)
    return bytes(out)

# --- PDS directory entry builders ----------------------------------------------
def pds_entry(name, ttrp=(0,0,1), alias=False, nttr=0, user_data=b''):
    e = bytearray()
    e += name.encode('cp037').ljust(8, b'\x40')[:8]
    e += bytes(ttrp)
    assert len(user_data) % 2 == 0
    indc = (0x80 if alias else 0) | ((nttr & 3) << 5) | ((len(user_data)//2) & 0x1F)
    e.append(indc)
    e += user_data
    return bytes(e)

def basic_user_data(epa=0, atr1=0xC2, atr2=0x00, ftb1=0x00, ftb2=0x18,
                    ttrt=(0,0,2), ttrn=(0,0,0), nl=0, stor=0x1000, ftbl=0x100,
                    pad=3):
    """21-byte basic section + `pad` zero bytes (real load libraries show
    24 bytes of user data: indicator 0x0C)."""
    ud = bytearray()
    ud += bytes(ttrt); ud.append(0); ud += bytes(ttrn); ud.append(nl)
    ud.append(atr1); ud.append(atr2)
    ud += struct.pack('>I', stor)[1:4]
    ud += struct.pack('>H', ftbl)
    ud += struct.pack('>I', epa)[1:4]
    ud += bytes([ftb1, ftb2, 0x00])   # FTB1/FTB2/FTB3
    ud += b'\x00' * pad
    assert len(ud) == 21 + pad
    return bytes(ud)

def scatter_section(slsz=16, ttsz=32, esdt=1, esdc=3):
    return struct.pack('>HHHH', slsz, ttsz, esdt, esdc)

def alias_section(epm=0, member='PROG1'):
    return struct.pack('>I', epm)[1:4] + member.encode('cp037').ljust(8, b'\x40')[:8]

def build_directory():
    # PROG1: basic load module entry, AMODE 31 / RMODE ANY
    # (FTB2 = PDSLRMOD(0x10) | PDSMAMOD=10(0x02))
    prog1_ud = basic_user_data(epa=0, atr1=0xC2, atr2=0x00, ftb2=0x1A)
    prog1 = pds_entry('PROG1', user_data=prog1_ud)
    # ALIAS1: alias of PROG1, basic + alias section (21 + 11 = 32 bytes)
    alias_ud = basic_user_data(epa=0, pad=0, ftb2=0x1A) \
        + alias_section(epm=0, member='PROG1')
    assert len(alias_ud) == 32
    alias1 = pds_entry('ALIAS1', alias=True, user_data=alias_ud)
    # PROG2: scatter-format load module, basic + scatter section
    # (21 + 8 = 29, odd -> 1 pad byte -> 30 bytes); AMODE 31 / RMODE 24
    scat_ud = basic_user_data(epa=8, atr1=0xC6, ttrn=(0,0,5), pad=0, ftb2=0x02) \
        + scatter_section() + b'\x00'
    assert len(scat_ud) == 30
    prog2 = pds_entry('PROG2', user_data=scat_ud)
    # PROG3: program-object-format member (PDS2LFMT in FTB1)
    prog3_ud = basic_user_data(epa=0, ftb1=0x04, ftb2=0x02)
    prog3 = pds_entry('PROG3', user_data=prog3_ud)
    # PAD0: 62 user-data bytes -> 74-byte entry; 158 + 74 = 232, leaving
    # 24 bytes in block 0 (too small for another 74-byte entry).
    pad0 = pds_entry('PAD0', user_data=b'\xA0'*62)
    # PAD1: same size; does NOT fit in block 0's remaining 24 bytes -> it
    # must start block 1 (entries never span blocks).
    pad1 = pds_entry('PAD1', user_data=b'\xAA'*62)

    blk0 = bytearray(256); blk1 = bytearray(256)
    o = 0
    for e in (prog1, alias1, prog2, prog3, pad0):
        blk0[o:o+len(e)] = e; o += len(e)
    # o = 36+44+42+36+74 = 232; PAD1 is 74 bytes and does not fit in the
    # remaining 24 -> it must start block 1.
    assert o == 232 and len(pad1) == 74 and 256 - o < len(pad1)
    blk1[0:len(pad1)] = pad1
    blk1[len(pad1):len(pad1)+8] = b'\xFF'*8   # end-of-directory marker
    img = bytes(blk0) + bytes(blk1)
    open(T+'zos_pds.dir','wb').write(img)
    print("wrote %szos_pds.dir (%d bytes, 2 blocks)" % (T, len(img)))
    return prog1, prog3

def pds_header(entry):
    h = bytearray()
    h += b'ZOSPDS21'
    h += struct.pack('>H', 1)
    h += struct.pack('>H', len(entry))
    h += entry
    return bytes(h)

def build():
    assemble(); apply_fixups()
    print("Capstone disassembly of synthetic code:")
    if not capstone_check(): sys.exit("capstone verification FAILED")
    prog1, prog3 = build_directory()

    member = build_member()
    open(T+'zos_pds.lmod','wb').write(pds_header(prog1) + member)
    print("wrote %szos_pds.lmod" % T)

    open(T+'zos_pds_progobj.lmod','wb').write(pds_header(prog3) + b'\x00'*64)
    print("wrote %szos_pds_progobj.lmod (PDS2LFMT: loader must refuse)" % T)

    # entry with no basic section (LUSR=0 -> 0 user-data bytes)
    no_basic = pds_entry('NOBS', user_data=b'')
    open(T+'zos_pds_nobs.lmod','wb').write(pds_header(no_basic) + member)
    print("wrote %szos_pds_nobs.lmod (no basic section: loader must refuse)" % T)

    open(T+'zos_pds_0b.lmod','wb').write(pds_header(prog1) + build_member(with_0b=True))
    print("wrote %szos_pds_0b.lmod (X'0B' record: loader must refuse)" % T)

    # malformed directory: entry at offset 0 has PDS2SCTR set in ATR1 but
    # only 24 user-data bytes -> the 8-byte scatter section does not fit
    bad = bytearray(256)
    e = pds_entry('BAD', user_data=basic_user_data(atr1=0xC6, pad=3))
    assert len(e) == 36
    bad[0:len(e)] = e
    open(T+'zos_pds_bad_trunc.dir','wb').write(bytes(bad))
    print("wrote %szos_pds_bad_trunc.dir" % T)

    open(T+'zos_pds_bad_len.dir','wb').write(b'\x00'*100)
    print("wrote %szos_pds_bad_len.dir" % T)

if __name__ == '__main__':
    build()
