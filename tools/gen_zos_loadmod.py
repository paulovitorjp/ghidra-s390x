#!/usr/bin/env python3
"""gen_zos_loadmod.py -- build a synthetic classic MVS load module for loader testing.

The file layout is:
  [directory header block][member records...]

The directory header is a documented test extension (real entry points live
in the PDS directory, which a raw member dump does not carry):
  magic      8B  ASCII "ZOSLMOD1"
  version    u16BE = 1
  member     8B  EBCDIC Cp037, blank-padded
  entry_off  u32BE  module-relative offset of the entry point
  amode      u8
  rmode      u8
  nalias     u16BE, then nalias * 8B EBCDIC alias names

Member records follow SA22-7644 Appendix B (z/OS MVS Program Management:
Advanced Facilities) for the documented subset:
  CESD record  (ID X'20'): 5 items of 16 bytes (SD MAIN, LR MAIN, LR SUBR,
               SD DATA, ER EXTFN)
  control/text (ID X'01') for the MAIN code
  control/text (ID X'01') for the DATA adcons, followed by
  RLD record   (ID X'02'): 1 A-type item (DATA+0 -> SUBR),
               1 Q-type item (DATA+4 -> EXTFN, unresolved)
  SYM record   (ID X'40') and scatter/translation record (ID X'10'):
               ignored by the MVS loader; skipped via count fields
  EOM control record (ID X'0D')

The code is hand-assembled and verified against Capstone mnemonic-for-mnemonic
(see the encoding lesson in LOADERS.md).

Output: tests/zos_smoke.lmod
"""
import struct, sys
import os

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

OUT = os.path.join(REPO_ROOT, 'tests/zos_smoke.lmod')

# --- tiny assembler with fixups (same idiom as gen_elf_smoke.py) ------------
code = bytearray()
labels = {}
fixups = []

def emit(*bs):
    code.extend(bs)

def label(name):
    labels[name] = len(code)

def brasl_r14(target):
    off = len(code)
    emit(0xC0, 0xE5, 0, 0, 0, 0)
    fixups.append((off, 'i32', target))

def jh(target):
    off = len(code); emit(0xA7, 0x24, 0, 0); fixups.append((off, 'i16', target))

def j(target):
    off = len(code); emit(0xA7, 0xF4, 0, 0); fixups.append((off, 'i16', target))

def assemble():
    label('main')
    brasl_r14('subr')
    emit(0xA7, 0xFF, 0x00, 0x2A)   # cghi %r15,42
    jh('Lbig')
    emit(0xA7, 0xF8, 0x00, 0x00)   # lhi %r15,0
    j('Lend')
    label('Lbig')
    emit(0xA7, 0xF8, 0x00, 0x01)   # lhi %r15,1
    label('Lend')
    emit(0x07, 0xFE)               # br %r14
    label('subr')
    emit(0xA7, 0xF8, 0x00, 0x2B)   # lhi %r15,43
    emit(0x07, 0xFE)               # br %r14

def apply_fixups():
    for off, kind, name in fixups:
        target = labels[name]
        val = (target - off) // 2
        if kind == 'i32':
            assert -(2**31) <= val < 2**31
            code[off+2:off+6] = struct.pack('>i', val)
        else:
            assert -(2**15) <= val < 2**15
            code[off+2:off+4] = struct.pack('>h', val)

EXPECTED = ["brasl", "cghi", "jh", "lhi", "j", "lhi", "br", "lhi", "br"]

def capstone_check():
    from capstone import Cs, CS_ARCH_SYSZ, CS_MODE_BIG_ENDIAN
    md = Cs(CS_ARCH_SYSZ, CS_MODE_BIG_ENDIAN)
    insns = list(md.disasm(bytes(code), 0))
    for ins in insns:
        print("  0x%x:\t%s\t%s" % (ins.address, ins.mnemonic, ins.op_str))
    got = [i.mnemonic for i in insns]
    ok = True
    if got != EXPECTED:
        print("MNEMONIC MISMATCH:\n got: %s\n exp: %s" % (got, EXPECTED)); ok = False
    covered = [False] * len(code)
    for ins in insns:
        for i in range(ins.address, ins.address + ins.size):
            if covered[i]: print("OVERLAP at", i); ok = False
            covered[i] = True
    if not all(covered):
        print("UNCOVERED:", [i for i, c in enumerate(covered) if not c]); ok = False
    return ok

# --- record builders ----------------------------------------------------------
def cesd_item(name, typ, addr, length_or_id, flags13=0x38):
    item = bytearray(16)
    item[0:8] = name.encode('cp037').ljust(8, b'\x40')
    item[8] = typ
    item[9:12] = struct.pack('>I', addr)[1:4]
    item[12] = flags13
    item[13:16] = struct.pack('>I', length_or_id)[1:4]
    return bytes(item)

def cesd_record(items):
    rec = bytearray()
    rec.append(0x20)                       # identification
    rec.append(0x80)                       # flag: byte 12 = AMODE/RMODE/RSECT
    rec += b'\x00\x00'                     # spare
    rec += struct.pack('>H', 1)            # ESDID of first item
    rec += struct.pack('>H', len(items)*16)
    for it in items: rec += it
    return bytes(rec)

def control_record(rld_count, cesd_id, text_len, text_addr, ident=0x01):
    rec = bytearray()
    rec.append(ident)
    rec += b'\x00\x00'                     # spare
    rec.append(rld_count)                  # RLD/CTL-RLD records after next text
    rec += struct.pack('>H', 4)            # control-data length (CESDID+len)
    rec += b'\x00\x00'                     # zeros
    # CCW: cmd=READ(0x02), data address (24b), flags, reserved, count (16b)
    rec.append(0x02)
    rec += struct.pack('>I', text_addr)[1:4]
    rec += b'\x00\x00'
    rec += struct.pack('>H', text_len)
    rec += struct.pack('>H', cesd_id)
    rec += struct.pack('>H', text_len)
    return bytes(rec)

def rld_record(items):
    # items: (r, p, flag, addr); addr is the MODULE-RELATIVE offset of the
    # adcon (as IEWL emits it). On-disk item: R(2) P(2) flag(1) addr(3);
    # RLD byte count lives at record offset 6-7, data at offset 16.
    rec = bytearray()
    rec.append(0x02)                       # RLD identification
    rec += b'\x00\x00\x00'                 # spare
    rec += struct.pack('>H', 0)            # off 4-5: (no ID/length list here)
    rec += struct.pack('>H', len(items)*8) # off 6-7: RLD byte count
    rec += b'\x00'*8                       # spare
    for (r, p, flag, addr) in items:
        rec += struct.pack('>H', r)
        rec += struct.pack('>H', p)
        rec.append(flag)
        rec += struct.pack('>I', addr)[1:4]
    return bytes(rec)

def sym_record(subtype=0x80, data=b''):
    # SYM record (ID X'40', LY26-3901-1 Fig.52 "SYM Record--Ignored by the
    # Loader"): ID(1), subtype(1), count(2), data(count bytes).
    rec = bytearray()
    rec.append(0x40)
    rec.append(subtype)
    rec += struct.pack('>H', len(data))
    rec += data
    return bytes(rec)

def scatter_record(data=b''):
    # Scatter/translation record (ID X'10', LY26-3901-1 Fig.54
    # "Scatter/Translation Record--Ignored by the Loader"): ID(1)=0x10,
    # zero(1), count(2), data(count bytes).
    rec = bytearray()
    rec.append(0x10)
    rec.append(0x00)
    rec += struct.pack('>H', len(data))
    rec += data
    return bytes(rec)

def dir_header(member, entry_off, amode=64, rmode=64, aliases=()):
    h = bytearray()
    h += b'ZOSLMOD1'
    h += struct.pack('>H', 1)
    h += member.encode('cp037').ljust(8, b'\x40')[:8]
    h += struct.pack('>I', entry_off)
    h += bytes([amode, rmode])
    h += struct.pack('>H', len(aliases))
    for a in aliases:
        h += a.encode('cp037').ljust(8, b'\x40')[:8]
    return bytes(h)

# --- build --------------------------------------------------------------------
def build():
    assemble(); apply_fixups()
    print("Capstone disassembly of synthetic code:")
    if not capstone_check():
        sys.exit("capstone verification FAILED")

    code_len = len(code)
    subr_off = labels['subr']
    data_off = (code_len + 7) & ~7
    print("code_len=%d subr_off=%d data_off=%d" % (code_len, subr_off, data_off))

    # CESD items (ESDID 1..5)
    SD, LR, ER = 0x00, 0x03, 0x02
    items = [
        cesd_item('MAIN', SD, 0, code_len),        # 1
        cesd_item('MAIN', LR, 0, 0),               # 2 (entry label)
        cesd_item('SUBR', LR, subr_off, 0),        # 3
        cesd_item('DATA', SD, data_off, 8),        # 4
        cesd_item('EXTFN', ER, 0, 0),              # 5
    ]

    out = bytearray()
    out += dir_header('MAIN', 0, aliases=('MAIN',))
    out += cesd_record(items)
    out += control_record(0, 1, code_len, 0)
    out += bytes(code)
    # DATA text: adcon1 = DC A(SUBR) (module-relative), adcon2 = Q-type (unresolved)
    data = struct.pack('>II', subr_off, 0)
    out += control_record(1, 4, len(data), data_off)
    out += data
    out += rld_record([
        (3, 4, 0x0C, data_off + 0),   # A-type 4B +: R=SUBR, P=DATA
        (5, 4, 0x8C, data_off + 4),   # Q-type 4B unresolved: R=EXTFN, P=DATA
    ])
    # Records the MVS loader ignores (LY26-3901-1 Fig.52/Fig.54): the loader
    # must skip them via their count fields and keep the record scan aligned.
    out += sym_record(0x80, b'\x00' * 32)
    out += scatter_record(b'\x00' * 24)
    out += control_record(0, 0, 0, 0, ident=0x0D)  # EOM

    open(OUT, 'wb').write(bytes(out))
    print("wrote %s (%d bytes)" % (OUT, len(out)))
    return bytes(out)

if __name__ == '__main__':
    build()
