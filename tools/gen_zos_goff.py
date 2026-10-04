#!/usr/bin/env python3
"""gen_zos_goff.py -- build a synthetic GOFF object file for loader testing.

80-byte records per SA22-7644 Appendix C (z/OS MVS Program Management:
Advanced Facilities), documented subset:
  HDR : PTV X'03F000', architecture level 1
  ESD : SD "MAIN" (id 1), ED "C_CODE" (id 2, parent 1, length = code+8),
        LD "ENTRY" (id 3, parent 2, offset 0), LD "SUBR" (id 4, parent 2,
        offset subr_off), ER "EXTFN" (id 5, parent 1)
  TXT : byte-oriented style, element 2, offset 0: code + 2 adcons
  RLD : 1 A-type item (element 2, offset Lc -> element 2 base),
        1 Q-type item (element 2, offset Lc+4 -> EXTFN, unresolved)
  END : entry point by ESDID+offset (element 2, offset 0)

The code is hand-assembled and verified against Capstone
mnemonic-for-mnemonic (see the encoding lesson in LOADERS.md).

Output: tests/zos_smoke.goff
"""
import struct, sys
import os

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

OUT = os.path.join(REPO_ROOT, 'tests/zos_smoke.goff')
RECLEN = 80

# --- tiny assembler (same idiom as gen_elf_smoke.py) ---------------------------
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
    emit(0xA7, 0xFF, 0x00, 0x2A)   # cghi %r15,42
    jh('Lbig')
    emit(0xA7, 0xF8,0x00,0x00)   # lhi %r15,0
    j('Lend')
    label('Lbig')
    emit(0xA7, 0xF8,0x00,0x01)   # lhi %r15,1
    label('Lend')
    emit(0x07,0xFE)             # br %r14
    label('subr')
    emit(0xA7, 0xF8,0x00,0x2B)   # lhi %r15,43
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
    cov=[False]*len(code)
    for ins in insns:
        for x in range(ins.address,ins.address+ins.size):
            if cov[x]: print("OVERLAP",x); ok=False
            cov[x]=True
    if not all(cov): print("UNCOVERED"); ok=False
    return ok

# --- GOFF records ---------------------------------------------------------------
def pad80(rec):
    assert len(rec) <= RECLEN, len(rec)
    return bytes(rec) + b'\x00'*(RECLEN-len(rec))

def hdr_record():
    r = bytearray()
    r += bytes([0x03,0xF0,0x00])   # PTV
    r += b'\x00'*45                # reserved 3-47
    r += struct.pack('>I',1)       # arch level 48-51
    r += struct.pack('>H',0)       # module properties length 52-53
    r += b'\x00'*6                 # reserved 54-59
    return pad80(r)

def esd_record(symtype, esdid, parent, offset, length, name):
    r = bytearray()
    r += bytes([0x03,0x00,0x00])   # PTV (not continued)
    r.append(symtype)
    r += struct.pack('>I',esdid)
    r += struct.pack('>I',parent)
    r += b'\x00'*4                 # reserved 12-15
    r += struct.pack('>I',offset)  # 16-19
    r += b'\x00'*4                 # reserved 20-23
    r += struct.pack('>I',length)  # 24-27
    r += b'\x00'*4                 # ext attr ESDID 28-31
    r += b'\x00'*4                 # ext attr offset 32-35
    r += b'\x00'*4                 # reserved 36-39
    r.append(1)                    # namespace 40 = normal external names
    r += b'\x00\x00\x00'           # fill/mangled/rename flags, fill byte 41-43
    r += b'\x00'*4                 # assoc data id 44-47
    r += b'\x00'*4                 # priority 48-51
    r += b'\x00'*8                 # reserved 52-59
    r += b'\x00'*10                # behavioral attributes 60-69 (ignored by loader)
    nb = name.encode('cp037')
    r += struct.pack('>H',len(nb)) # name length 70-71
    r += nb                        # name 72-*
    return pad80(r)

def txt_record(esdid, offset, data):
    r = bytearray()
    r += bytes([0x03,0x10,0x00])   # PTV
    r.append(0x00)                 # byte3: style B'0000' = byte-oriented
    r += struct.pack('>I',esdid)   # element ESDID 4-7
    r += b'\x00'*4                 # reserved 8-11
    r += struct.pack('>I',offset)  # offset 12-15
    r += struct.pack('>I',0)       # true length 16-19
    r += struct.pack('>H',0)       # encoding 20-21
    r += struct.pack('>H',len(data))  # data length 22-23
    r += data                      # data 24-*
    return pad80(r)

def rld_item(flags6, rptr, pptr, offset):
    it = bytearray()
    it += bytes(flags6)            # 0-5
    it += b'\x00\x00'              # reserved 6-7
    it += struct.pack('>I',rptr)   # R pointer 8-11
    it += struct.pack('>I',pptr)   # P pointer 12-15
    it += struct.pack('>I',offset) # offset 16-19
    it += b'\x00'*8                # reserved 20-27
    return bytes(it)

def rld_record(items):
    data = b''.join(items)
    r = bytearray()
    r += bytes([0x03,0x20,0x00])   # PTV
    r.append(0x00)                 # reserved
    r += struct.pack('>H',len(data))
    r += data
    return pad80(r)

def end_record(esdid, offset, recount):
    r = bytearray()
    r += bytes([0x03,0x40,0x00])   # PTV
    r.append(0x40)                 # byte3: flags B'01' = entry by ESDID+offset
    r.append(0x00)                 # AMODE (0 = unspecified in synthetic file)
    r += b'\x00\x00'               # reserved 5-7
    r += struct.pack('>I',recount) # record count 8-11
    r += struct.pack('>I',esdid)   # ESDID 12-15
    r += b'\x00'*4                 # reserved 16-19
    r += struct.pack('>I',offset)  # offset 20-23
    r += struct.pack('>H',0)       # name length 24-25
    return pad80(r)

def build():
    assemble(); apply_fixups()
    print("Capstone disassembly of synthetic code:")
    if not capstone_check(): sys.exit("capstone verification FAILED")
    Lc = len(code); subr_off = labels['subr']
    elem = bytes(code) + struct.pack('>II', subr_off, 0)  # adcon1=A(SUBR), adcon2=Q
    print("code_len=%d subr_off=%d elem_len=%d"%(Lc,subr_off,len(elem)))

    recs = []
    recs.append(hdr_record())
    SD,ED,LD,ER = 0x00,0x01,0x02,0x04
    recs.append(esd_record(SD,1,0,0,0,'MAIN'))
    recs.append(esd_record(ED,2,1,0,len(elem),'C_CODE'))
    recs.append(esd_record(LD,3,2,0,0,'ENTRY'))
    recs.append(esd_record(LD,4,2,subr_off,0,'SUBR'))
    recs.append(esd_record(ER,5,1,0,0,'EXTFN'))
    recs.append(txt_record(2,0,elem))
    # A-con: byte1 = ref type 0 (R-address, bits 1.0-3) | referent 1
    # (element, bits 1.4-7); action + (0), fetch (bit 2.7 = 0),
    # target byte length 4
    a_flags = [0x00,0x01,0x00,0x00,0x04,0x00]
    # Q-con (external): same shape; loader treats R->ER as external ref
    q_flags = [0x00,0x01,0x00,0x00,0x04,0x00]
    recs.append(rld_record([
        rld_item(a_flags,2,2,Lc),
        rld_item(q_flags,5,2,Lc+4),
    ]))
    recs.append(end_record(2,0,len(recs)+1))
    img = b''.join(recs)
    open(OUT,'wb').write(img)
    print("wrote %s (%d bytes, %d records)"%(OUT,len(img),len(recs)))

if __name__=='__main__':
    build()
