#!/usr/bin/env python3
"""gen_zos_goff_cont.py -- synthetic GOFF object with CONTINUED records.

Exercises ZosGoffLoader continuation chaining. PTV byte-1 low two bits
(SA22-7644 Appendix C): 01 = initial continued, 10/11 = continuation
(11 = continued further). Continuation records carry 77 payload bytes
after the 3-byte PTV.

Logical records that overflow one physical record:
  TXT : 100 bytes of data -> initial (56 bytes) + 1 continuation (44 bytes)
  RLD : 3 items (84 bytes) -> initial (74 bytes) + 1 continuation (10 bytes);
        item 3 straddles the physical-record boundary
  ESD : LD "VERYLONGENTRYNAME" (17 chars) -> initial (8 chars) + 1
        continuation (9 chars)
  END : entry by ESDID+offset (not continued)

TXT payload layout (100 bytes): the same hand-assembled program as
gen_zos_goff.py (34 bytes, verified against Capstone mnemonic-for-mnemonic
there), then 0xAA padding, then adcon1 (offset 92, A-type -> SUBR) and
adcon2 (offset 96, Q-type -> EXTFN, unresolved).
RLD items: A-type (elem 2, off 92 -> elem 2 base), Q-type (elem 2, off 96
-> EXTFN), A-type (elem 2, off 40 -> elem 2 base; tests a split item).

Output: tests/zos_smoke_cont.goff
"""
import struct, sys
import os

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

OUT = os.path.join(REPO_ROOT, 'tests/zos_smoke_cont.goff')
RECLEN = 80

# --- tiny assembler (same idiom as gen_zos_goff.py) ---------------------------
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

# --- GOFF records ---------------------------------------------------------------
def pad80(rec):
    assert len(rec) <= RECLEN, len(rec)
    return bytes(rec) + b'\x00'*(RECLEN-len(rec))

def hdr_record():
    r = bytearray()
    r += bytes([0x03,0xF0,0x00])   # PTV
    r += b'\x00'*45
    r += struct.pack('>I',1)       # arch level
    r += struct.pack('>H',0)
    r += b'\x00'*6
    return pad80(r)

def esd_fixed(symtype, esdid, parent, offset, length):
    r = bytearray()
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
    r.append(1)                    # namespace 40
    r += b'\x00\x00\x00'           # flags/fill 41-43
    r += b'\x00'*4                 # assoc data id 44-47
    r += b'\x00'*4                 # priority 48-51
    r += b'\x00'*8                 # reserved 52-59
    r += b'\x00'*10                # behavioral attributes 60-69
    assert len(r) == 67  # offsets 3..69; name length u16 at 70-71
    return r

def esd_record(symtype, esdid, parent, offset, length, name):
    r = bytearray(bytes([0x03,0x00,0x00]))
    r += esd_fixed(symtype, esdid, parent, offset, length)
    nb = name.encode('cp037')
    assert len(nb) <= 8
    r += struct.pack('>H',len(nb))
    r += nb
    return [pad80(r)]

def esd_record_cont(symtype, esdid, parent, offset, length, name):
    """ESD whose name overflows the 8 bytes available in one record."""
    nb = name.encode('cp037')
    assert len(nb) > 8
    r = bytearray(bytes([0x03,0x01,0x00]))  # PTV: ESD, initial continued
    r += esd_fixed(symtype, esdid, parent, offset, length)
    r += struct.pack('>H',len(nb))         # total name length
    r += nb[:8]
    recs = [pad80(r)]
    rest = nb[8:]
    while rest:
        chunk, rest = rest[:77], rest[77:]
        c = bytearray(bytes([0x03, 0x03 if rest else 0x02, 0x00]))
        c += chunk
        recs.append(pad80(c))
    return recs

def txt_record_cont(esdid, offset, data):
    """TXT with data longer than the 56 bytes of one record."""
    assert len(data) > 56
    r = bytearray(bytes([0x03,0x11,0x00]))  # PTV: TXT, initial continued
    r.append(0x00)                 # byte-oriented style
    r += struct.pack('>I',esdid)
    r += b'\x00'*4                 # reserved 8-11
    r += struct.pack('>I',offset)  # 12-15
    r += struct.pack('>I',0)       # true length 16-19
    r += struct.pack('>H',0)       # encoding 20-21
    r += struct.pack('>H',len(data))  # total data length 22-23
    first, rest = data[:56], data[56:]
    r += first
    recs = [pad80(r)]
    while rest:
        chunk, rest = rest[:77], rest[77:]
        c = bytearray(bytes([0x03, 0x13 if rest else 0x12, 0x00]))
        c += chunk
        recs.append(pad80(c))
    return recs

def rld_item(flags6, rptr, pptr, offset):
    it = bytearray()
    it += bytes(flags6)
    it += b'\x00\x00'
    it += struct.pack('>I',rptr)
    it += struct.pack('>I',pptr)
    it += struct.pack('>I',offset)
    it += b'\x00'*8
    return bytes(it)

def rld_record_cont(items):
    data = b''.join(items)
    assert len(data) > 74  # must overflow the 74 item bytes of one record
    r = bytearray(bytes([0x03,0x21,0x00]))  # PTV: RLD, initial continued
    r.append(0x00)
    r += struct.pack('>H',len(data))        # total items length
    first, rest = data[:74], data[74:]
    r += first
    recs = [pad80(r)]
    while rest:
        chunk, rest = rest[:77], rest[77:]
        c = bytearray(bytes([0x03, 0x23 if rest else 0x22, 0x00]))
        c += chunk
        recs.append(pad80(c))
    return recs

def end_record(esdid, offset, recount):
    r = bytearray()
    r += bytes([0x03,0x40,0x00])
    r.append(0x40)                 # flags B'01' = entry by ESDID+offset
    r.append(0x00)
    r += b'\x00\x00'
    r += struct.pack('>I',recount)
    r += struct.pack('>I',esdid)
    r += b'\x00'*4
    r += struct.pack('>I',offset)
    r += struct.pack('>H',0)
    return [pad80(r)]

def build():
    assemble(); apply_fixups()
    Lc = len(code); subr_off = labels['subr']
    assert Lc == 34 and subr_off == 28
    # 100-byte TXT payload: code + 0xAA pad + adcon1 + adcon2
    padlen = 100 - Lc - 8
    payload = bytes(code) + b'\xAA'*padlen + struct.pack('>II', subr_off, 0)
    assert len(payload) == 100
    adcon1_off = Lc + padlen       # 92
    adcon2_off = Lc + padlen + 4   # 96
    print("code=%d pad=%d adcon1@%d adcon2@%d" % (Lc, padlen, adcon1_off, adcon2_off))

    recs = []
    recs.append(hdr_record())
    SD,ED,LD,ER = 0x00,0x01,0x02,0x04
    recs += esd_record(SD,1,0,0,0,'MAIN')
    recs += esd_record(ED,2,1,0,len(payload),'C_CODE')
    recs += esd_record(LD,3,2,0,0,'ENTRY')
    recs += esd_record(LD,4,2,subr_off,0,'SUBR')
    recs += esd_record(ER,5,1,0,0,'EXTFN')
    recs += esd_record_cont(LD,6,2,0,0,'VERYLONGENTRYNAME')  # 17-char name
    recs += txt_record_cont(2,0,payload)
    a_flags = [0x00,0x01,0x00,0x00,0x04,0x00]  # A-type, element, +, fetch, len 4
    q_flags = [0x00,0x01,0x00,0x00,0x04,0x00]  # Q-type -> ER: left unresolved
    recs += rld_record_cont([
        rld_item(a_flags,2,2,adcon1_off),
        rld_item(q_flags,5,2,adcon2_off),
        rld_item(a_flags,2,2,40),   # split across the boundary (74 = 2*28+18)
    ])
    recs += end_record(2,0,len(recs)+1)
    img = b''.join(recs)
    assert len(img) % 80 == 0
    open(OUT,'wb').write(img)
    print("wrote %s (%d bytes, %d physical records)" % (OUT,len(img),len(recs)))

if __name__ == '__main__':
    build()
