#!/usr/bin/env python3
"""gen_elf_dyn_smoke.py -- build a minimal ET_DYN (PIE) ELF64-BE EM_S390 binary
with RELA relocations, to exercise S390_ElfRelocationHandler.

Linked at vaddr 0 (so load bias B == Ghidra's image base). Layout:

  .text @0x1000 : func: brasl %r14,target2  [R_390_PC32DBL sym=target2 A=2]
                         br %r14
                  target2: lhi %r2,42 ; br %r14
  .data @0x2000 : d_abs64    R_390_64      sym=d_target A=0
                  d_target   (8 bytes 0xDEADBEEFCAFEBABE)
                  d_rel      R_390_RELATIVE sym=0 A=0x500
                  d_gd       R_390_GLOB_DAT sym=func A=16
                  d_pc32     R_390_PC32    sym=target2 A=0
                  d_abs32    R_390_32      sym=d_abs64 A=4
                  d_abs16    R_390_16      sym=func A=2
                  d_abs8     R_390_8       sym=func A=3
                  d_pc16     R_390_PC16    sym=func A=0
                  d_tls      R_390_TLS_TPOFF sym=0 A=0 (must be warned+skipped)
                  -- extended vectors (offsets relative to .data base 0x2000) --
                  0x40  R_390_12      sym=target2 A=0      (preset 0xA000)
                  0x42  R_390_20      sym=func A=0x12345   (preset 0xABC00000)
                  0x46  R_390_PC16DBL sym=target2 A=2
                  0x48  R_390_PC12DBL sym=target2 A=2      (preset 0xB000)
                  0x4A  R_390_PC24DBL sym=target2 A=2      (preset 0xCD000000)
                  0x4E  R_390_PC64    sym=func A=0
                  0x56  R_390_GOT12   sym=d_abs64 A=0      (preset 0xD000)
                  0x58  R_390_GOT16   sym=d_target A=0
                  0x5A  R_390_GOT20   sym=func A=0         (preset 0xE1200000)
                  0x5E  R_390_GOT32   sym=target2 A=4
                  0x62  R_390_GOT64   sym=d_abs64 A=8
                  0x6A  R_390_GOTPLT12 sym=d_abs64 A=0     (preset 0xF000)
                  0x6C  R_390_GOTPLT16 sym=d_target A=0
                  0x6E  R_390_GOTPLT20 sym=func A=0        (preset 0xE2200000)
                  0x72  R_390_GOTPLT32 sym=target2 A=0
                  0x76  R_390_GOTPLT64 sym=d_abs64 A=0
                  0x7E  R_390_GOTENT  sym=func A=2
                  0x82  R_390_GOTPLTENT sym=target2 A=2
                  0x86  R_390_GOTPC   sym=func A=0
                  0x8A  R_390_GOTPCDBL sym=func A=2
                  0x8E  R_390_GOTOFF16 sym=d_target A=0
                  0x90  R_390_GOTOFF32 sym=d_target A=0
                  0x94  R_390_GOTOFF64 sym=func A=0
                  0x9C  R_390_PLT16DBL sym=target2 A=2
                  0x9E  R_390_PLT12DBL sym=target2 A=2     (preset 0xC000)
                  0xA0  R_390_PLT32DBL sym=func A=2
                  0xA4  R_390_PLT24DBL sym=func A=2        (preset 0xDD000000)
                  0xA8  R_390_PLT32   sym=target2 A=0
                  0xAC  R_390_PLT64   sym=func A=0
                  0xB4  R_390_PLTOFF16 sym=target2 A=0
                  0xB6  R_390_PLTOFF32 sym=target2 A=0
                  0xBA  R_390_PLTOFF64 sym=func A=0
                  0xC2  R_390_IRELATIVE sym=0 A=0x1008 (resolver; warned, B+A recorded)
                  0xCA  R_390_COPY    sym=d_target A=0 (preset 0x1122334455667788;
                                                       must stay untouched)
                  0xD2  R_390_GNU_VTINHERIT sym=d_target A=0 (no-op skip)
                  0xD3  R_390_GNU_VTENTRY   sym=d_target A=0 (no-op skip)
  .got.plt @0x3000 : slot[2] R_390_JMP_SLOT sym=extfunc(undefined) A=0
  .dynsym also carries _GLOBAL_OFFSET_TABLE_ (UNDEF, value 0) so the
  handler's synthesized-GOT path (ElfGotRelocationContext.allocateGot)
  triggers for the GOT-family relocations.

Output: tests/elf_dyn_smoke.elf
"""
import struct, sys

R = dict(NONE=0, R8=1, R12=2, R16=3, R32=4, PC32=5, GOT12=6, GOT32=7,
         PLT32=8, COPY=9, GLOB_DAT=10, JMP_SLOT=11, RELATIVE=12,
         GOTOFF32=13, GOTPC=14, GOT16=15, PC16=16, PC16DBL=17,
         PLT16DBL=18, PC32DBL=19, PLT32DBL=20, GOTPCDBL=21, R64=22,
         PC64=23, GOT64=24, PLT64=25, GOTENT=26, GOTOFF16=27,
         GOTOFF64=28, GOTPLT12=29, GOTPLT16=30, GOTPLT32=31,
         GOTPLT64=32, GOTPLTENT=33, PLTOFF16=34, PLTOFF32=35,
         PLTOFF64=36, R20=57, GOT20=58, GOTPLT20=59, IRELATIVE=61,
         PC12DBL=62, PLT12DBL=63, PC24DBL=64, PLT24DBL=65,
         TLS_TPOFF=56, VTINHERIT=250, VTENTRY=251)

TEXT_VADDR = 0x1000
DATA_VADDR = 0x2000
GOTPLT_VADDR = 0x3000

# --- .text ---
text = bytearray()
text += bytes([0xC0, 0xE5, 0, 0, 0, 0])   # 0x1000 func: brasl %r14,target2 (field patched by reloc)
text += bytes([0x07, 0xFE])               # br %r14
text += bytes([0xA7, 0x28, 0x00, 0x2A])   # 0x1008 target2: lhi %r2,42
text += bytes([0x07, 0xFE])               # br %r14

# --- .data ---
data = bytearray(0xE0)
struct.pack_into('>Q', data, 0x08, 0xDEADBEEFCAFEBABE)  # d_target
# presets whose neighbouring bits must survive masked relocations
struct.pack_into('>H', data, 0x40, 0xA000)
struct.pack_into('>I', data, 0x42, 0xABC00000)
struct.pack_into('>H', data, 0x48, 0xB000)
struct.pack_into('>I', data, 0x4A, 0xCD000000)
struct.pack_into('>H', data, 0x56, 0xD000)
struct.pack_into('>I', data, 0x5A, 0xE1200000)
struct.pack_into('>H', data, 0x6A, 0xF000)
struct.pack_into('>I', data, 0x6E, 0xE2200000)
struct.pack_into('>H', data, 0x9E, 0xC000)
struct.pack_into('>I', data, 0xA4, 0xDD000000)
struct.pack_into('>Q', data, 0xCA, 0x1122334455667788)  # COPY target: must stay
data[0xD2] = 0xAA  # VTINHERIT: untouched
data[0xD3] = 0xBB  # VTENTRY: untouched

# --- .got.plt ---
gotplt = bytearray(0x18)

# --- .dynstr ---
dynstr = b'\x00func\x00target2\x00d_abs64\x00d_target\x00extfunc\x00' \
         b'_GLOBAL_OFFSET_TABLE_\x00'
STT = {}  # name -> offset
off = 1
for n in (b'func', b'target2', b'd_abs64', b'd_target', b'extfunc',
          b'_GLOBAL_OFFSET_TABLE_'):
    STT[n] = off
    off += len(n) + 1

# --- .dynsym --- (st_name, st_info, st_other, st_shndx, st_value, st_size)
SEC_TEXT, SEC_DATA = 1, 2
dynsym = b'\x00' * 24
syms = [
    (STT[b'func'], 0x12, 0, SEC_TEXT, TEXT_VADDR, 8),
    (STT[b'target2'], 0x12, 0, SEC_TEXT, TEXT_VADDR + 8, 6),
    (STT[b'd_abs64'], 0x11, 0, SEC_DATA, DATA_VADDR, 8),
    (STT[b'd_target'], 0x11, 0, SEC_DATA, DATA_VADDR + 8, 8),
    (STT[b'extfunc'], 0x12, 0, 0, 0, 0),  # SHN_UNDEF
    (STT[b'_GLOBAL_OFFSET_TABLE_'], 0x10, 0, 0, 0, 0),  # SHN_UNDEF, value 0
]
for s in syms:
    dynsym += struct.pack('>IBBHQQ', *s)
S_FUNC, S_TARGET2, S_DABS64, S_DTARGET, S_EXTFUNC, S_GOT = 1, 2, 3, 4, 5, 6

# --- relocations ---
def rela(off_, sym, typ, addend):
    return struct.pack('>QQq', off_, (sym << 32) | R[typ], addend)

reladyn = b''.join([
    rela(TEXT_VADDR + 2, S_TARGET2, 'PC32DBL', 2),   # brasl field (gas emits A=2)
    rela(DATA_VADDR + 0x00, S_DTARGET, 'R64', 0),
    rela(DATA_VADDR + 0x10, 0, 'RELATIVE', 0x500),
    rela(DATA_VADDR + 0x18, S_FUNC, 'GLOB_DAT', 16),
    rela(DATA_VADDR + 0x20, S_TARGET2, 'PC32', 0),
    rela(DATA_VADDR + 0x24, S_DABS64, 'R32', 4),
    rela(DATA_VADDR + 0x28, S_FUNC, 'R16', 2),
    rela(DATA_VADDR + 0x2A, S_FUNC, 'R8', 3),
    rela(DATA_VADDR + 0x2B, S_FUNC, 'PC16', 0),
    rela(DATA_VADDR + 0x30, 0, 'TLS_TPOFF', 0),      # warned+skipped
    # --- extended vectors ---
    rela(DATA_VADDR + 0x40, S_TARGET2, 'R12', 0),
    rela(DATA_VADDR + 0x42, S_FUNC, 'R20', 0x12345),
    rela(DATA_VADDR + 0x46, S_TARGET2, 'PC16DBL', 2),
    rela(DATA_VADDR + 0x48, S_TARGET2, 'PC12DBL', 2),
    rela(DATA_VADDR + 0x4A, S_TARGET2, 'PC24DBL', 2),
    rela(DATA_VADDR + 0x4E, S_FUNC, 'PC64', 0),
    # GOT-entry relocs first: allocate entries in this order so that
    # d_abs64->GOT+0, d_target->GOT+8, func->GOT+16, target2->GOT+24
    rela(DATA_VADDR + 0x56, S_DABS64, 'GOT12', 0),
    rela(DATA_VADDR + 0x58, S_DTARGET, 'GOT16', 0),
    rela(DATA_VADDR + 0x5A, S_FUNC, 'GOT20', 0),
    rela(DATA_VADDR + 0x5E, S_TARGET2, 'GOT32', 4),
    rela(DATA_VADDR + 0x62, S_DABS64, 'GOT64', 8),
    rela(DATA_VADDR + 0x6A, S_DABS64, 'GOTPLT12', 0),
    rela(DATA_VADDR + 0x6C, S_DTARGET, 'GOTPLT16', 0),
    rela(DATA_VADDR + 0x6E, S_FUNC, 'GOTPLT20', 0),
    rela(DATA_VADDR + 0x72, S_TARGET2, 'GOTPLT32', 0),
    rela(DATA_VADDR + 0x76, S_DABS64, 'GOTPLT64', 0),
    rela(DATA_VADDR + 0x7E, S_FUNC, 'GOTENT', 2),
    rela(DATA_VADDR + 0x82, S_TARGET2, 'GOTPLTENT', 2),
    # GOT-base relocs (GOT already allocated above)
    rela(DATA_VADDR + 0x86, S_FUNC, 'GOTPC', 0),
    rela(DATA_VADDR + 0x8A, S_FUNC, 'GOTPCDBL', 2),
    rela(DATA_VADDR + 0x8E, S_DTARGET, 'GOTOFF16', 0),
    rela(DATA_VADDR + 0x90, S_DTARGET, 'GOTOFF32', 0),
    rela(DATA_VADDR + 0x94, S_FUNC, 'GOTOFF64', 0),
    # PLT-relative (L = defined symbol address)
    rela(DATA_VADDR + 0x9C, S_TARGET2, 'PLT16DBL', 2),
    rela(DATA_VADDR + 0x9E, S_TARGET2, 'PLT12DBL', 2),
    rela(DATA_VADDR + 0xA0, S_FUNC, 'PLT32DBL', 2),
    rela(DATA_VADDR + 0xA4, S_FUNC, 'PLT24DBL', 2),
    rela(DATA_VADDR + 0xA8, S_TARGET2, 'PLT32', 0),
    rela(DATA_VADDR + 0xAC, S_FUNC, 'PLT64', 0),
    rela(DATA_VADDR + 0xB4, S_TARGET2, 'PLTOFF16', 0),
    rela(DATA_VADDR + 0xB6, S_TARGET2, 'PLTOFF32', 0),
    rela(DATA_VADDR + 0xBA, S_FUNC, 'PLTOFF64', 0),
    # dynamic-linking edge cases
    rela(DATA_VADDR + 0xC2, 0, 'IRELATIVE', 0x1008),  # warned; B+A recorded
    rela(DATA_VADDR + 0xCA, S_DTARGET, 'COPY', 0),    # warned+skipped, untouched
    rela(DATA_VADDR + 0xD2, S_DTARGET, 'VTINHERIT', 0),  # no-op skip
    rela(DATA_VADDR + 0xD3, S_DTARGET, 'VTENTRY', 0),    # no-op skip
])
relaplt = rela(GOTPLT_VADDR + 0x10, S_EXTFUNC, 'JMP_SLOT', 0)

# --- .dynamic ---
dynamic = struct.pack('>qQ', 0, 0)  # DT_NULL

shstrtab = b'\x00.text\x00.data\x00.got.plt\x00.rela.dyn\x00.rela.plt\x00' \
            b'.dynsym\x00.dynstr\x00.dynamic\x00.shstrtab\x00'
SN = {}
o = 1
for n in (b'.text', b'.data', b'.got.plt', b'.rela.dyn', b'.rela.plt',
          b'.dynsym', b'.dynstr', b'.dynamic', b'.shstrtab'):
    SN[n] = o
    o += len(n) + 1

# --- layout ---
EHDR, PHDR = 64, 56
NPHDR = 2
blob_off = EHDR + NPHDR * PHDR
parts = []  # (name, vaddr, bytes, flags, align)
parts.append(('.text', TEXT_VADDR, bytes(text), 0x6, 16))
parts.append(('.data', DATA_VADDR, bytes(data), 0x3, 8))
parts.append(('.got.plt', GOTPLT_VADDR, bytes(gotplt), 0x3, 8))
parts.append(('.rela.dyn', 0, reladyn, 0, 8))
parts.append(('.rela.plt', 0, relaplt, 0, 8))
parts.append(('.dynsym', 0, dynsym, 0, 8))
parts.append(('.dynstr', 0, dynstr, 0, 1))
parts.append(('.dynamic', 0, dynamic, 0, 8))
parts.append(('.shstrtab', 0, shstrtab, 0, 1))

file_off, secinfo = blob_off, {}
for name, vaddr, bs, flags, align in parts:
    file_off = (file_off + align - 1) & ~(align - 1)
    secinfo[name] = (file_off, vaddr, len(bs), flags, align)
    file_off += len(bs)
shoff = (file_off + 7) & ~7
NSEC = 10  # null + 9
fsize = shoff + NSEC * 64
img = bytearray(fsize)
for name, vaddr, bs, flags, align in parts:
    fo, _, ln, _, _ = secinfo[name]
    img[fo:fo + ln] = bs

# ELF header: ET_DYN(3), EM_S390(22)
img[0:16] = b'\x7fELF' + bytes([2, 2, 1, 0, 0]) + b'\x00' * 7
struct.pack_into('>HHIQQQIHHHHHH', img, 16,
                 3, 22, 1, TEXT_VADDR, 64, shoff, 0, 64, 56, NPHDR, 64, NSEC, 9)
# PT_LOAD + PT_DYNAMIC
dyn_fo, _, dyn_ln, _, _ = secinfo['.dynamic']
struct.pack_into('>IIQQQQQQ', img, 64, 1, 7, 0, 0, 0, fsize, fsize, 0x1000)
struct.pack_into('>IIQQQQQQ', img, 64 + 56, 2, 4, dyn_fo, 0, 0, dyn_ln, dyn_ln, 8)

SHT = dict(NULL=0, PROGBITS=1, SYMTAB=2, STRTAB=3, RELA=4, DYNAMIC=6, DYNSYM=11)
def shent(idx, name, stype, flags, addr, offset, size, link, info, align, entsz):
    struct.pack_into('>IIQQQQIIQQ', img, shoff + idx * 64,
                     name, stype, flags, addr, offset, size, link, info, align, entsz)
shent(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
i = 1
order = ['.text', '.data', '.got.plt', '.rela.dyn', '.rela.plt',
         '.dynsym', '.dynstr', '.dynamic', '.shstrtab']
for name in order:
    fo, va, ln, fl, al = secinfo[name]
    st = {'.text': 1, '.data': 1, '.got.plt': 1, '.rela.dyn': 4, '.rela.plt': 4,
          '.dynsym': 11, '.dynstr': 3, '.dynamic': 6, '.shstrtab': 3}[name]
    link = info = 0
    entsz = 0
    if name == '.rela.dyn':
        link, info, entsz = 6, SEC_DATA, 24
    elif name == '.rela.plt':
        link, info, entsz = 6, 3, 24
    elif name == '.dynsym':
        link, info, entsz = 7, 1, 24
    shent(i, SN[name.encode()], st, fl, va, fo, ln, link, info, al, entsz)
    i += 1

out = os.path.join(REPO_ROOT, 'tests/elf_dyn_smoke.elf')
open(out, 'wb').write(bytes(img))
print('wrote %s (%d bytes)' % (out, len(img)))

# Capstone sanity on .text
from capstone import Cs, CS_ARCH_SYSZ, CS_MODE_BIG_ENDIAN
import os

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
md = Cs(CS_ARCH_SYSZ, CS_MODE_BIG_ENDIAN)
got = [ins.mnemonic for ins in md.disasm(bytes(text), TEXT_VADDR)]
print('text mnemonics:', got)
assert got == ['brasl', 'br', 'lhi', 'br'], got
print('capstone check OK')
print('rela.dyn entries:', len(reladyn) // 24)
