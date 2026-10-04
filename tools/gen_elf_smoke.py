#!/usr/bin/env python3
"""gen_elf_smoke.py -- build a minimal static ET_EXEC ELF64-BE EM_S390 test binary.

Contains three hand-assembled functions (Capstone-verified):
  _start : brasl %r14,main ; svc 1
  main   : stack frame, calls sum(10), if/else on result, returns 1 or 0
  sum    : counted loop (jnh) summing 1..n, returns total in %r2

Output: tests/elf_smoke.elf
"""
import struct, sys
import os

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

BASE_VADDR = 0x10000
TEXT_OFF = 0x78  # right after ehdr+phdr

# --- tiny assembler with fixups -------------------------------------------
code = bytearray()
labels = {}
fixups = []  # (offset, kind, label)

def emit(*bs):
    code.extend(bs)

def label(name):
    labels[name] = len(code)

def i16(addr, target):
    return (target - addr) // 2

def brasl_r14(target_label):
    # binutils: brasl = c005 -> byte0=0xC0, byte1=(R1<<4)|5 ; NOT 0xC5/0xE0
    # (0xC5 is BPRP, "branch prediction relative preload")
    off = len(code)
    emit(0xC0, 0xE5, 0, 0, 0, 0)
    fixups.append((off, 'i32', target_label))

def jh(target_label):
    off = len(code)
    emit(0xA7, 0x24, 0, 0)
    fixups.append((off, 'i16', target_label))

def j(target_label):
    off = len(code)
    emit(0xA7, 0xF4, 0, 0)
    fixups.append((off, 'i16', target_label))

def jnh(target_label):
    off = len(code)
    emit(0xA7, 0xD4, 0, 0)
    fixups.append((off, 'i16', target_label))

def assemble():
    label('_start')
    brasl_r14('main')
    emit(0x0A, 0x01)                      # svc 1

    label('main')
    emit(0xEB, 0xEF, 0xF0, 0x08, 0x00, 0x24)  # stmg %r14,%r15,8(%r15)
    emit(0xA7, 0xFB, 0xFF, 0x60)              # aghi %r15,-160
    emit(0xA7, 0x28, 0x00, 0x0A)              # lhi %r2,10
    brasl_r14('sum')
    emit(0xA7, 0x2F, 0x00, 0x32)              # cghi %r2,50
    jh('Lthen')
    emit(0xA7, 0x38, 0x00, 0x00)              # lhi %r3,0
    j('Lend')
    label('Lthen')
    emit(0xA7, 0x38, 0x00, 0x01)              # lhi %r3,1
    label('Lend')
    emit(0x18, 0x23)                         # lr %r2,%r3
    emit(0xA7, 0xFB, 0x00, 0xA0)              # aghi %r15,160
    emit(0xEB, 0xEF, 0xF0, 0xA8, 0x00, 0x04)  # lmg %r14,%r15,168(%r15)
    emit(0x07, 0xFE)                         # br %r14

    label('sum')
    emit(0xA7, 0x38, 0x00, 0x00)              # lhi %r3,0
    emit(0xA7, 0x48, 0x00, 0x01)              # lhi %r4,1
    label('Lloop')
    emit(0x1A, 0x34)                         # ar %r3,%r4
    emit(0xA7, 0x4A, 0x00, 0x01)              # ahi %r4,1
    emit(0x19, 0x42)                         # cr %r4,%r2
    jnh('Lloop')
    emit(0x18, 0x23)                         # lr %r2,%r3
    emit(0x07, 0xFE)                         # br %r14

def apply_fixups(text_vaddr):
    for off, kind, name in fixups:
        addr = text_vaddr + off
        target = text_vaddr + labels[name]
        if kind == 'i32':
            val = (target - addr) // 2
            assert -(2**31) <= val < 2**31, (kind, name, val)
            code[off+2:off+6] = struct.pack('>i', val)
        else:
            val = (target - addr) // 2
            assert -(2**15) <= val < 2**15, (kind, name, val)
            code[off+2:off+4] = struct.pack('>h', val)

EXPECTED_MNEMONICS = ["brasl", "svc", "stmg", "aghi", "lhi", "brasl", "cghi",
                      "jh", "lhi", "j", "lhi", "lr", "aghi", "lmg", "br",
                      "lhi", "lhi", "ar", "ahi", "cr", "jnh", "lr", "br"]

def capstone_check(text_vaddr):
    from capstone import Cs, CS_ARCH_SYSZ, CS_MODE_BIG_ENDIAN
    md = Cs(CS_ARCH_SYSZ, CS_MODE_BIG_ENDIAN)
    md.detail = False
    ok = True
    insns = list(md.disasm(bytes(code), text_vaddr))
    for ins in insns:
        print("  0x%x:\t%s\t%s" % (ins.address, ins.mnemonic, ins.op_str))
    got = [i.mnemonic for i in insns]
    if got != EXPECTED_MNEMONICS:
        print("MNEMONIC MISMATCH:\n got: %s\n exp: %s" % (got, EXPECTED_MNEMONICS))
        ok = False
    # every byte must be consumed by exactly one instruction
    covered = [False] * len(code)
    for ins in insns:
        for i in range(ins.address - text_vaddr, ins.address - text_vaddr + ins.size):
            if covered[i]:
                print("OVERLAP at offset", i); ok = False
            covered[i] = True
    if not all(covered):
        print("UNCOVERED bytes:", [i for i, c in enumerate(covered) if not c]); ok = False
    return ok

# --- ELF writer -------------------------------------------------------------
def build_elf():
    text_vaddr = BASE_VADDR + TEXT_OFF
    assemble()
    apply_fixups(text_vaddr)
    print("Capstone disassembly of .text:")
    if not capstone_check(text_vaddr):
        sys.exit("capstone verification FAILED")

    text = bytes(code)
    strtab = b'\x00_start\x00main\x00sum\x00'
    # symtab entries: name_off, info, other, shndx, value, size
    syms = [
        (1, 0x12, 0, 1, text_vaddr + labels['_start'], labels['main'] - labels['_start']),
        (8, 0x12, 0, 1, text_vaddr + labels['main'], labels['sum'] - labels['main']),
        (13, 0x12, 0, 1, text_vaddr + labels['sum'], len(text) - labels['sum']),
    ]
    symtab = b'\x00' * 24
    for name, info, other, shndx, value, size in syms:
        symtab += struct.pack('>IBBHQQ', name, info, other, shndx, value, size)
    shstrtab = b'\x00.text\x00.symtab\x00.strtab\x00.shstrtab\x00'

    # layout
    ehdr_size, phdr_size = 64, 56
    off = TEXT_OFF
    text_off = off; off += len(text)
    symtab_off = off; off += len(symtab)
    strtab_off = off; off += len(strtab)
    shstrtab_off = off; off += len(shstrtab)
    shoff = (off + 7) & ~7

    nsec = 5  # null, .text, .symtab, .strtab, .shstrtab
    fsize = shoff + nsec * 64
    img = bytearray(fsize)

    # ELF header
    img[0:16] = b'\x7fELF' + bytes([2, 2, 1, 0, 0]) + b'\x00' * 7
    struct.pack_into('>HHIQQQIHHHHHH', img, 16,
                     2, 22, 1, text_vaddr + labels['_start'],  # type, machine, ver, entry
                     64, shoff, 0, 64, 56, 1, 64, nsec, 4)    # phoff..shstrndx

    # PT_LOAD program header
    struct.pack_into('>IIQQQQQQ', img, 64,
                     1, 7, 0, BASE_VADDR, BASE_VADDR, fsize, fsize, 0x1000)

    img[text_off:text_off+len(text)] = text
    img[symtab_off:symtab_off+len(symtab)] = symtab
    img[strtab_off:strtab_off+len(strtab)] = strtab
    img[shstrtab_off:shstrtab_off+len(shstrtab)] = shstrtab

    def shent(idx, name, stype, flags, addr, offset, size, link, info, align, entsz):
        struct.pack_into('>IIQQQQIIQQ', img, shoff + idx*64,
                         name, stype, flags, addr, offset, size, link, info, align, entsz)
    shent(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    shent(1, 1, 1, 0x6, text_vaddr, text_off, len(text), 0, 0, 16, 0)      # .text
    shent(2, 7, 2, 0, 0, symtab_off, len(symtab), 3, 1, 8, 24)            # .symtab
    shent(3, 15, 3, 0, 0, strtab_off, len(strtab), 0, 0, 1, 0)            # .strtab
    shent(4, 23, 3, 0, 0, shstrtab_off, len(shstrtab), 0, 0, 1, 0)         # .shstrtab
    return bytes(img)

if __name__ == '__main__':
    img = build_elf()
    out = os.path.join(REPO_ROOT, 'tests/elf_smoke.elf')
    open(out, 'wb').write(img)
    print("wrote %s (%d bytes), entry=0x%x" % (out, len(img), BASE_VADDR + TEXT_OFF))
