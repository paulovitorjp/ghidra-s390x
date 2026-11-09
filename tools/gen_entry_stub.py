#!/usr/bin/env python3
"""Build a synthetic classic load module whose entry is a register-branch stub.

The bytes are generated here. They are the usual save / link / load / branch
sequence, plus one external symbol so auto-analysis sees more than a single
entry candidate. No captured program image is embedded.

Layout of the text (module-relative):
  0x00  nopr; stm r14,r12,12(r13); lr r5,r13; balr r15,0;
        lm r9,r15,18(r15); br r15
  0x1C  seven 4-byte address constants (the lm table). The r15 slot is an
        A-type adcon of the epilogue.
  0x38  epilogue: br r14
"""
import os
import struct
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(REPO_ROOT, "tests", "entry_stub.lmod")

SD, LR, ER = 0x00, 0x03, 0x02


def ebcdic(name):
    return name.encode("cp037").ljust(8, b"\x40")[:8]


def cesd_item(name, typ, addr, length_or_id, flags13=0x38):
    item = bytearray(16)
    item[0:8] = ebcdic(name)
    item[8] = typ
    item[9:12] = struct.pack(">I", addr)[1:4]
    item[12] = flags13
    item[13:16] = struct.pack(">I", length_or_id)[1:4]
    return bytes(item)


def cesd_record(items):
    rec = bytearray()
    rec.append(0x20)
    rec.append(0x80)
    rec += b"\x00\x00"
    rec += struct.pack(">H", 1)
    rec += struct.pack(">H", len(items) * 16)
    for it in items:
        rec += it
    return bytes(rec)


def control_record(rld_count, cesd_id, text_len, text_addr, ident=0x01):
    rec = bytearray()
    rec.append(ident)
    rec += b"\x00\x00"
    rec.append(rld_count)
    rec += struct.pack(">H", 4)
    rec += b"\x00\x00"
    rec.append(0x02)
    rec += struct.pack(">I", text_addr)[1:4]
    rec += b"\x00\x00"
    rec += struct.pack(">H", text_len)
    rec += struct.pack(">H", cesd_id)
    rec += struct.pack(">H", text_len)
    return bytes(rec)


def rld_record(items):
    rec = bytearray()
    rec.append(0x02)
    rec += b"\x00\x00\x00"
    rec += struct.pack(">H", 0)
    rec += struct.pack(">H", len(items) * 8)
    rec += b"\x00" * 8
    for r, p, flag, addr in items:
        rec += struct.pack(">H", r)
        rec += struct.pack(">H", p)
        rec.append(flag)
        rec += struct.pack(">I", addr)[1:4]
    return bytes(rec)


def dir_header(member, entry_off):
    h = bytearray()
    h += b"ZOSLMOD1"
    h += struct.pack(">H", 1)
    h += ebcdic(member)
    h += struct.pack(">I", entry_off)
    h += bytes([64, 64])
    h += struct.pack(">H", 0)
    return bytes(h)


def text_image():
    """Return (text, epilogue_off, adcon_off)."""
    stub = bytes([
        0x07, 0x00,              # nopr
        0x90, 0xEC, 0xD0, 0x0C,  # stm r14,r12,12(r13)
        0x18, 0x5D,              # lr r5,r13
        0x05, 0xF0,              # balr r15,0
        0x98, 0x9F, 0xF0, 0x12,  # lm r9,r15,18(r15)
        0x07, 0xFF,              # br r15
    ])
    # balr's next instruction is the lm at offset 10; 10 + 18 = 28.
    assert len(stub) == 16
    table_off = 10 + 0x12
    assert table_off == 28
    epilogue_off = table_off + 7 * 4
    text = bytearray(epilogue_off + 2)
    text[0:len(stub)] = stub
    # r15 is the 7th register loaded (r9..r15).
    struct.pack_into(">I", text, table_off + 6 * 4, epilogue_off)
    text[epilogue_off:epilogue_off + 2] = bytes([0x07, 0xFE])  # br r14
    return bytes(text), epilogue_off, table_off + 6 * 4


def build():
    text, epilogue_off, adcon_off = text_image()
    items = [
        cesd_item("CODE", SD, 0, len(text)),
        cesd_item("ENTRY", LR, 0, 0),
        cesd_item("EXTSYM", ER, 0, 0),
    ]
    out = bytearray()
    out += dir_header("ENTRY", 0)
    out += cesd_record(items)
    out += control_record(1, 1, len(text), 0)
    out += text
    # 4-byte A-type addend: stored module-relative epilogue offset.
    out += rld_record([(1, 1, 0x0C, adcon_off)])
    out += control_record(0, 0, 0, 0, ident=0x0D)
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "wb") as fh:
        fh.write(out)
    print("wrote %s (%d bytes) epilogue=%d adcon=%d" % (
        OUT, len(out), epilogue_off, adcon_off))
    return out


if __name__ == "__main__":
    blob = build()
    if blob[:8] != b"ZOSLMOD1":
        sys.exit("header mismatch")
