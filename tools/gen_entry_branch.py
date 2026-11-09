#!/usr/bin/env python3
"""Synthetic load module whose entry is a branch through r15.

Layout of the text (module-relative):
  0x00  47 F0 F0 14   unconditional branch, base r15, displacement 0x14
  0x04  16 bytes of padding (a short header that the branch skips)
  0x14  LHI r2,1
  0x18  BCR 15,14

If analysis never gives r15 the entry address, only the branch at 0x00 is
recovered and the instructions at 0x14 are missed. That is a failing result.
"""
import os
import struct
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(REPO_ROOT, "tests", "entry_branch.lmod")

SD, LR = 0x00, 0x03


def ebcdic(name):
    return name.encode("cp037").ljust(8, b"\x40")[:8]


def cesd_item(name, typ, addr, length_or_id):
    item = bytearray(16)
    item[0:8] = ebcdic(name)
    item[8] = typ
    item[9:12] = struct.pack(">I", addr)[1:4]
    item[12] = 0x38
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
    text = bytearray(0x1A)
    text[0:4] = bytes([0x47, 0xF0, 0xF0, 0x14])
    text[0x14:0x18] = bytes([0xA7, 0x28, 0x00, 0x01])  # LHI r2,1
    text[0x18:0x1A] = bytes([0x07, 0xFE])              # BCR 15,14
    return bytes(text)


def build():
    text = text_image()
    items = [
        cesd_item("CODE", SD, 0, len(text)),
        cesd_item("ENTRY", LR, 0, 0),
    ]
    out = bytearray()
    out += dir_header("ENTRY", 0)
    out += cesd_record(items)
    out += control_record(0, 1, len(text), 0)
    out += text
    out += control_record(0, 0, 0, 0, ident=0x0D)
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "wb") as fh:
        fh.write(out)
    print("wrote %s (%d bytes)" % (OUT, len(out)))
    return out


if __name__ == "__main__":
    blob = build()
    if blob[:8] != b"ZOSLMOD1":
        sys.exit("header mismatch")
    assert b"\x47\xF0\xF0\x14" in blob
    assert b"\xA7\x28\x00\x01\x07\xFE" in blob
