#!/usr/bin/env python3
"""Synthetic GOFF objects for relocation reuse and part-record text.

tests/goff_rld_reuse.goff
    One element, one label, and one relocation record of exactly 44 bytes:
    a full item plus two items that reuse both the R and P pointers.
    Three fetched 4-byte adds must be applied.

tests/goff_pr_text.goff
    One element and a child part that fits inside it. Text owned by the
    part is loaded at the part offset, and one relocation targets the part.
"""
import os
import struct

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RECLEN = 80


def pad80(rec):
    assert len(rec) <= RECLEN, len(rec)
    return bytes(rec) + b"\x00" * (RECLEN - len(rec))


def hdr_record():
    r = bytearray()
    r += bytes([0x03, 0xF0, 0x00])
    r += b"\x00" * 45
    r += struct.pack(">I", 1)
    r += struct.pack(">H", 0)
    r += b"\x00" * 6
    return pad80(r)


def esd_record(symtype, esdid, parent, offset, length, name):
    r = bytearray()
    r += bytes([0x03, 0x00, 0x00])
    r.append(symtype)
    r += struct.pack(">I", esdid)
    r += struct.pack(">I", parent)
    r += b"\x00" * 4
    r += struct.pack(">I", offset)
    r += b"\x00" * 4
    r += struct.pack(">I", length)
    r += b"\x00" * 4
    r += b"\x00" * 4
    r += b"\x00" * 4
    r.append(1)
    r += b"\x00\x00\x00"
    r += b"\x00" * 4
    r += b"\x00" * 4
    r += b"\x00" * 8
    r += b"\x00" * 10
    nb = name.encode("cp037")
    r += struct.pack(">H", len(nb))
    r += nb
    return pad80(r)


def txt_record(esdid, offset, data):
    r = bytearray()
    r += bytes([0x03, 0x10, 0x00])
    r.append(0x00)
    r += struct.pack(">I", esdid)
    r += b"\x00" * 4
    r += struct.pack(">I", offset)
    r += struct.pack(">I", 0)
    r += struct.pack(">H", 0)
    r += struct.pack(">H", len(data))
    r += data
    return pad80(r)


def rld_item(flags6, rptr, pptr, offset):
    it = bytearray()
    it += bytes(flags6)
    it += b"\x00\x00"
    same = flags6[0]
    if (same & 0x80) == 0:
        it += struct.pack(">I", rptr)
    if (same & 0x40) == 0:
        it += struct.pack(">I", pptr)
    if (same & 0x20) == 0:
        it += struct.pack(">I", offset)
    return bytes(it)


def rld_record(items):
    data = b"".join(items)
    r = bytearray()
    r += bytes([0x03, 0x20, 0x00])
    r.append(0x00)
    r += struct.pack(">H", len(data))
    r += data
    return pad80(r), len(data)


def end_record(esdid, offset, recount):
    r = bytearray()
    r += bytes([0x03, 0x40, 0x00])
    r.append(0x40)
    r.append(0x00)
    r += b"\x00\x00"
    r += struct.pack(">I", recount)
    r += struct.pack(">I", esdid)
    r += b"\x00" * 4
    r += struct.pack(">I", offset)
    r += struct.pack(">H", 0)
    return pad80(r)


def write(path, recs):
    img = b"".join(recs)
    assert len(img) % 80 == 0
    with open(path, "wb") as f:
        f.write(img)
    print("wrote %s (%d bytes)" % (os.path.basename(path), len(img)))


def build_rld_reuse():
    # flags1 = refType 0 << 4 | referentType 0 (label). flags4 = length 4.
    full = [0x00, 0x00, 0x00, 0x00, 0x04, 0x00]
    reuse = [0xC0, 0x00, 0x00, 0x00, 0x04, 0x00]
    items = [
        rld_item(full, 3, 2, 0),
        rld_item(reuse, 0, 0, 4),
        rld_item(reuse, 0, 0, 8),
    ]
    assert [len(it) for it in items] == [20, 12, 12]
    rec, dlen = rld_record(items)
    assert dlen == 44
    sd, ed, ld = 0x00, 0x01, 0x02
    recs = [
        hdr_record(),
        esd_record(sd, 1, 0, 0, 0, "SECT"),
        esd_record(ed, 2, 1, 0, 16, "CODE"),
        esd_record(ld, 3, 2, 0, 0, "LABEL"),
        txt_record(2, 0, b"\x00" * 12),
        rec,
        end_record(2, 0, 7),
    ]
    write(os.path.join(REPO_ROOT, "tests", "goff_rld_reuse.goff"), recs)


def build_pr_text():
    # R and P are both the part. Referent type 0, target length 4.
    full = [0x00, 0x00, 0x00, 0x00, 0x04, 0x00]
    items = [rld_item(full, 3, 3, 0)]
    assert len(items[0]) == 20
    rec, dlen = rld_record(items)
    assert dlen == 20
    sd, ed, pr = 0x00, 0x01, 0x03
    text = b"\x00\x00\x00\x00\x5A\x00\x00\x00"
    recs = [
        hdr_record(),
        esd_record(sd, 1, 0, 0, 0, "SECT"),
        esd_record(ed, 2, 1, 0, 32, "CODE"),
        esd_record(pr, 3, 2, 16, 8, "PART"),
        txt_record(3, 0, text),
        rec,
        end_record(2, 0, 7),
    ]
    write(os.path.join(REPO_ROOT, "tests", "goff_pr_text.goff"), recs)


if __name__ == "__main__":
    build_rld_reuse()
    build_pr_text()
