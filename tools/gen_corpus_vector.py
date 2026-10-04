#!/usr/bin/env python3
"""Generate tests/corpus_vector.json -- Capstone-verified vector test vectors.
Each vector: (name, hex_bytes, expected_mnemonic).
All vectors validated against Capstone 5.0.7 (CS_ARCH_SYSZ) before writing.
"""
import json, sys
from capstone import Cs, CS_ARCH_SYSZ, CS_MODE_BIG_ENDIAN

VECTORS = [
    # VL / VST (VRX)
    ("VL_v1",      "e71010000006", "vl"),
    ("VL_v17",     "e71010000806", "vl"),  # RXB=1 -> v17
    ("VL_v31",     "e7f010000806", "vl"),  # V1=15, RXB=1 -> v31
    ("VST_v2",     "e7201000000e", "vst"),
    ("VST_v18",    "e7201000080e", "vst"), # RXB=1 -> v18
    # VLR (VRR-a, OP2=0x56)
    ("VLR",        "e71200000056", "vlr"),  # v1,v2
    ("VLR_hi",     "e71200000c56", "vlr"),  # v17,v18 (RXB=1 for both)
    # VA / VS (VRR-c)
    ("VAB",        "e712300000f3", "vab"),
    ("VAH",        "e712300010f3", "vah"),
    ("VAF",        "e712300020f3", "vaf"),
    ("VAG",        "e712300030f3", "vag"),
    ("VSB",        "e712300000f7", "vsb"),
    ("VSH",        "e712300010f7", "vsh"),
    ("VSF",        "e712300020f7", "vsf"),
    ("VSG",        "e712300030f7", "vsg"),
    # VGBM (VRI-a) - avoid 0/0xFFFF to skip vzero/vone aliases
    ("VGBM",       "e71012340044", "vgbm"),
    ("VGBM_v16",   "e70012340844", "vgbm"),  # V1=0, RXB=1 -> v16
]

def main():
    md = Cs(CS_ARCH_SYSZ, CS_MODE_BIG_ENDIAN)
    out = []
    fails = 0
    for name, hx, want in VECTORS:
        code = bytes.fromhex(hx)
        res = list(md.disasm(code, 0x1000))
        if len(res) != 1:
            print(f"FAIL {name} {hx}: Capstone decoded {len(res)} insns", file=sys.stderr)
            fails += 1
            continue
        got = res[0].mnemonic
        # For vgbm, accept vzero/vone aliases if I2 matches, but our vectors avoid them
        if got != want:
            print(f"FAIL {name} {hx}: Capstone={got}, want={want}", file=sys.stderr)
            fails += 1
            continue
        out.append({"name": name, "hex": hx, "mnemonic": want,
                    "capstone_op": res[0].op_str, "size": res[0].size})
        print(f"ok {name:10s} {hx} -> {got} {res[0].op_str}")
    if fails:
        print(f"\n{fails} FAILURES - corpus not written", file=sys.stderr)
        return 1
    with open("tests/corpus_vector.json", "w") as f:
        json.dump(out, f, indent=2)
    print(f"\nWrote {len(out)} vectors to tests/corpus_vector.json")
    return 0

if __name__ == "__main__":
    sys.exit(main())
