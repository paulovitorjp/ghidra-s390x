#!/usr/bin/env python3
"""validate_system.py — validate s390x_system.sinc encodings against Capstone.

Every vector below was hand-assembled from the PoP (SA22-7832-14)
instruction figures: opcode bytes + field placement per the format.
Capstone 5.0.7 (CS_ARCH_SYSZ) is the oracle: each vector must decode
to the expected mnemonic and operand string.

Writes the validated vectors to tests/corpus_system.json using the
same schema as tests/corpus.json.
"""
import json
import os
import sys

from capstone import Cs, CS_ARCH_SYSZ, CS_MODE_BIG_ENDIAN

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.normpath(os.path.join(HERE, "..", "tests", "corpus_system.json"))

# (bytes_hex, expected_mnemonic, expected_op_str, category, notes)
# Field breakdowns follow the PoP figures (MSB=0 bit numbering).
VECTORS = [
    # --- TOD clock / CPU timer (S format: OP(0-15) B2(16-19) D2(20-31)) ---
    ("b2041000", "sck", "0(%r1)", "system",
     "SET CLOCK: B204, B2=1, D2=0"),
    ("b2051000", "stck", "0(%r1)", "system",
     "STORE CLOCK: B205, B2=1, D2=0"),
    ("b2051234", "stck", "0x234(%r1)", "system",
     "STORE CLOCK with nonzero displacement D2=0x234"),
    ("b2061000", "sckc", "0(%r1)", "system",
     "SET CLOCK COMPARATOR: B206"),
    ("b2071000", "stckc", "0(%r1)", "system",
     "STORE CLOCK COMPARATOR: B207"),
    ("b2081000", "spt", "0(%r1)", "system",
     "SET CPU TIMER: B208"),
    ("b2091000", "stpt", "0(%r1)", "system",
     "STORE CPU TIMER: B209"),
    ("b2781000", "stcke", "0(%r1)", "system",
     "STORE CLOCK EXTENDED: B278"),
    ("b27c1000", "stckf", "0(%r1)", "system",
     "STORE CLOCK FAST: B27C"),
    # --- CPU/system control (S format) ---
    ("b20a1000", "spka", "0(%r1)", "system",
     "SET PSW KEY FROM ADDRESS: B20A"),
    ("b2121000", "stap", "0(%r1)", "system",
     "STORE CPU ADDRESS: B212"),
    ("b2021000", "stidp", "0(%r1)", "system",
     "STORE CPU ID: B202"),
    ("b27d1000", "stsi", "0(%r1)", "system",
     "STORE SYSTEM INFORMATION: B27D"),
    ("b2791000", "sacf", "0(%r1)", "system",
     "SET ADDRESS SPACE CONTROL FAST: B279"),
    ("b2181000", "pc", "0(%r1)", "system",
     "PROGRAM CALL: B218 (not program counter)"),
    # --- Program mask (RR / RRE) ---
    # SPM: '04' R1(8-11) ignored(12-15); R1 designates a GPR.
    ("0430", "spm", "%r3", "system",
     "SET PROGRAM MASK: 04, R1=3"),
    ("0400", "spm", "%r0", "system",
     "SET PROGRAM MASK: 04, R1=0"),
    # IPM: 'B222' ignored(16-23) R1(24-27) ignored(28-31).
    ("b2220030", "ipm", "%r3", "system",
     "INSERT PROGRAM MASK: B222, R1=3"),
    # --- Crypto, RRE: 'OP' ignored(16-23) R1(24-27) R2(28-31) ---
    # Function codes live in GR0, not in the instruction (PoP 7-54).
    ("b92e0000", "km", "%r0, %r0", "crypto",
     "CIPHER MESSAGE: B92E"),
    ("b92f0000", "kmc", "%r0, %r0", "crypto",
     "CIPHER MESSAGE WITH CHAINING: B92F"),
    ("b92a0000", "kmf", "%r0, %r0", "crypto",
     "CIPHER MESSAGE WITH CIPHER FEEDBACK: B92A"),
    ("b92b0000", "kmo", "%r0, %r0", "crypto",
     "CIPHER MESSAGE WITH OUTPUT FEEDBACK: B92B"),
    ("b91e0012", "kmac", "%r1, %r2", "crypto",
     "COMPUTE MESSAGE AUTHENTICATION CODE: B91E, R1=1, R2=2"),
    ("b92c0000", "pcc", "", "crypto",
     "PERFORM CRYPTOGRAPHIC COMPUTATION: B92C, no operands"),
    ("b9280000", "pckmo", "", "crypto",
     "PERFORM CRYPTOGRAPHIC KEY MGMT OP: B928, no operands"),
    ("b93c0000", "ppno", "%r0, %r0", "crypto",
     "PERFORM RANDOM NUMBER OP: B93C (PoP alias PRNO; Capstone prints ppno)"),
    # --- Crypto, RRF-b: 'OP' R3(16-19) ignored(20-23) R1(24-27) R2(28-31) ---
    ("b9290000", "kma", "%r0, %r0, %r0", "crypto",
     "CIPHER MESSAGE WITH AUTHENTICATION: B929"),
    ("b92d0000", "kmctr", "%r0, %r0, %r0", "crypto",
     "CIPHER MESSAGE WITH COUNTER: B92D"),
    # --- Crypto, RRF-c: 'OP' M3(16-19) reserved(20-23) R1(24-27) R2(28-31) ---
    ("b93e0000", "kimd", "%r0, %r0", "crypto",
     "COMPUTE INTERMEDIATE MESSAGE DIGEST: B93E, M3=0 (not displayed)"),
    ("b93f0000", "klmd", "%r0, %r0", "crypto",
     "COMPUTE LAST MESSAGE DIGEST: B93F, M3=0 (not displayed)"),
]


def main():
    md = Cs(CS_ARCH_SYSZ, CS_MODE_BIG_ENDIAN)
    failures = []
    records = []
    for hx, mnem, op_str, cat, notes in VECTORS:
        data = bytes.fromhex(hx)
        ds = list(md.disasm(data, 0))
        if not ds:
            failures.append(f"{hx}: Capstone decoded nothing (want {mnem})")
            continue
        d = ds[0]
        if d.mnemonic != mnem or d.op_str != op_str:
            failures.append(
                f"{hx}: got '{d.mnemonic} {d.op_str}', want '{mnem} {op_str}'")
            continue
        if d.size != len(data):
            failures.append(f"{hx}: decoded size {d.size}, want {len(data)}")
            continue
        records.append({
            "bytes_hex": hx,
            "capstone_mnemonic": d.mnemonic,
            "capstone_op_str": d.op_str,
            "category": cat,
            "notes": notes,
        })
        print(f"ok  {hx} -> {d.mnemonic} {d.op_str}")

    with open(OUT, "w") as f:
        json.dump(records, f, indent=2)
        f.write("\n")
    print(f"wrote {len(records)} vectors to {OUT}")

    if failures:
        print(f"\n{len(failures)} FAILURES:")
        for fl in failures:
            print("  " + fl)
        sys.exit(1)
    print(f"\n{len(records)}/{len(VECTORS)} vectors validated against Capstone")


if __name__ == "__main__":
    main()
