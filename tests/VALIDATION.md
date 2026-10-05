# Validation

How the s390x SLEIGH module is validated, and the current results.

## HLASM exhaustive validation (2026-10-04)

All 4,356 SLEIGH constructors validated against IBM HLASM R6.0 (PTF UI30594)
on z/OS V2R2. Method: HLASM assemble → extract machine code from listing →
SLEIGH decode.

**Accounting:**

| Category | Count |
|---|---|
| Validated main-constructor encodings | 4,308 |
| Supplemental EBCDIC vectors | 18 |
| ARCH-gated (PoP-text only) | 41 |
| Deliberately unsupported (gap batch) | 29 |
| Duplicates / skipped / invalid | 7 |
| **Total constructors** | **4,356** |

Every correctly-extracted byte sequence decodes: **0 true SLEIGH gaps**.

The 41 ARCH-gated cases (SELECT family, MG/MGH, KMA, DFP converts) cannot
assemble at HLASM R6.0's default ARCH level — validated against PoP text only
until a higher-ARCH toolchain is available.

The 29 gap-batch mnemonics (privileged/system, DFP, unimplemented families)
are confirmed unsupported with assembler ground-truth bytes.

**Parser hardening:** 3270 screen-wrapping split labels (e.g. `T3`/`308`)
and glued ADDR digits to object code. 185 parser misses recovered from raw
listings. Batch source lines must stay ≤71 columns (column 72 is HLASM's
continuation indicator).

**Register constraints discovered:** XR/DFP extended pairs must start at
{0,4,8,12}; TRE/KM R1 must be even; MP/DP require L2<L1; TRAP4 needs an
immediate. 49 statements recovered across fix batches.

## Semantic validation (p-code)

Each validator dumps p-code, executes it in a flat-memory interpreter, and
checks registers/memory/CC against PoP rules. Re-run 2026-10-04, all green:

| Validator | Vectors | Covers |
|---|---|---|
| cond2 | 64/64 | Condition-code model, branches |
| tm16 | 40/40 | TM/TMY/TMHH/TMHL/TMLH/TMLL CC rules |
| div | 20/20 | Signed/unsigned divide semantics |
| trtt | 6/6 | TRTT partial-completion, CC, writeback |
| fp3 | 30/30 | Floating-point (vs Capstone) |
| gaps2 | 31/31 | Gap-family semantics |
| vector2 | 46/46 | Vector semantics |
| loadstore | 34/34 | Load/store (vs Capstone) |
| decimal | 32/32 | PACK/UNPK/ZAP/CP/AP/… |
| **Total** | **303/303** | |

Plus: differential corpora 1,665/1,665 vs Capstone (2026-09-21);
20,000-input fuzzer with 0 crashes and 0 misdecodes.

## Known limitations

- ~40 unimplemented mnemonics (LCTL/STCTL, SIGP, SPX, PTLB, MC, LRA, CS/CDS,
  DFP ops, MVCP/MVCS/MVCK, PLO, UNPKU, others) — no p-code.
- Approximate HFP semantics; unmodeled TRACE side effects and TLS.
- TRTT partial-completion approximated.
- XPLINK `br r7` not recognized as a return.
- No end-to-end decompiler differential vs reference compiler output.
- Runtime behavior on real z/OS (supervisor state, crypto) untested by design.

## Validation history

- **2026-09-17:** Differential corpus vs Capstone (203 vectors); SLEIGH
  compiler fixes (field namespace, attach order, 64-bit literals).
- **2026-09-21:** Final integration — 1,665/1,665 differential, 20k fuzzer
  clean, 303/303 semantic.
- **2026-10-02:** HLASM batches 01–11 re-pulled from cataloged listings;
  4,080/4,350 labels extracted; classifier fixed (display-name variants).
- **2026-10-04:** Gap batch 30/30, register fixes 49/49, parser misses
  185/185, EBCDIC batch 18/18. Final corpus: 4,326 entries, all decode.
