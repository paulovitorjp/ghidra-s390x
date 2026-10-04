# EBCDIC-Sensitive Validation — Report

**Date:** 2026-10-04
**Batch:** `hlasm_batches/batch_ebcdic.asm` (18 statements, labels E0001–E0018)
**Assembler:** IBM HLASM R6.0, PTF UI30594, on z/OS V2R2
**Job:** TASM0012 / JOB00525 — **0 assembler errors**, 18/18 labels extracted
**Listing:** `MUSE.ASM.LIST12` (cataloged)

## Result

| Check | Result |
|-------|--------|
| Statements assembled | 18/18, 0 errors |
| Encodings extracted | 18/18 |
| SLEIGH decode (`tests/s390x_decode`) | 18/18 OK, exact mnemonic match |

All 18 are base mnemonics — no display-name variants involved.

## What was validated

**Character immediates** — the assembler's EBCDIC code points land in the
immediate byte exactly as the PoP defines:
- `C'A'` → `0xC1`: MVI (92C14000), NI (94C14000)
- `C' '` → `0x40`: MVI (92404000), OI (96404000)
- `C'Z'` → `0xE9`: CLI (95E94000), XI (97E94000)
- `C'0'` → `0xF0`: CLI (95F04000)

**Zoned decimal** — `DC C'12345'` assembles to `F1F2F3F4F5`; PACK/UNPK/ZAP/CP/AP
reference it with correct lengths (L=3→2, L=6→5) and `P'123'` → `F067`:
PACK F2244000F062, UNPK F3514000F067, ZAP F8244000F062, CP F9244000F062,
AP FA244000F062.

**Translate** — 256-byte table `DC 256C' '` (all `0x40`); TR DC0F4000F069,
TRT DD0F4000F069, length 16 → `0x0F`.

**Edit** — pattern `X'40206B202020'` (`0x40` blank fill); ED DE074000F169,
EDMK DF074000F169, length 8 → `0x07`.

**Move/compare** — `DC C'HELLO123'`; MVC D2074000F16F, CLC D5074000F16F,
length 8 → `0x07`.

**Address consistency** — data layout verified against the listing:
ZD1 @0x62 (5 bytes) → PD1 @0x67 (2 bytes) → TRTAB @0x69 (256 bytes) →
EDPAT @0x169 (6 bytes) → EBCDAT @0x16F. All B2D2 fields match.

## Bugs found and fixed during this batch

1. **Listing-parser quote pairing** (fixed before this run, commit `e512c13`):
   `screen_text()` paired apostrophes naively, so `C'A'` / `C' '` / `X'...'`
   operands desynchronized listing rows and hid every EBCDIC label.
   **Validated live:** all 18 labels with quoted operands extracted correctly.

2. **ASMA144E submission artifact** (found and fixed this run): the first two
   submissions failed E0001 with `ASMA144E Begin-to-continue columns not
   blank`. Root cause: the 77-character comment line preceding E0001
   contaminated the next record through the fast `SUBMIT *` path (no per-line
   wait) — the record reached column 72 non-blank, which HLASM reads as a
   continuation indicator. Proven by bisection: the identical statement
   assembles cleanly with a short comment (probe LIST98: 92C14000, 0 errors;
   exact batch replica with the 77-char comment reproduces ASMA144E).
   Fix: shortened the comment to 20 chars. Lesson recorded in `AGENTS.md`:
   keep batch source lines ≤ 71 columns.

## Parser edge cases (listing extraction, not assembler/SLEIGH issues)

- Run 1: E0002/E0003 had ADDR-column digits (`00000`) glued to the object
  code (`924040000000`); true bytes `9240 4000` / `95E9 4000` read from the raw
  listing. Run 3 extracted both cleanly.
- Run 1: E0013's label wrapped across a screen chunk (`E001`/`3`); recovered
  `DC0F 4000 F065` from the raw listing. Run 3 extracted it cleanly.
- Run 3: E0010/E0011's labels wrapped (`E00`/`10`, `E`/`0011`); recovered
  `F824 4000 F062` / `F924 4000 F062` from raw listing lines L105–L106.

## Corpus

`tests/corpus_zos_hlasm_ebcdic.json` — 18 entries (schema-compatible with the
full corpus, plus a `provenance` field per entry). Merged into
`tests/corpus_zos_hlasm_full.json` (now 4,091 entries; the invalid all-zero
TRTO record T0512 was removed as part of this update).
