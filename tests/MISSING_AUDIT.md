# Missing-Records Audit — Main HLASM Batches (01–11)

**Date:** 2026-10-04
**Source:** `tests/batch_results_pulled.json` (listings re-pulled from
`MUSE.ASM.LIST01`–`LIST11`, 2026-10-02)

## Totals

276 labels produced no extracted bytes = **85 assembler errors** +
**191 parser misses** (assembled without error; bytes present in listing but
not extracted).

## The 85 assembler errors — corrected breakdown

The earlier "85 ARCH-gated" summary was wrong. By assembler diagnostic:

| Diagnostic | Count | Meaning |
|------------|-------|---------|
| ASMA057E undefined operation code | 39 | Mnemonic unknown at HLASM R6.0 default ARCH — genuinely ARCH-gated (or non-mnemonic) |
| ASMA029E incorrect register specification | 45 error lines / **39 distinct statements** | **Operand errors** — the generated statement violates register constraints (e.g. odd R1 where an even-odd pair is required). NOT arch-gating; recoverable by fixing operands. **Recovered 2026-10-04** (see tests/REGFIX_REPORT.md) |
| ASMA031E invalid immediate or mask field | 1 | Operand error; statement not individually identified |

### ASMA057E (39) — by mnemonic

- SELECT family (28): SELR×3, SELRO, SELRH, SELRL, SELRNE, SELRE, SELGR×4,
  SELGRO, SELGRH, SELGRL, SELGRNE, SELGRE, SELFHR×3, SELFHRH, SELFHRL,
  SELFHRNE, SELFHRE — need ARCH 10+ (select facility)
- MG×8, MGH×1 — note: `MG_*` are generated constructors in
  `s390x_muldiv_gen.sinc` (E3/84) whose display name `MG` is **not a real
  HLASM mnemonic** (hence "undefined operation code"); MGH is real but needs
  the high-word facility (ARCH-gated)
- KMA×1 — crypto facility, ARCH-gated
- CFDRA×1, CGERA×1, CGDRA×1 — DFP converts, ARCH-gated
- 2 unparsed (screen-split `M G` / `?`)

### ASMA029E (45 error lines, 39 distinct statements) — operand errors, RECOVERED 2026-10-04

24 in batch_02, 21 in batch_11. Clear cases: SRDL/SLDL/SRDA/SLDA with R1=1
(shift-double instructions require an even R1 for the even-odd pair);
M/D/DR/DL/MR with odd R1 (even-odd pair required). Exact statement↔error
mapping needs a listing re-pull (error lines carry only the operand, not the
T-label). **Recovery:** correct the operands (even R1) and re-assemble —
these are test-data bugs, not toolchain limits.

### ASMA031E (1)

Single "invalid immediate or mask field" in batch_02; statement unidentified
from the pulled data. Recover on re-pull.

## The 191 parser misses — cluster analysis

Assembled cleanly; the listing parser failed to locate the bytes. Strong
clustering (top mnemonics): STMG 15, BASSM 14, LMH 14, STMY 13, BSM 13,
LMG 12, STMH 11, LAM/STAM 7 each, LM 7, LAE 6, STM 6, LOCHHI 5, CLCL 5,
CIT 4, CGIT 3, VSB 3, MVCL 2 …

By source file: `s390x_loadstore_gen.sinc` 65, `s390x_gaps2.sinc` 47,
`s390x_cond.sinc` 23, `s390x_muldiv_gen.sinc` 22, `s390x_fp2.sinc` 14 —
i.e. concentrated in generated constructor variants, especially
RSY/RXY long-displacement load/store-multiple forms (`74565(3)`) and
branch-and-save (BSM/BASSM). Mechanism (parser vs listing quirk) to be
determined from raw listing lines on re-pull.

## Recovery plan (needs mainframe)

1. ~~Regenerate the 45 ASMA029E statements with corrected (even) registers;
   submit as a fix batch.~~ DONE 2026-10-04: 39 statements, 39/39 assembled,
   39/39 decoded (tests/REGFIX_REPORT.md; batch_fix_regs.asm).
2. Re-pull `MUSE.ASM.LIST01`–`LIST11`; examine raw lines for the 191 misses;
   fix the parser or hand-recover as with the EBCDIC batch.
3. Re-run the 30-case gap batch (`hlasm_batches/batch_gap.asm`) — its last
   result predates the parser fixes.

## Recovery update — 2026-10-04 (final)

All recoverable records have been recovered. Corpus
`tests/corpus_zos_hlasm_full.json` now holds **4,326 entries**
(4,308 T-labels + 18 EBCDIC).

### Recovered 2026-10-04
- **39 ASMA029E statements** → batch_fix_regs.asm (TASM0022/JOB00591),
  39/39 assembled, 39/39 decoded. See tests/REGFIX_REPORT.md.
- **9 more 029E/length errors** → batch_fix_regs2.asm (TASM0025/JOB00611):
  MXR/LXR (0,0), MFY/DL (R1→2), KMC/KMF (2,2), TROO (0,2),
  MP/DP (L2<L1: 8,4). 9/9 assembled, 9/9 decoded.
- **1 ASMA031E** (T0489 SRP): I3 171→0 → `F07040003010`, decodes.
- **1 ASMA040S** (T0127 TRAP4): needs immediate → `TRAP4 171` →
  `B2FF00AB`, decodes.
- **185 parser misses** recovered by raw-listing extraction
  (split-label `...\n...` wrap artifacts). 175 via script + 10 manual.
  All decode in SLEIGH.

### Genuinely unrecoverable (42 T-labels)
- **41× ASMA057E** — ARCH-gated at HLASM R6.0 default ARCH:
  SELECT family (26), MG×9, MGH, KMA, CFDRA/CGERA/CGDRA/CFERA (4).
  PoP-text-only until a higher-ARCH toolchain exists.
- **1× TRTO** (T0512) — invalid all-zero extraction artifact, correctly
  excluded.

### Final accounting
4,356 constructors = 4,308 T-labels in corpus + 41 ARCH-gated 057E +
1 invalid TRTO + 5 dupes + 1 skip (DIAGNOSE). The corpus file holds
4,326 entries (4,308 T + 18 supplemental EBCDIC).

## raw_sample.json

`tests/raw_sample.json` (258 bytes): three raw listing-line samples
(T0048 SLAG, T0098 JNE, T0114 BRC) kept as evidence for the split-LOC
screen-wrapping parser bug. Kept intentionally.
