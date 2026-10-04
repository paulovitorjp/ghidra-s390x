# Gap-batch validation report — 2026-10-04 (final)

30 confirmed spec-gap families from `hlasm_batches/batch_gap.asm`,
assembled live on z/OS (HLASM R6.0, PTF UI30594) and decoded with the
SLEIGH spec. Final clean run: job `TASM0019/JOB00559`,
listing `MUSE.ASM.LIST19` — **30/30 assembled, 0 assembler errors**.

## Classification

| result | count | labels |
|---|---|---|
| SLEIGH NODECODE (true gap) | 29 | all except G0021 |
| SLEIGH decodes (spec covers it) | 1 | G0021 OILF |

G0021 `OILF 1,305419896` → `C01D12345678` → decodes as
`OILF r1, 0x12345678`. OILF was misclassified as a gap; the spec
covers it. (G0020 OIHF → `C01C12345678` is NODECODE — a true gap.)

## Ground-truth encodings (all 30)

| label | statement (corrected) | bytes | SLEIGH |
|---|---|---|---|
| G0001 | LCTL 1,3,16(4) | B7134010 | NODECODE |
| G0002 | STCTL 1,3,16(4) | B6134010 | NODECODE |
| G0003 | SIGP 1,2,16(3) | AE123010 | NODECODE |
| G0004 | SPX 16(3) | B2103010 | NODECODE |
| G0005 | PTLB | B20D0000 | NODECODE |
| G0006 | MC 16(3),15 | AF0F3010 | NODECODE |
| G0007 | LRA 1,16(2,3) | B1123010 | NODECODE |
| G0008 | LRAG 1,74565(2,3) | E31233451203 | NODECODE |
| G0009 | CS 1,3,16(4) | BA134010 | NODECODE |
| G0010 | CDS 2,4,16(4) | BB244010 | NODECODE |
| G0011 | MVCP 0(4),16(5),1 | DA4100005010 | NODECODE |
| G0012 | MVCS 0(4),16(5),1 | DB4100005010 | NODECODE |
| G0013 | MVCK 0(4),16(5),1 | D94100005010 | NODECODE |
| G0014 | PLO 1,16(5),0,0 | EE1050100000 | NODECODE |
| G0015 | UNPKU 0(4),16(5) | E20300005010 | NODECODE |
| G0016 | STFL 16(3) | B2B13010 | NODECODE |
| G0017 | CVBY 1,74565(2,3) | E31233451206 | NODECODE |
| G0018 | CVDY 1,74565(2,3) | E31233451226 | NODECODE |
| G0019 | LGFI 1,305419896 | C01112345678 | NODECODE |
| G0020 | OIHF 1,305419896 | C01C12345678 | NODECODE |
| G0021 | OILF 1,305419896 | C01D12345678 | **decodes** |
| G0022 | CLFEBR 1,7,2,7 | B39C7712 | NODECODE |
| G0023 | CDLGBR 1,7,2,7 | B3A17712 | NODECODE |
| G0024 | IDTE 1,2,7 | B98E2017 | NODECODE |
| G0025 | FIDTR 1,7,2,7 | B3D77712 | NODECODE |
| G0026 | CDFTR 1,7,2,7 | B9517712 | NODECODE |
| G0027 | CFDTR 1,7,2,7 | B9417712 | NODECODE |
| G0028 | ADTRA 1,7,2,7 | B3D22717 | NODECODE |
| G0029 | BPRP 7,BT1,BT2 | C57FBC000006 | NODECODE |
| G0030 | LMD 1,3,0(4),16(5) | EF1340005010 | NODECODE |

## Statement corrections (11 test-data bugs fixed 2026-10-04)

The original batch had invalid HLASM for 11 statements (13 assembler
diagnostics on the first run). Corrected via probe jobs TASM0015–0018:

- **MC**: `MC 16(3),171` → `MC 16(3),15`. HLASM rejects I2=171
  (ASMA031E); I2 accepts 0–15 here. Bytes `AF0F3010`.
- **CDS**: `CDS 1,3,16(4)` → `CDS 2,4,16(4)`. Both R1 and R3 must be
  even (register-pair operands). Bytes `BB244010`.
- **MVCK**: `MVCK 0(4),16(5)` → `MVCK 0(4),16(5),1`. The 2-operand form
  is a delimiter error; the 3-operand (access-register) form assembles.
  Bytes `D94100005010`.
- **PLO**: `PLO 1,0(4),16(5)` → `PLO 1,16(5),0,0`. PLO takes four
  operands `R1,D2(B2),R3,R4`; 2- and 3-operand forms fail. Bytes
  `EE1050100000`.
- **UNPKU**: `UNPKU 0(8,4),16(8,3)` → `UNPKU 0(4),16(5)`. No length
  operands. Bytes `E20300005010`.
- **DFP converts** (CLFEBR, CDLGBR, FIDTR, CDFTR, CFDTR, ADTRA):
  3-operand `R1,M3,R2` → 4-operand `R1,M3,R2,M4`, e.g.
  `CLFEBR 1,7,2,7` → `B39C7712`. The 3-operand form gives
  ASMA175S "expected comma".

## Parser artifacts (not assembler/SLEIGH issues)

The final run extracted 27/30 automatically; 3 needed raw-line
verification, all confirmed correct:
- G0006, G0007, G0008: labels split across 3270 screen chunks
  (`G00`/`06`, `G00`/`07`, `G0`/`008`) — known wrap edge case.
- G0001–G0003: ADDR column (`00010`) glued to object bytes on screen
  (`B71340100001`); true bytes `B7134010` etc. — known glue edge case.

## Bottom line

29 of 30 gap candidates are confirmed true SLEIGH gaps with
assembler ground-truth encodings. OILF is covered by the spec and was
removed from the gap list. No new spec work was done in this pass —
these remain documented gaps (privileged/system, DFP, and other
unimplemented families).
