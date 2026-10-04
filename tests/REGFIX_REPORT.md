# Register-operand fix report — 2026-10-04

49 statements that failed with assembler diagnostics were corrected
and reassembled. Two fix batches:
- batch_fix_regs.asm: 39 statements (TASM0022/JOB00591) — 39/39
  assembled, 39/39 SLEIGH-decodable.
- batch_fix_regs2.asm: 9 statements (TASM0025/JOB00611) — 9/9
  assembled, 9/9 decoded. Plus T0489 SRP (031E) and T0127 TRAP4 (040S)
  fixed individually.

## Register constraints discovered (via probe jobs TASM0020/0021)

| family | constraint | example fix |
|---|---|---|
| SRDL/SLDL/SRDA/SLDA | R1 must be even (register pair) | `SRDL 1,16(3)` → `SRDL 2,16(3)` |
| TRE/TRTE/TRTT/TROT | R1 must be even (selects even/odd addr/len pair) | `TRE 1,2` → `TRE 0,2` → `B2A50002` |
| CLCLE/CLCLU | R1 and R3 must be even (pairs) | `CLCLE 1,3,16(3)` → `CLCLE 2,4,16(3)` |
| FIXBRA (DFP) | R1 and R2 must designate valid FP pairs {0,4,8,12} | `FIXBRA 1,7,2,7` → `FIXBRA 0,7,0,7` → `B3477700` |
| LDXR/LEXR | R1 single FPR (any), R2 must be valid FP pair {0,4,8,12} | `LDXR 1,2` → `LDXR 1,0` → `2510` |
| AXR/SXR/LPXR/LNXR/LTXR/LCXR/FIXR/CXR | R1,R2 must be valid FP pairs {0,4,8,12} | `AXR 1,2` → `AXR 0,0` → `3600` |
| M/MR/ML/MLR/MLG/MLGR/D/DR/DLG/DLGR/DSG/DSGR/DSGF/DSGFR | R1 must be even (pair) | `MR 1,2` → `MR 2,2` |
| KM/KMO/PPNO | R1 must be even | `KM 1,2` → `KM 2,2` → `B92E0022` |
| KMCTR | R1,R3,R2: R1 and R3 even | `KMCTR 1,3,2` → `KMCTR 2,4,2` |
| MP/DP | L2 < L1 (ASMA069S) | `MP 0(8,4),16(8,3)` → `MP 0(8,4),16(4,3)` → `FC7340003010` |
| SRP | I3 shift amount range | `SRP 0(8,4),16(3),171` → `SRP 0(8,4),16(3),0` → `F07040003010` |
| TRAP4 | needs immediate (ASMA040S) | `TRAP4` → `TRAP4 171` → `B2FF00AB` |

Key finding: for HFP extended (XR) and DFP extended-pair operands,
HLASM requires the register to designate a "valid FP register pair",
which empirically is **R ∈ {0,4,8,12}** (R mod 4 == 0), not merely
even — `LDXR 1,2` and `LDXR 0,2` fail, `LDXR 1,0` and `LDXR 1,4`
assemble.

## Accounting correction

The audit counted "45× ASMA029E" — that was 45 error *lines*.
Distinct statements: **39** (some, e.g. KMCTR, emit two 029E lines;
a few 029E lines are split across 3270 screen chunks). All 39 are
now recovered. The "45 register errors" in MISSING_AUDIT.md should
read 39 distinct statements.

## Parser artifacts in this run

4 labels needed raw-line verification (all confirmed correct):
- T0509 TRE (label split `T`/`0509`), bytes `B2A50002`
- T4176 DR (label split), bytes `1D22`
- T4149 MLG (label split), bytes `E32233451286`
- T4167 D (label split), bytes `5D223010`
