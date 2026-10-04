# p-code / Decompiler / Runtime — Status Report

**Date:** 2026-10-04
**Scope note:** HLASM encoding, SLEIGH display, p-code semantics, and runtime
behavior are separate evidence levels. Encoding+display are validated
(`tests/COVERAGE_REPORT.md`: 4,091/4,091 decode). This report covers p-code
semantics only.

## Method

Each semantic validator dumps p-code via `tests/s390x_pcode`, executes it in
a tiny flat-memory interpreter, and checks registers/memory/CC against PoP
rules (and Capstone where applicable).

## Scoreboard (re-run 2026-10-04, all green)

| Validator | Vectors | Covers |
|-----------|---------|--------|
| validate_cond2.py | 64/64 | Condition-code model, branches |
| validate_tm16.py | 40/40 | TM/TMY/TMHH/TMHL/TMLH/TMLL CC rules |
| validate_div.py | 20/20 | Signed/unsigned divide semantics |
| validate_trtt.py | 6/6 | TRTT partial-completion, CC, writeback |
| validate_fp3.py | 30/30 | Floating-point (vs Capstone) |
| validate_gaps2.py | 31/31 | Gap-family semantics |
| validate_vector2.py | 46/46 | Vector semantics |
| validate_loadstore.py | 34/34 | Load/store (vs Capstone) |
| validate_decimal.py | 32/32 | PACK/UNPK/ZAP/CP/AP/… (31/31 Capstone-agree; SS-format not decodable by Capstone 5.0.x) |
| **Total** | **303/303** | |

Notes:
- `validate_decimal.py` harness was broken (double-`@include` of
  `s390x_decimal.sinc`); fixed 2026-10-04, now 32/32.
- `validate_fp3.py` / `validate_gaps2.py` default to `/tmp` isolation builds;
  pass `data/languages/s390x.sla` explicitly (as done here).
- Differential fuzzer (2026-09-21): 20,000 inputs, 0 crashes, 0 misdecodes
  (not re-run today).

## Not covered / known limitations

- ~40 unimplemented mnemonics (LCTL/STCTL, SIGP, SPX, PTLB, MC, LRA, CS/CDS,
  DFP ops, MVCP/MVCS/MVCK, PLO, UNPKU, others) — no p-code at all.
- Approximate HFP semantics; unmodeled TRACE side effects and TLS.
- TRTT partial-completion approximated.
- XPLINK `br r7` not recognized as a return.
- No end-to-end decompiler differential vs a reference compiler output;
  Ghidra smoke tests (raw/ELF/XPLINK) pass but are not semantic proofs.
- Runtime behavior on real z/OS (supervisor state, crypto facilities) is
  untested by design in this phase.
