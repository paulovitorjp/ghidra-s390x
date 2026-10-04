# Condition-Code Cleanup — 2026-09-20

## What changed

The `cc` varnode now holds the condition code as a plain 0–3 value.
Previously it was packed into bits 4–5 of a byte: every CC-setting
instruction did a read-modify-write (`cc = (cc & 0xcf) | (ncc << 4)`)
and every conditional branch extracted it back (`(cc >> 4) & 0x3`).
That packing was pure p-code noise — the byte is a synthetic register,
so the bit placement bought nothing — and it created a false data
dependency (every CC write appeared to read the old CC).

Edits (4 source files, decode and architectural semantics untouched):
- `s390x_arith.sinc`: `cc_set(ncc)` body is now `cc = ncc;`
- `s390x_branch.sinc` (18), `s390x_branch2.sinc` (14),
  `s390x_cond.sinc` (277): all 309 `_?ccval = (cc >> 4) & 0x3;`
  readers are now `_?ccval = cc;`
- Header comments in the three files updated to the new convention.

## Bug found and fixed along the way

`s390x_decimal.sinc` (23 sites: AP/SP/MP/DP/CP/TP/TRT/…) and the
MVCL-family code in `s390x_gaps.sinc` were already writing raw 0–3
values to `cc`, while every branch reader unpacked bits 4–5. Under the
old convention a branch after one of those instructions modeled
`(raw_cc >> 4) & 3` — always 0 — instead of the real condition code.
Unifying on raw 0–3 fixed this; those 727 writes are now correct as-is.

## Verification

- Spec recompiles with 0 errors; compiler warnings byte-identical to the
  pre-change build (verified by rebuilding the pristine sources).
- Differential harness `tests/sleigh_diff.py` (645 implemented vectors):
  **645/645 passed, 0 failed** — and the identical 645/645 on the
  pre-change module, proving decode is unchanged.
- Sample disassemblies byte-identical before/after (only p-code changed).
- P-code per CC write: 3 ops → 1 (`COPY`). Per conditional branch:
  5 ops → 3 (the 2-op extract is gone). No more read-modify-write on `cc`.

## Before / after (AP decimal-add followed by JHE)

Before — the branch tested a twice-mangled value (`>> 4 & 3` applied to
an already-raw CC, always folding to 0):

```c
if ((8U >> ((byte)(bVar18 * '\x03' + ('\x01' - bVar18) *
             ('\x01' - bVar19) * ('\x02' - bVar9)) >> 4 & 3) & 10) == 0) {
```

After — the branch tests the condition code directly:

```c
if ((8U >> bVar18 * '\x03' + ('\x01' - bVar18) *
         ('\x01' - bVar19) * ('\x02' - bVar9) & 10) == 0)
{
```

(The `8U >> cc & mask` idiom is inherent to the architecture — mask bit
for CC=i is `8>>i` per PoP 7-47 — and is unchanged.)
