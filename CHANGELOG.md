# Changelog

## 2026-11-06 — Entry recovery, indirect register branches, signed relatives

- Load-module and GOFF section blocks are readable, writable, and executable.
  A non-executable section made entry-point analysis drop a subroutine whose
  prologue ends in a register branch.
- BCR/BR, BCTR, and BCTGR branch to the address held in the register.
- BALR, BASR, and BAKR test the R2 field. R2=0 stores a link (BALR/BASR) or
  performs no branch (BAKR) and does not emit a call. Any other R2 is an
  indirect call or branch.
- 32-bit PC-relative operands sign-extend the halfword count. BRASL/BRCL
  and LARL use that signed target. A negative BRASL no longer wraps into
  the high half of the 64-bit address space.
- LAY and XY print the signed 20-bit displacement and omit a zero index.
  Other long-displacement forms already compute the signed address; their
  listing text still shows the low 12 bits.
- The constant `zero` base/index is tracked as 0 and assigned at function
  entry so it is not a free decompiler input.

Not claimed: a full COBOL front end. Inline parameter lists that a callee
skips before returning are still ordinary bytes. Invalid packed digit or
sign codes still do not raise a data exception. PACK/UNPK placed every
digit except the units digit in the wrong nibble, and CP treated equal
nonzero magnitudes with opposite signs as equal; both are corrected.

## 2026-10-04 — HLASM exhaustive validation complete

All 4,356 SLEIGH constructors validated against IBM HLASM R6.0 on z/OS:
4,308 main-constructor encodings + 18 EBCDIC vectors, every correctly-extracted
byte sequence decodes (0 true SLEIGH gaps). 41 instructions are ARCH-gated at
HLASM R6.0's default level (SELECT, MG/MGH, KMA, DFP converts) — validated
against PoP text only. 29 deliberately unsupported mnemonics confirmed with
assembler ground-truth bytes. Full details in `tests/VALIDATION.md`.

## 2026-10-02 — Listing parser hardened

Fixed 3270 screen-wrapping artifacts that split labels (e.g. `T3`/`308`) and
glued ADDR digits to object code. 185 parser misses recovered from raw
listings. Batch source lines must stay ≤71 columns (column 72 is HLASM's
continuation indicator).

## 2026-09-21 — Integration and validation pass

Final integration: differential corpora 1,665/1,665 green vs Capstone,
20,000-input fuzzer with 0 crashes and 0 misdecodes, semantic validators
303/303, loaders validated (classic/GOFF/PDS), ELF relocation smoke 55/55,
Ghidra 12.1.3 raw/ELF/XPLINK smokes green. Four real bugs fixed: sdiv64
INT64_MIN/-1 trap, signed division using unsigned ops, 32-bit quotient
overflow check, TRTT modeled at wrong opcode (D9→B990). TRTT partial
completion and XPLINK returns documented as known limitations.

## 2026-09-20 — Condition-code cleanup

The `cc` varnode now holds a plain 0–3 value (was packed into bits 4–5 of a
byte). Removed 310 noisy pack/unpack conversions. Fixed a latent bug: decimal
and MVCL-family instructions wrote raw CC values while branch readers
unpacked bits 4–5, so branches after those instructions always saw CC=0.

## 2026-09-18 — Decimal and string p-code

MP/DP/TRE/CVD/CVB/MVCL/CLCL got real p-code semantics (were stubs).
Spec at 2,981 constructors, compiles with 0 errors. z/OS loaders
implemented and validated end-to-end against synthetic fixtures.

## 2026-09-17 — Ghidra integration smoke test

Module loads in Ghidra 12.1.3, disassembles correctly, decompiler produces
C output. Two defects found and fixed: a UTF-8 em-dash in XML comments that
silently killed the decompiler, and incorrect BCR p-code semantics.
