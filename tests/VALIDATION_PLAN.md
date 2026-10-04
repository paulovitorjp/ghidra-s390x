# z/Architecture SLEIGH Module — Validation Plan

Date: 2026-09-17. Scope: `data/languages/s390x.slaspec` (+ `s390x_*.sinc`).

## 1. Differential corpus vs Capstone — DONE

- `tests/diff_harness.py` decodes every vector in `tests/corpus.json` with the
  Capstone oracle (`CS_ARCH_SYSZ`) and records the mnemonic/operands the SLEIGH
  spec must produce.
- **Corpus: 203 accepted vectors** — load 28, store 25, arith 48, logic 28,
  cmp 27, branch 20, priv 8, misc 1, fp 18.
- `tests/decode_failures.log`: exactly one genuine decode failure —
  `PR 0100` (Capstone 5.0.7/5.0.9 has no PR mnemonic). All previously reported
  `QUIRK-RRE` notes were false alarms and have been removed; Capstone decodes
  LLGC/LLGH/LCGR/LNGR/LPGR/GFR forms correctly.
- `tests/validate_loadstore.py` (pre-existing) is untouched and still passes.
- Toolchain note: `pip` reports capstone 5.0.9 but `capstone.__version__`
  reports 5.0.7; architecture constant is `CS_ARCH_SYSZ`.

## 2. SLEIGH compiler (sleighc) — BUILT, spec does NOT compile

- No `sleighc` binary ships with Ghidra releases. Built `sleigh_opt` from
  upstream decompiler sources (github.com/NationalSecurityAgency/ghidra,
  `Ghidra/Features/Decompiler/src/decompile/cpp`), placed at
  `ghidra/decompile-cpp/sleigh_opt` (built with system flex/bison/m4;
  `make sleigh_opt -j2 LEX=flex`, ~45 s). It is the real SLEIGH compiler
  (`-a`/`-u` flags, emits `.sla`).
- Verdict: `sleigh_opt s390x.slaspec` → **33 errors, no `.sla` produced**.
  Every error was reproduced in isolation against the compiler grammar
  (`slghparse.y` / `slghscan.l`) and against upstream specs (x86 `ia.sinc`).
  Seven root causes, all in the spec (not the compiler):

### 2a. Field names must be globally unique (23 errors)
`define token` fields share one global namespace (`"OP: redefined as field"`,
lines 43–261). `OP`, `R1`, `R2`, `X2`, `B2`, `D2`, `M1`, `M3`, `DL2`, `DH2`,
`OP2`, `I2`, `I3`, `I4`, `L1`, `B1`, `D1`, `B4`, `D4`, `RI`, … are redefined in
every token. (Only the first redefinition per token is reported; fixing `OP`
will surface the rest.) **Fix:** prefix every field per token
(`RR_OP`, `RXa_R1`, …) — 20+ tokens × ~6 fields. Minimal repros confirm a
second token reusing a field name is rejected.

### 2b. Missing `define space register` (masked syntax errors)
`define register offset=…` requires a prior
`define space register type=register_space size=8;` (grammar `varnodedef`
needs a `SPACESYM`; no `register` space is predefined — verified in
`slgh_compile.cc:predefinedSymbols`). The spec's comment "space is implied"
is wrong. Currently masked by earlier errors; will surface once 2a is fixed.

### 2c. `attach variables` argument order is backwards (6 errors, lines 322–336)
Spec: `attach variables [ r0 … r15 ] [ 0 … 15 ] R1;`
Grammar (`varattach: ATTACH_KEY VARIABLES_KEY valuelist varlist`):
`attach variables [ <fields> ] [ <varnodes> ];` — fields first, varnodes
second, numbers optional (verified against x86 `ia.sinc:691`).
**Fix:** e.g. `attach variables [ RR_R1 RR_R2 ] [ r0 … r15 ];`
(one statement per field after the 2a rename). Note each field's value range
must exactly match the varnode list length (`attachVarnodes`,
`slgh_compile.cc:2938`).

### 2d. `@include "file.sinc";` — drop the semicolon (line 1 of sinc)
Preprocessor directives take no `;` ("Extra characters in preprocessor
directive"). Upstream `x86.slaspec` uses `@include "ia.sinc"` bare. Confirmed
compiling with a bare `@include`.

### 2e. `if (…) { … }` blocks do not exist in SLEIGH (macro `ea_D20`, line 363)
The only conditional is `if <expr> goto <label>;` (pcode-level `CBRANCH`,
`slghparse.y:383`). The C-style blocks in `ea_D20`/`rel_RI32` are invalid.
**Fix:** sign-extend with shifts, e.g.
`local shifted:8 = DH << 56; dest = shifted s>> 56;`
(`INT_SRIGHT` sign-extends; verified compiling).

### 2f. Integer literals are 32-bit (line 376)
`local bias:8 = 0x100000000;` → `BADINTEGER` syntax error; the lexer rejects
>32-bit literals. Express 64-bit constants via 32-bit-safe ops, e.g.
`local hi:8 = 0xffffffff; off = (hi << 32) | off;` (verified compiling).

### 2g. Macro semantics are strict
Unused macro parameters and temporaries read-but-not-written are reported
(`"Temporary is read but not written"`); keep macro bodies minimal and use
every parameter.

## 3. Fallback validation (until the spec compiles)

1. Corpus differential vs Capstone (this plan §1) — already green; it
   validates the *intended* decode table independent of SLEIGH syntax.
2. Per-construct isolation tests against `sleigh_opt` (as done in §2) before
   editing the spec.
3. After the 7 fixes: compile to `.sla`, then decode all 203 corpus vectors
   through the compiled spec (Ghidra `SleighDebug`/`sleigh_opt -a`) and diff
   against `diff_harness.py` output.

## 4. Deliberately not done

- No repair of `data/languages/*` sources (user decision pending).
- No cross-assembler available for an independent oracle; Capstone is the
  single decode oracle.
- `ghidra/decompile-cpp/` holds only upstream compiler sources used to build
  `sleigh_opt`; it is not part of the language module.
