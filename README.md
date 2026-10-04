# s390x Ghidra processor module for IBM Z / z/Architecture

A from-scratch Ghidra processor module for IBM z/Architecture (s390x),
built because no public SLEIGH specification for this architecture existed.
It covers the instruction set, Linux ELF importing, and — the part that
matters for real mainframe work — loaders for z/OS load modules.

Licensed under the Apache License, Version 2.0. See `LICENSE`.

## Status

- **Processor spec:** `data/languages/s390x.slaspec` + extension `.sinc` files,
  ~4,356 constructors, compiles with Ghidra's SLEIGH compiler with 0 errors.
- **Language ID:** `s390x:BE:64:default`
- **HLASM validation on real z/OS:** 4,308 instruction encodings assembled
  with IBM HLASM R6.0 and validated against the SLEIGH decoder — every
  correctly-extracted byte sequence decodes (0 true SLEIGH gaps).
  Plus 18 EBCDIC-sensitive vectors. See `tests/COVERAGE_REPORT.md`,
  `tests/GAP_REPORT.md`, `tests/REGFIX_REPORT.md`.
- **Semantic validation:** 303/303 p-code vectors green (branches, TM,
  division, TRTT, FP, decimal, vector, load/store).
- **Differential fuzzing:** 20,000 inputs, 0 crashes, 0 misdecodes.
- **Smoke-tested in Ghidra 12.1.3:** module loads, raw and ELF binaries import,
  disassembly matches Capstone, and the decompiler produces structured C
  (recovered `do/while` loops, if/else, function calls/returns).
- **z/OS loaders:** classic MVS load modules (CESD/ESD/text/RLD parsing with
  relocation) and GOFF, each validated in headless Ghidra against synthetic
  test files. Plus a z/OS Language Environment ABI compiler spec (`zos`)
  auto-selected by both loaders.

See `INTEGRATION_REPORT.md` and `LOADERS.md` for the full reports, and
`CONVENTIONS.md` for the authoring conventions used throughout the spec.

## Layout

```
data/languages/      SLEIGH sources (s390x.slaspec + *.sinc), compiled s390x.sla,
                     pspec/cspec (Linux + z/OS LE), ldefs, opinion file
loaders/src/         Java sources: ZosLoadModuleLoader, ZosGoffLoader,
                     ZosProgramObjectLoader (PM3+ detector), ZosUtil
tools/               Generators, HLASM batch driver (tools/zos_asm.py),
                     corpus validation harness, loader build script
tests/               Differential corpora (4,326 validated encodings),
                     HLASM batch results, coverage/gap/p-code reports,
                     Ghidra smoke scripts
hlasm_batches/       HLASM test batches (11 main + gap + EBCDIC + fix batches)
CONVENTIONS.md       SLEIGH authoring conventions (read before editing the spec)
INTEGRATION_REPORT.md End-to-end integration and validation report
LOADERS.md           Loader design, formats, validation, honest boundaries
```

## Build

Requires Ghidra 12.1.3 (OpenJDK 21) and Python 3 with Capstone for validation.

```sh
# Rebuild the .sla from sources (sleigh compiler ships with Ghidra)
GHIDRA=<path-to-ghidra_12.1.3_PUBLIC>
$GHIDRA/support/sleigh -a data/languages   # produces data/languages/s390x.sla

# Compile the z/OS loaders
tools/build_zos_loaders.sh
```

## Install

Copy the module into your Ghidra installation:

```sh
cp -r . $GHIDRA/Ghidra/Processors/s390x/
```

Then import: raw binaries via the stock Raw Binary loader
(`-processor s390x:BE:64:default`), Linux s390x ELF via the stock ELF loader,
classic load modules / GOFF via the `ZosLoadModuleLoader` / `ZosGoffLoader`
loaders (selected automatically by file signature).

## Validation

```sh
python3 tests/sleigh_diff.py        # differential harness vs Capstone
python3 tests/elf_smoke_test.py     # Linux ELF import smoke test
```

The z/OS loader checks run inside headless Ghidra; see `LOADERS.md` for the
exact commands and `tools/gen_zos_loadmod.py` / `tools/gen_zos_goff.py` for
the synthetic input generators.

The HLASM corpus (`tests/corpus_zos_hlasm_full.json`, 4,326 entries) was
validated against real IBM HLASM R6.0 output on z/OS; the batch driver
(`tools/zos_asm.py`) needs a 3270 connection and TSO credentials.

## Known limitations

- 41 instructions are ARCH-gated at HLASM R6.0's default ARCH level
  (SELECT family, MG/MGH, KMA, DFP convert variants) — validated against
  PoP text only until a higher-ARCH toolchain is available.
- 29 confirmed SLEIGH gaps (privileged/system, DFP, unimplemented families)
  documented in `tests/GAP_REPORT.md` with assembler ground-truth bytes.
- Modern PM3+ program objects are detected but refused (IBM's binder layout is
  not publicly documented; no samples available to validate against).
- CTL+RLD, overlay/scatter, and continued records are refused, not half-parsed.
- Full PDS-image parsing is not implemented; XPLINK is not modeled.
- Some privileged/crypto operations use intentionally opaque semantics; vector
  semantics are incomplete in places; fixed-point divide exceptions are not
  modeled.
- Ghidra has no s390x ELF relocation handler (static ET_EXEC only).
- Decompiled branch conditions show Ghidra-style condition-code bit manipulation.

## References

- IBM *z/Architecture Principles of Operation*, SA22-7832 (15th ed.)
  https://publibfp.dhe.ibm.com/epubs/pdf/dz9zr003.pdf
- IBM s390x ABI: https://github.com/IBM/s390xabi
- IBM *MVS Program Management: Advanced Facilities*: SA22-7644
  (load module / GOFF record layouts, Appendices B and C)
