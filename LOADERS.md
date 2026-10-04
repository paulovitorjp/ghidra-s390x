# s390x Loaders

**Date:** 2026-09-17 (raw/ELF); z/OS loaders added 2026-09-18
**Ghidra:** 12.1.3 PUBLIC, OpenJDK 21 (Temurin, `~/workspace/java/jdk-21.0.12.1+1`)

How to get s390x binaries into Ghidra for disassembly and decompilation.
The Linux/raw paths below work with Ghidra's stock loaders. The z/OS
paths (classic MVS load modules, GOFF objects) need the custom Java
loaders in `loaders/` plus the z/OS Language Environment compiler spec.

## TL;DR

| Binary kind | Loader | Language selection | Status |
|---|---|---|---|
| Raw big-endian bytes | Stock **BinaryLoader** ("Raw Binary") | `-processor s390x:BE:64:default`, base via `-loader-baseAddr` | Works |
| Linux s390x ELF (EM_S390 = 22) | Stock **ElfLoader** | Automatic via new `data/languages/s390x.opinion` | Works |
| Classic MVS load module | **ZosLoadModuleLoader** ("z/OS MVS Load Module") | Automatic → `s390x:BE:64:zos` | Works (documented subset) |
| GOFF object file | **ZosGoffLoader** ("z/OS GOFF Object File") | Automatic → `s390x:BE:64:zos` | Works (documented subset) |
| Program object (PM1–PM5) | **ZosProgramObjectLoader** | Detects `IEWPLMH`, then refuses with a diagnostic | Not supported (blocker documented) |

## What was added

- **`data/languages/s390x.opinion`** (new, also installed into
  `~/workspace/ghidra-dist/ghidra_12.1.3_PUBLIC/Ghidra/Processors/s390x/data/languages/`):
  maps ELF `e_machine = 22` ("IBM S390") to `s390x:BE:64:default` for the
  stock ELF loader, following the same `.opinion` mechanism every other
  Ghidra processor module uses (cf. `AARCH64.opinion`).
- **`tools/gen_elf_smoke.py`** (new): builds `tests/elf_smoke.elf`, a minimal
  static ET_EXEC ELF64-BE with hand-assembled `_start`/`main`/`sum`
  (call + if/else + counted loop). Every instruction is verified against
  Capstone **including mnemonic assertions** (coverage-only checks are not
  enough — see "Encoding lesson" below).
- **`tests/elf_smoke.elf`** (new): the test binary (672 bytes).
- **`tests/elf_smoke_decompile.c`** (new): decompiler output for `main`.
- **`tests/ElfSmokeS390x.java`** (new): headless post-script used for validation.
- **`tests/RawBaseCheck.java`** (new): minimal headless post-script proving the
  raw loader honors `-loader-baseAddr`.

No `loaders/` source directory was needed: both loaders are Ghidra stock, so
there is no custom Java to build. The only new module artifact is
`s390x.opinion`.

## 1. Raw binary path (stock BinaryLoader)

No custom raw loader is needed. Ghidra's built-in Raw Binary loader already
accepts any file and lets the caller pick the language and base address:

```
support/analyzeHeadless <projdir> <projname> \
  -import <file> -loader BinaryLoader \
  -processor s390x:BE:64:default \
  -loader-baseAddr 400000 \
  -postScript SmokeS390x.java -scriptPath tests
```

**Important:** the base address is plain hex with **no** `0x` prefix
(`-loader-baseAddr 400000`, not `0x400000`) — with the prefix the value is
silently ignored and the file loads at 0.

Verified: `tests/ghidra_smoke.bin` (28 bytes) imports at base `0x400000`
(range `00400000 .. 0040001b`), first instruction decodes as `brasl`, and
the full SmokeS390x disassembly/decompile flow works. In the Ghidra GUI the
same is achieved with File → Add To Program, choosing "Raw Binary" and
setting the language to `s390x:BE:64:default` plus the desired base address
in the options dialog.

## 2. Linux s390x ELF path (stock ElfLoader)

**Finding:** Ghidra's `ElfLoader` is fully generic over `e_machine` — it does
*not* reject EM_S390. The only thing missing was the language mapping: with
no `.opinion` entry, the loader had no `LoadSpec` for machine 22 and the
user had to pick the language by hand. Adding `s390x.opinion` makes import
fully automatic:

```
INFO  Using Loader: Executable and Linking Format (ELF)
INFO  Using Language/Compiler: s390x:BE:64:default:default
```

Verified on `tests/elf_smoke.elf`:
- PT_LOAD segment mapped at image base `0x10000` (from `p_vaddr`).
- Entry point honored (`e_entry = 0x10078`).
- `.symtab` function symbols applied: `_start @ 0x10078`,
  `main @ 0x10080`, `sum @ 0x100b6`; Ghidra auto-created all three functions.
- All 23 instructions disassemble at correct boundaries.
- Decompiler runs on `main` and `sum` (see `tests/elf_smoke_decompile.c`).

### Known gaps (ELF)

- **Relocations are not applied.** Ghidra ships no `ElfRelocationHandler`
  for EM_S390 (`ElfRelocationHandlerFactory.getHandler()` returns null), so
  `.rela.*` sections in dynamic/PIE binaries are skipped. Static ET_EXEC
  binaries (like the test file) are unaffected. Writing an
  `S390ElfRelocationHandler` is future work.
- **TLS, `.eh_frame`, s390x-specific notes** are not specially handled; the
  generic loader maps them as data.
- The `entry` symbol was not created by the loader for this file (functions
  from `.symtab` were); entry-point disassembly still ran via the
  "Disassemble Entry Points" analyzer.

## 2b. s390x ELF relocation handler (ET_DYN/PIE)

**Finding:** Ghidra ships no `ElfRelocationHandler` for EM_S390, so PIE/shared
objects imported with the stock `ElfLoader` kept their RELA relocations
unapplied. Added (extension auto-discovered by `ClassSearcher`; no factory or
registration file needed):

- `loaders/src/ghidra/app/util/bin/format/elf/relocation/S390_ElfRelocationType.java`
  — all `R_390_*` type IDs (0–65, 250–251) with ABI formulas in comments.
- `.../S390_ElfRelocationContext.java` — extends `ElfGotRelocationContext`
  (must live in `ghidra.app.util.bin.format.elf.relocation`: the base ctor is
  package-private). `requiresGotEntry()` covers GOT/GOTPLT/GOTENT forms.
- `.../S390_ElfRelocationHandler.java` — claims 64-bit EM_S390 only
  (`canRelocate`: `e_machine == EM_S390 && is64Bit()`).

Supported (semantics verified against binutils `elf64-s390.c` HOWTOs and
glibc `dl-machine.h`; s390x is RELA-only, addend always from the entry;
`P` = address of the relocated field, `>>1` = arithmetic halfword shift):
absolute `R_390_8/12/16/20/32/64` (12/20-bit preserve neighbouring
instruction bits via mask, matching the assembler's field layout);
PC-relative `PC16/PC16DBL/PC12DBL/PC32/PC32DBL/PC24DBL/PC64`;
GOT-relative `GOT12/16/20/32/64`, `GOTPLT12/16/20/32/64`, `GOTENT`,
`GOTPLTENT`; `GOTPC/GOTPCDBL`, `GOTOFF16/32/64`; PLT-relative
`PLT16DBL/PLT12DBL/PLT32DBL/PLT24DBL/PLT32/PLT64`, `PLTOFF16/32/64`;
`GLOB_DAT`, `JMP_SLOT` (writes slot + `createExternalFunctionLinkage` thunk),
`RELATIVE`, `IRELATIVE` (records resolver address, warns it was not invoked),
`R_390_GNU_VTINHERIT/VTENTRY` (no-op markers, skipped silently).

Explicitly warned + skipped: `R_390_COPY` (runtime copy unsupported) and all
`R_390_TLS_*` (no TLS model). `R_390_GNU_VTINHERIT/VTENTRY` are recognized
as GNU vtable-verification markers and skipped silently (no memory fixup
is ever required for them).

Build/install: `tools/build_elf_reloc.sh` compiles the new package into
`Ghidra/Processors/s390x/lib/s390x-elf-reloc.jar` (the z/OS loaders build is
untouched; the z/OS loader sources were not modified).

Verified end-to-end in headless Ghidra 12.1.3 with a handcrafted ET_DYN
(`tools/gen_elf_dyn_smoke.py` → `tests/elf_dyn_smoke.elf`, linked at vaddr 0)
and `tests/ElfDynSmokeS390x.java` post-script — **ALL PASS (0 failures)**,
see `tests/elf_dyn_smoke_test.txt`: `R_390_64`, `R_390_RELATIVE`,
`R_390_GLOB_DAT`, `R_390_PC32`, `R_390_32`, `R_390_16`, `R_390_8`,
`R_390_PC16`, `R_390_PC32DBL` (on a real `brasl %r14,target2`, disassembly
flows to the relocated target), `R_390_JMP_SLOT` (slot + external thunk
linkage), `R_390_12`/`R_390_20` (neighbour-bit masking preserved),
`R_390_PC16DBL/PC12DBL/PC24DBL/PC64`, the full GOT family (`GOT12/16/20/32/64`,
`GOTPLT12/16/20/32/64`, `GOTENT`, `GOTPLTENT` — via the synthesized GOT from
`ElfGotRelocationContext`, whose entry order and contents are asserted),
`GOTPC/GOTPCDBL`, `GOTOFF16/32/64`, the PLT family (`PLT16DBL/PLT12DBL/
PLT32DBL/PLT24DBL/PLT32/PLT64`, `PLTOFF16/32/64`), `R_390_IRELATIVE`
(warned, `B+A` recorded), `R_390_COPY` (warned+skipped, memory untouched),
`R_390_GNU_VTINHERIT/VTENTRY` (silently skipped, memory untouched),
`R_390_TLS_TPOFF` warned + skipped (memory untouched), zero ERROR
relocation bookmarks (3 WARNINGs: TLS, IRELATIVE, COPY — all expected).

## Decompiler quality notes (processor-side, not loader issues)

The loader delivers correct bytes; what the decompiler makes of them is
determined by the SLEIGH p-code. Two observations for the processor work:

1. **Conditional relative branches emit indirect jumps.** The RIc family
   (`:jh`, `:jl`, `:je`, `:jnh`, `:j`, …) computes the target correctly but
   emits `goto [tgt]` (BRANCHIND) instead of a direct `goto tgt`. The
   decompiler cannot resolve the constant target through the indirect jump,
   so if/else bodies and loops come out with "Removing unreachable block"
   warnings and, in `sum`, a bogus indirect call. `main` still decompiles
   recognizably (call to `sum`, compare against 50, if/else on the result),
   but the condition leaks CC bit-twiddling (`(8U >> sVar1 & 2) == 0`)
   instead of folding to `uVar2 > 0x32`. Changing `goto [tgt]` to a direct
   branch in the RIc constructors should substantially improve CFG recovery.
   (Loaders task — left for processor work.)
2. **STMG/LMG display** shows raw register numbers (`STMG 14,15,0x8(r15)`)
   rather than `%r14` names — cosmetic, decode and p-code are correct.

## Encoding lesson (validates the test binary, not the loader)

While building `tests/elf_smoke.elf` I initially emitted BRASL as
`C5 E0 …`. Binutils (`opcodes/s390-opc.txt`) is authoritative here:

- `brasl` = `c005` → bytes `C0 E5 …` (the SLEIGH spec was right)
- `c5` = **BPRP** "branch prediction relative preload" (zEC12) — a real,
  different instruction that Capstone 5.0.7 decodes without complaint

A coverage-only Capstone check ("every byte decoded") passed the wrong
encoding. `gen_elf_smoke.py` now asserts the full expected mnemonic
sequence, and the final binary matches Capstone mnemonic-for-mnemonic.

## Reproducing the validation

```bash
export JAVA_HOME=~/workspace/java/jdk-21.0.12.1+1
G=~/workspace/ghidra-dist/ghidra_12.1.3_PUBLIC

# rebuild the test ELF
python3 tools/gen_elf_smoke.py

# ELF import + auto-analysis + decompile
rm -rf /tmp/ghidra_loader_proj
$G/support/analyzeHeadless /tmp/ghidra_loader_proj loader_test \
  -import tests/elf_smoke.elf \
  -postScript ElfSmokeS390x.java -scriptPath tests -deleteProject

# raw import at a chosen base address (hex, NO 0x prefix)
rm -rf /tmp/ghidra_raw_proj
$G/support/analyzeHeadless /tmp/ghidra_raw_proj raw_test \
  -import tests/ghidra_smoke.bin -loader BinaryLoader \
  -processor s390x:BE:64:default -loader-baseAddr 400000 \
  -postScript RawBaseCheck.java -scriptPath tests -deleteProject
```

Note: Ghidra 12.1.3 headless runs Jython only via PyGhidra (not present
here); post-scripts must be **Java** (`.java`), not Python.

---

# z/OS additions (2026-09-18)

Real mainframe COBOL/PL/I/HLASM output is z/OS containers, not Linux ELF:
classic MVS load modules and GOFF objects, linked with the z/OS Language
Environment (LE) ABI. The SLEIGH instruction decoding is source-language
independent, but the stock Linux-oriented module is wrong for these
binaries in two ways: it cannot parse the containers, and its `default`
compiler spec models the Linux s390x ABI (args in r2–r6, return in r2,
stack in r15). Both gaps are closed below.

## 3. z/OS Language Environment compiler spec (`zos`)

**Files:** `data/languages/s390x-zos.cspec` (new), `s390x.ldefs`
(registers `<compiler name="zos" spec="s390x-zos.cspec" id="zos"/>`).
Both installed into the module's `data/languages/`.

Modeled conventions (classic non-XPLINK OS linkage, per IBM *z/OS XL C/C++
Programming Guide*, "Register content at exit from a non-XPLINK ASM
routine", and *z/OS XL C/C++ Language Reference* `OS_NOSTACK`):

| Item | Convention |
|---|---|
| Stack pointer | r13 → caller's save area (chain at offset 4); 144-byte areas in 64-bit |
| Return address | r14 |
| Entry point / integer+pointer return value | r15 (0 if no value; FP0 for float/double) |
| Arguments | r1 → parameter address list (addresses of the actual arguments) |
| Volatile | r0, r1 |
| Callee-saved | r2–r13 (EDCEPIL/EDCPRLG), f8–f15 |
| Data model | ILP64-ish: int/long 4 bytes, long long/pointers 8, wchar_t 2 |

Simplifications (documented in the cspec header): the decompiler sees r1
as a single parameter-list pointer — individual arguments are not
decomposed from the indirect list; XPLINK (r1–r3 args, r3 return) is not
modeled. Select it in the GUI via the language/compiler pair
`s390x:BE:64:zos`; the z/OS loaders below select it automatically.

## 4. Classic MVS load-module loader (`ZosLoadModuleLoader`)

**Source:** `loaders/src/s390x/loaders/ZosLoadModuleLoader.java`
(+ `ZosUtil.java`), built by `tools/build_zos_loaders.sh` into
`Ghidra/Processors/s390x/lib/s390x-zos-loaders.jar`. Discovered by Ghidra's
`ClassSearcher` with no `.opinion` file; headless selection is by class
name: `-loader ZosLoadModuleLoader` (the `-loader` flag takes the class
simple name, not the display name).

Parses the documented subset of SA22-7644 Appendix B ("Load module
formats"), verified against IBM *z/OS MVS Program Management: Advanced
Facilities* (2025):

- **CESD** (X'20'): SD/LR/ER items (also PC/WX item types recognized);
  the byte-12 AMODE/RMODE/RSECT layout follows the manual's Figure 13.
- **Control/text** (X'01'/X'05'/X'0D'): CCW address+count, CESDID/length
  control data; EOM (X'0D') terminates.
- **RLD** (X'02'/X'06'/X'0E'): A-type (non-branch) and V-type (branch)
  2/3/4-byte adcons relocated by the image load bias (±); Q-type and
  adcons pointing at ER/WX items are left unresolved and recorded as
  external symbols in an `EXTERNAL` block (`ZOS_IMPORTS` library).
- **SYM** (X'40'), **IDR** (X'80'), and **scatter/translation** (X'10') records
  are skipped (the real MVS loader ignores SYM/scatter records per
  LY26-3901-1 Figs. 52/54).
- **Combined CTL+RLD** (X'03'/X'07'/X'0F'): parsed and relocated like their
  standalone counterparts (same RLD item layout).
- **Refused with a clear error:** CTL+RLD record X'0B', unknown record IDs.
  X'0B' is not a defined load-module record ID: IBM *z/OS MVS Program
  Management: Advanced Facilities* Appendix B, Figs. 15–17, enumerates the
  record identification bytes exhaustively — control X'01'/X'05'/X'0D',
  RLD X'02'/X'06'/X'0E', combined CTL+RLD X'03'/X'07'/X'0F' — and public-domain
  linkage-editor source likewise defines only 01/02/03/05/06/07/0D/0E/0F. It is refused rather than
  guessed at. (Overlay modules on disk use the *defined* X'05'/X'06'/X'07'
  "last of segment" IDs; correct overlay relocation would additionally
  need per-segment origins from the overlay note list, which is not
  implemented — overlay/scatter modules get an explicit warning that
  relocation is applied flat.)

What it builds: one initialized block per SD csect (name = csect name),
text bytes at module-relative addresses + image base (default `0x10000`,
overridable via the "Image Base (hex)" option), LR labels, ER/WX
externals, relocated adcons, and an external entry point. **It does not
create functions** — disassembly/analysis does that from the flow.

**Entry point and PDS directory support (honest boundary):** a real
load-module member does not carry its entry point; it lives in the PDS
directory entry (`PDS2EPA`, or `PDS2EPM` for alias entries). This loader
accepts an optional raw PDS directory entry prepended to the member bytes
(magic `ZOSPDS21`, u16BE version=1, u16BE entry length, then the on-disk
PDS2 entry: 8B EBCDIC name + 3B TTRP + indicator + user data) — see
`tools/gen_zos_pds.py`. The entry is parsed by `PdsDirectory.java`
(dependency-free, unit-tested standalone in `tests/ZosPdsDirCheck.java`):
PDS2 entry framing, indicator byte (alias/NTTR/LUSR), basic section
(TTRT/TTRN/NL/ATR1/ATR2/STOR/FTBL/EPA/FTB1-3), optional scatter section,
alias section, AMODE/RMODE from PDS2FTB2 (PDSMAMOD/PDSAAMOD/PDSLRMOD/
PDSLRM64 per IBM "PDS directory entry format on entry to STOW").
The entry point comes from PDS2EPA (PDS2EPM for alias entries with an
alias section); attributes are logged, a `PDS2LFMT` (program-object
format) entry is refused as a program object, and overlay/scatter
modules get an explicit warning that relocation is applied flat.
The older `ZOSLMOD1` test header is still accepted as a fallback.
**Not implemented:** mapping a directory TTR to bytes on a real DASD
volume (that needs CKD track/record geometry or the member's record
framing); the loader does not pretend a TTR is a flat-file offset.
Without any header, the whole file is parsed as the member and the entry
defaults to the first LR item (else offset 0).

## 5. GOFF object loader (`ZosGoffLoader`)

**Source:** `loaders/src/s390x/loaders/ZosGoffLoader.java`, same jar;
headless: `-loader ZosGoffLoader`.

Parses the documented subset of SA22-7644 Appendix C ("Generalized
object file format"): 80-byte fixed records, HDR (X'03F000'), ESD
(X'030000': SD/ED/LD/PR/ER/WX with parents, offsets, lengths, EBCDIC
names), TXT (X'031000', byte-oriented style), RLD (X'032000') with
same-R/same-P/same-offset compression bits, and END (X'034000') entry by
ESDID+offset or by LD name. Relocation items support reference type 0
(R-address) with referent types 0 (label) / 1 (element), action +/−,
fetch/store modes, and target lengths 2/4/8; references to ER/WX items
become external symbols and are left unresolved. **Continued records
(X'03n100') are chained**: a `flattenRecords()` pre-pass follows the PTV
low-two-bit convention (01 initial / 10,11 continuation, per the public
PTV table and LLVM's GOFF implementation) and concatenates continued
payloads, so ESD/TXT/RLD/END records split across physical records parse
unchanged; malformed chains (orphan/type-mismatch/truncated) are refused
with specific errors. One block per ED element, entry point from END
(fallback: first element), externals in an `EXTERNAL` block.

## 6. Program objects PM1–PM5: not supported (blocker documented)

`ZosProgramObjectLoader` detects the EBCDIC `IEWPLMH ` eyecatcher and
then throws a `LoadException` explaining the situation instead of
mis-parsing the file. Modern program objects (PM1/PM2/PM3/PM4/PM4SUB2/
PM4SUB3/PM5/PM5SUB2) are binder-managed block/section/class structures in
PDSE or USS storage.

**Why not just parse them (research 2026-09-21):** IBM *z/OS MVS Program
Management: Advanced Facilities* (z/OS 3.1, ieab200) was read
chapter-by-chapter for a stored byte layout. What it documents:
- Ch. 3 — the IEWBIND callable API (regular program management).
- Ch. 4 — the IEWBFDAT fast data access API and its record formats.
- Ch. 6 + Appendix D — IEWBUFF logical-buffer API formats, incl. the
  PMAR conduit (whose actual mapping lives in the separate *z/OS MVS
  Data Areas* IEWPMAR macro, not in this book).
- Appendix B — the classic load-module record layouts (used by §4).
None of these specify the **portable on-disk byte layout** of a program
object as stored in a PDSE or USS file. The PM-level markers (PO1..PO5 /
PM1..PM5) appear only in API return buffers (e.g. `CUI_TYPE` in the
compile-unit information buffer), never as a stored-file grammar. In
short, the authoritative source documents program objects exclusively
through binder APIs — there is no published stored-format specification
to implement. Writing a parser from guesses would be mis-parsing, not
support.

What would unblock it: the stored-format specification, binder APIs on a
live z/OS system, or real program-object samples to validate a
reverse-engineered parser against. Workaround: use the z/OS binder
(IEWL/IEWBLINK) to convert to a classic load module or GOFF object
first.

## 7. z/OS validation (all end-to-end in headless Ghidra 12.1.3)

Synthetic inputs (no real z/OS binaries available; every instruction
verified against Capstone mnemonic-for-mnemonic):

- `tools/gen_zos_loadmod.py` → `tests/zos_smoke.lmod`: CESD (SD/LR/ER),
  2 text records, RLD (A-type + Q-type), directory header with entry.
- `tools/gen_zos_goff.py` → `tests/zos_smoke.goff`: HDR, SD/ED/LD/LD/ER,
  TXT, RLD (A-type + Q-type), END with ESDID+offset entry.
- `tests/ZosLoadersSmoke.java`: 12-check post-script (blocks, symbols,
  entry, relocated vs unresolved adcons, `zos` compiler selection,
  disassembly, decompile with call + if/else); mode `pds` reuses the
  lmod checks against the `ZOSPDS21` header path.
- `tools/gen_zos_pds.py` → `tests/zos_pds.dir` (raw 256-byte-block PDS
  directory: PROG1 basic entry, ALIAS1 alias entry, PROG2 scatter entry,
  PROG3 program-object-format entry, PAD0/PAD1 block-packing entries),
  `tests/zos_pds.lmod` (`ZOSPDS21` header + member),
  `tests/zos_pds_progobj.lmod` (PDS2LFMT entry → must refuse),
  `tests/zos_pds_nobs.lmod` (entry without basic section → must refuse),
  `tests/zos_pds_0b.lmod` (X'0B' record → must refuse),
  `tests/zos_pds_bad_trunc.dir` / `tests/zos_pds_bad_len.dir` (malformed).
- `tests/ZosPdsDirCheck.java`: 43-check standalone parser regression
  (no Ghidra needed): entries, alias/scatter sections, AMODE/RMODE bit
  edges, program-object flag, block packing, malformed refusals.

Results (2026-09-18, re-verified 2026-09-21 after the W6 changes):

- Classic load module: **12/12 PASS**, including with the directory header
  stripped (raw member path, entry falls back to first LR).
- GOFF: **11/11 PASS** (`relocations: applied=1 skipped/unresolved=1`).
- GOFF continued records: **14/14 PASS**.
- PDS directory entry path (`ZOSPDS21` + `tests/zos_pds.lmod`, mode
  `pds`): **12/12 PASS** — entry point 0x10000 from PDS2EPA, member
  PROG1, AMODE 31 / RMODE ANY / RENT,REUS,EXEC all decoded from the
  directory entry; disassembly and decompile identical to the classic
  path.
- PDS directory parser standalone (`tests/ZosPdsDirCheck.java`, no
  Ghidra needed): **43/43 PASS** (entries, alias/scatter sections,
  AMODE/RMODE bit edges, PDS2LFMT flag, two-block packing, 4 malformed
  refusals: truncated entry, overrun, bad length, non-256-byte image).
- Negative imports (all refused in headless Ghidra, exact messages
  verified by direct loader invocation):
  - `tests/zos_pds_progobj.lmod` (PDS2LFMT set): "PDS member 'PROG3' is
    stored in program object format (PDS2LFMT set); classic load-module
    parsing does not apply. See LOADERS.md section 6."
  - `tests/zos_pds_nobs.lmod` (no basic section): "PDS directory entry
    for 'NOBS' has no load-module basic section (0 user-data bytes)"
  - `tests/zos_pds_0b.lmod` (X'0B' record): "load-module record ID 0x0B
    at offset 0xfa is not a defined load-module record ID (see
    LOADERS.md); refusing"
  - `tests/zos_progobj.eye` (Cp037 `IEWPLMH ` eyecatcher): program-object
    refusal with the LOADERS.md §6 chapter-by-chapter blocker analysis.
- Disassembly matches Capstone exactly on both files.
- Decompiled output (`tests/zos_smoke_lmod_decompile.c`,
  `tests/zos_smoke_goff_decompile.c`) is structured C using the `zos`
  spec: `subr()` call, if/else on the compared return value, integer
  result returned in r15 per the LE convention. (The branch-condition
  rendering still shows the pre-existing CC bit-twiddling style also
  seen under the Linux cspec — a processor-side characteristic, not a
  loader defect.)
- PM3+ detector: import fails cleanly with the explanatory diagnostic.

Repro:

```bash
export JAVA_HOME=~/workspace/java/jdk-21.0.12.1+1
G=~/workspace/ghidra-dist/ghidra_12.1.3_PUBLIC

# rebuild loaders after any source change
tools/build_zos_loaders.sh

# rebuild test inputs
python3 tools/gen_zos_loadmod.py
python3 tools/gen_zos_goff.py

# classic load module: import + 12 checks + decompile
$G/support/analyzeHeadless /tmp/zosproj zos_lmod \
  -import tests/zos_smoke.lmod -loader ZosLoadModuleLoader \
  -postScript ZosLoadersSmoke.java lmod -noanalysis \
  -scriptPath tests -deleteProject

# GOFF object: same, mode "goff"
$G/support/analyzeHeadless /tmp/zosproj zos_goff \
  -import tests/zos_smoke.goff -loader ZosGoffLoader \
  -postScript ZosLoadersSmoke.java goff -noanalysis \
  -scriptPath tests -deleteProject
```

Note: the post-script directory must compile cleanly — Ghidra reports
script compile failures misleadingly ("The class could not be found");
when that happens, compile with `javac` against all Ghidra jars first to
see the real error.
