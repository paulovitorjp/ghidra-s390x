# Real Module Testing — genuine IFOX00/IEWL load module vs. the z/OS loaders

Date: 2026-09-19. Status: **done, 10/10 checks green** against a real
assembler/link-editor-produced load module.

## What was built

The custom Ghidra loaders were validated against genuine
assembler/link-editor output instead of synthetic fixtures alone:

- A test environment was set up with a stock assembler (**IFOX00**) and
  linkage editor (**IEWL**), producing real load modules for validation.
- No IBM-licensed compilers used.

## Test program

Three CSECTs designed to force inter-CSECT relocation metadata:

- `PROG1` — save-area linkage, `L 15,=A(SUBR)` (A-type adcon to another
  CSECT), `BALR 14,15` call.
- `SUBR` — returns 42 in R2 (`LA 2,42`).
- `DATAC` — `DC V(SUBR)` (V-type adcon), `DC A(SUBR)`, `DC CL8'TESTDATA'`.

Sources: the test sources (`prog1.asm`, ), .
JCL was generated for the assembly/link steps.
Submitted via the virtual card reader (`devinit 00c …/asmtest.jcl`) under
the stock `HERC01`/`CUL8TR` identity, `MSGCLASS=Z`.

Two JCL lessons (both fixed in the committed generator):
1. IFOX00 writes object modules through `SYSGO`, not `SYSPUNCH`, and the
   `&&OBJn` temporary datasets need
   `DCB=(RECFM=FB,LRECL=80,BLKSIZE=3120)` or the link step reads garbage.
2. Concatenating `SYSLIN` requires continuation DDs without a ddname —
   three separate `//SYSLIN DD` statements silently keep only one input.

Final result: `ASM1/ASM2/ASM3 RC=0000`, `IEWL RC=0000`, link map:

```
PROG1   origin 00  length 74
SUBR    origin 78  length 64
DATAC   origin E0  length 10
  relocation map: 70 -> SUBR, E0 -> SUBR, E4 -> SUBR
ENTRY ADDRESS 00, TOTAL LENGTH F0
```

## Extraction

`dasdpdsu` cannot read load-library members (it assumes 80-byte blocks),
so the DASD image was read directly
(L1/L2 tables, zlib/bzip2 track images, big-endian CKD records, VTOC,
PDS directory) and extracts the raw member blocks. Output:
the extracted `PROG1.bin` (658 bytes, 7 blocks).

## Loader bugs found by the real module (all fixed)

The synthetic fixtures had encoded the loader author's *guesses* about
the format; the real IEWL bytes disagreed in six places. Authoritative
reference used for the fixes: IBM *MVS Program Management: Advanced
Facilities* load-module format figures, cross-checked against the
HEWL/IEWFETCH-derived notes in
`https://github.com/mvslovers/cc370/blob/HEAD/docs/load-module-format.md`.

1. **IDR record length off-by-one** (`ZosLoadModuleLoader.java`).
   Byte 1 is the data byte count = record length − 1, so the skip is
   `1 + (img[pos+1] & 0xff)`, not `img[pos+1] & 0xff`. The real
   `80 FA …` IDR is 251 bytes, not 250.
2. **RLD byte-count offset.** It lives at record offset 6–7 (`RLDLEN`),
   not 4–5. Real RLD-only record `0E … 00 14 …`: the old code read
   count = 0 and silently dropped every relocation.
3. **RLD item field order.** Real order is `R-pointer(2) P-pointer(2)
   flag(1) address(3)`; the loader read `flag P R addr`.
4. **RLD continuation items.** When the previous item's flag has bit
   `0x01` (`SAMERP`) set, the next item is 4 bytes (`flag + address`
   only) reusing the same R&P. The real module uses one:
   `… 1D … E0 | 0C 00 00 E4` (the DATAC A-type adcon reuses DATAC/SUBR).
5. **RLD address is module-relative.** `imageBase + r.addr`, not
   `imageBase + pItem.addr + r.addr`. The V-type adcon at module offset
   `0xE0` carries RLD address `0xE0` (P-relative would be `0x00`).
6. **Text writes must clip to created blocks.** The loader creates one
   memory block per CSECT, but text records are module-contiguous and
   CSECTs can have alignment gaps (`PROG1` ends `0x74`, `SUBR` starts
   `0x78`). The old whole-chunk `setBytes` failed and left memory zeroed.

Also implemented rather than rejected:
- **Combined CTL+RLD records** (`0x03`/`0x07`/`0x0F`): RLD info first at
  offset 16 (`rldlen` bytes), then the ID/length list, then the text
  record. Previously threw `LoadException`.
- **CESD `0x28`** (last-ESD marker) accepted alongside `0x20`.
- Flag-byte decode now follows the documented `TTTT LL S Tn` layout:
  relocate only if `(flag & 0xE0) == 0` (`RELREQ`), length `((flag>>2)&3)+1`,
  subtract if `flag & 0x02` (`RELNEG`).

The synthetic fixture generator (`tools/gen_zos_loadmod.py`) was updated
to emit the real RLD layout (count at 6–7, `R P flag addr` order,
module-relative addresses) so the synthetic suite stays faithful; the
regenerated `tests/zos_smoke.lmod` still passes 11/11.

a Python replica (`lmscan.py`) is of the record
scanner for quick iteration; it decodes the real module as:
3 CESD (PROG1/SUBR/DATAC), 3 IDRs, 1 CTL+240B text, 1 RLD record with
3 items (`0x0c R=2 P=1 @0x70`, `0x1d R=2 P=3 @0xE0`,
`0x0c cont. R=2 P=3 @0xE4`) — exactly matching the IEWL link map.

## Headless Ghidra validation (`tests/RealModuleCheck.java`)

```
analyzeHeadless … -import realmod/PROG1.bin -loader ZosLoadModuleLoader \
  -postScript RealModuleCheck.java -noanalysis -scriptPath tests
```

Result **10/10 PASS**:

- blocks `PROG1 @0x10000 len 0x74`, `SUBR @0x10078 len 0x64`,
  `DATAC @0x100e0 len 0x10`
- A-type adcon `@0x10070` → `0x10078` (SUBR)
- V-type adcon `@0x100e0` → `0x10078` (SUBR)
- A-type adcon `@0x100e4` → `0x10078` (SUBR)
- entry point `0x10000`; `relocations: applied=3 skipped/unresolved=0`
- disassembly correct, e.g. SUBR:
  `STM 14,12,0xc(r13)` `LR r12,r15` `LA r2,0x2a` … `BR r14`
- entry and SUBR functions decompile without errors

One adjustment vs. the synthetic smoke test: the z/OS cspec's save-area
handling defeats the decompiler's constant propagation for R2, so the
"returns 42" assertion checks the disassembly (`LA r2,0x2a`) rather than
the decompiled C. That is a decompiler/cspec quality note, not a loader
issue.

Synthetic suites re-verified after the fixes: load-module 11/11,
GOFF all green.

## What is *not* claimed

- Only the classic load-module path is validated against real output.
  GOFF validation is still synthetic-fixture-only (no GOFF-producing
  toolchain installed).
- Overlay/scatter programs, SYM/TEST records, and program objects are
  still unsupported by design.
- GCCMVS/PDPCLIB C compilation was not achieved in this pass (no
  usable public-domain C toolchain located yet); C-language
  coverage remains future work.
7. Rebuild: `bash ~/workspace/zarch-sleigh/tools/build_zos_loaders.sh`
8. Headless check as above.
