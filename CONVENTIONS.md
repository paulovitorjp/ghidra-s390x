# s390x SLEIGH — conventions (Phase 1)

## Naming conventions

| Kind | Convention | Example |
|---|---|---|
| Tokens | `<FORMAT><variant>` — format name plus the PoP sub-variant letter, exactly as in SA22-7832 Figure 5-1 | `RXa`, `RSYb`, `RILc`, `SSf` |
| Fields | **Globally unique per-token prefix**: `<TOKEN>_<FIELD>` where `<TOKEN>` is the token name and `<FIELD>` is the PoP UPPERCASE spelling. SLEIGH requires all token field names to be globally unique across the entire spec (verified against `slghparse.y`). **Bit numbering:** SLEIGH numbers bits with bit 0 = *least* significant bit regardless of endianness, so a PoP range (s,e) on an N-bit token is written as (N-1-e,N-1-s). Example: token `RXa` has fields `RXa_OP`, `RXa_R1`, `RXa_X2`, `RXa_B2`, `RXa_D2`. | `RXa_R1 = (20,23)` (PoP bits 8-11) |
| Registers | Architectural lowercase (`r0`–`r15`, `a0`–`a15`, `f0`–`f15`, `v0`–`v31`, `psw`, `pswm`, `pswia`, `cc`); one pseudo-register `zero` (constant 0, never written) | `r14` |
| Macros | `snake_case`, destination varnode first | `ea_D12(dest, B, X, D)` |

**Why fields are prefixed:** SLEIGH has a single global symbol table for all
token fields. A field named `R1` in token `RXa` would collide with `R1` in
token `RR`. All fields are therefore prefixed with their token name
(`RXa_R1`, `RR_R1`, etc.) to ensure global uniqueness. The UPPERCASE PoP
spelling is preserved after the prefix, and uppercase names can never collide
with the lowercase architectural register names.

**Attached fields:** `*_R1`/`*_R2`/`*_R3` attach value *n* → register `rN` (r0 is a
real register for operands). `*_B1`/`*_B2`/`*_B4`/`*_X2` attach value 0 → `zero` and
*n* → `rN`, because B=0/X=0 means "no base/index", not GPR0. `*_M1`/`*_M3`
masks, `*_I2`/`*_I3` immediates, `*_D*` displacements, `*_L*` lengths stay numeric.

**EA macros** (in `s390x.slaspec`):
- `ea_D12(dest, B, X, D)` — 12-bit *unsigned* displacement (RX/RS/SI/S/SS).
- `ea_D20(dest, B, X, DH, DL)` — 20-bit *signed* displacement (RXY/RSY/SIY);
  for `RXYc` pass `(dest, B2, X2, DXH2, DXL2)`.
- `rel_RI32(dest, RI)` — PC-relative target for halfword-counted 32-bit
  offsets: `inst_start + 2 * sign_extend_32(RI)` (RIL-b/c, RI-b/c branches).

## Recipe: adding one instruction constructor (Phase 2)

1. **Find the facts in the PoP, never invent them.** Use the instruction
   summary table (Appendix A of SA22-7832): note the mnemonic, format
   (e.g. `RX-a`), and opcode bytes (e.g. `B2 59` for COMPARE CY — do not
   copy this example without re-checking; it is illustrative only).
2. **Pick the token** matching the format variant (`RXa`, `RILb`, …).
3. **Write the constructor skeleton** below the "Phase 2" marker in
   `s390x.slaspec`, constraining every opcode byte/nibble as a literal:
   - The display section prints the assembler syntax with attached fields
     (attached `R1` etc. print as register names automatically).
   - The pcode section computes the EA with the macros above and emits
     semantics; branches assign `pswia`, calls/links write `r14`,
     returns use `return r14;`, condition-setting writes `cc`.
4. **Mark anything uncertain** with `# TODO(verify)` — especially opcodes
   copied from secondary sources, CC semantics, and exception behavior.

### Skeleton (RX-format load-type instruction — placeholders only)

```
# TODO(verify): opcode bytes below are placeholders; take them from the PoP.
:LOAD_EXAMPLE RXa OP=0x00, R1, X2, B2, D2 is OP=0x00 & R1 & X2 & B2 & D2
{
    local ea:8;
    ea_D12(ea, B2, X2, D2);
    R1 = *(ea);          # size the load to the real operand width
}
```

### Checklist before committing a constructor
- [ ] Opcode bytes/nibbles verified against SA22-7832 (not binutils/r2).
- [ ] Correct token variant (a/b/c) for the operand kinds.
- [ ] B=0/X=0 handling comes free via the `zero` attachment — no branches.
- [ ] 20-bit displacements go through `ea_D20` (signed), 12-bit through `ea_D12`.
- [ ] Relative branches go through `rel_RI32` and assign `pswia`.
- [ ] Display syntax matches HLASM operand order for the mnemonic.
