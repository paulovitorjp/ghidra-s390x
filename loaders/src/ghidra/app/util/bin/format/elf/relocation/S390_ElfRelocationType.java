// S390_ElfRelocationType.java -- s390x ELF relocation type IDs.
//
// Numbers and calculation semantics follow the s390x ELF ABI as implemented
// by GNU binutils (include/elf/s390.h) and glibc (sysdeps/s390/dl-machine.h).
// Notation: S = symbol value, A = addend (RELA), P = relocation address,
//           B = load bias, GOT = global offset table base,
//           G = GOT entry address for S minus GOT.
//
// s390x uses RELA relocations exclusively; the addend always comes from the
// relocation entry. For the PC-relative *DBL types the relocation address P
// is the *field* address (not the instruction address); assemblers emit an
// addend compensating for the field offset (e.g. A=2 for the 32-bit branch
// field at instruction+2), so no extra adjustment is needed here.

package ghidra.app.util.bin.format.elf.relocation;

public enum S390_ElfRelocationType implements ElfRelocationType {

	R_390_NONE(0),          // no relocation
	R_390_8(1),            // direct 8 bit:          (S + A) & 0xff
	R_390_12(2),           // direct 12 bit:         low 12 of halfword, top 4 bits preserved
	R_390_16(3),           // direct 16 bit:         S + A
	R_390_32(4),           // direct 32 bit:         S + A
	R_390_PC32(5),         // PC relative 32 bit:    S + A - P
	R_390_GOT12(6),        // 12 bit GOT offset:     low 12 of (G + A), top 4 bits preserved
	R_390_GOT32(7),        // 32 bit GOT offset:     G + A
	R_390_PLT32(8),        // 32 bit PC rel PLT:     L + A - P (L = PLT entry address)
	R_390_COPY(9),         // copy symbol at runtime (not supported statically)
	R_390_GLOB_DAT(10),    // 64 bit:                S + A
	R_390_JMP_SLOT(11),    // 64 bit:                S + A
	R_390_RELATIVE(12),    // 64 bit:                B + A
	R_390_GOTOFF32(13),    // 32 bit offset to GOT:  S + A - GOT
	R_390_GOTPC(14),       // 32 bit PC rel to GOT:  GOT + A - P
	R_390_GOT16(15),       // 16 bit GOT offset:     G + A
	R_390_PC16(16),        // PC relative 16 bit:    S + A - P
	R_390_PC16DBL(17),     // PC rel 16 bit >>1:     (S + A - P) >> 1
	R_390_PLT16DBL(18),    // 16 bit PC rel PLT >>1: (L + A - P) >> 1
	R_390_PC32DBL(19),     // PC rel 32 bit >>1:     (S + A - P) >> 1
	R_390_PLT32DBL(20),    // 32 bit PC rel PLT >>1: (L + A - P) >> 1
	R_390_GOTPCDBL(21),    // 32 bit PC rel GOT >>1: (GOT + A - P) >> 1
	R_390_64(22),          // direct 64 bit:         S + A
	R_390_PC64(23),        // PC relative 64 bit:    S + A - P
	R_390_GOT64(24),       // 64 bit GOT offset:     G + A
	R_390_PLT64(25),       // 64 bit PC rel PLT:     L + A - P
	R_390_GOTENT(26),      // 32 bit PC rel to GOT entry >>1: (G + A - P) >> 1
	R_390_GOTOFF16(27),    // 16 bit offset to GOT:  S + A - GOT
	R_390_GOTOFF64(28),    // 64 bit offset to GOT:  S + A - GOT
	R_390_GOTPLT12(29),    // 12 bit offset to jump slot: low 12 of (G + A)
	R_390_GOTPLT16(30),    // 16 bit offset to jump slot: G + A
	R_390_GOTPLT32(31),    // 32 bit offset to jump slot: G + A
	R_390_GOTPLT64(32),    // 64 bit offset to jump slot: G + A
	R_390_GOTPLTENT(33),   // 32 bit rel offset to jump slot >>1: (G + A - P) >> 1
	R_390_PLTOFF16(34),    // 16 bit offset from GOT to PLT: L + A - GOT
	R_390_PLTOFF32(35),    // 32 bit offset from GOT to PLT: L + A - GOT
	R_390_PLTOFF64(36),    // 64 bit offset from GOT to PLT: L + A - GOT
	R_390_TLS_LOAD(37),    // tag for load insn in TLS code (not modeled)
	R_390_TLS_GDCALL(38),  // tag for call in TLS general-dynamic (not modeled)
	R_390_TLS_LDCALL(39),  // tag for call in TLS local-dynamic (not modeled)
	R_390_TLS_GD32(40),    // TLS general-dynamic 32 bit (not modeled)
	R_390_TLS_GD64(41),    // TLS general-dynamic 64 bit (not modeled)
	R_390_TLS_GOTIE12(42), // TLS initial-exec 12 bit GOT offset (not modeled)
	R_390_TLS_GOTIE32(43), // TLS initial-exec 32 bit GOT offset (not modeled)
	R_390_TLS_GOTIE64(44), // TLS initial-exec 64 bit GOT offset (not modeled)
	R_390_TLS_LDM32(45),   // TLS local-dynamic 32 bit (not modeled)
	R_390_TLS_LDM64(46),   // TLS local-dynamic 64 bit (not modeled)
	R_390_TLS_IE32(47),    // TLS initial-exec 32 bit (not modeled)
	R_390_TLS_IE64(48),    // TLS initial-exec 64 bit (not modeled)
	R_390_TLS_IEENT(49),   // TLS initial-exec GOT entry rel offset (not modeled)
	R_390_TLS_LE32(50),    // TLS local-exec 32 bit (not modeled)
	R_390_TLS_LE64(51),    // TLS local-exec 64 bit (not modeled)
	R_390_TLS_LDO32(52),   // TLS local-dynamic offset 32 bit (not modeled)
	R_390_TLS_LDO64(53),   // TLS local-dynamic offset 64 bit (not modeled)
	R_390_TLS_DTPMOD(54),  // TLS module id (not modeled)
	R_390_TLS_DTPOFF(55),  // TLS block offset (not modeled)
	R_390_TLS_TPOFF(56),   // TLS static offset (not modeled)
	R_390_20(57),          // direct 20 bit:         low 20 of word, top 12 bits preserved
	R_390_GOT20(58),       // 20 bit GOT offset:     low 20 of (G + A)
	R_390_GOTPLT20(59),    // 20 bit offset to jump slot: low 20 of (G + A)
	R_390_TLS_GOTIE20(60), // TLS initial-exec 20 bit GOT offset (not modeled)
	R_390_IRELATIVE(61),   // 64 bit:                B + A (IFUNC resolver not invoked)
	R_390_PC12DBL(62),     // PC rel 12 bit >>1:     low 12 of ((S + A - P) >> 1)
	R_390_PLT12DBL(63),    // 12 bit PC rel PLT >>1: low 12 of ((L + A - P) >> 1)
	R_390_PC24DBL(64),     // PC rel 24 bit >>1:     low 24 of ((S + A - P) >> 1)
	R_390_PLT24DBL(65),    // 24 bit PC rel PLT >>1: low 24 of ((L + A - P) >> 1)
	R_390_GNU_VTINHERIT(250), // GNU vtable inherit: no-op marker, skipped
	R_390_GNU_VTENTRY(251);   // GNU vtable entry: no-op marker, skipped

	public final int typeId;

	private S390_ElfRelocationType(int typeId) {
		this.typeId = typeId;
	}

	@Override
	public int typeId() {
		return typeId;
	}
}
