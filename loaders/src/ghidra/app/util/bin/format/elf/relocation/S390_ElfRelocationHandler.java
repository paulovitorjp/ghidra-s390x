// S390_ElfRelocationHandler.java -- Ghidra ELF relocation handler for s390x.
//
// Discovered automatically by Ghidra's ClassSearcher (name ends in
// "ElfRelocationHandler", public default constructor, ExtensionPoint base).
// Claims 64-bit EM_S390 objects; applies RELA relocations per the s390x ELF
// ABI (binutils include/elf/s390.h, glibc sysdeps/s390/dl-machine.h,
// gas/config/tc-s390.c for field layouts).
//
// Notation: S = symbol value (image-adjusted), A = RELA addend, P = address
// being relocated, B = image base adjustment, GOT = GOT base,
// G = GOT-entry address for S minus GOT, L = PLT entry address for S.
//
// Supported: all R_390_* absolute, PC-relative, GOT-relative, GOTOFF,
// PLT-relative, GLOB_DAT, JMP_SLOT, RELATIVE and IRELATIVE types, plus
// R_390_GNU_VTINHERIT/VTENTRY (no-op markers, skipped without a bookmark).
// Explicitly warned+skipped: R_390_COPY (runtime copy unsupported) and all
// R_390_TLS_* (no TLS model).

package ghidra.app.util.bin.format.elf.relocation;

import java.util.Map;

import ghidra.app.util.bin.format.elf.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.program.model.reloc.RelocationResult;
import ghidra.util.exception.NotFoundException;

public class S390_ElfRelocationHandler extends
		AbstractElfRelocationHandler<S390_ElfRelocationType, S390_ElfRelocationContext> {

	public S390_ElfRelocationHandler() {
		super(S390_ElfRelocationType.class);
	}

	@Override
	public boolean canRelocate(ElfHeader elf) {
		// EM_S390 covers both 31-bit s390 and 64-bit s390x; this handler
		// implements the 64-bit (s390x) relocation semantics only.
		return elf.e_machine() == ElfConstants.EM_S390 && elf.is64Bit();
	}

	@Override
	public int getRelrRelocationType() {
		return S390_ElfRelocationType.R_390_RELATIVE.typeId;
	}

	@Override
	public S390_ElfRelocationContext createRelocationContext(ElfLoadHelper loadHelper,
			Map<ElfSymbol, Address> symbolMap) {
		return new S390_ElfRelocationContext(this, loadHelper, symbolMap);
	}

	/**
	 * G = GOT entry address for sym minus GOT base. Marks an error and
	 * returns null if no GOT entry could be established.
	 */
	private Long gotEntryOffset(S390_ElfRelocationContext ctx, Program program,
			Address relocationAddress, S390_ElfRelocationType type, ElfSymbol sym,
			String symbolName, int symbolIndex) {
		Address gotEntry = ctx.getGotEntryAddress(sym);
		if (gotEntry == null) {
			markAsError(program, relocationAddress, type, symbolName, symbolIndex,
				"GOT allocation failure", ctx.getLog());
			return null;
		}
		Long got = gotBase(ctx, program, relocationAddress, type, symbolName, symbolIndex);
		if (got == null) {
			return null;
		}
		return gotEntry.getOffset() - got;
	}

	/**
	 * GOT base address. Marks an error and returns null if it cannot be
	 * identified.
	 */
	private Long gotBase(S390_ElfRelocationContext ctx, Program program,
			Address relocationAddress, S390_ElfRelocationType type, String symbolName,
			int symbolIndex) {
		try {
			return ctx.getGOTValue();
		}
		catch (NotFoundException e) {
			markAsError(program, relocationAddress, type, symbolName, symbolIndex,
				"Failed to identify _GLOBAL_OFFSET_TABLE_", ctx.getLog());
			return null;
		}
	}

	@Override
	protected RelocationResult relocate(S390_ElfRelocationContext ctx,
			ElfRelocation relocation, S390_ElfRelocationType type, Address relocationAddress,
			ElfSymbol sym, Address symbolAddr, long symbolValue, String symbolName)
			throws MemoryAccessException {

		Program program = ctx.getProgram();
		Memory memory = program.getMemory();

		int symbolIndex = relocation.getSymbolIndex();
		long addend = relocation.getAddend(); // s390x uses RELA exclusively
		long offset = relocationAddress.getOffset(); // P
		long relocbase = ctx.getImageBaseWordAdjustmentOffset(); // B

		// Relocations which do not require a resolved symbol
		switch (type) {
			case R_390_RELATIVE:
				memory.setLong(relocationAddress, relocbase + addend);
				return new RelocationResult(Status.APPLIED, 8);
			case R_390_IRELATIVE:
				// IFUNC resolvers cannot be invoked during static import;
				// record the resolver address the way the runtime would
				// before invoking it, and warn that it was not invoked.
				markAsWarning(program, relocationAddress, type, symbolName, symbolIndex,
					"IFUNC resolver not invoked; address of resolver recorded",
					ctx.getLog());
				memory.setLong(relocationAddress, relocbase + addend);
				return new RelocationResult(Status.APPLIED, 8);
			case R_390_COPY:
				markAsUnsupportedCopy(program, relocationAddress, type, symbolName,
					symbolIndex, sym.getSize(), ctx.getLog());
				return RelocationResult.UNSUPPORTED;
			case R_390_GNU_VTINHERIT:
			case R_390_GNU_VTENTRY:
				// GNU vtable verification markers: no memory fixup is ever
				// required; skip silently rather than flagging as unhandled.
				return RelocationResult.SKIPPED;
			case R_390_TLS_LOAD:
			case R_390_TLS_GDCALL:
			case R_390_TLS_LDCALL:
			case R_390_TLS_GD32:
			case R_390_TLS_GD64:
			case R_390_TLS_GOTIE12:
			case R_390_TLS_GOTIE32:
			case R_390_TLS_GOTIE64:
			case R_390_TLS_GOTIE20:
			case R_390_TLS_LDM32:
			case R_390_TLS_LDM64:
			case R_390_TLS_IE32:
			case R_390_TLS_IE64:
			case R_390_TLS_IEENT:
			case R_390_TLS_LE32:
			case R_390_TLS_LE64:
			case R_390_TLS_LDO32:
			case R_390_TLS_LDO64:
			case R_390_TLS_DTPMOD:
			case R_390_TLS_DTPOFF:
			case R_390_TLS_TPOFF:
				markAsWarning(program, relocationAddress, type, symbolName, symbolIndex,
					"TLS relocation not modeled for s390x", ctx.getLog());
				return RelocationResult.UNSUPPORTED;
			default:
				break;
		}

		// Remaining types require a resolved symbol
		if (handleUnresolvedSymbol(ctx, relocation, relocationAddress)) {
			return RelocationResult.FAILURE;
		}

		long newValue;
		int byteLength;
		switch (type) {
			// ---- direct absolute ----
			case R_390_8:
				memory.setByte(relocationAddress, (byte) (symbolValue + addend));
				byteLength = 1;
				break;
			case R_390_12: {
				// 12-bit field: preserve the neighbouring register nibble
				int old = memory.getShort(relocationAddress) & 0xffff;
				newValue = (old & 0xf000) | ((symbolValue + addend) & 0xfff);
				memory.setShort(relocationAddress, (short) newValue);
				byteLength = 2;
				break;
			}
			case R_390_16:
				memory.setShort(relocationAddress, (short) (symbolValue + addend));
				byteLength = 2;
				break;
			case R_390_20: {
				// 20-bit field in a 32-bit container: preserve top 12 bits
				int old = memory.getInt(relocationAddress);
				newValue = (old & 0xfff00000) | ((int) (symbolValue + addend) & 0xfffff);
				memory.setInt(relocationAddress, (int) newValue);
				byteLength = 4;
				break;
			}
			case R_390_32:
				memory.setInt(relocationAddress, (int) (symbolValue + addend));
				if (symbolIndex != 0 && addend != 0 && !sym.isSection()) {
					warnExternalOffsetRelocation(program, relocationAddress, symbolAddr,
						symbolName, addend, ctx.getLog());
					applyComponentOffsetPointer(program, relocationAddress, addend);
				}
				byteLength = 4;
				break;
			case R_390_64:
				memory.setLong(relocationAddress, symbolValue + addend);
				if (symbolIndex != 0 && addend != 0 && !sym.isSection()) {
					warnExternalOffsetRelocation(program, relocationAddress, symbolAddr,
						symbolName, addend, ctx.getLog());
					applyComponentOffsetPointer(program, relocationAddress, addend);
				}
				byteLength = 8;
				break;

			// ---- PC-relative ----
			case R_390_PC16:
				memory.setShort(relocationAddress, (short) (symbolValue + addend - offset));
				byteLength = 2;
				break;
			case R_390_PC16DBL: {
				int diff = (int) (symbolValue + addend - offset);
				memory.setShort(relocationAddress, (short) ((short) diff >> 1));
				byteLength = 2;
				break;
			}
			case R_390_PC12DBL: {
				int old = memory.getShort(relocationAddress) & 0xffff;
				int diff = (int) (symbolValue + addend - offset);
				newValue = (old & 0xf000) | (((diff >> 1)) & 0xfff);
				memory.setShort(relocationAddress, (short) newValue);
				byteLength = 2;
				break;
			}
			case R_390_PC32:
				memory.setInt(relocationAddress, (int) (symbolValue + addend - offset));
				byteLength = 4;
				break;
			case R_390_PC32DBL: {
				int diff = (int) (symbolValue + addend - offset);
				memory.setInt(relocationAddress, diff >> 1);
				byteLength = 4;
				break;
			}
			case R_390_PC24DBL: {
				int old = memory.getInt(relocationAddress);
				int diff = (int) (symbolValue + addend - offset);
				newValue = (old & 0xff000000) | ((diff >> 1) & 0xffffff);
				memory.setInt(relocationAddress, (int) newValue);
				byteLength = 4;
				break;
			}
			case R_390_PC64:
				memory.setLong(relocationAddress, symbolValue + addend - offset);
				byteLength = 8;
				break;

			// ---- GOT-relative (G = GOT entry for S minus GOT) ----
			case R_390_GOT12: {
				Long g = gotEntryOffset(ctx, program, relocationAddress, type, sym,
					symbolName, symbolIndex);
				if (g == null) {
					return RelocationResult.FAILURE;
				}
				int old = memory.getShort(relocationAddress) & 0xffff;
				newValue = (old & 0xf000) | ((g + addend) & 0xfff);
				memory.setShort(relocationAddress, (short) newValue);
				byteLength = 2;
				break;
			}
			case R_390_GOTPLT12: {
				Long g = gotEntryOffset(ctx, program, relocationAddress, type, sym,
					symbolName, symbolIndex);
				if (g == null) {
					return RelocationResult.FAILURE;
				}
				int old = memory.getShort(relocationAddress) & 0xffff;
				newValue = (old & 0xf000) | ((g + addend) & 0xfff);
				memory.setShort(relocationAddress, (short) newValue);
				byteLength = 2;
				break;
			}
			case R_390_GOT16:
			case R_390_GOTPLT16: {
				Long g = gotEntryOffset(ctx, program, relocationAddress, type, sym,
					symbolName, symbolIndex);
				if (g == null) {
					return RelocationResult.FAILURE;
				}
				memory.setShort(relocationAddress, (short) (g + addend));
				byteLength = 2;
				break;
			}
			case R_390_GOT20:
			case R_390_GOTPLT20: {
				Long g = gotEntryOffset(ctx, program, relocationAddress, type, sym,
					symbolName, symbolIndex);
				if (g == null) {
					return RelocationResult.FAILURE;
				}
				int old = memory.getInt(relocationAddress);
				newValue = (old & 0xfff00000) | ((int) (g + addend) & 0xfffff);
				memory.setInt(relocationAddress, (int) newValue);
				byteLength = 4;
				break;
			}
			case R_390_GOT32:
			case R_390_GOTPLT32: {
				Long g = gotEntryOffset(ctx, program, relocationAddress, type, sym,
					symbolName, symbolIndex);
				if (g == null) {
					return RelocationResult.FAILURE;
				}
				memory.setInt(relocationAddress, (int) (g + addend));
				byteLength = 4;
				break;
			}
			case R_390_GOT64:
			case R_390_GOTPLT64: {
				Long g = gotEntryOffset(ctx, program, relocationAddress, type, sym,
					symbolName, symbolIndex);
				if (g == null) {
					return RelocationResult.FAILURE;
				}
				memory.setLong(relocationAddress, g + addend);
				byteLength = 8;
				break;
			}
			case R_390_GOTENT:
			case R_390_GOTPLTENT: {
				Long g = gotEntryOffset(ctx, program, relocationAddress, type, sym,
					symbolName, symbolIndex);
				if (g == null) {
					return RelocationResult.FAILURE;
				}
				int diff = (int) (g + addend - offset);
				memory.setInt(relocationAddress, diff >> 1);
				byteLength = 4;
				break;
			}

			// ---- GOT base relative ----
			case R_390_GOTPC: {
				Long got = gotBase(ctx, program, relocationAddress, type, symbolName,
					symbolIndex);
				if (got == null) {
					return RelocationResult.FAILURE;
				}
				memory.setInt(relocationAddress, (int) (got + addend - offset));
				byteLength = 4;
				break;
			}
			case R_390_GOTPCDBL: {
				Long got = gotBase(ctx, program, relocationAddress, type, symbolName,
					symbolIndex);
				if (got == null) {
					return RelocationResult.FAILURE;
				}
				int diff = (int) (got + addend - offset);
				memory.setInt(relocationAddress, diff >> 1);
				byteLength = 4;
				break;
			}
			case R_390_GOTOFF16: {
				Long got = gotBase(ctx, program, relocationAddress, type, symbolName,
					symbolIndex);
				if (got == null) {
					return RelocationResult.FAILURE;
				}
				memory.setShort(relocationAddress, (short) (symbolValue + addend - got));
				byteLength = 2;
				break;
			}
			case R_390_GOTOFF32: {
				Long got = gotBase(ctx, program, relocationAddress, type, symbolName,
					symbolIndex);
				if (got == null) {
					return RelocationResult.FAILURE;
				}
				memory.setInt(relocationAddress, (int) (symbolValue + addend - got));
				byteLength = 4;
				break;
			}
			case R_390_GOTOFF64: {
				Long got = gotBase(ctx, program, relocationAddress, type, symbolName,
					symbolIndex);
				if (got == null) {
					return RelocationResult.FAILURE;
				}
				memory.setLong(relocationAddress, symbolValue + addend - got);
				byteLength = 8;
				break;
			}

			// ---- PLT-relative (L = PLT entry address for S) ----
			case R_390_PLT16DBL: {
				long l = symbolAddr.getOffset();
				int diff = (int) (l + addend - offset);
				memory.setShort(relocationAddress, (short) (diff >> 1));
				byteLength = 2;
				break;
			}
			case R_390_PLT12DBL: {
				long l = symbolAddr.getOffset();
				int old = memory.getShort(relocationAddress) & 0xffff;
				int diff = (int) (l + addend - offset);
				newValue = (old & 0xf000) | ((diff >> 1) & 0xfff);
				memory.setShort(relocationAddress, (short) newValue);
				byteLength = 2;
				break;
			}
			case R_390_PLT32DBL: {
				long l = symbolAddr.getOffset();
				int diff = (int) (l + addend - offset);
				memory.setInt(relocationAddress, diff >> 1);
				byteLength = 4;
				break;
			}
			case R_390_PLT24DBL: {
				long l = symbolAddr.getOffset();
				int old = memory.getInt(relocationAddress);
				int diff = (int) (l + addend - offset);
				newValue = (old & 0xff000000) | ((diff >> 1) & 0xffffff);
				memory.setInt(relocationAddress, (int) newValue);
				byteLength = 4;
				break;
			}
			case R_390_PLT32: {
				long l = symbolAddr.getOffset();
				memory.setInt(relocationAddress, (int) (l + addend - offset));
				byteLength = 4;
				break;
			}
			case R_390_PLT64: {
				long l = symbolAddr.getOffset();
				memory.setLong(relocationAddress, l + addend - offset);
				byteLength = 8;
				break;
			}
			case R_390_PLTOFF16: {
				Long got = gotBase(ctx, program, relocationAddress, type, symbolName,
					symbolIndex);
				if (got == null) {
					return RelocationResult.FAILURE;
				}
				long l = symbolAddr.getOffset();
				memory.setShort(relocationAddress, (short) (l + addend - got));
				byteLength = 2;
				break;
			}
			case R_390_PLTOFF32: {
				Long got = gotBase(ctx, program, relocationAddress, type, symbolName,
					symbolIndex);
				if (got == null) {
					return RelocationResult.FAILURE;
				}
				long l = symbolAddr.getOffset();
				memory.setInt(relocationAddress, (int) (l + addend - got));
				byteLength = 4;
				break;
			}
			case R_390_PLTOFF64: {
				Long got = gotBase(ctx, program, relocationAddress, type, symbolName,
					symbolIndex);
				if (got == null) {
					return RelocationResult.FAILURE;
				}
				long l = symbolAddr.getOffset();
				memory.setLong(relocationAddress, l + addend - got);
				byteLength = 8;
				break;
			}

			// ---- dynamic linking ----
			case R_390_GLOB_DAT:
				memory.setLong(relocationAddress, symbolValue + addend);
				if (symbolIndex != 0 && addend != 0 && !sym.isSection()) {
					warnExternalOffsetRelocation(program, relocationAddress, symbolAddr,
						symbolName, addend, ctx.getLog());
					applyComponentOffsetPointer(program, relocationAddress, addend);
				}
				byteLength = 8;
				break;
			case R_390_JMP_SLOT: {
				memory.setLong(relocationAddress, symbolValue + addend);
				// Give imported functions a proper external linkage so calls
				// through the slot resolve to a named external function.
				MemoryBlock block = memory.getBlock(symbolAddr);
				boolean isExternal = block != null &&
					MemoryBlock.EXTERNAL_BLOCK_NAME.equals(block.getName());
				if (isExternal && symbolName != null && !symbolName.trim().isEmpty()) {
					Function extFunction = ctx.getLoadHelper()
							.createExternalFunctionLinkage(symbolName, symbolAddr, null);
					if (extFunction == null) {
						markAsError(program, relocationAddress, type, symbolName,
							symbolIndex, "Failed to create external function",
							ctx.getLog());
						// relocation already applied above
					}
				}
				byteLength = 8;
				break;
			}

			default:
				markAsUnhandled(program, relocationAddress, type, symbolIndex, symbolName,
					ctx.getLog());
				return RelocationResult.UNSUPPORTED;
		}
		return new RelocationResult(Status.APPLIED, byteLength);
	}
}
