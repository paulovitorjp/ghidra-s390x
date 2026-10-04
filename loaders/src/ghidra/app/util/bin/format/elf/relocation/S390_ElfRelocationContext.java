// S390_ElfRelocationContext.java -- relocation context for s390x.
//
// Extends Ghidra's ElfGotRelocationContext so that GOT-relative relocations
// (R_390_GOT*, R_390_GOTPLT*, R_390_GOTENT, R_390_GOTPLTENT) encountered in
// relocatable objects get a synthesized GOT, mirroring the AArch64 handler.

package ghidra.app.util.bin.format.elf.relocation;

import java.util.Map;

import ghidra.app.util.bin.format.elf.*;
import ghidra.program.model.address.Address;

class S390_ElfRelocationContext extends ElfGotRelocationContext<S390_ElfRelocationHandler> {

	S390_ElfRelocationContext(S390_ElfRelocationHandler handler, ElfLoadHelper loadHelper,
			Map<ElfSymbol, Address> symbolMap) {
		super(handler, loadHelper, symbolMap);
	}

	@Override
	protected boolean requiresGotEntry(ElfRelocation r) {
		S390_ElfRelocationType type = handler.getRelocationType(r.getType());
		if (type == null) {
			return false;
		}
		switch (type) {
			case R_390_GOT12:
			case R_390_GOT16:
			case R_390_GOT20:
			case R_390_GOT32:
			case R_390_GOT64:
			case R_390_GOTPLT12:
			case R_390_GOTPLT16:
			case R_390_GOTPLT20:
			case R_390_GOTPLT32:
			case R_390_GOTPLT64:
			case R_390_GOTENT:
			case R_390_GOTPLTENT:
				return true;
			default:
				return false;
		}
	}
}
