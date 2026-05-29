package paradise;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;

final class ParadiseStringUtil {
	private static final int MAX_STRING_BYTES = 512;
	private static final int MIN_STRING_CHARS = 2;

	private ParadiseStringUtil() {
	}

	static ParadiseString stringAt(Program program, Address address) {
		if (program == null || address == null || !address.isMemoryAddress()) {
			return null;
		}
		ParadiseString defined = definedStringAt(program, address);
		if (defined != null) {
			return defined;
		}
		return rawStringAt(program, address);
	}

	private static ParadiseString definedStringAt(Program program, Address address) {
		Data data = program.getListing().getDefinedDataContaining(address);
		if (data == null || !StringDataInstance.isString(data)) {
			return null;
		}
		StringDataInstance stringData = StringDataInstance.getStringDataInstance(data);
		if (stringData == null) {
			return null;
		}
		String value = stringData.getStringValue();
		if (value == null || value.isBlank()) {
			value = stringData.getStringRepresentation();
		}
		if (value == null || value.isBlank()) {
			return null;
		}
		return new ParadiseString(data.getMinAddress(), value);
	}

	private static ParadiseString rawStringAt(Program program, Address address) {
		Memory memory = program.getMemory();
		MemoryBlock block = memory.getBlock(address);
		if (block == null || !block.isInitialized() || !block.isRead()) {
			return null;
		}

		String ascii = asciiStringAt(memory, block, address);
		String utf16 = utf16StringAt(memory, block, address, false);
		String utf16be = utf16StringAt(memory, block, address, true);
		String best = longest(ascii, utf16, utf16be);
		return best == null ? null : new ParadiseString(address, best);
	}

	private static String asciiStringAt(Memory memory, MemoryBlock block, Address address) {
		StringBuilder builder = new StringBuilder();
		for (int offset = 0; offset < MAX_STRING_BYTES; offset++) {
			Address current = add(address, offset);
			if (current == null || !block.contains(current)) {
				break;
			}
			int value = byteAt(memory, current);
			if (value < 0) {
				break;
			}
			if (value == 0) {
				return acceptable(builder) ? builder.toString() : null;
			}
			if (!isTextByte(value)) {
				return null;
			}
			builder.append((char) value);
		}
		return acceptable(builder) ? builder.toString() : null;
	}

	private static String utf16StringAt(Memory memory, MemoryBlock block, Address address,
			boolean bigEndian) {
		StringBuilder builder = new StringBuilder();
		for (int offset = 0; offset < MAX_STRING_BYTES; offset += 2) {
			Address first = add(address, offset);
			Address second = add(address, offset + 1);
			if (first == null || second == null || !block.contains(first) || !block.contains(second)) {
				break;
			}
			int b0 = byteAt(memory, first);
			int b1 = byteAt(memory, second);
			if (b0 < 0 || b1 < 0) {
				break;
			}
			int value = bigEndian ? (b0 << 8) | b1 : (b1 << 8) | b0;
			if (value == 0) {
				return acceptable(builder) ? builder.toString() : null;
			}
			if (!isTextChar(value)) {
				return null;
			}
			builder.append((char) value);
		}
		return acceptable(builder) ? builder.toString() : null;
	}

	private static Address add(Address address, long offset) {
		try {
			return address.add(offset);
		}
		catch (RuntimeException e) {
			return null;
		}
	}

	private static int byteAt(Memory memory, Address address) {
		try {
			return memory.getByte(address) & 0xff;
		}
		catch (MemoryAccessException e) {
			return -1;
		}
	}

	private static boolean acceptable(StringBuilder builder) {
		if (builder.length() < MIN_STRING_CHARS) {
			return false;
		}
		int visible = 0;
		for (int i = 0; i < builder.length(); i++) {
			if (!Character.isWhitespace(builder.charAt(i))) {
				visible++;
			}
		}
		return visible > 0;
	}

	private static boolean isTextByte(int value) {
		return value == '\t' || value == '\n' || value == '\r' ||
			(value >= 0x20 && value <= 0x7e);
	}

	private static boolean isTextChar(int value) {
		return value == '\t' || value == '\n' || value == '\r' ||
			(value >= 0x20 && value <= 0x7e);
	}

	private static String longest(String first, String second, String third) {
		String best = first;
		if (second != null && (best == null || second.length() > best.length())) {
			best = second;
		}
		if (third != null && (best == null || third.length() > best.length())) {
			best = third;
		}
		return best;
	}

	record ParadiseString(Address address, String value) {
	}
}
