package paradise;

import ghidra.app.decompiler.ClangToken;
import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.HighSymbol;

record ParadiseTokenSpan(int start, int end, ClangToken token, Address minAddress, Address maxAddress,
		HighSymbol highSymbol, int syntaxType) {

	boolean contains(int offset) {
		return start <= offset && offset < end;
	}

	int length() {
		return end - start;
	}

	Address address() {
		return minAddress != null ? minAddress : maxAddress;
	}
}
