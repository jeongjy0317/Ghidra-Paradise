package paradise;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

record ParadiseXrefRow(Address from, Function function, String type, String preview) {
	String functionName() {
		return function == null ? "" : function.getName();
	}
}
