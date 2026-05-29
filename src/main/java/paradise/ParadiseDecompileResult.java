package paradise;

import java.util.List;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;

record ParadiseDecompileResult(Program program, Function function, boolean success, String code,
		String signature, String message, HighFunction highFunction, List<ParadiseTokenSpan> tokenSpans,
		List<String> cleanups, String rawCode, List<ParadiseTokenSpan> rawTokenSpans) {

	ParadiseDecompileResult(Program program, Function function, boolean success, String code,
			String signature, String message, HighFunction highFunction,
			List<ParadiseTokenSpan> tokenSpans) {
		this(program, function, success, code, signature, message, highFunction, tokenSpans,
			List.of(), code, tokenSpans);
	}

	ParadiseDecompileResult(Program program, Function function, boolean success, String code,
			String signature, String message, HighFunction highFunction,
			List<ParadiseTokenSpan> tokenSpans, List<String> cleanups) {
		this(program, function, success, code, signature, message, highFunction, tokenSpans,
			cleanups, code, tokenSpans);
	}

	static ParadiseDecompileResult failure(Program program, Function function, String message) {
		String safeMessage = message == null || message.isBlank() ? "Decompiler failed" : message;
		String code = "/*\n * " + safeMessage.replace("*/", "* /") + "\n */\n";
		return new ParadiseDecompileResult(program, function, false, code, null, safeMessage, null,
			List.of());
	}

	ParadiseTokenSpan tokenAt(int offset) {
		for (ParadiseTokenSpan span : tokenSpans) {
			if (span.contains(offset)) {
				return span;
			}
		}
		return null;
	}
}
