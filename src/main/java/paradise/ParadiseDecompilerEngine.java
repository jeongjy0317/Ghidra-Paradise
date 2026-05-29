package paradise;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.decompiler.*;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.task.TaskMonitor;

final class ParadiseDecompilerEngine implements AutoCloseable {
	private static final int WRAPPER_DETECTION_TIMEOUT_SECONDS = 10;

	private final Map<Program, DecompInterface> interfaces = new IdentityHashMap<>();
	private final Map<Program, Map<CacheKey, ParadiseDecompileResult>> cache = new IdentityHashMap<>();
	private final Map<Program, Map<String, VarargsWrapper>> varargsWrapperCache =
		new IdentityHashMap<>();
	private final Map<Program, Set<String>> varargsWrapperMissCache = new IdentityHashMap<>();
	private final Map<Program, Set<Function>> varargsWrapperInProgress = new IdentityHashMap<>();

	synchronized ParadiseDecompileResult decompile(Program program, Function function, int timeoutSeconds,
			boolean force, TaskMonitor monitor) {
		return decompile(program, function, timeoutSeconds, force, monitor, false, false, false,
			false);
	}

	synchronized ParadiseDecompileResult decompile(Program program, Function function, int timeoutSeconds,
			boolean force, TaskMonitor monitor, boolean cleanC, boolean typeAliases,
			boolean cleanLiterals, boolean addressComments) {
		return decompile(program, function, timeoutSeconds, force, monitor,
			ParadiseCleanupOptions.fromCleanC(cleanC), typeAliases, cleanLiterals, addressComments);
	}

	synchronized ParadiseDecompileResult decompile(Program program, Function function, int timeoutSeconds,
			boolean force, TaskMonitor monitor, ParadiseCleanupOptions cleanupOptions,
			boolean typeAliases, boolean cleanLiterals, boolean addressComments) {
		if (program == null || function == null) {
			return ParadiseDecompileResult.failure(program, function, "No function is selected.");
		}
		ParadiseCleanupOptions options = cleanupOptions == null ? ParadiseCleanupOptions.disabled()
				: cleanupOptions;

		CacheKey key = new CacheKey(function.getEntryPoint(), options, typeAliases,
			cleanLiterals, addressComments);
		Map<CacheKey, ParadiseDecompileResult> programCache =
			cache.computeIfAbsent(program, p -> new LinkedHashMap<>());
		if (!force) {
			ParadiseDecompileResult cached = programCache.get(key);
			if (cached != null) {
				return cached;
			}
		}

		DecompInterface ifc = getInterface(program);
		DecompileResults results = ifc.decompileFunction(function, timeoutSeconds, monitor);
		if (results == null) {
			return ParadiseDecompileResult.failure(program, function, ifc.getLastMessage());
		}
		if (!results.decompileCompleted()) {
			String message = results.getErrorMessage();
			if (results.isTimedOut()) {
				message = "Decompiler timed out after " + timeoutSeconds + " seconds.";
			}
			ParadiseDecompileResult failure = ParadiseDecompileResult.failure(program, function, message);
			programCache.put(key, failure);
			return failure;
		}

		ParadiseDecompileResult result = buildResult(program, function, results, timeoutSeconds,
			monitor, options, typeAliases, cleanLiterals, addressComments);
		programCache.put(key, result);
		return result;
	}

	synchronized void clearProgramCache(Program program) {
		Map<CacheKey, ParadiseDecompileResult> programCache = cache.get(program);
		if (programCache != null) {
			programCache.clear();
		}
		Map<String, VarargsWrapper> wrapperCache = varargsWrapperCache.get(program);
		if (wrapperCache != null) {
			wrapperCache.clear();
		}
		Set<String> misses = varargsWrapperMissCache.get(program);
		if (misses != null) {
			misses.clear();
		}
		DecompInterface ifc = interfaces.get(program);
		if (ifc != null) {
			ifc.flushCache();
		}
	}

	synchronized void close(Program program) {
		cache.remove(program);
		varargsWrapperCache.remove(program);
		varargsWrapperMissCache.remove(program);
		varargsWrapperInProgress.remove(program);
		DecompInterface ifc = interfaces.remove(program);
		if (ifc != null) {
			ifc.dispose();
		}
	}

	@Override
	public synchronized void close() {
		for (DecompInterface ifc : interfaces.values()) {
			ifc.dispose();
		}
		interfaces.clear();
		cache.clear();
		varargsWrapperCache.clear();
		varargsWrapperMissCache.clear();
		varargsWrapperInProgress.clear();
	}

	private DecompInterface getInterface(Program program) {
		DecompInterface ifc = interfaces.get(program);
		if (ifc != null) {
			return ifc;
		}

		DecompileOptions options = new DecompileOptions();
		options.grabFromProgram(program);

		ifc = new DecompInterface();
		ifc.setOptions(options);
		ifc.toggleCCode(true);
		ifc.toggleSyntaxTree(true);
		if (!ifc.openProgram(program)) {
			throw new IllegalStateException(ifc.getLastMessage());
		}
		interfaces.put(program, ifc);
		return ifc;
	}

	private ParadiseDecompileResult buildResult(Program program, Function function,
			DecompileResults results, int timeoutSeconds, TaskMonitor monitor,
			ParadiseCleanupOptions cleanupOptions,
			boolean typeAliases, boolean cleanLiterals, boolean addressComments) {
		ClangTokenGroup markup = results.getCCodeMarkup();
		DecompiledFunction decompiled = results.getDecompiledFunction();
		HighFunction highFunction = results.getHighFunction();
		String warning = results.getErrorMessage();
		String signature = decompiled == null ? function.getPrototypeString(false, true)
				: decompiled.getSignature();

		if (markup == null) {
			String code = decompiled == null ? "" : decompiled.getC();
			if (typeAliases || cleanupOptions.enabled()) {
				code = applyTypeAliases(code);
			}
			if (cleanupOptions.enabled()) {
				code = stripWarningComments(code);
			}
			if (cleanLiterals) {
				code = applyLiteralAliases(code);
			}
			String rawCode = code;
			List<String> cleanups = List.of();
			if (cleanupOptions.enabled()) {
				RenderedMarkup cleaned = applyParadiseCleanup(program, function, timeoutSeconds,
					monitor, new RenderedMarkup(code, List.of()), cleanupOptions);
				code = cleaned.code();
				cleanups = cleaned.cleanups();
			}
			return new ParadiseDecompileResult(program, function, true, code, signature, warning,
				highFunction, List.of(), cleanups, rawCode, List.of());
		}

		RenderedMarkup rendered = renderMarkup(program, function, markup, highFunction,
			timeoutSeconds, monitor, cleanupOptions, typeAliases, cleanLiterals, addressComments);
		return new ParadiseDecompileResult(program, function, true, rendered.code(), signature, warning,
			highFunction, rendered.spans(), rendered.cleanups(), rendered.rawCode(),
			rendered.rawSpans());
	}

	private RenderedMarkup renderMarkup(Program program, Function function, ClangTokenGroup markup,
			HighFunction highFunction, int timeoutSeconds, TaskMonitor monitor,
			ParadiseCleanupOptions cleanupOptions,
			boolean typeAliases, boolean cleanLiterals, boolean addressComments) {
		PrettyPrinter printer = new PrettyPrinter(function, markup, null);
		StringBuilder code = new StringBuilder();
		List<ParadiseTokenSpan> spans = new ArrayList<>();

		for (ClangLine line : printer.getLines()) {
			if (cleanupOptions.enabled() && isWarningLine(line)) {
				continue;
			}
			code.append(line.getIndentString());
			for (ClangToken token : line.getAllTokens()) {
				String text = token.getText();
				if (text == null || text.isEmpty()) {
					continue;
				}
				if (typeAliases || cleanupOptions.enabled()) {
					text = applyTypeAlias(text);
				}
				if (cleanLiterals) {
					text = applyLiteralAlias(token, text);
				}
				int start = code.length();
				code.append(text);
				int end = code.length();
				Address minAddress = token.getMinAddress();
				Address maxAddress = token.getMaxAddress();
				spans.add(new ParadiseTokenSpan(start, end, token, minAddress, maxAddress,
					highSymbol(token, highFunction), token.getSyntaxType()));
				if (addressComments && shouldAnnotateAddress(token)) {
					Address address = minAddress != null ? minAddress : maxAddress;
					if (address != null) {
						code.append(" /* @").append(address).append(" */");
					}
				}
			}
			code.append(System.lineSeparator());
		}

		RenderedMarkup raw = new RenderedMarkup(code.toString(), List.copyOf(spans));
		RenderedMarkup rawAnnotated = annotateListingComments(program, raw);
		RenderedMarkup rendered = cleanupOptions.enabled() ? applyParadiseCleanup(program,
			function, timeoutSeconds, monitor, raw, cleanupOptions) : raw;
		RenderedMarkup annotated = annotateListingComments(program, rendered);
		return new RenderedMarkup(annotated.code(), annotated.spans(), annotated.cleanups(),
			rawAnnotated.code(), rawAnnotated.spans());
	}

	private HighSymbol highSymbol(ClangToken token, HighFunction highFunction) {
		if (highFunction == null) {
			return null;
		}
		try {
			return token.getHighSymbol(highFunction);
		}
		catch (RuntimeException e) {
			return null;
		}
	}

	Function functionForToken(Program program, ParadiseTokenSpan span) {
		if (program == null || span == null) {
			return null;
		}
		if (span.token() instanceof ClangFuncNameToken funcNameToken) {
			return DecompilerUtils.getFunction(program, funcNameToken);
		}
		return null;
	}

	private void collectLineAddress(Set<Address> addresses, Address address) {
		if (address != null) {
			addresses.add(address);
		}
	}

	private RenderedMarkup annotateListingComments(Program program, RenderedMarkup rendered) {
		if (program == null || rendered.spans().isEmpty()) {
			return rendered;
		}
		List<CodeLine> lines = codeLines(rendered.code());
		StringBuilder annotated = new StringBuilder(rendered.code().length());
		List<ParadiseTokenSpan> spans = new ArrayList<>();
		for (CodeLine line : lines) {
			int newStart = annotated.length();
			annotated.append(line.text());
			String comment = listingComment(program, lineAddresses(line, rendered.spans()));
			if (comment != null && !lineContainsComment(annotated, newStart, comment)) {
				annotated.append(" // ").append(comment);
			}
			annotated.append('\n');
			copyLineSpans(rendered.spans(), spans, line, newStart);
		}
		return new RenderedMarkup(annotated.toString(), List.copyOf(spans), rendered.cleanups(),
			rendered.rawCode(), rendered.rawSpans());
	}

	private Set<Address> lineAddresses(CodeLine line, List<ParadiseTokenSpan> spans) {
		Set<Address> addresses = new LinkedHashSet<>();
		for (ParadiseTokenSpan span : spans) {
			if (span.end() <= line.start()) {
				continue;
			}
			if (span.start() >= line.end()) {
				break;
			}
			collectLineAddress(addresses, span.minAddress());
			collectLineAddress(addresses, span.maxAddress());
		}
		return addresses;
	}

	private String listingComment(Program program, Set<Address> addresses) {
		if (program == null || addresses.isEmpty()) {
			return null;
		}
		List<String> comments = new ArrayList<>();
		for (Address address : addresses) {
			CodeUnit codeUnit = program.getListing().getCodeUnitAt(address);
			if (codeUnit == null) {
				continue;
			}
			for (CommentType type : commentOrder()) {
				String comment = normalizeComment(codeUnit.getComment(type));
				if (comment == null || hasEquivalentComment(comments, comment)) {
					continue;
				}
				comments.add(comment);
			}
		}
		return comments.isEmpty() ? null : String.join(" | ", comments);
	}

	private List<CommentType> commentOrder() {
		return List.of(CommentType.EOL, CommentType.REPEATABLE, CommentType.PLATE,
			CommentType.PRE, CommentType.POST);
	}

	private String normalizeComment(String comment) {
		if (comment == null) {
			return null;
		}
		String normalized = comment.strip().replace('\r', '\n')
				.replaceAll("\\s*\\n\\s*", " ")
				.replaceAll("\\s+", " ");
		if (normalized.isBlank()) {
			return null;
		}
		return previewComment(normalized, 160);
	}

	private boolean hasEquivalentComment(List<String> comments, String comment) {
		for (String existing : comments) {
			if (existing.equals(comment) || existing.contains(comment) || comment.contains(existing)) {
				return true;
			}
		}
		return false;
	}

	private String previewComment(String value, int maxLength) {
		if (value.length() <= maxLength) {
			return value;
		}
		return value.substring(0, Math.max(0, maxLength - 3)).stripTrailing() + "...";
	}

	private boolean lineContainsComment(StringBuilder code, int lineStart, String comment) {
		if (lineStart < 0 || lineStart > code.length()) {
			return false;
		}
		String line = code.substring(lineStart);
		return line.contains(comment);
	}

	private boolean shouldAnnotateAddress(ClangToken token) {
		int syntaxType = token.getSyntaxType();
		return syntaxType == ClangToken.FUNCTION_COLOR || syntaxType == ClangToken.GLOBAL_COLOR;
	}

	private String applyTypeAliases(String code) {
		String result = code;
		for (Map.Entry<String, String> entry : typeAliases().entrySet()) {
			result = result.replaceAll("\\b" + entry.getKey() + "\\b", entry.getValue());
		}
		return result;
	}

	private String applyTypeAlias(String text) {
		return typeAliases().getOrDefault(text, text);
	}

	private String applyLiteralAliases(String code) {
		String result = code;
		result = result.replaceAll("(?i)\\b0x[f]{16}(?:u|l|ul|lu|ull|llu|ll)?\\b", "-1");
		result = result.replaceAll("(?i)\\b0x[f]{8}(?:u|l|ul|lu|ull|llu|ll)?\\b", "-1");
		return result;
	}

	private String applyLiteralAlias(ClangToken token, String text) {
		if (!isIntegerConstant(token, text) || isBitwiseContext(token)) {
			return text;
		}

		IntegerLiteral literal = integerLiteral(text);
		if (literal == null || literal.negative()) {
			return text;
		}

		Scalar scalar = safeScalar(token);
		int bitLength = scalar == null ? literal.bitLengthFromText() : scalar.bitLength();
		long value = scalar == null ? literal.value() : scalar.getUnsignedValue();
		if (isAllOnes(value, bitLength) || literal.isAllOnes()) {
			return "-1";
		}

		if (isByteSizedLiteral(token, literal, bitLength)) {
			String charLiteral = charLiteral((int) (value & 0xff));
			if (charLiteral != null) {
				return charLiteral;
			}
		}
		return text;
	}

	private boolean isIntegerConstant(ClangToken token, String text) {
		if (token == null || text == null || text.isBlank()) {
			return false;
		}
		if (text.indexOf('\'') >= 0 || text.indexOf('"') >= 0 || text.indexOf('.') >= 0) {
			return false;
		}
		return token.getSyntaxType() == ClangToken.CONST_COLOR || safeScalar(token) != null;
	}

	private boolean isBitwiseContext(ClangToken token) {
		PcodeOp op;
		try {
			op = token.getPcodeOp();
		}
		catch (RuntimeException e) {
			return false;
		}
		if (op == null) {
			return false;
		}
		return switch (op.getOpcode()) {
			case PcodeOp.INT_AND, PcodeOp.INT_OR, PcodeOp.INT_XOR, PcodeOp.INT_LEFT,
					PcodeOp.INT_RIGHT, PcodeOp.INT_SRIGHT -> true;
			default -> false;
		};
	}

	private Scalar safeScalar(ClangToken token) {
		try {
			return token.getScalar();
		}
		catch (RuntimeException e) {
			return null;
		}
	}

	private IntegerLiteral integerLiteral(String text) {
		String trimmed = text.trim();
		boolean negative = trimmed.startsWith("-");
		if (negative || trimmed.startsWith("+")) {
			trimmed = trimmed.substring(1);
		}
		if (trimmed.isEmpty()) {
			return null;
		}

		String body = stripIntegerSuffix(trimmed);
		String lower = body.toLowerCase(Locale.ROOT);
		int radix = 10;
		String digits = body;
		boolean hex = false;
		if (lower.startsWith("0x")) {
			radix = 16;
			digits = body.substring(2);
			hex = true;
		}
		else if (body.length() > 1 && body.charAt(0) == '0') {
			radix = 8;
			digits = body.substring(1);
		}

		if (digits.isEmpty() || !validDigits(digits, radix)) {
			return null;
		}
		try {
			long value = Long.parseUnsignedLong(digits, radix);
			return new IntegerLiteral(value, negative, hex, hex ? digits.length() : 0,
				hex && allHexFs(digits));
		}
		catch (NumberFormatException e) {
			return null;
		}
	}

	private String stripIntegerSuffix(String text) {
		int end = text.length();
		while (end > 0) {
			char c = text.charAt(end - 1);
			if (c != 'u' && c != 'U' && c != 'l' && c != 'L') {
				break;
			}
			end--;
		}
		return text.substring(0, end);
	}

	private boolean validDigits(String digits, int radix) {
		for (int i = 0; i < digits.length(); i++) {
			if (Character.digit(digits.charAt(i), radix) < 0) {
				return false;
			}
		}
		return true;
	}

	private boolean allHexFs(String digits) {
		for (int i = 0; i < digits.length(); i++) {
			if (Character.toLowerCase(digits.charAt(i)) != 'f') {
				return false;
			}
		}
		return true;
	}

	private boolean isAllOnes(long value, int bitLength) {
		if (bitLength != Byte.SIZE && bitLength != Short.SIZE && bitLength != Integer.SIZE &&
			bitLength != Long.SIZE) {
			return false;
		}
		if (bitLength == Long.SIZE) {
			return value == -1L;
		}
		long mask = (1L << bitLength) - 1;
		return (value & mask) == mask;
	}

	private boolean isByteSizedLiteral(ClangToken token, IntegerLiteral literal, int bitLength) {
		if (literal.hex() && literal.hexDigits() == 2) {
			return true;
		}
		if (bitLength > 0 && bitLength <= Byte.SIZE) {
			return true;
		}
		try {
			Varnode varnode = token.getVarnode();
			return varnode != null && varnode.isConstant() && varnode.getSize() == 1;
		}
		catch (RuntimeException e) {
			return false;
		}
	}

	private String charLiteral(int value) {
		return switch (value) {
			case '\t' -> "'\\t'";
			case '\n' -> "'\\n'";
			case '\r' -> "'\\r'";
			case '\'' -> "'\\''";
			case '\\' -> "'\\\\'";
			default -> value >= 0x20 && value <= 0x7e ? "'" + (char) value + "'" : null;
		};
	}

	private Map<String, String> typeAliases() {
		Map<String, String> aliases = new LinkedHashMap<>();
		aliases.put("undefined1", "uint8_t");
		aliases.put("undefined2", "uint16_t");
		aliases.put("undefined4", "uint32_t");
		aliases.put("undefined8", "uint64_t");
		aliases.put("undefined", "uint8_t");
		aliases.put("byte", "uint8_t");
		aliases.put("word", "uint16_t");
		aliases.put("dword", "uint32_t");
		aliases.put("qword", "uint64_t");
		aliases.put("uchar", "uint8_t");
		aliases.put("ushort", "uint16_t");
		aliases.put("uint", "uint32_t");
		aliases.put("ulong", "uint64_t");
		aliases.put("ulonglong", "uint64_t");
		aliases.put("char16", "uint16_t");
		aliases.put("char32", "uint32_t");
		aliases.put("longlong", "int64_t");
		return aliases;
	}

	private boolean isWarningLine(ClangLine line) {
		String text = PrettyPrinter.getText(line);
		return text != null && text.contains("WARNING:");
	}

	private String stripWarningComments(String code) {
		StringBuilder cleaned = new StringBuilder();
		boolean skippingWarningBlock = false;
		for (String line : code.split("\\R", -1)) {
			String trimmed = line.trim();
			if (skippingWarningBlock) {
				if (trimmed.contains("*/")) {
					skippingWarningBlock = false;
				}
				continue;
			}
			if (trimmed.startsWith("/*") && trimmed.contains("WARNING:")) {
				if (!trimmed.contains("*/")) {
					skippingWarningBlock = true;
				}
				continue;
			}
			cleaned.append(line).append(System.lineSeparator());
		}
		return cleaned.toString();
	}

	private String applyParadiseCleanup(String code) {
		return applyParadiseCleanup(null, null, WRAPPER_DETECTION_TIMEOUT_SECONDS,
			TaskMonitor.DUMMY, new RenderedMarkup(code, List.of()),
			ParadiseCleanupOptions.cleanCDefaults()).code();
	}

	private String applyParadiseCleanup(Program program, Function function, int timeoutSeconds,
			TaskMonitor monitor, String code) {
		return applyParadiseCleanup(program, function, timeoutSeconds, monitor,
			new RenderedMarkup(code, List.of()), ParadiseCleanupOptions.cleanCDefaults()).code();
	}

	private RenderedMarkup applyParadiseCleanup(Program program, Function function,
			int timeoutSeconds, TaskMonitor monitor, RenderedMarkup rendered,
			ParadiseCleanupOptions cleanupOptions) {
		List<CodeLine> lines = codeLines(rendered.code());
		CleanupPlan plan = buildCleanupPlan(lines,
			new CleanupContext(program, function, timeoutSeconds, monitor, cleanupOptions));
		StringBuilder cleaned = new StringBuilder(rendered.code().length());
		List<ParadiseTokenSpan> spans = new ArrayList<>();

		for (int i = 0; i < lines.size(); i++) {
			CodeLine line = lines.get(i);
			List<String> replacement = plan.replacements.get(i);
			if (replacement != null) {
				for (String replacementLine : replacement) {
					appendLineWithRemappedSpans(cleaned, spans, rendered.spans(), line,
						replacementLine);
				}
				continue;
			}
			if (plan.skipLines.contains(i)) {
				continue;
			}
			String declarationName = declarationName(line.text());
			if (declarationName != null && plan.removableDeclarations.contains(declarationName) &&
				!hasUseAfterPlan(declarationName, i, lines, plan)) {
				continue;
			}

			String text = line.text();
			String normalized = normalizeCleanLine(text, plan);
			if (normalized.equals(text)) {
				int newStart = cleaned.length();
				cleaned.append(text).append('\n');
				copyLineSpans(rendered.spans(), spans, line, newStart);
			}
			else {
				appendLineWithRemappedSpans(cleaned, spans, rendered.spans(), line, normalized);
			}
		}
		RenderedMarkup cleanedMarkup = new RenderedMarkup(cleaned.toString(), List.copyOf(spans),
			plan.cleanupDescriptions(), rendered.rawCode(), rendered.rawSpans());
		if (cleanupOptions.localAliases()) {
			cleanedMarkup = applyLocalAliases(cleanedMarkup, plan);
		}
		return cleanedMarkup;
	}

	private RenderedMarkup applyLocalAliases(RenderedMarkup rendered, CleanupPlan plan) {
		Map<String, String> aliases = localAliasesFor(rendered.code());
		if (aliases.isEmpty()) {
			return rendered;
		}
		List<CodeLine> lines = codeLines(rendered.code());
		StringBuilder aliased = new StringBuilder(rendered.code().length());
		List<ParadiseTokenSpan> spans = new ArrayList<>();
		for (CodeLine line : lines) {
			String replacement = replaceLocalAliases(line.text(), aliases);
			appendLineWithRemappedSpans(aliased, spans, rendered.spans(), line, replacement);
		}
		for (int i = 0; i < aliases.size(); i++) {
			plan.recordCleanup("Displayed local aliases");
		}
		return new RenderedMarkup(aliased.toString(), List.copyOf(spans),
			plan.cleanupDescriptions(), rendered.rawCode(), rendered.rawSpans());
	}

	private Map<String, String> localAliasesFor(String code) {
		Map<String, String> declarations = localDeclarations(code);
		if (declarations.isEmpty()) {
			return Map.of();
		}
		Set<String> existingNames = identifiersIn(code);
		Map<String, String> aliases = new LinkedHashMap<>();
		Set<String> usedAliases = new HashSet<>();
		for (Map.Entry<String, String> entry : declarations.entrySet()) {
			String name = entry.getKey();
			String type = entry.getValue();
			String alias = suggestedAliasFor(code, name, type);
			if (alias == null || alias.equals(name)) {
				continue;
			}
			aliases.put(name, uniqueAlias(alias, existingNames, usedAliases));
		}
		return aliases;
	}

	private Map<String, String> localDeclarations(String code) {
		Map<String, String> declarations = new LinkedHashMap<>();
		Pattern declaration = Pattern.compile("^\\s*((?:[A-Za-z_][A-Za-z0-9_]*\\s+)+(?:\\*\\s*)?)(local_[0-9A-Za-z_]+)(?:\\s*\\[[^\\]]+\\])?\\s*;\\s*$",
			Pattern.MULTILINE);
		Matcher matcher = declaration.matcher(code);
		while (matcher.find()) {
			declarations.put(matcher.group(2), matcher.group(1).replaceAll("\\s+", " ").trim());
		}
		return declarations;
	}

	private Set<String> identifiersIn(String code) {
		Set<String> identifiers = new HashSet<>();
		Matcher matcher = Pattern.compile("\\b[A-Za-z_]\\w*\\b").matcher(code);
		while (matcher.find()) {
			identifiers.add(matcher.group());
		}
		return identifiers;
	}

	private String suggestedAliasFor(String code, String name, String type) {
		String lowerType = type.toLowerCase(Locale.ROOT);
		if (lowerType.contains("file") && Pattern.compile("\\b" + Pattern.quote(name) +
			"\\s*=\\s*fopen\\s*\\([^\\n;]*\"r").matcher(code).find()) {
			return "stream";
		}
		if (lowerType.contains("file") && Pattern.compile("\\b" + Pattern.quote(name) +
			"\\s*=\\s*fopen\\s*\\([^\\n;]*\"w").matcher(code).find()) {
			return "out";
		}
		if ((lowerType.contains("uint8_t") || lowerType.contains("byte") ||
			lowerType.contains("char")) && lowerType.contains("*") &&
			Pattern.compile("\\b" + Pattern.quote(name) + "\\s*=\\s*&\\s*DAT_")
					.matcher(code).find()) {
			return "key";
		}
		if ((lowerType.contains("uint8_t") || lowerType.contains("char")) &&
			Pattern.compile("&\\s*" + Pattern.quote(name) + "\\b[^;]*(?:fread|fwrite)|(?:fread|fwrite)\\s*\\([^;]*&\\s*" +
				Pattern.quote(name) + "\\b").matcher(code).find()) {
			return "ptr";
		}
		if (lowerType.matches(".*\\b(?:int|uint32_t|int32_t|size_t)\\b.*") &&
			Pattern.compile("(?:\\+\\+|--)\\s*" + Pattern.quote(name) + "\\b|\\b" +
				Pattern.quote(name) + "\\s*(?:\\+\\+|--)|\\b" + Pattern.quote(name) +
				"\\s*%").matcher(code).find()) {
			return "i";
		}
		return null;
	}

	private String uniqueAlias(String alias, Set<String> existingNames, Set<String> usedAliases) {
		String proposedName = alias;
		int suffix = 2;
		while (existingNames.contains(proposedName) || usedAliases.contains(proposedName)) {
			proposedName = alias + suffix++;
		}
		usedAliases.add(proposedName);
		return proposedName;
	}

	private String replaceLocalAliases(String line, Map<String, String> aliases) {
		String result = line;
		for (Map.Entry<String, String> entry : aliases.entrySet()) {
			result = result.replaceAll("\\b" + Pattern.quote(entry.getKey()) + "\\b",
				Matcher.quoteReplacement(entry.getValue()));
		}
		return result;
	}

	private CleanupPlan buildCleanupPlan(List<CodeLine> lines, CleanupContext context) {
		CleanupPlan plan = new CleanupPlan(context.cleanupOptions());
		VarargsWrapperCleanup wrapperCleanup = varargsWrapperCleanupAt(lines);
		if (context.cleanupOptions().callArguments() && wrapperCleanup != null) {
			rememberVarargsWrapper(context.program(), wrapperCleanup.wrapper());
			applyVarargsWrapperCleanup(wrapperCleanup, plan);
			plan.recordCleanup("Varargs wrapper rendered with va_start/va_end");
		}
		for (int i = 0; i < lines.size(); i++) {
			String text = lines.get(i).text();
			if (plan.skipLines.contains(i) || plan.replacements.containsKey(i)) {
				continue;
			}
			if (context.cleanupOptions().stackCanary() && collectSecurityCookieLine(text, plan)) {
				plan.skipLines.add(i);
				continue;
			}

			StackCanaryCheckCleanup stackCanaryCheck = context.cleanupOptions().stackCanary()
					? stackCanaryCheckAt(lines, i, plan) : null;
			if (stackCanaryCheck != null) {
				for (int j = i; j <= stackCanaryCheck.endIndex(); j++) {
					plan.skipLines.add(j);
				}
				plan.recordCleanup("Removed stack canary setup/check");
				i = stackCanaryCheck.endIndex();
				continue;
			}

			FreadLoopCleanup freadLoop = context.cleanupOptions().loops()
					? freadLoopCleanupAt(lines, i, plan) : null;
			if (freadLoop != null) {
				plan.replacements.put(i, List.of(freadLoop.headerLine()));
				for (int j = i + 1; j <= freadLoop.endIndex(); j++) {
					plan.skipLines.add(j);
				}
				plan.removableDeclarations.add(freadLoop.variable());
				plan.recordCleanup("Converted fread break loop to while condition");
				i = freadLoop.endIndex();
				continue;
			}

			ForLoopCleanup forLoop = context.cleanupOptions().loops() ? forLoopCleanupAt(lines, i)
					: null;
			if (forLoop != null) {
				plan.replacements.put(i, forLoop.lines());
				plan.intIndexLocals.add(forLoop.variable());
				for (int j = i; j <= forLoop.endIndex(); j++) {
					plan.skipLines.add(j);
				}
				plan.recordCleanup("Converted bounded while(true) loop to for");
				i = forLoop.endIndex();
				continue;
			}

			ZeroLoop zeroLoop = context.cleanupOptions().loops() ? zeroLoopAt(lines, i) : null;
			if (zeroLoop != null) {
				plan.replacements.put(i, List.of(zeroLoop.indent() + "memset(" +
					zeroLoop.buffer() + ", 0, sizeof(" + zeroLoop.buffer() + "));"));
				for (int j = i; j <= i + 4; j++) {
					plan.skipLines.add(j);
				}
				plan.charBuffers.add(zeroLoop.buffer());
				plan.removableDeclarations.add(zeroLoop.pointer());
				plan.removableDeclarations.add(zeroLoop.counter());
				plan.recordCleanup("Rendered zero-fill loop as memset");
				i += 4;
				continue;
			}

			ByteMutationCleanup byteMutation = context.cleanupOptions().compoundAssignments()
					? byteMutationCleanupAt(lines, i) : null;
			if (byteMutation != null) {
				plan.replacements.put(i, byteMutation.lines());
				plan.skipLines.add(i);
				plan.recordCleanup("Split byte xor/add assignment");
				continue;
			}

			IfCallCleanup ifCleanup = ifCallCleanupAt(lines, i, plan);
			if (ifCleanup != null) {
				plan.replacements.put(i, ifCleanup.lines());
				for (int j = i; j <= i + 6; j++) {
					plan.skipLines.add(j);
				}
				plan.removableDeclarations.add(ifCleanup.variable());
				plan.recordCleanup("Collapsed temporary if/call block");
				i += 6;
				continue;
			}

			SimpleBlockCleanup simpleBlock = simpleBlockCleanupAt(lines, i, plan);
			if (simpleBlock != null) {
				plan.replacements.put(i, simpleBlock.lines());
				for (int j = i; j <= simpleBlock.endIndex(); j++) {
					plan.skipLines.add(j);
				}
				plan.recordCleanup("Removed braces from simple one-line branch");
				i = simpleBlock.endIndex();
				continue;
			}

			if (context.cleanupOptions().callArguments()) {
				String callLine = cleanCallLine(text, plan, context);
				if (!callLine.equals(text)) {
					plan.replacements.put(i, List.of(callLine));
					plan.skipLines.add(i);
				}
			}
		}
		plan.removableDeclarations.addAll(plan.securityCookieLocals);
		plan.removableDeclarations.addAll(plan.securityCookieScratch);
		plan.removableDeclarations.addAll(plan.removedArgumentVars);
		return plan;
	}

	private boolean collectSecurityCookieLine(String line, CleanupPlan plan) {
		Matcher matcher = Pattern.compile(
			"^\\s*(\\w+)\\s*=\\s*DAT_[0-9a-fA-F]+\\s*\\^\\s*\\(uint64_t\\)(\\w+)\\s*;\\s*$")
				.matcher(line);
		if (matcher.matches()) {
			plan.securityCookieLocals.add(matcher.group(1));
			plan.securityCookieScratch.add(matcher.group(2));
			plan.removableDeclarations.add(matcher.group(1));
			plan.removableDeclarations.add(matcher.group(2));
			plan.recordCleanup("Removed stack canary setup/check");
			return true;
		}
		matcher = Pattern.compile("^\\s*(\\w+)\\s*=\\s*" + fsCanaryReadPattern("(\\w+)") +
			"\\s*;\\s*$").matcher(line);
		if (matcher.matches()) {
			plan.securityCookieLocals.add(matcher.group(1));
			plan.securityCookieScratch.add(matcher.group(2));
			plan.removableDeclarations.add(matcher.group(1));
			plan.removableDeclarations.add(matcher.group(2));
			plan.recordCleanup("Removed stack canary setup/check");
			return true;
		}
		return false;
	}

	private String fsCanaryReadPattern(String scratchPattern) {
		return "\\*\\s*\\(\\s*(?:long|u?int64_t)\\s*\\*\\s*\\)\\s*\\(\\s*" +
			scratchPattern + "\\s*\\+\\s*(?:'\\('|0x28u?|40u?)\\s*\\)";
	}

	private StackCanaryCheckCleanup stackCanaryCheckAt(List<CodeLine> lines, int index,
			CleanupPlan plan) {
		if (index + 1 >= lines.size()) {
			return null;
		}
		Matcher condition = Pattern.compile("^\\s*if\\s*\\(\\s*(\\w+)\\s*!=\\s*" +
			fsCanaryReadPattern("(\\w+)") + "\\s*\\)\\s*(\\{)?\\s*$")
				.matcher(lines.get(index).text());
		if (!condition.matches()) {
			return null;
		}
		String canaryLocal = condition.group(1);
		if (!plan.securityCookieLocals.contains(canaryLocal)) {
			return null;
		}
		if (!lines.get(index + 1).text().trim().equals("__stack_chk_fail();")) {
			return null;
		}
		int endIndex = index + 1;
		if (condition.group(3) != null) {
			if (index + 2 >= lines.size() || !lines.get(index + 2).text().trim().equals("}")) {
				return null;
			}
			endIndex = index + 2;
		}
		plan.securityCookieScratch.add(condition.group(2));
		plan.removableDeclarations.add(condition.group(2));
		return new StackCanaryCheckCleanup(endIndex);
	}

	private VarargsWrapperCleanup varargsWrapperCleanupAt(List<CodeLine> lines) {
		int signatureIndex = -1;
		Matcher signature = null;
		for (int i = 0; i < lines.size(); i++) {
			Matcher matcher = Pattern.compile(
				"^(\\s*.*?\\b)(FUN_[A-Za-z0-9_]+)\\s*\\((.*)\\)\\s*$")
					.matcher(lines.get(i).text());
			if (!matcher.matches()) {
				continue;
			}
			int next = nextNonBlankLine(lines, i + 1);
			if (next >= 0 && "{".equals(lines.get(next).text().trim())) {
				signatureIndex = i;
				signature = matcher;
				break;
			}
		}
		if (signature == null) {
			return null;
		}

		String functionName = signature.group(2);
		List<String> parameters = splitArguments(signature.group(3));
		if (parameters.size() < 2) {
			return null;
		}
		String firstParameter = parameters.get(0).trim();
		String firstParameterName = parameterName(firstParameter);
		if (firstParameterName == null || !firstParameter.contains("char")) {
			return null;
		}
		Set<String> parameterNames = new HashSet<>();
		for (String parameter : parameters) {
			String name = parameterName(parameter);
			if (name != null) {
				parameterNames.add(name);
			}
		}

		Map<String, String> varargLocals = new LinkedHashMap<>();
		List<Integer> assignmentIndexes = new ArrayList<>();
		for (int i = 0; i < lines.size(); i++) {
			Matcher assignment = Pattern.compile(
				"^\\s*(local_res[0-9A-Za-z_]+)\\s*=\\s*(param_\\d+)\\s*;\\s*$")
					.matcher(lines.get(i).text());
			if (!assignment.matches() || !parameterNames.contains(assignment.group(2))) {
				continue;
			}
			varargLocals.put(assignment.group(1), assignment.group(2));
			assignmentIndexes.add(i);
		}
		if (varargLocals.isEmpty()) {
			return null;
		}
		String vaListLocal = varargLocals.keySet().iterator().next();

		int callIndex = -1;
		String callLine = null;
		for (int i = 0; i < lines.size(); i++) {
			String text = lines.get(i).text();
			if (Pattern.compile("\\(va_list\\)\\s*&\\s*" + Pattern.quote(vaListLocal) + "\\b")
					.matcher(text).find()) {
				callIndex = i;
				callLine = text;
				break;
			}
		}
		if (callIndex < 0) {
			return null;
		}

		VarargsWrapperKind kind = varargsWrapperKind(lines, callLine);
		if (kind == null) {
			return null;
		}

		List<Integer> declarationIndexes = new ArrayList<>();
		for (int i = 0; i < lines.size(); i++) {
			String declared = localResDeclarationName(lines.get(i).text());
			if (declared != null && varargLocals.containsKey(declared)) {
				declarationIndexes.add(i);
			}
		}
		if (declarationIndexes.isEmpty() || assignmentIndexes.isEmpty()) {
			return null;
		}

		String argsName = freshVaListName(lines);
		VarargsWrapper wrapper =
			new VarargsWrapper(functionName, kind, firstParameterName, argsName);
		Map<Integer, List<String>> replacements = new HashMap<>();
		Set<Integer> skipLines = new HashSet<>();

		replacements.put(signatureIndex,
			List.of(signature.group(1) + functionName + "(const char *" + firstParameterName +
				", ...)"));
		for (int i = 0; i < declarationIndexes.size(); i++) {
			int declarationIndex = declarationIndexes.get(i);
			if (i == 0) {
				replacements.put(declarationIndex,
					List.of(lineIndent(lines.get(declarationIndex).text()) + "va_list " +
						argsName + ";"));
			}
			else {
				skipLines.add(declarationIndex);
			}
		}
		for (int i = 0; i < assignmentIndexes.size(); i++) {
			int assignmentIndex = assignmentIndexes.get(i);
			if (i == 0) {
				replacements.put(assignmentIndex,
					List.of(lineIndent(lines.get(assignmentIndex).text()) + "va_start(" +
						argsName + ", " + firstParameterName + ");"));
			}
			else {
				skipLines.add(assignmentIndex);
			}
		}

		String callReplacement = Pattern.compile("\\(va_list\\)\\s*&\\s*" +
			Pattern.quote(vaListLocal) + "\\b").matcher(callLine).replaceAll(argsName);
		replacements.put(callIndex, List.of(normalizeCallSpacing(callReplacement)));

		int returnIndex = wrapperReturnIndex(lines, callIndex);
		if (returnIndex >= 0) {
			String returnLine = lines.get(returnIndex).text();
			replacements.put(returnIndex,
				List.of(lineIndent(returnLine) + "va_end(" + argsName + ");", returnLine));
		}

		return new VarargsWrapperCleanup(wrapper, replacements, skipLines);
	}

	private void applyVarargsWrapperCleanup(VarargsWrapperCleanup wrapperCleanup,
			CleanupPlan plan) {
		plan.detectedWrappers.put(wrapperCleanup.wrapper().name(), wrapperCleanup.wrapper());
		plan.replacements.putAll(wrapperCleanup.replacements());
		plan.skipLines.addAll(wrapperCleanup.skipLines());
	}

	private int nextNonBlankLine(List<CodeLine> lines, int start) {
		for (int i = start; i < lines.size(); i++) {
			if (!lines.get(i).text().isBlank()) {
				return i;
			}
		}
		return -1;
	}

	private String parameterName(String parameter) {
		Matcher matcher = Pattern.compile(
			"\\b([A-Za-z_][A-Za-z0-9_]*)\\s*(?:\\[[^\\]]*\\])?\\s*$")
				.matcher(parameter.trim());
		return matcher.find() ? matcher.group(1) : null;
	}

	private String localResDeclarationName(String line) {
		Matcher matcher = Pattern.compile(
			"^\\s*.+\\s+(local_res[0-9A-Za-z_]+)(?:\\s*\\[[^\\]]+\\])?\\s*;\\s*$")
				.matcher(line);
		return matcher.matches() ? matcher.group(1) : null;
	}

	private VarargsWrapperKind varargsWrapperKind(List<CodeLine> lines, String callLine) {
		for (CodeLine line : lines) {
			Matcher matcher = Pattern.compile("__acrt_iob_func\\s*\\(\\s*(0x[0-9a-fA-F]+|\\d+)\\s*\\)")
					.matcher(line.text());
			if (!matcher.find()) {
				continue;
			}
			Long streamIndex = integerValue(matcher.group(1));
			if (streamIndex == null) {
				continue;
			}
			return streamIndex == 0 ? VarargsWrapperKind.SCAN : VarargsWrapperKind.PRINT;
		}
		if (callLine.contains("vfscanf") || callLine.contains("vscanf")) {
			return VarargsWrapperKind.SCAN;
		}
		if (callLine.contains("vfprintf") || callLine.contains("vprintf")) {
			return VarargsWrapperKind.PRINT;
		}
		return null;
	}

	private String freshVaListName(List<CodeLine> lines) {
		for (String nameOption : List.of("args", "ap", "va_args")) {
			Pattern use = Pattern.compile("\\b" + Pattern.quote(nameOption) + "\\b");
			boolean used = false;
			for (CodeLine line : lines) {
				if (use.matcher(line.text()).find()) {
					used = true;
					break;
				}
			}
			if (!used) {
				return nameOption;
			}
		}
		return "va_args";
	}

	private int wrapperReturnIndex(List<CodeLine> lines, int callIndex) {
		Matcher assignment = Pattern.compile("^\\s*(\\w+)\\s*=\\s*.*;\\s*$")
				.matcher(lines.get(callIndex).text());
		String returnVariable = assignment.matches() ? assignment.group(1) : null;
		int limit = Math.min(lines.size(), callIndex + 4);
		for (int i = callIndex + 1; i < limit; i++) {
			String text = lines.get(i).text().trim();
			if (returnVariable != null && text.equals("return " + returnVariable + ";")) {
				return i;
			}
			if (text.startsWith("return ")) {
				return i;
			}
		}
		return -1;
	}

	private String lineIndent(String line) {
		int index = 0;
		while (index < line.length() && Character.isWhitespace(line.charAt(index))) {
			index++;
		}
		return line.substring(0, index);
	}

	private ZeroLoop zeroLoopAt(List<CodeLine> lines, int index) {
		if (index + 4 >= lines.size()) {
			return null;
		}
		Matcher assign = Pattern.compile("^(\\s*)(\\w+)\\s*=\\s*(\\w+)\\s*;\\s*$")
				.matcher(lines.get(index).text());
		if (!assign.matches()) {
			return null;
		}
		String indent = assign.group(1);
		String pointer = assign.group(2);
		String buffer = assign.group(3);
		Matcher loop = Pattern.compile("^\\s*for\\s*\\(\\s*(\\w+)\\s*=\\s*(?:0x[0-9a-fA-F]+|\\d+)\\s*;\\s*\\1\\s*!=\\s*0\\s*;\\s*\\1\\s*=\\s*\\1\\s*\\+\\s*-1\\s*\\)\\s*\\{\\s*$")
				.matcher(lines.get(index + 1).text());
		if (!loop.matches()) {
			return null;
		}
		String counter = loop.group(1);
		String count = "";
		if (!lines.get(index + 2).text().trim().equals("*" + pointer + " = 0;")) {
			return null;
		}
		if (!lines.get(index + 3).text().trim().equals(pointer + " = " + pointer + " + 1;")) {
			return null;
		}
		if (!lines.get(index + 4).text().trim().equals("}")) {
			return null;
		}
		return new ZeroLoop(indent, pointer, counter, buffer, count);
	}

	private FreadLoopCleanup freadLoopCleanupAt(List<CodeLine> lines, int index,
			CleanupPlan plan) {
		if (index + 2 >= lines.size()) {
			return null;
		}
		Matcher loop = Pattern.compile("^(\\s*)while\\s*\\(\\s*true\\s*\\)\\s*\\{\\s*$")
				.matcher(lines.get(index).text());
		if (!loop.matches()) {
			return null;
		}
		String indent = loop.group(1);
		Matcher assignment = Pattern.compile("^\\s*(\\w+)\\s*=\\s*(fread\\s*\\(.*\\))\\s*;\\s*$")
				.matcher(lines.get(index + 1).text());
		if (!assignment.matches()) {
			return null;
		}
		String variable = assignment.group(1);
		String freadCall = normalizeByteIoCalls(normalizeCallExpression(assignment.group(2)), plan);
		Matcher singleBreak = Pattern.compile("^\\s*if\\s*\\(\\s*" + Pattern.quote(variable) +
			"\\s*!=\\s*(?:1|0x1|1u)\\s*\\)\\s*break\\s*;\\s*$")
				.matcher(lines.get(index + 2).text());
		if (singleBreak.matches()) {
			return new FreadLoopCleanup(index + 2,
				indent + "while (" + freadCall + " == 1) {", variable);
		}
		if (index + 4 >= lines.size()) {
			return null;
		}
		Matcher blockBreak = Pattern.compile("^\\s*if\\s*\\(\\s*" + Pattern.quote(variable) +
			"\\s*!=\\s*(?:1|0x1|1u)\\s*\\)\\s*\\{\\s*$")
				.matcher(lines.get(index + 2).text());
		if (blockBreak.matches() && lines.get(index + 3).text().trim().equals("break;") &&
			lines.get(index + 4).text().trim().equals("}")) {
			return new FreadLoopCleanup(index + 4,
				indent + "while (" + freadCall + " == 1) {", variable);
		}
		return null;
	}

	private String normalizeCallExpression(String expression) {
		Matcher matcher = Pattern.compile("^(\\w+)\\s*\\((.*)\\)$").matcher(expression.trim());
		if (!matcher.matches()) {
			return cleanCommonExpressions(expression).replaceAll("\\s+", " ").trim();
		}
		List<String> args = splitArguments(matcher.group(2));
		for (int i = 0; i < args.size(); i++) {
			args.set(i, cleanCommonExpressions(args.get(i).trim()));
		}
		return matcher.group(1) + "(" + String.join(", ", args) + ")";
	}

	private String normalizeByteIoCalls(String text, CleanupPlan plan) {
		Matcher matcher = Pattern.compile("\\b(fread|fwrite)\\s*\\(").matcher(text);
		StringBuilder result = new StringBuilder();
		int index = 0;
		boolean changed = false;
		while (matcher.find(index)) {
			int openParen = text.indexOf('(', matcher.start());
			int closeParen = matchingParen(text, openParen);
			if (openParen < 0 || closeParen < 0) {
				break;
			}
			String functionName = matcher.group(1);
			List<String> args = splitArguments(text.substring(openParen + 1, closeParen));
			if (args.size() < 3) {
				index = closeParen + 1;
				continue;
			}
			for (int i = 0; i < args.size(); i++) {
				args.set(i, cleanCommonExpressions(args.get(i).trim()));
			}
			boolean callChanged = false;
			for (int i : List.of(1, 2)) {
				String unsigned = unsignedOne(args.get(i));
				if (!unsigned.equals(args.get(i))) {
					args.set(i, unsigned);
					callChanged = true;
				}
			}
			if (!callChanged) {
				index = closeParen + 1;
				continue;
			}
			result.append(text, index, matcher.start());
			result.append(functionName).append('(').append(String.join(", ", args)).append(')');
			index = closeParen + 1;
			changed = true;
		}
		if (!changed) {
			return text;
		}
		result.append(text.substring(index));
		plan.recordCleanup("Rendered fread/fwrite byte counts as unsigned");
		return result.toString();
	}

	private int matchingParen(String text, int openParen) {
		if (openParen < 0 || openParen >= text.length() || text.charAt(openParen) != '(') {
			return -1;
		}
		boolean inString = false;
		boolean escaped = false;
		int depth = 0;
		for (int i = openParen; i < text.length(); i++) {
			char c = text.charAt(i);
			if (inString) {
				if (escaped) {
					escaped = false;
				}
				else if (c == '\\') {
					escaped = true;
				}
				else if (c == '"') {
					inString = false;
				}
				continue;
			}
			if (c == '"') {
				inString = true;
				continue;
			}
			if (c == '(') {
				depth++;
			}
			else if (c == ')') {
				depth--;
				if (depth == 0) {
					return i;
				}
			}
		}
		return -1;
	}

	private String unsignedOne(String arg) {
		return arg.matches("(?i)(1|0x1)") ? "1u" : arg;
	}

	private ByteMutationCleanup byteMutationCleanupAt(List<CodeLine> lines, int index) {
		Matcher matcher = Pattern.compile("^(\\s*)(\\w+)\\s*=\\s*\\(\\s*\\2\\s*\\^\\s*(.+)\\)\\s*\\+\\s*(0x[0-9a-fA-F]+|\\d+)\\s*;\\s*$")
				.matcher(lines.get(index).text());
		if (!matcher.matches()) {
			return null;
		}
		String indent = matcher.group(1);
		String variable = matcher.group(2);
		String xorOperand = cleanCommonExpressions(matcher.group(3).trim());
		Long addend = integerValue(matcher.group(4));
		if (addend == null) {
			return null;
		}
		return new ByteMutationCleanup(List.of(
			indent + variable + " ^= " + xorOperand + ";",
			indent + variable + " += " + Long.toUnsignedString(addend) + ";"));
	}

	private ForLoopCleanup forLoopCleanupAt(List<CodeLine> lines, int index) {
		if (index + 8 >= lines.size()) {
			return null;
		}
		Matcher init = Pattern.compile("^(\\s*)(\\w+)\\s*=\\s*(?:0|0x0)\\s*;\\s*$")
				.matcher(lines.get(index).text());
		if (!init.matches()) {
			return null;
		}
		String indent = init.group(1);
		String variable = init.group(2);
		if (!Pattern.compile("^\\s*while\\s*\\(\\s*true\\s*\\)\\s*\\{\\s*$")
				.matcher(lines.get(index + 1).text()).matches()) {
			return null;
		}

		Matcher bound = Pattern.compile("^\\s*if\\s*\\(\\s*(0x[0-9a-fA-F]+|\\d+)\\s*<\\s*" +
			Pattern.quote(variable) + "\\s*\\)\\s*\\{\\s*$").matcher(lines.get(index + 2).text());
		if (!bound.matches()) {
			return null;
		}
		Long inclusiveBound = integerValue(bound.group(1));
		if (inclusiveBound == null || inclusiveBound == Long.MAX_VALUE) {
			return null;
		}
		String successReturn = returnValue(lines.get(index + 3).text());
		if (successReturn == null || !lines.get(index + 4).text().trim().equals("}")) {
			return null;
		}

		ConditionBlock conditionBlock = breakConditionAt(lines, index + 5);
		if (conditionBlock == null) {
			return null;
		}
		int incrementIndex = conditionBlock.endIndex() + 1;
		if (incrementIndex + 2 >= lines.size()) {
			return null;
		}
		if (!Pattern.compile("^\\s*" + Pattern.quote(variable) + "\\s*=\\s*" +
			Pattern.quote(variable) + "\\s*\\+\\s*1\\s*;\\s*$")
				.matcher(lines.get(incrementIndex).text()).matches() &&
			!Pattern.compile("^\\s*" + Pattern.quote(variable) + "\\s*\\+\\+\\s*;\\s*$")
					.matcher(lines.get(incrementIndex).text()).matches()) {
			return null;
		}
		if (!lines.get(incrementIndex + 1).text().trim().equals("}")) {
			return null;
		}
		String failureReturn = returnValue(lines.get(incrementIndex + 2).text());
		if (failureReturn == null) {
			return null;
		}

		String condition = cleanLoopCondition(conditionBlock.condition(), variable);
		List<String> replacement = new ArrayList<>();
		replacement.add(indent + "for (" + variable + " = 0; " + variable + " < " +
			(inclusiveBound + 1) + "; " + variable + "++) {");
		addLoopConditionLines(replacement, indent, condition, failureReturn);
		replacement.add(indent + "}");
		replacement.add(indent + "return " + successReturn + ";");
		return new ForLoopCleanup(incrementIndex + 2, List.copyOf(replacement), variable);
	}

	private ConditionBlock breakConditionAt(List<CodeLine> lines, int index) {
		if (index >= lines.size()) {
			return null;
		}
		StringBuilder builder = new StringBuilder();
		for (int i = index; i < lines.size(); i++) {
			String trimmed = lines.get(i).text().trim();
			if (i == index) {
				if (!trimmed.startsWith("if")) {
					return null;
				}
				builder.append(trimmed);
			}
			else {
				builder.append(' ').append(trimmed);
			}
			if (trimmed.endsWith("break;")) {
				Matcher matcher = Pattern.compile("^if\\s*\\((.*)\\)\\s*break;\\s*$")
						.matcher(builder.toString());
				if (!matcher.matches()) {
					return null;
				}
				return new ConditionBlock(i, matcher.group(1).trim());
			}
			if (i - index > 4) {
				return null;
			}
		}
		return null;
	}

	private void addLoopConditionLines(List<String> lines, String indent, String condition,
			String failureReturn) {
		int notEquals = condition.indexOf(" != ");
		if (condition.length() > 88 && notEquals > 0) {
			lines.add(indent + "  if (" + condition.substring(0, notEquals + 3));
			lines.add(indent + "      " + condition.substring(notEquals + 4) + ")");
		}
		else {
			lines.add(indent + "  if (" + condition + ")");
		}
		lines.add(indent + "    return " + failureReturn + ";");
	}

	private String cleanLoopCondition(String condition, String variable) {
		String result = condition;
		result = result.replaceAll("\\(int\\)\\s*" + Pattern.quote(variable), variable);
		return cleanCommonExpressions(result).replaceAll("\\s+", " ").trim();
	}

	private Long integerValue(String text) {
		try {
			String trimmed = text.trim();
			if (trimmed.startsWith("0x") || trimmed.startsWith("0X")) {
				return Long.parseUnsignedLong(trimmed.substring(2), 16);
			}
			return Long.parseUnsignedLong(trimmed, 10);
		}
		catch (NumberFormatException e) {
			return null;
		}
	}

	private String returnValue(String line) {
		Matcher matcher = Pattern.compile("^\\s*return\\s+([^;]+)\\s*;\\s*$").matcher(line);
		return matcher.matches() ? matcher.group(1).trim() : null;
	}

	private IfCallCleanup ifCallCleanupAt(List<CodeLine> lines, int index, CleanupPlan plan) {
		if (index + 6 >= lines.size()) {
			return null;
		}
		Matcher assign = Pattern.compile("^(\\s*)(\\w+)\\s*=\\s*(\\w+\\s*\\(.*\\))\\s*;\\s*$")
				.matcher(lines.get(index).text());
		if (!assign.matches()) {
			return null;
		}
		String indent = assign.group(1);
		String variable = assign.group(2);
		String expression = cleanPointerCasts(assign.group(3), plan);
		Matcher condition = Pattern.compile("^\\s*if\\s*\\(\\s*\\(int\\)" + Pattern.quote(variable) +
			"\\s*==\\s*0\\s*\\)\\s*\\{\\s*$").matcher(lines.get(index + 1).text());
		if (!condition.matches() || !lines.get(index + 3).text().trim().equals("}") ||
			!lines.get(index + 4).text().trim().equals("else {") ||
			!lines.get(index + 6).text().trim().equals("}")) {
			return null;
		}
		String falseStatement = lines.get(index + 2).text();
		String trueStatement = lines.get(index + 5).text();
		List<String> replacement = List.of(
			indent + "if ((uint32_t)" + expression + ") {",
			trueStatement,
			indent + "}",
			indent + "else {",
			falseStatement,
			indent + "}");
		return new IfCallCleanup(variable, replacement);
	}

	private SimpleBlockCleanup simpleBlockCleanupAt(List<CodeLine> lines, int index,
			CleanupPlan plan) {
		if (index + 2 >= lines.size()) {
			return null;
		}
		Matcher header = Pattern.compile("^(\\s*)(if\\s*\\(.+\\))\\s*\\{\\s*$")
				.matcher(lines.get(index).text());
		if (!header.matches()) {
			return null;
		}
		String indent = header.group(1);
		String statement = lines.get(index + 1).text();
		if (!statement.startsWith(indent + "  ") || !isSimpleStatement(statement.trim())) {
			return null;
		}
		if (!lines.get(index + 2).text().trim().equals("}")) {
			return null;
		}
		int next = nextNonBlankLine(lines, index + 3);
		if (next >= 0 && lines.get(next).text().trim().startsWith("else")) {
			return null;
		}
		String headerLine = indent + cleanCommonExpressions(header.group(2));
		if (plan.cleanupOptions().conditions()) {
			headerLine = cleanNullPointerCheck(headerLine, plan);
			headerLine = cleanBooleanCondition(headerLine, plan);
		}
		String statementLine = cleanSimpleStatementLine(statement, plan);
		return new SimpleBlockCleanup(index + 2,
			List.of(headerLine, statementLine));
	}

	private String cleanSimpleStatementLine(String line, CleanupPlan plan) {
		if (plan.cleanupOptions().compoundAssignments()) {
			String incrementCleaned = cleanIncrementAssignment(line, plan);
			if (!incrementCleaned.equals(line)) {
				return incrementCleaned;
			}
			String compoundCleaned = cleanCompoundAssignment(line, plan);
			if (!compoundCleaned.equals(line)) {
				return compoundCleaned;
			}
		}
		if (plan.cleanupOptions().callArguments()) {
			String byteIoCleaned = normalizeByteIoCalls(line, plan);
			if (!byteIoCleaned.equals(line)) {
				return normalizeCallSpacing(byteIoCleaned);
			}
		}
		String castCleaned = cleanPointerCasts(line, plan);
		if (!castCleaned.equals(line)) {
			plan.recordCleanup("Simplified pointer casts/common expressions");
			return normalizeCallSpacing(castCleaned);
		}
		String expressionCleaned = cleanCommonExpressions(line);
		if (!expressionCleaned.equals(line)) {
			plan.recordCleanup("Simplified pointer casts/common expressions");
		}
		return normalizeCallSpacing(expressionCleaned);
	}

	private boolean isSimpleStatement(String statement) {
		if (!statement.endsWith(";") || statement.contains("{") || statement.contains("}")) {
			return false;
		}
		return !(statement.startsWith("if ") || statement.startsWith("if(") ||
			statement.startsWith("for ") || statement.startsWith("for(") ||
			statement.startsWith("while ") || statement.startsWith("while(") ||
			statement.startsWith("switch ") || statement.startsWith("switch("));
	}

	private String cleanCallLine(String line, CleanupPlan plan, CleanupContext context) {
		Matcher matcher = Pattern.compile("^(\\s*)(\\w+)\\s*\\((.*)\\)\\s*;\\s*$").matcher(line);
		if (!matcher.matches()) {
			return line;
		}
		String functionName = matcher.group(2);
		List<String> args = splitArguments(matcher.group(3));
		if (args.isEmpty()) {
			return line;
		}
		List<String> cleanedArgs = new ArrayList<>(args);
		String first = cleanedArgs.get(0).trim();
		if (isStringLiteral(first)) {
			VarargsWrapper wrapper = wrapperForCall(functionName, plan, context);
			int keepCount = -1;
			if (wrapper != null) {
				keepCount = 1 + switch (wrapper.kind()) {
					case PRINT -> printfArgumentCount(first);
					case SCAN -> scanfDestinationCount(first);
				};
			}
			else {
				int formatArgs = formatArgumentCount(first);
				if (formatArgs > 0) {
					keepCount = 1 + formatArgs;
				}
			}
			if (keepCount >= 0 && cleanedArgs.size() > keepCount) {
				for (int i = keepCount; i < cleanedArgs.size(); i++) {
					rememberRemovedArgument(cleanedArgs.get(i), plan);
				}
				cleanedArgs = new ArrayList<>(cleanedArgs.subList(0, keepCount));
				plan.recordCleanup("Trimmed unused wrapper/call arguments");
				for (int i = 1; i < cleanedArgs.size(); i++) {
					String arg = cleanedArgs.get(i).trim();
					if (isSimpleIdentifier(arg)) {
						plan.charBuffers.add(arg);
					}
				}
			}
		}
		while (!cleanedArgs.isEmpty() && isInputRegister(cleanedArgs.get(cleanedArgs.size() - 1))) {
			rememberRemovedArgument(cleanedArgs.remove(cleanedArgs.size() - 1), plan);
			plan.recordCleanup("Trimmed unused wrapper/call arguments");
		}
		for (int i = 0; i < cleanedArgs.size(); i++) {
			cleanedArgs.set(i, cleanPointerCasts(cleanedArgs.get(i).trim(), plan));
		}
		String normalized = matcher.group(1) + matcher.group(2) + "(" +
			String.join(", ", cleanedArgs) + ");";
		return normalized.equals(line) ? line : normalized;
	}

	private VarargsWrapper wrapperForCall(String functionName, CleanupPlan plan,
			CleanupContext context) {
		VarargsWrapper local = plan.detectedWrappers.get(functionName);
		if (local != null) {
			return local;
		}
		if (context.program() == null || !functionName.startsWith("FUN_")) {
			return null;
		}
		Map<String, VarargsWrapper> programCache = varargsWrapperCache.get(context.program());
		if (programCache != null) {
			VarargsWrapper cached = programCache.get(functionName);
			if (cached != null) {
				return cached;
			}
		}
		Set<String> misses = varargsWrapperMissCache.get(context.program());
		if (misses != null && misses.contains(functionName)) {
			return null;
		}

		Function callee = functionByName(context.program(), functionName);
		if (callee == null || callee.isExternal() || callee.equals(context.function())) {
			rememberVarargsWrapperMiss(context.program(), functionName);
			return null;
		}
		Set<Function> inProgress =
			varargsWrapperInProgress.computeIfAbsent(context.program(), p -> new HashSet<>());
		if (inProgress.contains(callee)) {
			return null;
		}
		inProgress.add(callee);
		try {
			decompile(context.program(), callee,
				Math.max(WRAPPER_DETECTION_TIMEOUT_SECONDS, context.timeoutSeconds()), false,
				TaskMonitor.DUMMY, ParadiseCleanupOptions.cleanCDefaults(), true, false, false);
		}
		catch (RuntimeException e) {
			rememberVarargsWrapperMiss(context.program(), functionName);
			return null;
		}
		finally {
			inProgress.remove(callee);
		}

		programCache = varargsWrapperCache.get(context.program());
		VarargsWrapper detected = programCache == null ? null : programCache.get(functionName);
		if (detected == null) {
			rememberVarargsWrapperMiss(context.program(), functionName);
		}
		return detected;
	}

	private Function functionByName(Program program, String functionName) {
		for (Function function : program.getFunctionManager().getFunctions(true)) {
			if (function.getName().equals(functionName)) {
				return function;
			}
		}
		return null;
	}

	private void rememberVarargsWrapper(Program program, VarargsWrapper wrapper) {
		if (program == null || wrapper == null) {
			return;
		}
		varargsWrapperCache.computeIfAbsent(program, p -> new HashMap<>())
				.put(wrapper.name(), wrapper);
		Set<String> misses = varargsWrapperMissCache.get(program);
		if (misses != null) {
			misses.remove(wrapper.name());
		}
	}

	private void rememberVarargsWrapperMiss(Program program, String functionName) {
		if (program == null || functionName == null) {
			return;
		}
		varargsWrapperMissCache.computeIfAbsent(program, p -> new HashSet<>()).add(functionName);
	}

	private String normalizeCleanLine(String line, CleanupPlan plan) {
		String trimmed = line.trim();
		if (trimmed.startsWith("int main(")) {
			return line.replace("int main(int argc,char **argv,char **envp)",
				"int main(int argc, const char **argv, const char **envp)");
		}
		Matcher arrayDecl = Pattern.compile("^(\\s*)uint8_t\\s+(\\w+)\\s+\\[(\\d+)\\]\\s*;\\s*$")
				.matcher(line);
		if (arrayDecl.matches() && plan.charBuffers.contains(arrayDecl.group(2))) {
			return arrayDecl.group(1) + "char " + arrayDecl.group(2) + "[" +
				arrayDecl.group(3) + "];";
		}
		Matcher indexDecl = Pattern.compile("^(\\s*)uint32_t\\s+(\\w+)\\s*;\\s*$").matcher(line);
		if (indexDecl.matches() && plan.intIndexLocals.contains(indexDecl.group(2))) {
			return indexDecl.group(1) + "int " + indexDecl.group(2) + ";";
		}
		if (plan.cleanupOptions().conditions()) {
			String nullCheckCleaned = cleanNullPointerCheck(line, plan);
			if (!nullCheckCleaned.equals(line)) {
				return normalizeCallSpacing(nullCheckCleaned);
			}
			String conditionCleaned = cleanBooleanCondition(line, plan);
			if (!conditionCleaned.equals(line)) {
				return normalizeCallSpacing(conditionCleaned);
			}
		}
		if (plan.cleanupOptions().compoundAssignments()) {
			String incrementCleaned = cleanIncrementAssignment(line, plan);
			if (!incrementCleaned.equals(line)) {
				return incrementCleaned;
			}
			String compoundCleaned = cleanCompoundAssignment(line, plan);
			if (!compoundCleaned.equals(line)) {
				return compoundCleaned;
			}
		}
		if (plan.cleanupOptions().callArguments()) {
			String byteIoCleaned = normalizeByteIoCalls(line, plan);
			if (!byteIoCleaned.equals(line)) {
				return normalizeCallSpacing(byteIoCleaned);
			}
		}
		String castCleaned = cleanPointerCasts(line, plan);
		if (!castCleaned.equals(line)) {
			plan.recordCleanup("Simplified pointer casts/common expressions");
			return normalizeCallSpacing(castCleaned);
		}
		String expressionCleaned = cleanCommonExpressions(line);
		if (!expressionCleaned.equals(line)) {
			plan.recordCleanup("Simplified pointer casts/common expressions");
		}
		return normalizeCallSpacing(expressionCleaned);
	}

	private String cleanNullPointerCheck(String line, CleanupPlan plan) {
		Matcher matcher = Pattern.compile("^(\\s*)if\\s*\\(\\s*([A-Za-z_]\\w*)\\s*==\\s*(?:\\([^)]*\\*\\)\\s*)?(?:0x0|0|NULL|null)\\s*\\)(.*)$")
				.matcher(line);
		if (!matcher.matches()) {
			return line;
		}
		plan.recordCleanup("Simplified null pointer checks");
		return matcher.group(1) + "if (!" + matcher.group(2) + ")" + matcher.group(3);
	}

	private String cleanBooleanCondition(String line, CleanupPlan plan) {
		Matcher start = Pattern.compile("^(\\s*)if\\s*\\(").matcher(line);
		if (!start.find()) {
			return line;
		}
		int openParen = line.indexOf('(', start.start());
		int closeParen = matchingParen(line, openParen);
		if (openParen < 0 || closeParen < 0) {
			return line;
		}
		String condition = line.substring(openParen + 1, closeParen);
		ConditionText cleaned = cleanConditionExpression(condition);
		if (cleaned == null || cleaned.text().equals(condition.trim())) {
			return line;
		}
		plan.recordCleanup(cleaned.cleanup());
		return line.substring(0, openParen + 1) + cleaned.text() + line.substring(closeParen);
	}

	private ConditionText cleanConditionExpression(String condition) {
		String trimmed = condition.trim();
		String zeroPattern = "(?:\\([^)]*\\)\\s*)?(?:0x0|0|NULL|null)";
		Matcher equalsZero = Pattern.compile("^(?:" + scalarCastPattern() +
			"\\s*)?(.+?)\\s*==\\s*" + zeroPattern + "$").matcher(trimmed);
		if (equalsZero.matches() && isSimpleBooleanExpression(equalsZero.group(1))) {
			return new ConditionText("!" + parenthesizeConditionOperand(equalsZero.group(1).trim()),
				"Simplified boolean conditions");
		}
		Matcher notEqualsZero = Pattern.compile("^(?:" + scalarCastPattern() +
			"\\s*)?(.+?)\\s*!=\\s*" + zeroPattern + "$").matcher(trimmed);
		if (notEqualsZero.matches() && isSimpleBooleanExpression(notEqualsZero.group(1))) {
			return new ConditionText(parenthesizeConditionOperand(notEqualsZero.group(1).trim()),
				"Simplified boolean conditions");
		}
		Matcher castOnly = Pattern.compile("^" + scalarCastPattern() +
			"\\s*(.+)$").matcher(trimmed);
		if (castOnly.matches() && isSimpleBooleanExpression(castOnly.group(1))) {
			return new ConditionText(parenthesizeConditionOperand(castOnly.group(1).trim()),
				"Simplified boolean conditions");
		}
		return null;
	}

	private String scalarCastPattern() {
		return "\\((?:u?int(?:8|16|32|64)?_t|int(?:8|16|32|64)?_t|uint(?:8|16|32|64)?_t|int|uint|bool|char|long|ulong)\\)";
	}

	private boolean isSimpleBooleanExpression(String expression) {
		String trimmed = expression.trim();
		if (trimmed.isEmpty() || trimmed.contains("&&") || trimmed.contains("||") ||
			trimmed.contains("?")) {
			return false;
		}
		return trimmed.matches("[A-Za-z_]\\w*") ||
			trimmed.matches("[A-Za-z_]\\w*\\s*\\([^;{}]*\\)") ||
			trimmed.matches("\\([^;{}]+\\)");
	}

	private String parenthesizeConditionOperand(String expression) {
		String trimmed = expression.trim();
		if (trimmed.matches("[A-Za-z_]\\w*") ||
			trimmed.matches("[A-Za-z_]\\w*\\s*\\([^;{}]*\\)") ||
			(trimmed.startsWith("(") && trimmed.endsWith(")"))) {
			return trimmed;
		}
		return "(" + trimmed + ")";
	}

	private String cleanIncrementAssignment(String line, CleanupPlan plan) {
		Matcher matcher = Pattern.compile("^(\\s*)([A-Za-z_]\\w*)\\s*=\\s*\\2\\s*\\+\\s*(?:1|0x1)\\s*;\\s*$")
				.matcher(line);
		if (!matcher.matches()) {
			return line;
		}
		plan.recordCleanup("Simplified increment assignments");
		return matcher.group(1) + "++" + matcher.group(2) + ";";
	}

	private String cleanCompoundAssignment(String line, CleanupPlan plan) {
		Matcher direct = Pattern.compile("^(\\s*)([A-Za-z_]\\w*(?:\\s*\\[[^\\]]+\\])?)\\s*=\\s*\\2\\s*(<<|>>|[+\\-*/%&|^])\\s*(.+?)\\s*;\\s*$")
				.matcher(line);
		if (direct.matches() && isCompoundAssignmentRhs(direct.group(4))) {
			plan.recordCleanup("Simplified compound assignments");
			return direct.group(1) + direct.group(2).trim() + " " + direct.group(3) + "= " +
				direct.group(4).trim() + ";";
		}
		Matcher reversed = Pattern.compile("^(\\s*)([A-Za-z_]\\w*(?:\\s*\\[[^\\]]+\\])?)\\s*=\\s*(.+?)\\s*([+*&|^])\\s*\\2\\s*;\\s*$")
				.matcher(line);
		if (reversed.matches() && isCompoundAssignmentRhs(reversed.group(3))) {
			plan.recordCleanup("Simplified compound assignments");
			return reversed.group(1) + reversed.group(2).trim() + " " + reversed.group(4) +
				"= " + reversed.group(3).trim() + ";";
		}
		return line;
	}

	private boolean isCompoundAssignmentRhs(String rhs) {
		String trimmed = rhs.trim();
		return !trimmed.isEmpty() && !trimmed.contains(";") && !trimmed.contains("{") &&
			!trimmed.contains("}");
	}

	private String normalizeCallSpacing(String line) {
		Matcher assignment = Pattern.compile("^(\\s*\\w+\\s*=\\s*)(\\w+)\\s*\\((.*)\\)\\s*;\\s*$")
				.matcher(line);
		if (assignment.matches()) {
			List<String> args = splitArguments(assignment.group(3));
			if (args.size() < 2) {
				return line;
			}
			return assignment.group(1) + assignment.group(2) + "(" + String.join(", ", args) +
				");";
		}
		Matcher matcher = Pattern.compile("^(\\s*)(\\w+)\\s*\\((.*)\\)\\s*;\\s*$").matcher(line);
		if (!matcher.matches()) {
			return line;
		}
		List<String> args = splitArguments(matcher.group(3));
		if (args.size() < 2) {
			return line;
		}
		return matcher.group(1) + matcher.group(2) + "(" + String.join(", ", args) + ");";
	}

	private String cleanPointerCasts(String text, CleanupPlan plan) {
		String result = text;
		for (String buffer : plan.charBuffers) {
			result = result.replaceAll("\\(int64_t\\)\\s*" + Pattern.quote(buffer), buffer);
			result = result.replaceAll("\\(uint64_t\\)\\s*" + Pattern.quote(buffer), buffer);
		}
		for (String indexLocal : plan.intIndexLocals) {
			result = result.replaceAll("\\(int\\)\\s*" + Pattern.quote(indexLocal), indexLocal);
		}
		return cleanCommonExpressions(result);
	}

	private String cleanCommonExpressions(String text) {
		String result = text;
		result = result.replaceAll("\\(uint32_t\\)\\s*\\(uint8_t\\)", "(uint8_t)");
		result = result.replaceAll("\\(uint32_t\\)\\s*\\(uint16_t\\)", "(uint16_t)");
		result = result.replaceAll("\\(uint64_t\\)\\s*\\(uint8_t\\)", "(uint8_t)");
		result = result.replaceAll("\\(uint64_t\\)\\s*\\(uint16_t\\)", "(uint16_t)");
		result = result.replaceAll("\\(uint64_t\\)\\s*\\(uint32_t\\)", "(uint32_t)");
		result = result.replaceAll("\\(int32_t\\)\\s*\\(int8_t\\)", "(int8_t)");
		result = result.replaceAll("\\(int32_t\\)\\s*\\(int16_t\\)", "(int16_t)");
		result = result.replaceAll("\\(int64_t\\)\\s*\\(int8_t\\)", "(int8_t)");
		result = result.replaceAll("\\(int64_t\\)\\s*\\(int16_t\\)", "(int16_t)");
		result = result.replaceAll("\\(int64_t\\)\\s*\\(int32_t\\)", "(int32_t)");
		result = Pattern.compile("\\(&\\s*(DAT_[0-9a-fA-F]+)\\s*\\)\\s*\\[\\s*([^\\]]+?)\\s*\\]")
				.matcher(result).replaceAll("$1[$2]");
		result = result.replaceAll("\\b(DAT_[0-9a-fA-F]+\\s*\\[\\s*)\\(int\\)\\s*([A-Za-z_]\\w*)\\s*\\]",
			"$1$2]");
		result = result.replaceAll("\\b(param_\\d+)\\s*\\+\\s*\\(int\\)\\s*([A-Za-z_]\\w*)",
			"$1 + $2");
		return result;
	}

	private boolean hasUseAfterPlan(String variable, int declarationIndex, List<CodeLine> lines,
			CleanupPlan plan) {
		Pattern usePattern = Pattern.compile("\\b" + Pattern.quote(variable) + "\\b");
		for (int i = 0; i < lines.size(); i++) {
			if (i == declarationIndex) {
				continue;
			}
			List<String> replacement = plan.replacements.get(i);
			if (replacement != null) {
				for (String replacementLine : replacement) {
					if (usePattern.matcher(replacementLine).find()) {
						return true;
					}
				}
				continue;
			}
			if (plan.skipLines.contains(i)) {
				continue;
			}
			String line = lines.get(i).text();
			if (declarationName(line) != null) {
				continue;
			}
			if (usePattern.matcher(line).find()) {
				return true;
			}
		}
		return false;
	}

	private String declarationName(String line) {
		Matcher matcher = Pattern.compile("^\\s*(?:[A-Za-z_][A-Za-z0-9_]*\\s+)+(?:\\*\\s*)?([A-Za-z_]\\w*)(?:\\s*\\[[^\\]]+\\])?\\s*;\\s*$")
				.matcher(line);
		if (matcher.matches()) {
			return matcher.group(1);
		}
		return null;
	}

	private void rememberRemovedArgument(String arg, CleanupPlan plan) {
		String trimmed = arg.trim();
		if (isSimpleIdentifier(trimmed) && isInputRegister(trimmed)) {
			plan.removedArgumentVars.add(trimmed);
		}
	}

	private boolean isInputRegister(String arg) {
		return arg.trim().matches("in_[A-Za-z0-9]+");
	}

	private boolean isSimpleIdentifier(String arg) {
		return arg.matches("[A-Za-z_][A-Za-z0-9_]*");
	}

	private boolean isStringLiteral(String text) {
		String trimmed = text.trim();
		return trimmed.length() >= 2 && trimmed.startsWith("\"") && trimmed.endsWith("\"");
	}

	private int formatArgumentCount(String literal) {
		return scanfDestinationCount(literal);
	}

	private int printfArgumentCount(String literal) {
		String text = literal.substring(1, literal.length() - 1);
		int count = 0;
		for (int i = 0; i < text.length(); i++) {
			if (text.charAt(i) != '%') {
				continue;
			}
			if (i + 1 < text.length() && text.charAt(i + 1) == '%') {
				i++;
				continue;
			}
			int j = i + 1;
			while (j < text.length() && "-+ #0".indexOf(text.charAt(j)) >= 0) {
				j++;
			}
			if (j < text.length() && text.charAt(j) == '*') {
				count++;
				j++;
			}
			else {
				while (j < text.length() && Character.isDigit(text.charAt(j))) {
					j++;
				}
			}
			if (j < text.length() && text.charAt(j) == '.') {
				j++;
				if (j < text.length() && text.charAt(j) == '*') {
					count++;
					j++;
				}
				else {
					while (j < text.length() && Character.isDigit(text.charAt(j))) {
						j++;
					}
				}
			}
			while (j < text.length() && "hljztLI0123456789".indexOf(text.charAt(j)) >= 0) {
				j++;
			}
			if (j < text.length()) {
				count++;
				i = j;
			}
		}
		return count;
	}

	private int scanfDestinationCount(String literal) {
		String text = literal.substring(1, literal.length() - 1);
		int count = 0;
		for (int i = 0; i < text.length(); i++) {
			if (text.charAt(i) != '%') {
				continue;
			}
			if (i + 1 < text.length() && text.charAt(i + 1) == '%') {
				i++;
				continue;
			}
			int j = i + 1;
			boolean suppressed = false;
			if (j < text.length() && text.charAt(j) == '*') {
				suppressed = true;
				j++;
			}
			while (j < text.length() && Character.isDigit(text.charAt(j))) {
				j++;
			}
			while (j < text.length() && "hljztLI0123456789".indexOf(text.charAt(j)) >= 0) {
				j++;
			}
			if (j >= text.length()) {
				break;
			}
			char specifier = text.charAt(j);
			if (specifier == '[') {
				j++;
				if (j < text.length() && text.charAt(j) == '^') {
					j++;
				}
				if (j < text.length() && text.charAt(j) == ']') {
					j++;
				}
				while (j < text.length() && text.charAt(j) != ']') {
					j++;
				}
			}
			if (!suppressed) {
				count++;
			}
			i = j;
		}
		return count;
	}

	private List<String> splitArguments(String text) {
		List<String> args = new ArrayList<>();
		StringBuilder current = new StringBuilder();
		boolean inString = false;
		boolean escaped = false;
		int depth = 0;
		for (int i = 0; i < text.length(); i++) {
			char c = text.charAt(i);
			if (inString) {
				current.append(c);
				if (escaped) {
					escaped = false;
				}
				else if (c == '\\') {
					escaped = true;
				}
				else if (c == '"') {
					inString = false;
				}
				continue;
			}
			switch (c) {
				case '"' -> {
					inString = true;
					current.append(c);
				}
				case '(' -> {
					depth++;
					current.append(c);
				}
				case ')' -> {
					depth = Math.max(0, depth - 1);
					current.append(c);
				}
				case ',' -> {
					if (depth == 0) {
						args.add(current.toString().trim());
						current.setLength(0);
					}
					else {
						current.append(c);
					}
				}
				default -> current.append(c);
			}
		}
		if (!current.isEmpty() || !text.isBlank()) {
			args.add(current.toString().trim());
		}
		return args;
	}

	private void appendSyntheticLine(StringBuilder builder, String line) {
		builder.append(line).append('\n');
	}

	private void appendLineWithRemappedSpans(StringBuilder builder, List<ParadiseTokenSpan> destination,
			List<ParadiseTokenSpan> source, CodeLine sourceLine, String newLine) {
		int newStart = builder.length();
		builder.append(newLine).append('\n');
		copyRemappedLineSpans(source, destination, sourceLine, newLine, newStart);
	}

	private void copyLineSpans(List<ParadiseTokenSpan> source, List<ParadiseTokenSpan> destination,
			CodeLine line, int newLineStart) {
		for (ParadiseTokenSpan span : source) {
			if (span.start() < line.start() || span.end() > line.end()) {
				continue;
			}
			int start = newLineStart + (span.start() - line.start());
			int end = newLineStart + (span.end() - line.start());
			destination.add(new ParadiseTokenSpan(start, end, span.token(), span.minAddress(),
				span.maxAddress(), span.highSymbol(), span.syntaxType()));
		}
	}

	private void copyRemappedLineSpans(List<ParadiseTokenSpan> source, List<ParadiseTokenSpan> destination,
			CodeLine sourceLine, String newLine, int newLineStart) {
		int searchFrom = 0;
		for (ParadiseTokenSpan span : source) {
			if (span.start() < sourceLine.start() || span.end() > sourceLine.end()) {
				continue;
			}
			int relativeStart = span.start() - sourceLine.start();
			int relativeEnd = span.end() - sourceLine.start();
			if (relativeStart < 0 || relativeEnd > sourceLine.text().length()) {
				continue;
			}
			String oldText = sourceLine.text().substring(relativeStart, relativeEnd);
			String newText = remappedSpanText(oldText, newLine);
			if (newText.isBlank()) {
				continue;
			}
			int found = newLine.indexOf(newText, searchFrom);
			if (found < 0 && !oldText.equals(newText)) {
				found = newLine.indexOf(newText);
			}
			if (found < 0) {
				continue;
			}
			destination.add(new ParadiseTokenSpan(newLineStart + found, newLineStart + found +
				newText.length(), span.token(), span.minAddress(), span.maxAddress(),
				span.highSymbol(), span.syntaxType()));
			searchFrom = found + newText.length();
		}
	}

	private String remappedSpanText(String oldText, String newLine) {
		String text = oldText.trim();
		if (text.equals("uint8_t") && newLine.contains("char ")) {
			return "char";
		}
		if (text.equals("int64_t") && !newLine.contains("int64_t")) {
			return "";
		}
		if (text.equals("uint64_t") && !newLine.contains("uint64_t")) {
			return "";
		}
		return text;
	}

	private List<CodeLine> codeLines(String code) {
		List<CodeLine> lines = new ArrayList<>();
		int start = 0;
		while (start < code.length()) {
			int newline = code.indexOf('\n', start);
			int end = newline < 0 ? code.length() : newline;
			String text = code.substring(start, end);
			if (text.endsWith("\r")) {
				text = text.substring(0, text.length() - 1);
			}
			lines.add(new CodeLine(text, start, end));
			if (newline < 0) {
				break;
			}
			start = newline + 1;
		}
		if (code.isEmpty()) {
			lines.add(new CodeLine("", 0, 0));
		}
		return lines;
	}

	private record RenderedMarkup(String code, List<ParadiseTokenSpan> spans, List<String> cleanups,
			String rawCode, List<ParadiseTokenSpan> rawSpans) {
		RenderedMarkup(String code, List<ParadiseTokenSpan> spans) {
			this(code, spans, List.of(), code, spans);
		}

		RenderedMarkup(String code, List<ParadiseTokenSpan> spans, List<String> cleanups) {
			this(code, spans, cleanups, code, spans);
		}
	}

	private record CodeLine(String text, int start, int end) {
	}

	private record ZeroLoop(String indent, String pointer, String counter, String buffer,
			String count) {
	}

	private record StackCanaryCheckCleanup(int endIndex) {
	}

	private record FreadLoopCleanup(int endIndex, String headerLine, String variable) {
	}

	private record ByteMutationCleanup(List<String> lines) {
	}

	private record ConditionText(String text, String cleanup) {
	}

	private record IfCallCleanup(String variable, List<String> lines) {
	}

	private record SimpleBlockCleanup(int endIndex, List<String> lines) {
	}

	private record ForLoopCleanup(int endIndex, List<String> lines, String variable) {
	}

	private record ConditionBlock(int endIndex, String condition) {
	}

	private record CleanupContext(Program program, Function function, int timeoutSeconds,
			TaskMonitor monitor, ParadiseCleanupOptions cleanupOptions) {
	}

	private enum VarargsWrapperKind {
		PRINT,
		SCAN
	}

	private record VarargsWrapper(String name, VarargsWrapperKind kind, String formatParameter,
			String vaListName) {
	}

	private record VarargsWrapperCleanup(VarargsWrapper wrapper,
			Map<Integer, List<String>> replacements, Set<Integer> skipLines) {
	}

	private static final class CleanupPlan {
		private final ParadiseCleanupOptions cleanupOptions;
		private final Map<Integer, List<String>> replacements = new HashMap<>();
		private final Set<Integer> skipLines = new HashSet<>();
		private final Set<String> charBuffers = new HashSet<>();
		private final Set<String> intIndexLocals = new HashSet<>();
		private final Set<String> securityCookieLocals = new HashSet<>();
		private final Set<String> securityCookieScratch = new HashSet<>();
		private final Set<String> removedArgumentVars = new HashSet<>();
		private final Set<String> removableDeclarations = new HashSet<>();
		private final Map<String, VarargsWrapper> detectedWrappers = new HashMap<>();
		private final Map<String, Integer> appliedCleanups = new LinkedHashMap<>();

		private CleanupPlan(ParadiseCleanupOptions cleanupOptions) {
			this.cleanupOptions = cleanupOptions == null ? ParadiseCleanupOptions.cleanCDefaults()
					: cleanupOptions;
		}

		private ParadiseCleanupOptions cleanupOptions() {
			return cleanupOptions;
		}

		private void recordCleanup(String cleanup) {
			if (cleanup != null && !cleanup.isBlank()) {
				appliedCleanups.merge(cleanup, 1, Integer::sum);
			}
		}

		private List<String> cleanupDescriptions() {
			List<String> descriptions = new ArrayList<>();
			for (Map.Entry<String, Integer> entry : appliedCleanups.entrySet()) {
				descriptions.add(entry.getKey() + " x" + entry.getValue());
			}
			return descriptions;
		}
	}

	private record IntegerLiteral(long value, boolean negative, boolean hex, int hexDigits,
			boolean allHexFs) {
		int bitLengthFromText() {
			return hex ? hexDigits * 4 : Long.SIZE;
		}

		boolean isAllOnes() {
			return hex && (hexDigits == 2 || hexDigits == 4 || hexDigits == 8 ||
				hexDigits == 16) && allHexFs;
		}
	}

	private record CacheKey(Address entry, ParadiseCleanupOptions cleanupOptions, boolean typeAliases,
			boolean cleanLiterals,
			boolean addressComments) {
	}
}

record ParadiseCleanupOptions(boolean enabled, boolean stackCanary, boolean loops,
		boolean conditions, boolean compoundAssignments, boolean callArguments,
		boolean localAliases) {
	static ParadiseCleanupOptions disabled() {
		return new ParadiseCleanupOptions(false, false, false, false, false, false, false);
	}

	static ParadiseCleanupOptions cleanCDefaults() {
		return fromCleanC(true);
	}

	static ParadiseCleanupOptions fromCleanC(boolean cleanC) {
		return cleanC ? new ParadiseCleanupOptions(true, true, true, true, true, true, false)
				: disabled();
	}
}
