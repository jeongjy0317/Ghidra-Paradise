package paradise;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.StringJoiner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

final class ParadiseFindScanner {
	private static final int MIN_RAW_TEXT = 4;
	private static final int MAX_RAW_TEXT = 512;
	private static final Pattern URL_WITH_SCHEME = Pattern.compile(
		"(?i)\\b(?:https?|ftp|wss?|ws)://[^\\s\"'<>)]{3,}");
	private static final Pattern DOMAIN_WITH_CONTEXT = Pattern.compile(
		"(?i)\\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+" +
		"(?:com|net|org|io|co|kr|ru|cn|xyz|top|info|biz|dev|app|site|online|me|edu|gov|mil)" +
		"(?::\\d{1,5})?(?:/[A-Za-z0-9._~:/?#\\[\\]@!$&'()*+,;=%-]*)?");
	private static final Pattern HOST_PORT_PATH = Pattern.compile(
		"\\b(?:\\d{1,3}\\.){3}\\d{1,3}(?::\\d{1,5})?(?:/[A-Za-z0-9._~:/?#\\[\\]@!$&'()*+,;=%-]+)");
	private static final Pattern WINDOWS_DRIVE_PATH = Pattern.compile(
		"(?i)\\b[A-Z]:[\\\\/](?:[^\\s\"'<>|]+[\\\\/]?)+");
	private static final Pattern WINDOWS_UNC_PATH = Pattern.compile(
		"\\\\\\\\[A-Za-z0-9._$-]+\\\\[A-Za-z0-9._$-]+(?:\\\\[^\\s\"'<>|]+)*");
	private static final Pattern WINDOWS_ENV_PATH = Pattern.compile(
		"(?i)%[A-Z0-9_]+%[\\\\/][^\\s\"'<>|]+");
	private static final Pattern UNIX_PATH = Pattern.compile(
		"(?<!:)\\B/(?:etc|tmp|var|usr|bin|sbin|home|root|opt|proc|sys|dev|mnt|media|lib|run)" +
		"(?:/[^\\s\"'<>]+)+");
	private static final Pattern RELATIVE_PATH = Pattern.compile(
		"(?<![A-Za-z0-9_])\\.\\.?/[^\\s\"'<>]+(?:/[^\\s\"'<>]+)*");

	private ParadiseFindScanner() {
	}

	static List<Row> scanFunction(Function function, boolean mergeRepeated, TaskMonitor monitor)
			throws CancelledException {
		if (function == null) {
			return List.of();
		}
		Program program = function.getProgram();
		monitor.setMessage("Scanning function strings");
		List<TextSource> sources = textSourcesForBody(program, function.getBody(), monitor);
		return scanSources(sources, mergeRepeated, monitor);
	}

	static List<Row> scanProgram(Program program, boolean mergeRepeated, TaskMonitor monitor)
			throws CancelledException {
		if (program == null) {
			return List.of();
		}
		monitor.setMessage("Scanning program strings");
		Map<String, TextSource> sources = new LinkedHashMap<>();
		for (TextSource source : definedTextSources(program, monitor)) {
			putSource(sources, source);
		}
		for (TextSource source : rawTextSources(program, monitor)) {
			putSource(sources, source);
		}
		return scanSources(List.copyOf(sources.values()), mergeRepeated, monitor);
	}

	private static List<TextSource> textSourcesForBody(Program program, AddressSetView body,
			TaskMonitor monitor) throws CancelledException {
		Map<String, TextSource> sources = new LinkedHashMap<>();
		Listing listing = program.getListing();
		for (Instruction instruction : listing.getInstructions(body, true)) {
			monitor.checkCancelled();
			for (Reference reference : instruction.getReferencesFrom()) {
				ParadiseStringUtil.ParadiseString string =
					ParadiseStringUtil.stringAt(program, reference.getToAddress());
				if (string != null) {
					putSource(sources,
						new TextSource(instruction.getAddress(), string.address(), string.value()));
				}
			}
		}
		return List.copyOf(sources.values());
	}

	private static List<TextSource> definedTextSources(Program program, TaskMonitor monitor)
			throws CancelledException {
		List<TextSource> sources = new ArrayList<>();
		DataIterator iterator = program.getListing().getDefinedData(true);
		while (iterator.hasNext()) {
			monitor.checkCancelled();
			Data data = iterator.next();
			if (!StringDataInstance.isString(data)) {
				continue;
			}
			StringDataInstance stringData = StringDataInstance.getStringDataInstance(data);
			if (stringData == null) {
				continue;
			}
			String value = stringData.getStringValue();
			if (value == null || value.isBlank()) {
				value = stringData.getStringRepresentation();
			}
			if (value == null || value.isBlank()) {
				continue;
			}
			addWithRefs(program, sources, data.getMinAddress(), value);
		}
		return sources;
	}

	private static List<TextSource> rawTextSources(Program program, TaskMonitor monitor)
			throws CancelledException {
		List<TextSource> sources = new ArrayList<>();
		Memory memory = program.getMemory();
		for (MemoryBlock block : memory.getBlocks()) {
			monitor.checkCancelled();
			if (!block.isInitialized() || !block.isRead()) {
				continue;
			}
			Address current = block.getStart();
			Address end = block.getEnd();
			while (current != null && current.compareTo(end) <= 0) {
				monitor.checkCancelled();
				RawText raw = rawTextAt(memory, block, current);
				if (raw != null) {
					addWithRefs(program, sources, current, raw.value());
					current = add(current, raw.length());
				}
				else {
					current = add(current, 1);
				}
			}
		}
		return sources;
	}

	private static RawText rawTextAt(Memory memory, MemoryBlock block, Address address) {
		StringBuilder builder = new StringBuilder();
		for (int offset = 0; offset < MAX_RAW_TEXT; offset++) {
			Address current = add(address, offset);
			if (current == null || !block.contains(current)) {
				break;
			}
			int value = byteAt(memory, current);
			if (value < 0) {
				break;
			}
			if (value == 0) {
				return builder.length() >= MIN_RAW_TEXT ? new RawText(builder.toString(), offset + 1)
						: null;
			}
			if (!isTextByte(value)) {
				return null;
			}
			builder.append((char) value);
		}
		return builder.length() >= MIN_RAW_TEXT ? new RawText(builder.toString(), builder.length())
				: null;
	}

	private static void addWithRefs(Program program, List<TextSource> sources, Address textAddress,
			String value) {
		boolean addedRef = false;
		ReferenceIterator refs = program.getReferenceManager().getReferencesTo(textAddress);
		while (refs.hasNext()) {
			Reference ref = refs.next();
			sources.add(new TextSource(ref.getFromAddress(), textAddress, value));
			addedRef = true;
		}
		if (!addedRef) {
			sources.add(new TextSource(null, textAddress, value));
		}
	}

	private static void putSource(Map<String, TextSource> sources, TextSource source) {
		String key = Objects.toString(source.useAddress(), "") + "\u0000" +
			Objects.toString(source.textAddress(), "") + "\u0000" + source.value();
		sources.putIfAbsent(key, source);
	}

	private static List<Row> scanSources(List<TextSource> sources, boolean mergeRepeated,
			TaskMonitor monitor) throws CancelledException {
		Map<String, Row> rows = new LinkedHashMap<>();
		monitor.initialize(sources.size());
		for (TextSource source : sources) {
			monitor.checkCancelled();
			monitor.incrementProgress(1);
			for (ScanText text : scanTexts(source)) {
				addUrlRows(rows, source, text, mergeRepeated);
				addPathRows(rows, source, text, mergeRepeated);
			}
		}
		List<Row> sorted = new ArrayList<>(rows.values());
		sorted.sort(Comparator.comparingInt(Row::priority)
				.thenComparing(Comparator.comparingInt(Row::count).reversed())
				.thenComparing(Row::kind)
				.thenComparing(Row::value)
				.thenComparing(row -> Objects.toString(row.textAddress(), "")));
		return List.copyOf(sorted);
	}

	private static List<ScanText> scanTexts(TextSource source) {
		List<ScanText> texts = new ArrayList<>();
		for (ParadiseDecodeUtil.Result result : ParadiseDecodeUtil.results(source.value(), true)) {
			texts.add(new ScanText("decoded", result.chain(), result.decodedDisplay(),
				result.confidence()));
		}
		texts.add(new ScanText("plain", "", source.value(), 100));
		return texts;
	}

	private static void addUrlRows(Map<String, Row> rows, TextSource source, ScanText text,
			boolean mergeRepeated) {
		String normalized = normalizeUrlText(text.value());
		addMatches(rows, source, text, normalized, URL_WITH_SCHEME, "URL", "network scheme", true,
			mergeRepeated);
		addMatches(rows, source, text, normalized, HOST_PORT_PATH, "URL", "IP host path", true,
			mergeRepeated);
		Matcher matcher = DOMAIN_WITH_CONTEXT.matcher(normalized);
		while (matcher.find()) {
			String value = trimMatch(matcher.group());
			if (!domainHasContext(value)) {
				continue;
			}
			addRow(rows, source, text, "URL", value, evidence(text, "domain/path pattern"),
				priority(text, value, true), mergeRepeated);
		}
	}

	private static void addPathRows(Map<String, Row> rows, TextSource source, ScanText text,
			boolean mergeRepeated) {
		addMatches(rows, source, text, text.value(), WINDOWS_DRIVE_PATH, "Windows path",
			"drive path", false, mergeRepeated);
		addMatches(rows, source, text, text.value(), WINDOWS_UNC_PATH, "UNC path", "UNC path",
			false, mergeRepeated);
		addMatches(rows, source, text, text.value(), WINDOWS_ENV_PATH, "Windows path",
			"environment path", false, mergeRepeated);
		addPathMatches(rows, source, text, UNIX_PATH, "Unix path", "absolute path", mergeRepeated);
		addPathMatches(rows, source, text, RELATIVE_PATH, "Relative path", "relative path",
			mergeRepeated);
	}

	private static void addMatches(Map<String, Row> rows, TextSource source, ScanText text,
			String scanValue, Pattern pattern, String kind, String reason, boolean url,
			boolean mergeRepeated) {
		Matcher matcher = pattern.matcher(scanValue);
		while (matcher.find()) {
			String value = trimMatch(matcher.group());
			addRow(rows, source, text, kind, value, evidence(text, reason),
				priority(text, value, url), mergeRepeated);
		}
	}

	private static void addPathMatches(Map<String, Row> rows, TextSource source, ScanText text,
			Pattern pattern, String kind, String reason, boolean mergeRepeated) {
		Matcher matcher = pattern.matcher(text.value());
		while (matcher.find()) {
			if (matcher.start() > 0 && text.value().charAt(matcher.start() - 1) == ':') {
				continue;
			}
			String value = trimMatch(matcher.group());
			addRow(rows, source, text, kind, value, evidence(text, reason),
				priority(text, value, false), mergeRepeated);
		}
	}

	private static void addRow(Map<String, Row> rows, TextSource source, ScanText text, String kind,
			String value, String evidence, int priority, boolean mergeRepeated) {
		if (value == null || value.length() < 3) {
			return;
		}
		String key = mergeRepeated ? kind + "\u0000" + value + "\u0000" + text.source() + "\u0000" +
			text.chain()
				: kind + "\u0000" + value + "\u0000" +
					Objects.toString(source.textAddress(), "") + "\u0000" +
					Objects.toString(source.useAddress(), "") + "\u0000" + text.source() +
					"\u0000" + text.chain();
		Row existing = rows.get(key);
		if (existing == null) {
			rows.put(key, new Row(priority, 1, kind, source.textAddress(), source.useAddress(),
				text.source(), text.chain(), value, evidence));
			return;
		}
		rows.put(key, mergeRepeated ? existing.withOccurrence(priority) : existing);
	}

	private static String normalizeUrlText(String value) {
		return value.replace("hxxps://", "https://")
				.replace("hxxp://", "http://")
				.replace("HXXPS://", "https://")
				.replace("HXXP://", "http://")
				.replace("[.]", ".")
				.replace("(.)", ".")
				.replace("[:]", ":");
	}

	private static boolean domainHasContext(String value) {
		String lower = value.toLowerCase(Locale.ROOT);
		return lower.contains("/") || lower.contains("?") || lower.contains(":") ||
			lower.endsWith(".php") || lower.endsWith(".asp") || lower.endsWith(".jsp") ||
			lower.endsWith(".json") || lower.endsWith(".zip") || lower.endsWith(".exe") ||
			lower.endsWith(".dll");
	}

	private static String evidence(ScanText text, String reason) {
		StringJoiner joiner = new StringJoiner(", ");
		joiner.add(reason);
		if (!text.chain().isBlank()) {
			joiner.add("decoded " + text.chain());
		}
		if (text.confidence() < 100) {
			joiner.add(text.confidence() + "% decode");
		}
		return joiner.toString();
	}

	private static int priority(ScanText text, String value, boolean url) {
		int score = 3;
		String lower = value.toLowerCase(Locale.ROOT);
		if (!text.chain().isBlank()) {
			score--;
		}
		if (url && (lower.contains("token=") || lower.contains("key=") ||
			lower.contains("cmd=") || lower.contains("pass="))) {
			score--;
		}
		if (!url && (lower.endsWith(".exe") || lower.endsWith(".dll") ||
			lower.endsWith(".sh") || lower.endsWith(".key") || lower.endsWith(".pem") ||
			lower.contains("/.ssh/") || lower.contains("\\startup\\"))) {
			score--;
		}
		if (value.length() > 12 && (value.contains("/") || value.contains("\\"))) {
			score--;
		}
		return Math.max(1, score);
	}

	private static String trimMatch(String value) {
		String trimmed = value;
		while (!trimmed.isEmpty() && ".,;:)]}'\"".indexOf(trimmed.charAt(trimmed.length() - 1)) >= 0) {
			trimmed = trimmed.substring(0, trimmed.length() - 1);
		}
		return trimmed;
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

	private static boolean isTextByte(int value) {
		return value == '\t' || value == '\n' || value == '\r' ||
			(value >= 0x20 && value <= 0x7e);
	}

	record Row(int priority, int count, String kind, Address textAddress, Address useAddress,
			String source, String chain, String value, String evidence) {
		private Row withOccurrence(int priority) {
			return new Row(Math.min(this.priority, priority), count + 1, kind, textAddress,
				useAddress, source, chain, value, evidence);
		}
	}

	private record TextSource(Address useAddress, Address textAddress, String value) {
	}

	private record ScanText(String source, String chain, String value, int confidence) {
	}

	private record RawText(String value, int length) {
	}
}
