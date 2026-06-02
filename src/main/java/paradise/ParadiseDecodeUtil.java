package paradise;

import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class ParadiseDecodeUtil {
	private static final int MAX_RECURSIVE_STEPS = 5;
	private static final Pattern WHITESPACE_PATTERN = Pattern.compile("\\s+");
	private static final Pattern BASE64_PAYLOAD_PATTERN = Pattern.compile("[A-Za-z0-9+/=_-]+");
	private static final Pattern PADDING_PATTERN = Pattern.compile("=+");
	private static final Pattern HEX_ESCAPE_PATTERN = Pattern.compile("\\\\x([0-9A-Fa-f]{2})");
	private static final Pattern HEX_PREFIX_PATTERN = Pattern.compile("(?i)0x");
	private static final Pattern HEX_SEPARATOR_PATTERN = Pattern.compile("[\\s,;:_-]+");
	private static final Pattern HEX_PAYLOAD_PATTERN = Pattern.compile("[0-9A-Fa-f]+");
	private static final Pattern URL_ESCAPE_PATTERN = Pattern.compile("%[0-9A-Fa-f]{2}");
	private static final Pattern BASE32_SEPARATOR_PATTERN = Pattern.compile("[\\s-]+");
	private static final Pattern BASE32_PAYLOAD_PATTERN = Pattern.compile("[A-Z2-7=]+");
	private static final Pattern WINDOWS_DRIVE_PATH_PATTERN = Pattern.compile("^[a-z]:\\\\.*");

	private ParadiseDecodeUtil() {
	}

	static List<Result> resultsForSelection(String source, Codec codec) {
		if (source == null || source.isBlank()) {
			return List.of();
		}
		if (codec == Codec.AUTO) {
			return results(source, true);
		}
		Result result = directResult(source, codec);
		return result == null ? List.of() : List.of(result);
	}

	static Set<Codec> availableCodecs(String source) {
		EnumSet<Codec> codecs = EnumSet.noneOf(Codec.class);
		for (Codec codec : Codec.directCodecs()) {
			if (step(source, codec) != null) {
				codecs.add(codec);
			}
		}
		return codecs;
	}

	static List<Result> results(String source, boolean recursive) {
		List<Result> results = new ArrayList<>();
		expand(source, List.of(), 0, recursive, results, new HashSet<>());
		results.sort(Comparator.comparingInt(Result::confidence).reversed()
				.thenComparingInt(Result::depth)
				.thenComparing(Result::chain));
		return results.size() <= 12 ? results : List.copyOf(results.subList(0, 12));
	}

	static String preview(String value, int maxLength) {
		if (value == null) {
			return "";
		}
		String oneLine = value.replace('\n', ' ').replace('\r', ' ').replace('\t', ' ');
		return oneLine.length() <= maxLength ? oneLine : oneLine.substring(0, maxLength - 1) + "...";
	}

	private static void expand(String source, List<Codec> chain, int depth, boolean recursive,
			List<Result> results, Set<String> seen) {
		if (source == null || source.isBlank() || depth >= MAX_RECURSIVE_STEPS) {
			return;
		}
		for (Codec codec : Codec.directCodecs()) {
			Step step = step(source, codec);
			if (step == null) {
				continue;
			}
			List<Codec> nextChain = appendCodec(chain, codec);
			Result result = result(nextChain, step);
			String key = result.chain() + "\u0000" + result.decodedDisplay();
			if (seen.add(key)) {
				results.add(result);
			}
			String nextSource = step.text() != null ? step.text() : asciiText(step.bytes());
			if (recursive && nextSource != null && !nextSource.equals(source)) {
				expand(nextSource, nextChain, depth + 1, true, results, seen);
			}
		}
	}

	private static Result directResult(String source, Codec codec) {
		Step step = step(source, codec);
		return step == null ? null : result(List.of(codec), step);
	}

	private static Step step(String source, Codec codec) {
		if (source == null || source.isBlank()) {
			return null;
		}
		return switch (codec) {
			case BASE64 -> base64Step(source);
			case HEX -> hexStep(source);
			case URL -> urlStep(source);
			case BASE32 -> base32Step(source);
			case UTF16_LE -> utf16Step(source, true);
			case UTF16_BE -> utf16Step(source, false);
			case AUTO -> null;
		};
	}

	private static Step base64Step(String source) {
		String encoded = base64Payload(source);
		if (encoded == null) {
			return null;
		}
		byte[] decoded = decodeBase64(encoded);
		if (!usefulBase64Decode(encoded, decoded)) {
			return null;
		}
		return new Step(Codec.BASE64, decoded, asciiText(decoded), mostlyText(decoded) ? 90 : 72);
	}

	private static Step hexStep(String source) {
		byte[] decoded = hexBytes(source);
		if (!usefulByteDecode(decoded)) {
			return null;
		}
		return new Step(Codec.HEX, decoded, asciiText(decoded), mostlyText(decoded) ? 84 : 60);
	}

	private static Step urlStep(String source) {
		byte[] decoded = urlBytes(source);
		if (!usefulByteDecode(decoded)) {
			return null;
		}
		return new Step(Codec.URL, decoded, asciiText(decoded), mostlyText(decoded) ? 82 : 58);
	}

	private static Step base32Step(String source) {
		String payload = base32Payload(source);
		if (payload == null) {
			return null;
		}
		byte[] decoded = decodeBase32(payload);
		if (!usefulByteDecode(decoded)) {
			return null;
		}
		return new Step(Codec.BASE32, decoded, asciiText(decoded), mostlyText(decoded) ? 82 : 58);
	}

	private static Step utf16Step(String source, boolean littleEndian) {
		byte[] bytes = byteLikeBytes(source);
		if (bytes == null || bytes.length < 4 || (bytes.length & 1) != 0) {
			return null;
		}
		String text = new String(bytes,
			littleEndian ? java.nio.charset.StandardCharsets.UTF_16LE
					: java.nio.charset.StandardCharsets.UTF_16BE);
		if (!usefulDecodedText(text)) {
			return null;
		}
		byte[] textBytes = text.getBytes(java.nio.charset.StandardCharsets.UTF_8);
		return new Step(littleEndian ? Codec.UTF16_LE : Codec.UTF16_BE, textBytes, text, 78);
	}

	private static Result result(List<Codec> chain, Step step) {
		String display = step.text() != null ? step.text()
				: mostlyText(step.bytes()) ? decodedTextPreview(step.bytes()) : decodedHexPreview(step.bytes());
		String kind = step.text() != null || mostlyText(step.bytes()) ? textKind(display) : "binary";
		int chainPenalty = Math.max(0, chain.size() - 1) * 3;
		int confidence = Math.max(1, step.confidence() - chainPenalty);
		return new Result(chain.get(0), chainDisplay(chain), display, preview(display, 200), kind,
			chain.size(), confidence);
	}

	private static List<Codec> appendCodec(List<Codec> chain, Codec codec) {
		List<Codec> next = new ArrayList<>(chain);
		next.add(codec);
		return List.copyOf(next);
	}

	private static String chainDisplay(List<Codec> chain) {
		StringBuilder builder = new StringBuilder();
		for (int i = 0; i < chain.size();) {
			Codec codec = chain.get(i);
			int count = 1;
			while (i + count < chain.size() && chain.get(i + count) == codec) {
				count++;
			}
			if (!builder.isEmpty()) {
				builder.append(" -> ");
			}
			builder.append(codec.displayName());
			if (count > 1) {
				builder.append(" x").append(count);
			}
			i += count;
		}
		return builder.toString();
	}

	private static boolean usefulBase64Decode(String encoded, byte[] decoded) {
		if (decoded == null || decoded.length < 4) {
			return false;
		}
		boolean text = mostlyText(decoded);
		boolean padded = encoded != null && encoded.indexOf('=') >= 0;
		return padded || (encoded != null && encoded.length() >= 16) || text;
	}

	private static boolean usefulByteDecode(byte[] decoded) {
		return decoded != null && (mostlyText(decoded) || decoded.length >= 4);
	}

	private static String base64Payload(String value) {
		if (value == null) {
			return null;
		}
		String text = value.trim();
		int dataComma = text.indexOf(',');
		if (dataComma > 0 && text.regionMatches(true, 0, "data:", 0, 5) &&
			text.substring(0, dataComma).toLowerCase(Locale.ROOT).contains(";base64")) {
			text = text.substring(dataComma + 1);
		}
			String compact = WHITESPACE_PATTERN.matcher(text).replaceAll("");
			if (compact.length() < 8 || compact.length() % 4 == 1 ||
				!BASE64_PAYLOAD_PATTERN.matcher(compact).matches()) {
				return null;
			}
			int firstPadding = compact.indexOf('=');
			if (firstPadding >= 0 && !PADDING_PATTERN.matcher(compact.substring(firstPadding)).matches()) {
				return null;
			}
			return compact;
	}

	private static byte[] decodeBase64(String encoded) {
		String padded = encoded;
		int remainder = padded.length() % 4;
		if (remainder == 1) {
			return null;
		}
		if (remainder > 0) {
			padded += "=".repeat(4 - remainder);
		}
		try {
			Base64.Decoder decoder =
				encoded.indexOf('-') >= 0 || encoded.indexOf('_') >= 0 ? Base64.getUrlDecoder()
						: Base64.getDecoder();
			return decoder.decode(padded);
		}
		catch (IllegalArgumentException e) {
			return null;
		}
	}

	private static byte[] hexBytes(String source) {
		if (source == null) {
			return null;
		}
			Matcher escaped = HEX_ESCAPE_PATTERN.matcher(source);
			java.io.ByteArrayOutputStream escapedOut = new java.io.ByteArrayOutputStream();
			while (escaped.find()) {
				escapedOut.write(Integer.parseInt(escaped.group(1), 16));
		}
		if (escapedOut.size() > 0) {
			return escapedOut.toByteArray();
		}

			String compact = HEX_SEPARATOR_PATTERN.matcher(
				HEX_PREFIX_PATTERN.matcher(source.trim()).replaceAll("")).replaceAll("");
			if (!HEX_PAYLOAD_PATTERN.matcher(compact).matches()) {
				return null;
			}
		if (compact.length() < 4 || (compact.length() & 1) != 0) {
			return null;
		}
		byte[] out = new byte[compact.length() / 2];
		for (int i = 0; i < out.length; i++) {
			out[i] = (byte) Integer.parseInt(compact.substring(i * 2, i * 2 + 2), 16);
		}
		return out;
	}

	private static byte[] urlBytes(String source) {
			if (source == null || !URL_ESCAPE_PATTERN.matcher(source).find()) {
				return null;
			}
		java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
		boolean changed = false;
		for (int i = 0; i < source.length(); i++) {
			char c = source.charAt(i);
			if (c == '%' && i + 2 < source.length()) {
				int hi = hexNibble(source.charAt(i + 1));
				int lo = hexNibble(source.charAt(i + 2));
				if (hi >= 0 && lo >= 0) {
					out.write((hi << 4) | lo);
					i += 2;
					changed = true;
					continue;
				}
			}
			out.write(c == '+' ? ' ' : (byte) c);
		}
		return changed ? out.toByteArray() : null;
	}

	private static String base32Payload(String source) {
		if (source == null) {
			return null;
		}
			String compact = BASE32_SEPARATOR_PATTERN.matcher(source.trim()).replaceAll("")
					.toUpperCase(Locale.ROOT);
			if (compact.length() < 8 || !BASE32_PAYLOAD_PATTERN.matcher(compact).matches()) {
				return null;
			}
			int firstPadding = compact.indexOf('=');
			if (firstPadding >= 0 && !PADDING_PATTERN.matcher(compact.substring(firstPadding)).matches()) {
				return null;
			}
		if (firstPadding < 0 && compact.length() < 16) {
			return null;
		}
		return compact;
	}

	private static byte[] decodeBase32(String payload) {
		java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
		int buffer = 0;
		int bits = 0;
		for (int i = 0; i < payload.length(); i++) {
			char c = payload.charAt(i);
			if (c == '=') {
				break;
			}
			int value;
			if (c >= 'A' && c <= 'Z') {
				value = c - 'A';
			}
			else if (c >= '2' && c <= '7') {
				value = c - '2' + 26;
			}
			else {
				return null;
			}
			buffer = (buffer << 5) | value;
			bits += 5;
			if (bits >= 8) {
				out.write((buffer >> (bits - 8)) & 0xff);
				bits -= 8;
			}
		}
		return out.toByteArray();
	}

	private static byte[] byteLikeBytes(String source) {
		byte[] hex = hexBytes(source);
		if (hex != null) {
			return hex;
		}
		if (source == null || source.indexOf('\0') < 0) {
			return null;
		}
		byte[] bytes = new byte[source.length()];
		for (int i = 0; i < source.length(); i++) {
			bytes[i] = (byte) source.charAt(i);
		}
		return bytes;
	}

	static int hexNibble(char c) {
		if (c >= '0' && c <= '9') {
			return c - '0';
		}
		if (c >= 'a' && c <= 'f') {
			return c - 'a' + 10;
		}
		if (c >= 'A' && c <= 'F') {
			return c - 'A' + 10;
		}
		return -1;
	}

	private static boolean usefulDecodedText(String text) {
		if (text == null || text.length() < 2 || text.indexOf('\ufffd') >= 0) {
			return false;
		}
		int useful = 0;
		for (int i = 0; i < text.length(); i++) {
			char c = text.charAt(i);
			if (!Character.isISOControl(c) || Character.isWhitespace(c)) {
				useful++;
			}
		}
		return useful >= Math.ceil(text.length() * 0.75);
	}

	private static String textKind(String text) {
		String lower = text == null ? "" : text.toLowerCase(Locale.ROOT);
		if (lower.startsWith("http://") || lower.startsWith("https://")) {
			return "url";
		}
			if (WINDOWS_DRIVE_PATH_PATTERN.matcher(lower).matches() || lower.startsWith("/") ||
				lower.startsWith("\\\\")) {
				return "path";
			}
		return "text";
	}

	private static boolean mostlyText(byte[] bytes) {
		int text = 0;
		for (byte b : bytes) {
			int value = b & 0xff;
			if (value == '\t' || value == '\n' || value == '\r' ||
				(value >= 0x20 && value <= 0x7e)) {
				text++;
			}
		}
		return bytes.length > 0 && text >= Math.ceil(bytes.length * 0.75);
	}

	private static String decodedTextPreview(byte[] bytes) {
		StringBuilder builder = new StringBuilder();
		for (byte b : bytes) {
			int value = b & 0xff;
			if (value == '\n' || value == '\r' || value == '\t') {
				builder.append(' ');
			}
			else if (value >= 0x20 && value <= 0x7e) {
				builder.append((char) value);
			}
			else {
				builder.append('.');
			}
		}
		return preview(builder.toString(), 200);
	}

	private static String decodedHexPreview(byte[] bytes) {
		StringBuilder builder = new StringBuilder();
		int count = Math.min(bytes.length, 24);
		for (int i = 0; i < count; i++) {
			if (i > 0) {
				builder.append(' ');
			}
			builder.append(String.format(Locale.ROOT, "%02x", bytes[i] & 0xff));
		}
		if (bytes.length > count) {
			builder.append(" ...");
		}
		return builder.toString();
	}

	private static String asciiText(byte[] bytes) {
		StringBuilder builder = new StringBuilder();
		for (byte b : bytes) {
			int value = b & 0xff;
			if (value == '\t' || value == '\n' || value == '\r' ||
				(value >= 0x20 && value <= 0x7e)) {
				builder.append((char) value);
			}
			else {
				return null;
			}
		}
		return builder.toString();
	}

	enum Codec {
		AUTO("Auto"),
		BASE64("Base64"),
		HEX("Hex"),
		URL("URL percent"),
		BASE32("Base32"),
		UTF16_LE("UTF-16LE"),
		UTF16_BE("UTF-16BE");

		private static final List<Codec> DIRECT_CODECS =
			List.of(BASE64, HEX, URL, BASE32, UTF16_LE, UTF16_BE);
		private static final List<Codec> STRING_TABS =
			List.of(BASE64, HEX, URL, BASE32, UTF16_LE, UTF16_BE);

		private final String displayName;

		Codec(String displayName) {
			this.displayName = displayName;
		}

		String displayName() {
			return displayName;
		}

		String tabTitle() {
			return this == URL ? "URL" : displayName;
		}

		static List<Codec> directCodecs() {
			return DIRECT_CODECS;
		}

		static List<Codec> stringTabs() {
			return STRING_TABS;
		}
	}

	record Step(Codec codec, byte[] bytes, String text, int confidence) {
	}

	record Result(Codec codec, String chain, String decodedDisplay, String decodedPreview,
			String kind, int depth, int confidence) {
	}
}
