package paradise;

import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Window;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.*;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

import javax.swing.*;

import docking.ActionContext;
import docking.action.*;
import ghidra.app.nav.Navigatable;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.GoToService;
import ghidra.app.util.datatype.DataTypeSelectionDialog;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.Swing;
import ghidra.util.data.DataTypeParser.AllowedDataTypes;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.*;

//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = ParadisePluginPackage.NAME,
	category = PluginCategoryNames.CODE_VIEWER,
	shortDescription = "Paradise decompiler workflow",
	description = "Adds Paradise decompiler workflow actions and a pseudocode provider backed by Ghidra's native decompiler.",
	servicesRequired = {
		GoToService.class
	}
)
//@formatter:on
public class ParadisePlugin extends ProgramPlugin {
	static final String OPTIONS_TITLE = "Paradise";
	private static final String MENU_GROUP = "Paradise";
	private static final String OPTIONS_MENU_GROUP = "Paradise Options";
	private static final String EXPORT_SINGLE_FILE = "Single C file";
	private static final String EXPORT_PER_FUNCTION = "One C file per function";
	private static final String THEME_LIGHT = "Paradise Light";
	private static final String THEME_DARK = "Paradise Dark";
	private static final int MAC_DECOMPILE_MODIFIERS =
		InputEvent.META_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK;

	private static final String OPTION_ENABLE_HOTKEYS = "Enable hotkeys";
	private static final String OPTION_SYNC_LISTING = "Sync listing on token click";
	private static final String OPTION_FOLLOW_EXTERNAL_LOCATION =
		"Follow Listing/Decompiler location";
	private static final String OPTION_TIMEOUT_SECONDS = "Decompiler timeout seconds";
	private static final String OPTION_FONT_SIZE = "Pseudocode font size";
	private static final String OPTION_THEME_PRESET = "Theme preset";
	private static final String OPTION_SHOW_GUTTER = "Show pseudocode gutter";
	private static final String OPTION_SHOW_LINE_NUMBERS = "Show line numbers";
	private static final String OPTION_SHOW_TOKEN_ADDRESSES = "Show gutter addresses";
	private static final String OPTION_SHOW_AUX_PANELS = "Show analysis panels";
	private static final String OPTION_VIEW_XREFS = "Show Xrefs panel";
	private static final String OPTION_VIEW_LOCALS = "Show Locals panel";
	private static final String OPTION_VIEW_TRACE = "Show Trace panel";
	private static final String OPTION_VIEW_CALLS = "Show Calls panel";
	private static final String OPTION_VIEW_STRINGS = "Show Strings panel";
	private static final String OPTION_VIEW_DIFF = "Show Diff panel";
	private static final String OPTION_VIEW_DRAFTS = "Show Drafts panel";
	private static final String OPTION_VIEW_SUGGESTIONS = "Show Suggestions panel";
	private static final String OPTION_VIEW_TRIAGE = "Show Triage panel";
	private static final String OPTION_VIEW_CLEANUPS = "Show Cleanups panel";
	private static final String OPTION_VIEW_FINDS_WINDOW = "Show URL/path inspector window";
	private static final String OPTION_FIND_MERGE_REPEATED = "Merge repeated Inspector rows";
	private static final String OPTION_FIND_COLUMN_PRIORITY = "Show Inspector Priority column";
	private static final String OPTION_FIND_COLUMN_COUNT = "Show Inspector Count column";
	private static final String OPTION_FIND_COLUMN_KIND = "Show Inspector Kind column";
	private static final String OPTION_FIND_COLUMN_ADDRESS = "Show Inspector Address column";
	private static final String OPTION_FIND_COLUMN_USE = "Show Inspector Use column";
	private static final String OPTION_FIND_COLUMN_SOURCE = "Show Inspector Source column";
	private static final String OPTION_FIND_COLUMN_CHAIN = "Show Inspector Decode Chain column";
	private static final String OPTION_FIND_COLUMN_VALUE = "Show Inspector Value column";
	private static final String OPTION_FIND_COLUMN_EVIDENCE = "Show Inspector Evidence column";
	private static final String OPTION_CURRENT_LINE = "Highlight current line";
	private static final String OPTION_BRACE_MATCHING = "Highlight matching braces";
	private static final String OPTION_OPEN_CALLEE_NEW_TAB = "Open callees in new tabs";
	private static final String OPTION_XREF_OPEN_PSEUDOCODE = "Open pseudocode from xrefs";
	private static final String OPTION_HIGHLIGHT_USES = "Highlight matching token uses";
	private static final String OPTION_OPEN_DETECTED_MAIN = "Open detected user main";
	private static final String OPTION_CLEAN_C = "Clean C mode";
	private static final String OPTION_CLEAN_LITERALS = "Clean integer literals";
	private static final String OPTION_CLEAN_STACK_CANARY = "Stack canary cleanup";
	private static final String OPTION_CLEAN_LOOPS = "Loop cleanup";
	private static final String OPTION_CLEAN_CONDITIONS = "Condition cleanup";
	private static final String OPTION_CLEAN_COMPOUND_ASSIGNMENTS =
		"Compound assignment cleanup";
	private static final String OPTION_CLEAN_CALL_ARGUMENTS = "Call argument cleanup";
	private static final String OPTION_CLEAN_LOCAL_ALIASES = "Local alias display";
	private static final String OPTION_TYPE_ALIASES = "Display type aliases";
	private static final String OPTION_ADDRESS_COMMENTS = "Show address comments";
	private static final String OPTION_EXPORT_MODE = "Export mode";
	private static final String OPTION_EXPORT_METADATA = "Export metadata JSON";
	private static final String OPTION_DIAGRAM_VIEW_STATE = "Diagram view state";

	private static final boolean DEFAULT_ENABLE_HOTKEYS = true;
	private static final boolean DEFAULT_SYNC_LISTING = true;
	private static final boolean DEFAULT_FOLLOW_EXTERNAL_LOCATION = true;
	private static final int DEFAULT_TIMEOUT_SECONDS = 30;
	private static final int DEFAULT_FONT_SIZE = 13;
	private static final boolean DEFAULT_SHOW_GUTTER = true;
	private static final boolean DEFAULT_SHOW_LINE_NUMBERS = true;
	private static final boolean DEFAULT_SHOW_TOKEN_ADDRESSES = true;
	private static final boolean DEFAULT_SHOW_AUX_PANELS = true;
	private static final boolean DEFAULT_SHOW_AUX_TAB = true;
	private static final boolean DEFAULT_CURRENT_LINE = true;
	private static final boolean DEFAULT_BRACE_MATCHING = true;
	private static final boolean DEFAULT_OPEN_CALLEE_NEW_TAB = true;
	private static final boolean DEFAULT_XREF_OPEN_PSEUDOCODE = true;
	private static final boolean DEFAULT_HIGHLIGHT_USES = true;
	private static final boolean DEFAULT_OPEN_DETECTED_MAIN = true;
	private static final boolean DEFAULT_CLEAN_C = true;
	private static final boolean DEFAULT_CLEAN_LITERALS = true;
	private static final boolean DEFAULT_CLEAN_STACK_CANARY = true;
	private static final boolean DEFAULT_CLEAN_LOOPS = true;
	private static final boolean DEFAULT_CLEAN_CONDITIONS = true;
	private static final boolean DEFAULT_CLEAN_COMPOUND_ASSIGNMENTS = true;
	private static final boolean DEFAULT_CLEAN_CALL_ARGUMENTS = true;
	private static final boolean DEFAULT_CLEAN_LOCAL_ALIASES = false;
	private static final boolean DEFAULT_TYPE_ALIASES = false;
	private static final boolean DEFAULT_ADDRESS_COMMENTS = false;
	private static final boolean DEFAULT_EXPORT_METADATA = true;
	private static final boolean DEFAULT_FIND_MERGE_REPEATED = true;

	private final ParadiseDecompilerEngine engine = new ParadiseDecompilerEngine();
	private final ParadiseDecompilerProvider provider;
	private final ParadiseGraphProvider graphProvider;
	private final ParadiseFindProvider findProvider;
	private boolean suppressLocationFollow;
	private Address suppressedNavigationAddress;

	public ParadisePlugin(PluginTool tool) {
		super(tool);
		provider = new ParadiseDecompilerProvider(this);
		graphProvider = new ParadiseGraphProvider(this);
		findProvider = new ParadiseFindProvider(this);
		provider.addToTool();
		graphProvider.addToTool();
		findProvider.addToTool();
		createActions();
	}

	@Override
	public void init() {
		super.init();
		registerOptions();
		findProvider.setVisible(showFindsWindow());
	}

	@Override
	protected void programClosed(Program program) {
		engine.close(program);
		provider.programClosed(program);
		graphProvider.programClosed(program);
		findProvider.programClosed(program);
	}

	@Override
	protected void locationChanged(ProgramLocation location) {
		super.locationChanged(location);
		if (location != null && location.getAddress() != null) {
			graphProvider.revealAddress(location.getAddress());
		}
		followExternalLocation(location);
	}

	@Override
	public void dispose() {
		provider.removeFromTool();
		graphProvider.removeFromTool();
		findProvider.removeFromTool();
		engine.close();
		super.dispose();
	}

	int timeoutSeconds() {
		return Math.max(1, options().getInt(OPTION_TIMEOUT_SECONDS, DEFAULT_TIMEOUT_SECONDS));
	}

	int fontSize() {
		return Math.max(8, options().getInt(OPTION_FONT_SIZE, DEFAULT_FONT_SIZE));
	}

	boolean syncListingOnClick() {
		return options().getBoolean(OPTION_SYNC_LISTING, DEFAULT_SYNC_LISTING);
	}

	boolean followExternalLocation() {
		return options().getBoolean(OPTION_FOLLOW_EXTERNAL_LOCATION,
			DEFAULT_FOLLOW_EXTERNAL_LOCATION);
	}

	boolean hotkeysEnabled() {
		return options().getBoolean(OPTION_ENABLE_HOTKEYS, DEFAULT_ENABLE_HOTKEYS);
	}

	boolean highlightUsesEnabled() {
		return options().getBoolean(OPTION_HIGHLIGHT_USES, DEFAULT_HIGHLIGHT_USES);
	}

	boolean darkTheme() {
		return THEME_DARK.equals(options().getString(OPTION_THEME_PRESET, THEME_LIGHT));
	}

	boolean showGutter() {
		return options().getBoolean(OPTION_SHOW_GUTTER, DEFAULT_SHOW_GUTTER);
	}

	boolean showLineNumbers() {
		return options().getBoolean(OPTION_SHOW_LINE_NUMBERS, DEFAULT_SHOW_LINE_NUMBERS);
	}

	boolean showTokenAddresses() {
		return options().getBoolean(OPTION_SHOW_TOKEN_ADDRESSES, DEFAULT_SHOW_TOKEN_ADDRESSES);
	}

	String diagramViewState(String key) {
		if (key == null || key.isBlank()) {
			return "";
		}
		for (String line : options().getString(OPTION_DIAGRAM_VIEW_STATE, "").split("\\R")) {
			int tab = line.indexOf('\t');
			if (tab > 0 && line.substring(0, tab).equals(key)) {
				return line.substring(tab + 1);
			}
		}
		return "";
	}

	void setDiagramViewState(String key, String state) {
		if (key == null || key.isBlank()) {
			return;
		}
		Map<String, String> states = new LinkedHashMap<>();
		for (String line : options().getString(OPTION_DIAGRAM_VIEW_STATE, "").split("\\R")) {
			int tab = line.indexOf('\t');
			if (tab > 0) {
				states.put(line.substring(0, tab), line.substring(tab + 1));
			}
		}
		if (state == null || state.isBlank()) {
			states.remove(key);
		}
		else {
			states.put(key, state);
		}
		StringBuilder builder = new StringBuilder();
		for (Map.Entry<String, String> entry : states.entrySet()) {
			if (!builder.isEmpty()) {
				builder.append('\n');
			}
			builder.append(entry.getKey()).append('\t').append(entry.getValue());
		}
		options().setString(OPTION_DIAGRAM_VIEW_STATE, builder.toString());
	}

	boolean showAuxPanels() {
		return options().getBoolean(OPTION_SHOW_AUX_PANELS, DEFAULT_SHOW_AUX_PANELS);
	}

	boolean showAuxTab(String title) {
		String option = switch (title) {
			case "Xrefs" -> OPTION_VIEW_XREFS;
			case "Locals" -> OPTION_VIEW_LOCALS;
			case "Trace" -> OPTION_VIEW_TRACE;
			case "Calls" -> OPTION_VIEW_CALLS;
			case "Strings" -> OPTION_VIEW_STRINGS;
			case "Diff" -> OPTION_VIEW_DIFF;
			case "Drafts" -> OPTION_VIEW_DRAFTS;
			case "Suggestions" -> OPTION_VIEW_SUGGESTIONS;
			case "Triage" -> OPTION_VIEW_TRIAGE;
			case "Cleanups" -> OPTION_VIEW_CLEANUPS;
			default -> null;
		};
		return option == null || options().getBoolean(option, DEFAULT_SHOW_AUX_TAB);
	}

	boolean showFindsWindow() {
		return options().getBoolean(OPTION_VIEW_FINDS_WINDOW, DEFAULT_SHOW_AUX_TAB);
	}

	boolean mergeRepeatedFinds() {
		return options().getBoolean(OPTION_FIND_MERGE_REPEATED, DEFAULT_FIND_MERGE_REPEATED);
	}

	boolean showFindColumn(String title) {
		String option = switch (title) {
			case "Priority" -> OPTION_FIND_COLUMN_PRIORITY;
			case "Count" -> OPTION_FIND_COLUMN_COUNT;
			case "Kind" -> OPTION_FIND_COLUMN_KIND;
			case "Address" -> OPTION_FIND_COLUMN_ADDRESS;
			case "Use" -> OPTION_FIND_COLUMN_USE;
			case "Source" -> OPTION_FIND_COLUMN_SOURCE;
			case "Decode Chain" -> OPTION_FIND_COLUMN_CHAIN;
			case "Value" -> OPTION_FIND_COLUMN_VALUE;
			case "Evidence" -> OPTION_FIND_COLUMN_EVIDENCE;
			default -> null;
		};
		return option == null || options().getBoolean(option, true);
	}

	boolean currentLineHighlight() {
		return options().getBoolean(OPTION_CURRENT_LINE, DEFAULT_CURRENT_LINE);
	}

	boolean braceMatching() {
		return options().getBoolean(OPTION_BRACE_MATCHING, DEFAULT_BRACE_MATCHING);
	}

	boolean openPseudocodeFromXrefsSetting() {
		return openPseudocodeFromXrefs();
	}

	void decompileFunction(Function function, boolean force, boolean addHistory) {
		decompileFunction(function, force, addHistory, false);
	}

	void decompileFunction(Function function, boolean force, boolean addHistory,
			boolean reuseActiveTab) {
		decompileFunction(function, force, addHistory, reuseActiveTab, true, null);
	}

	private void decompileFunction(Function function, boolean force, boolean addHistory,
			boolean reuseActiveTab, boolean focusProvider, Address revealAddress) {
		decompileFunction(function, force, addHistory, reuseActiveTab, focusProvider,
			revealAddress, null, null);
	}

	private void decompileFunction(Function function, boolean force, boolean addHistory,
			boolean reuseActiveTab, boolean focusProvider, Address revealAddress, String rawValue,
			String value) {
		if (function == null) {
			Msg.showInfo(this, provider.getComponent(), "Paradise", "No function selected.");
			return;
		}

		Program program = function.getProgram();
		provider.showLoading(function, addHistory, reuseActiveTab, focusProvider);
		TaskLauncher.launchNonModal("Decompile " + function.getName(), monitor -> {
			ParadiseDecompileResult result;
			boolean redirectedToMain = false;
			try {
				result = engine.decompile(program, function, timeoutSeconds(), force, monitor,
					cleanupOptions(), displayTypeAliases(), cleanLiterals(), showAddressComments());
				Function userMain = openDetectedMain() ? detectedUserMain(result) : null;
				if (userMain != null && !sameFunction(userMain, function)) {
					if (prepareDetectedUserMain(userMain)) {
						engine.clearProgramCache(program);
					}
					result = engine.decompile(program, userMain, timeoutSeconds(), true, monitor,
						cleanupOptions(), displayTypeAliases(), cleanLiterals(),
						showAddressComments());
					redirectedToMain = true;
				}
			}
			catch (RuntimeException e) {
				result = ParadiseDecompileResult.failure(program, function, e.getMessage());
			}
			ParadiseDecompileResult displayResult = result;
			boolean reuseRedirectTab = redirectedToMain;
			Swing.runLater(() -> {
				provider.showResult(displayResult, reuseRedirectTab, focusProvider);
				if (revealAddress != null) {
					revealPseudocodeUsage(revealAddress, rawValue, value);
				}
			});
		});
	}

	void togglePseudocode() {
		if (provider.isVisible()) {
			provider.setVisible(false);
			return;
		}
		Function function = functionAtCursor();
		if (function != null) {
			decompileFunction(function, false, true);
			return;
		}
		if (provider.currentResult() != null) {
			provider.setVisible(true);
			provider.focusText();
		}
	}

	boolean navigateTo(Address address) {
		if (address == null) {
			return false;
		}
		GoToService goToService = tool.getService(GoToService.class);
		if (goToService == null) {
			return false;
		}
		boolean navigated = false;
		suppressLocationFollow = true;
		suppressedNavigationAddress = address;
		try {
			Program program = navigationProgram();
			if (program != null) {
				ProgramLocation location = new ProgramLocation(program, address);
				Navigatable navigatable = goToService.getDefaultNavigatable();
				if (navigatable != null && goToService.goTo(navigatable, location, program)) {
					navigated = true;
					return true;
				}
				if (goToService.goTo(location, program)) {
					navigated = true;
					return true;
				}
				if (goToService.goTo(address, program)) {
					navigated = true;
					return true;
				}
			}
			navigated = goToService.goTo(address);
			return navigated;
		}
		finally {
			if (!navigated) {
				suppressedNavigationAddress = null;
			}
			Swing.runLater(() -> suppressLocationFollow = false);
		}
	}

	void focusPseudocodeAt(Address address) {
		if (address == null) {
			return;
		}
		focusPseudocodeUsage(address, null, null);
	}

	void focusPseudocodeUsage(Address address, String rawValue, String value) {
		if (address == null) {
			return;
		}
		Program program = navigationProgram();
		if (program == null) {
			return;
		}
		Function function = program.getFunctionManager().getFunctionContaining(address);
		if (function == null) {
			return;
		}
		Function displayed = provider.displayedFunction();
		if (sameFunction(displayed, function) && provider.currentResult() != null) {
			provider.setVisible(true);
			revealPseudocodeUsage(address, rawValue, value);
			provider.focusText();
			return;
		}
		decompileFunction(function, false, false, true, true, address, rawValue, value);
	}

	private boolean revealPseudocodeUsage(Address address, String rawValue, String value) {
		if (rawValue == null && value == null) {
			return provider.revealAddress(address);
		}
		return provider.revealUsage(address, rawValue, value);
	}

	void jumpToDisassembly(ParadiseTokenSpan span) {
		Address address = disassemblyAddress(span);
		if (address == null) {
			Msg.showInfo(this, provider.getComponent(), "Jump to Disassembly",
				"No pseudocode token or program location is selected.");
			return;
		}
		if (!navigateTo(address)) {
			Msg.showInfo(this, provider.getComponent(), "Jump to Disassembly",
				"Could not navigate to " + address + ".");
		}
	}

	private Address disassemblyAddress(ParadiseTokenSpan span) {
		Address spanAddress = span == null ? null : span.address();
		Address selectionAddress =
			currentSelection == null || currentSelection.isEmpty() ? null
					: currentSelection.getMinAddress();
		Address toolAddress = selectionAddress != null ? selectionAddress
				: currentLocation == null ? null : currentLocation.getAddress();
		Function providerFunction = provider.currentFunction();
		Program program = navigationProgram();

		if (toolAddress != null && program != null) {
			Function locationFunction =
				program.getFunctionManager().getFunctionContaining(toolAddress);
			if (locationFunction != null && providerFunction != null &&
				!sameFunction(locationFunction, providerFunction)) {
				return locationFunction.getEntryPoint();
			}
			if (spanAddress == null) {
				return locationFunction == null ? toolAddress : locationFunction.getEntryPoint();
			}
		}
		if (spanAddress != null) {
			return spanAddress;
		}
		if (toolAddress != null) {
			return toolAddress;
		}
		return providerFunction == null ? null : providerFunction.getEntryPoint();
	}

	private Program navigationProgram() {
		ParadiseDecompileResult result = provider.currentResult();
		if (result != null && result.program() != null) {
			return result.program();
		}
		if (currentProgram != null) {
			return currentProgram;
		}
		Function function = provider.currentFunction();
		return function == null ? null : function.getProgram();
	}

	Program activeProgramForFinds() {
		return navigationProgram();
	}

	Function activeFunctionForFinds() {
		Function function = functionAtCursor();
		return function == null ? provider.currentFunction() : function;
	}

	private void followExternalLocation(ProgramLocation location) {
		if (!followExternalLocation() || location == null || !provider.isVisible()) {
			return;
		}
		Address address = location.getAddress();
		if (address == null) {
			return;
		}
		if (address.equals(suppressedNavigationAddress)) {
			suppressedNavigationAddress = null;
			return;
		}
		if (suppressLocationFollow) {
			return;
		}
		Program program = location.getProgram();
		if (program == null) {
			program = currentProgram;
		}
		if (program == null || (currentProgram != null && program != currentProgram)) {
			return;
		}
		Function function = program.getFunctionManager().getFunctionContaining(address);
		if (function == null) {
			return;
		}
		Function displayed = provider.displayedFunction();
		if (sameFunction(displayed, function)) {
			provider.revealAddress(address);
			return;
		}
		decompileFunction(function, false, false, true, false, address);
	}

	void goToAddressOrSymbol(String text) {
		Program program = currentProgram;
		if (program == null && provider.currentResult() != null) {
			program = provider.currentResult().program();
		}
		if (program == null || text == null || text.isBlank()) {
			return;
		}
		Address address = program.getAddressFactory().getAddress(text);
		if (address == null) {
			String normalized = text.startsWith("0x") || text.startsWith("0X") ? text.substring(2)
					: text;
			try {
				long offset = Long.parseUnsignedLong(normalized, 16);
				address = program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
			}
			catch (RuntimeException e) {
				// Fall through to symbol lookup.
			}
		}
		if (address == null) {
			SymbolIterator iterator = program.getSymbolTable().getSymbols(text);
			if (iterator.hasNext()) {
				address = iterator.next().getAddress();
			}
		}
		if (address == null) {
			Msg.showInfo(this, provider.getComponent(), "Go To", "No address or symbol found: " + text);
			return;
		}
		navigateTo(address);
		Function function = program.getFunctionManager().getFunctionContaining(address);
		if (function != null) {
			decompileFunction(function, false, true);
		}
	}

	boolean canOpenCallee(ParadiseTokenSpan span) {
		ParadiseDecompileResult result = provider.currentResult();
		if (result == null || span == null) {
			return false;
		}
		Function target = engine.functionForToken(result.program(), span);
		return target != null && !sameFunction(target, result.function());
	}

	void openCalleeOrJump(ParadiseTokenSpan span) {
		ParadiseDecompileResult result = provider.currentResult();
		if (result == null || span == null) {
			return;
		}
		Function target = engine.functionForToken(result.program(), span);
		if (target != null && !sameFunction(target, result.function())) {
			decompileFunction(target, false, true, !openCalleesInNewTabs());
			return;
		}
		navigateTo(span.address());
	}

	void renameSelectedToken(ParadiseTokenSpan span) {
		ParadiseDecompileResult result = provider.currentResult();
		if (result == null || !result.success()) {
			return;
		}

		if (span != null && span.token().isVariableRef() && span.highSymbol() != null &&
			!span.highSymbol().isGlobal()) {
			renameVariable(result, span);
			return;
		}

		Function function = span == null ? result.function()
				: engine.functionForToken(result.program(), span);
		if (function != null) {
			renameFunction(function);
			return;
		}

		Symbol symbol = symbolForSpan(result, span);
		if (symbol != null) {
			renameSymbol(symbol);
			return;
		}

		renameFunction(result.function());
	}

	void retypeSelectedToken(ParadiseTokenSpan span) {
		ParadiseDecompileResult result = provider.currentResult();
		if (result == null || !result.success()) {
			return;
		}

		if (span != null && span.token().isVariableRef() && span.highSymbol() != null &&
			!span.highSymbol().isGlobal()) {
			DataType dataType = chooseDataType(result.program(), span.highSymbol().getDataType());
			if (dataType != null) {
				updateVariableType(result, span, dataType);
			}
			return;
		}

		editFunctionSignature(result.function());
	}

	void editComment(ParadiseTokenSpan span) {
		ParadiseDecompileResult result = provider.currentResult();
		if (result == null || !result.success()) {
			return;
		}

		Program program = result.program();
		Address address = span == null ? result.function().getEntryPoint() : span.address();
		CodeUnit codeUnit = address == null ? null : program.getListing().getCodeUnitContaining(address);
		String existing = codeUnit == null ? result.function().getComment()
				: codeUnit.getComment(CommentType.EOL);

		JTextArea area = new JTextArea(existing == null ? "" : existing, 7, 64);
		int response = JOptionPane.showConfirmDialog(provider.getComponent(), new JScrollPane(area),
			"Edit Comment", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
		if (response != JOptionPane.OK_OPTION) {
			return;
		}

		String comment = area.getText().trim();
		if (comment.isEmpty()) {
			comment = null;
		}

		int tx = program.startTransaction("Paradise edit comment");
		boolean commit = false;
		try {
			if (codeUnit == null) {
				result.function().setComment(comment);
			}
			else {
				codeUnit.setComment(CommentType.EOL, comment);
			}
			commit = true;
		}
		finally {
			program.endTransaction(tx, commit);
		}
		engine.clearProgramCache(program);
		decompileFunction(result.function(), true, false);
	}

	void applyDraftComment() {
		ParadiseDecompileResult result = provider.currentResult();
		if (result == null || !result.success()) {
			return;
		}
		Function function = result.function();
		String existing = function.getComment();
		String draft = provider.draftComment(result);
		JTextArea area = new JTextArea(existing == null || existing.isBlank() ? draft : existing +
			System.lineSeparator() + draft, 7, 64);
		int response = JOptionPane.showConfirmDialog(provider.getComponent(), new JScrollPane(area),
			"Draft Function Comment", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
		if (response != JOptionPane.OK_OPTION) {
			return;
		}
		String comment = area.getText().trim();
		if (comment.isEmpty()) {
			comment = null;
		}
		Program program = result.program();
		int tx = program.startTransaction("Paradise draft comment");
		boolean commit = false;
		try {
			function.setComment(comment);
			commit = true;
		}
		finally {
			program.endTransaction(tx, commit);
		}
		engine.clearProgramCache(program);
		decompileFunction(function, true, false);
	}

	void showXrefs(ParadiseTokenSpan span) {
		ParadiseDecompileResult result = provider.currentResult();
		if (result == null || !result.success()) {
			return;
		}
		Program program = result.program();
		Address target = xrefTarget(result, span);
		if (target == null) {
			Msg.showInfo(this, provider.getComponent(), "Xrefs", "No address is selected.");
			return;
		}

		List<ParadiseXrefRow> rows = xrefsTo(program, target);
		if (rows.isEmpty()) {
			Msg.showInfo(this, provider.getComponent(), "Xrefs",
				"No references to " + target + ".");
			return;
		}
		provider.showXrefsRows(target, rows);
	}

	void showStringPreview(ParadiseTokenSpan span) {
		StringInfo stringInfo = findStringForSelection(provider.currentResult(), span);
		if (stringInfo == null) {
			Msg.showInfo(this, provider.getComponent(), "String Preview", "No string reference found.");
			return;
		}
		Msg.showInfo(this, provider.getComponent(), "String Preview",
			stringInfo.address() + ": " + preview(stringInfo.value(), 512));
	}

	void renameFromSelectedString(ParadiseTokenSpan span) {
		ParadiseDecompileResult result = provider.currentResult();
		if (result == null || !result.success()) {
			return;
		}
		StringInfo stringInfo = findStringForSelection(result, span);
		if (stringInfo == null) {
			Msg.showInfo(this, provider.getComponent(), "Rename From String",
				"No string reference found.");
			return;
		}

		String suggested = sanitizeIdentifier(stringInfo.value(), "str_" + stringInfo.address());
		String newName = prompt("Rename Function From String", "New function name:", suggested);
		if (newName != null) {
			renameFunctionTo(result.function(), newName);
		}
	}

	void renameWrapperFromTarget(Function function) {
		if (function == null) {
			return;
		}
		Function target = singleDirectCallTarget(function);
		if (target == null) {
			Msg.showInfo(this, provider.getComponent(), "Wrapper Rename",
				"Current function does not have a single direct call target.");
			return;
		}
		String suggested = sanitizeIdentifier("j_" + target.getName(), "j_" + target.getEntryPoint());
		String newName = prompt("Rename Wrapper From Target", "New function name:", suggested);
		if (newName != null) {
			renameFunctionTo(function, newName);
		}
	}

	void openDetectedUserMain() {
		ParadiseDecompileResult result = provider.currentResult();
		Function userMain = detectedUserMain(result);
		if (userMain == null) {
			Msg.showInfo(this, provider.getComponent(), "Detected User Main",
				"No MSVC CRT user main pattern found in the current pseudocode.");
			return;
		}
		if (prepareDetectedUserMain(userMain)) {
			engine.clearProgramCache(userMain.getProgram());
		}
		decompileFunction(userMain, true, true, !openCalleesInNewTabs());
	}

	void openFunctionDiagram() {
		Function function = provider.currentFunction();
		if (function == null) {
			function = functionAtCursor();
		}
		if (function == null) {
			Msg.showInfo(this, provider.getComponent(), "Paradise Diagram",
				"Place the cursor inside a function first.");
			return;
		}
		graphProvider.showGraph(function);
	}

	void openBinaryDiagram() {
		Program program = currentProgram;
		if (program == null && provider.currentResult() != null) {
			program = provider.currentResult().program();
		}
		if (program == null) {
			Msg.showInfo(this, provider.getComponent(), "Paradise Diagram",
				"Open a program first.");
			return;
		}
		graphProvider.showGraph(program);
	}

	void openFunctionFinds() {
		findProvider.scanActiveFunction();
	}

	void openProgramFinds() {
		findProvider.scanWholeProgram();
	}

	void exportCurrentFunction() {
		ParadiseDecompileResult result = provider.currentResult();
		if (result == null) {
			Function function = functionAtCursor();
			if (function != null) {
				decompileFunction(function, false, true);
			}
			return;
		}

		JFileChooser chooser = new JFileChooser();
		chooser.setSelectedFile(new File(safeFileName(result.function().getName()) + ".c"));
		if (chooser.showSaveDialog(provider.getComponent()) != JFileChooser.APPROVE_OPTION) {
			return;
		}

		try {
			Files.writeString(chooser.getSelectedFile().toPath(), codeForExport(result, true),
				StandardCharsets.UTF_8);
			if (exportMetadata()) {
				File metadataFile = metadataFileFor(chooser.getSelectedFile());
				writeMetadata(result.program(), List.of(metadataFor(result.program(), result.function(), result)),
					metadataFile);
			}
			Msg.showInfo(this, provider.getComponent(), "Export Complete",
				"Wrote " + chooser.getSelectedFile());
		}
		catch (IOException e) {
			Msg.showError(this, provider.getComponent(), "Export Failed", e.getMessage(), e);
		}
	}

	private void createActions() {
		addAction("Paradise Decompile Current Function",
			new String[] { "Paradise", "Pseudocode", "Decompile" },
			decompileKeyCode(), decompileKeyModifiers(),
			() -> currentProgram != null || provider.currentResult() != null,
			c -> decompileOrRefresh());
		addAction("Paradise Toggle Pseudocode",
			new String[] { "Paradise", "Pseudocode", "Toggle Pseudocode" }, KeyEvent.VK_TAB, 0,
			() -> currentProgram != null || provider.currentResult() != null,
			c -> togglePseudocode());
		addAction("Paradise Open Function Diagram",
			new String[] { "Paradise", "Diagram", "Open Function Diagram" }, -1, 0,
			() -> currentProgram != null || provider.currentFunction() != null,
			c -> openFunctionDiagram());
		addAction("Paradise Open Binary Diagram",
			new String[] { "Paradise", "Diagram", "Open Binary Diagram" }, -1, 0,
			() -> currentProgram != null || provider.currentResult() != null,
			c -> openBinaryDiagram());
		addAction("Paradise Scan Function Inspector",
			new String[] { "Paradise", "Inspect", "Scan Function URL/Path Inspector" }, -1, 0,
			() -> activeFunctionForFinds() != null, c -> openFunctionFinds());
		addAction("Paradise Scan Binary Inspector",
			new String[] { "Paradise", "Inspect", "Scan Binary URL/Path Inspector" }, -1, 0,
			() -> activeProgramForFinds() != null, c -> openProgramFinds());
		addAction("Paradise Pseudocode Back", new String[] { "Paradise", "Navigate", "Back" },
			KeyEvent.VK_LEFT, historyKeyModifiers(), provider::isVisible, c -> provider.goBack());
		addAction("Paradise Pseudocode Forward", new String[] { "Paradise", "Navigate", "Forward" },
			KeyEvent.VK_RIGHT, historyKeyModifiers(), provider::isVisible,
			c -> provider.goForward());
		addAction("Paradise Pseudocode Close",
			new String[] { "Paradise", "Pseudocode", "Back/Close" },
			KeyEvent.VK_ESCAPE, 0, provider::isVisible, c -> provider.goBackOrClose());
		addAction("Paradise Rename", new String[] { "Paradise", "Edit", "Rename" }, KeyEvent.VK_N, 0,
			() -> provider.currentResult() != null, c -> providerRename());
		addAction("Paradise Retype", new String[] { "Paradise", "Edit", "Retype / Signature" },
			KeyEvent.VK_Y, 0, () -> provider.currentResult() != null, c -> providerRetype());
		addAction("Paradise Comment", new String[] { "Paradise", "Edit", "Comment" },
			KeyEvent.VK_SEMICOLON, 0, () -> provider.currentResult() != null,
			c -> editComment(provider.selectedSpan()));
		addAction("Paradise Show Xrefs", new String[] { "Paradise", "Inspect", "Show Xrefs" },
			KeyEvent.VK_X, 0, () -> provider.currentResult() != null,
			c -> showXrefs(provider.selectedSpan()));
		addAction("Paradise Follow", new String[] { "Paradise", "Navigate", "Follow" },
			KeyEvent.VK_ENTER, 0,
			() -> provider.currentResult() != null, c -> openCalleeOrJump(provider.selectedSpan()));
		addAction("Paradise Jump to Disassembly",
			new String[] { "Paradise", "Navigate", "Jump to Disassembly" }, KeyEvent.VK_SPACE, 0,
			() -> provider.currentResult() != null || currentLocation != null,
			c -> jumpToDisassembly(provider.selectedSpan()));
		addAction("Paradise Go To", new String[] { "Paradise", "Navigate", "Go To" }, KeyEvent.VK_G, 0,
			() -> provider.currentResult() != null, c -> provider.promptGoTo());
		addAction("Paradise Search Pseudocode", new String[] { "Paradise", "Search", "Search" },
			KeyEvent.VK_F, menuShortcutModifiers(), () -> provider.currentResult() != null,
			c -> provider.searchInCurrentTab());
		addAction("Paradise Find Next", new String[] { "Paradise", "Search", "Find Next" },
			KeyEvent.VK_F3, 0, () -> provider.currentResult() != null,
			c -> provider.findNextInCurrentTab());
		addAction("Paradise Refresh Pseudocode",
			new String[] { "Paradise", "Pseudocode", "Refresh" }, -1, 0,
			() -> provider.currentResult() != null, c -> provider.refreshCurrent());
		addAction("Paradise String Preview",
			new String[] { "Paradise", "Inspect", "String Preview" }, -1, 0,
			() -> provider.currentResult() != null, c -> showStringPreview(provider.selectedSpan()));
		addAction("Paradise Rename From String",
			new String[] { "Paradise", "Edit", "Rename Function From String" }, -1, 0,
			() -> provider.currentResult() != null,
			c -> renameFromSelectedString(provider.selectedSpan()));
		addAction("Paradise Rename Wrapper",
			new String[] { "Paradise", "Edit", "Rename Wrapper From Target" }, -1, 0,
			() -> provider.currentFunction() != null,
			c -> renameWrapperFromTarget(provider.currentFunction()));
		addAction("Paradise Open Detected User Main",
			new String[] { "Paradise", "Pseudocode", "Open Detected User Main" }, -1, 0,
			() -> provider.currentResult() != null, c -> openDetectedUserMain());
		addAction("Paradise Highlight Uses", new String[] { "Paradise", "Inspect", "Highlight Uses" },
			-1, 0, () -> provider.currentResult() != null, c -> provider.highlightUses());
		addAction("Paradise Export Current Function",
			new String[] { "Paradise", "Export", "Export Current Function" }, -1, 0,
			() -> provider.currentResult() != null || functionAtCursor() != null,
			c -> exportCurrentFunction());
		addAction("Paradise Export All Functions",
			new String[] { "Paradise", "Export", "Export All Functions" }, -1, 0,
			() -> currentProgram != null, c -> exportAllFunctions());
		addAction("Paradise Settings", new String[] { "Paradise", "Options", "Settings" }, -1, 0,
			() -> true, c -> showSettingsDialog());
		addAction("Paradise Reset Layout", new String[] { "Paradise", "Options", "Reset Layout" }, -1,
			0, () -> true, c -> resetParadiseLayoutDefaults());
	}

	private void addAction(String name, String[] menuPath, int keyCode, int modifiers,
			BooleanSupplier enabled, Consumer<ActionContext> handler) {
		DockingAction action = new DockingAction(name, getName()) {
			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return (keyCode < 0 || hotkeysEnabled()) && enabled.getAsBoolean();
			}

			@Override
			public void actionPerformed(ActionContext context) {
				handler.accept(context);
			}
		};
		MenuData menuData = new MenuData(menuPath, MENU_GROUP);
		if (menuPath.length > 2 && menuPath[0].equals("Paradise")) {
			menuData.setParentMenuGroup(menuPath[1].equals("Options") ? OPTIONS_MENU_GROUP
					: MENU_GROUP);
		}
		action.setMenuBarData(menuData);
		if (keyCode >= 0) {
			action.setKeyBindingData(new KeyBindingData(keyCode, modifiers));
		}
		action.setHelpLocation(new HelpLocation(OPTIONS_TITLE, name));
		action.markHelpUnnecessary();
		tool.addAction(action);
	}

	private int decompileKeyCode() {
		return isMacOs() ? KeyEvent.VK_D : KeyEvent.VK_F5;
	}

	private int decompileKeyModifiers() {
		return isMacOs() ? MAC_DECOMPILE_MODIFIERS : 0;
	}

	private int menuShortcutModifiers() {
		return isMacOs() ? InputEvent.META_DOWN_MASK : InputEvent.CTRL_DOWN_MASK;
	}

	private int historyKeyModifiers() {
		return isMacOs() ? InputEvent.META_DOWN_MASK : InputEvent.ALT_DOWN_MASK;
	}

	private boolean isMacOs() {
		return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("mac");
	}

	private void decompileOrRefresh() {
		if (provider.hasFocusInProvider() && provider.currentResult() != null) {
			provider.refreshCurrent();
			return;
		}
		decompileAtCursor();
	}

	private void providerRename() {
		if (!hotkeysEnabled()) {
			return;
		}
		renameSelectedToken(provider.selectedSpan());
	}

	private void providerRetype() {
		if (!hotkeysEnabled()) {
			return;
		}
		retypeSelectedToken(provider.selectedSpan());
	}

	private void decompileAtCursor() {
		Function function = functionAtCursor();
		if (function == null) {
			Msg.showInfo(this, provider.getComponent(), "Paradise",
				"Place the cursor inside a function first.");
			return;
		}
		decompileFunction(function, false, true);
	}

	private Function functionAtCursor() {
		if (currentProgram == null) {
			return provider.currentFunction();
		}
		if (currentLocation == null || currentLocation.getAddress() == null) {
			return provider.currentFunction();
		}
		return currentProgram.getFunctionManager()
				.getFunctionContaining(currentLocation.getAddress());
	}

	private void renameVariable(ParadiseDecompileResult result, ParadiseTokenSpan span) {
		String currentName = span.highSymbol().getName();
		String newName = prompt("Rename Variable", "New variable name:", currentName);
		if (newName == null || newName.equals(currentName)) {
			return;
		}

		Program program = result.program();
		int tx = program.startTransaction("Paradise rename variable");
		boolean commit = false;
		try {
			HighFunctionDBUtil.updateDBVariable(span.highSymbol(), newName, null,
				SourceType.USER_DEFINED);
			commit = true;
		}
		catch (Exception e) {
			Msg.showError(this, provider.getComponent(), "Rename Failed", e.getMessage(), e);
		}
		finally {
			program.endTransaction(tx, commit);
		}
		if (commit) {
			engine.clearProgramCache(program);
			decompileFunction(result.function(), true, false);
		}
	}

	private void renameFunction(Function function) {
		String currentName = function.getName();
		String newName = prompt("Rename Function", "New function name:", currentName);
		if (newName == null || newName.equals(currentName)) {
			return;
		}
		renameFunctionTo(function, newName);
	}

	private void renameFunctionTo(Function function, String newName) {
		Program program = function.getProgram();
		int tx = program.startTransaction("Paradise rename function");
		boolean commit = false;
		try {
			function.setName(newName, SourceType.USER_DEFINED);
			commit = true;
		}
		catch (Exception e) {
			Msg.showError(this, provider.getComponent(), "Rename Failed", e.getMessage(), e);
		}
		finally {
			program.endTransaction(tx, commit);
		}
		if (commit) {
			engine.clearProgramCache(program);
			Function current = provider.currentFunction();
			if (current != null && current.getProgram() == program) {
				decompileFunction(current, true, false);
			}
		}
	}

	private void renameSymbol(Symbol symbol) {
		String currentName = symbol.getName();
		String newName = prompt("Rename Symbol", "New symbol name:", currentName);
		if (newName == null || newName.equals(currentName)) {
			return;
		}

		Program program = symbol.getProgram();
		int tx = program.startTransaction("Paradise rename symbol");
		boolean commit = false;
		try {
			symbol.setName(newName, SourceType.USER_DEFINED);
			commit = true;
		}
		catch (Exception e) {
			Msg.showError(this, provider.getComponent(), "Rename Failed", e.getMessage(), e);
		}
		finally {
			program.endTransaction(tx, commit);
		}
		if (commit) {
			engine.clearProgramCache(program);
			Function current = provider.currentFunction();
			if (current != null && current.getProgram() == program) {
				decompileFunction(current, true, false);
			}
		}
	}

	private void updateVariableType(ParadiseDecompileResult result, ParadiseTokenSpan span,
			DataType dataType) {
		Program program = result.program();
		int tx = program.startTransaction("Paradise retype variable");
		boolean commit = false;
		try {
			if (dataType.getDataTypeManager() != program.getDataTypeManager()) {
				dataType = program.getDataTypeManager().resolve(dataType, null);
			}
			HighFunctionDBUtil.updateDBVariable(span.highSymbol(), null, dataType,
				SourceType.USER_DEFINED);
			commit = true;
		}
		catch (Exception e) {
			Msg.showError(this, provider.getComponent(), "Retype Failed", e.getMessage(), e);
		}
		finally {
			program.endTransaction(tx, commit);
		}
		if (commit) {
			engine.clearProgramCache(program);
			decompileFunction(result.function(), true, false);
		}
	}

	private void editFunctionSignature(Function function) {
		JTextArea area = new JTextArea(function.getPrototypeString(false, true), 4, 72);
		int response = JOptionPane.showConfirmDialog(provider.getComponent(), new JScrollPane(area),
			"Edit Function Signature", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
		if (response != JOptionPane.OK_OPTION) {
			return;
		}

		String signature = area.getText().trim();
		if (signature.isEmpty()) {
			return;
		}

		Program program = function.getProgram();
		try {
			FunctionSignatureParser parser =
				new FunctionSignatureParser(program.getDataTypeManager(), null);
			FunctionDefinitionDataType definition = parser.parse(function.getSignature(), signature);
			ApplyFunctionSignatureCmd command =
				new ApplyFunctionSignatureCmd(function.getEntryPoint(), definition,
					SourceType.USER_DEFINED);
			int tx = program.startTransaction("Paradise edit function signature");
			boolean commit = false;
			try {
				commit = command.applyTo(program, TaskMonitor.DUMMY);
				if (!commit) {
					Msg.showError(this, provider.getComponent(), "Signature Failed",
						command.getStatusMsg());
				}
			}
			finally {
				program.endTransaction(tx, commit);
			}
			if (commit) {
				engine.clearProgramCache(program);
				Function updated = program.getFunctionManager().getFunctionAt(function.getEntryPoint());
				decompileFunction(updated == null ? function : updated, true, false);
			}
		}
		catch (Exception e) {
			Msg.showError(this, provider.getComponent(), "Signature Failed", e.getMessage(), e);
		}
	}

	private DataType chooseDataType(Program program, DataType initialType) {
		DataTypeSelectionDialog dialog = new DataTypeSelectionDialog(tool,
			program.getDataTypeManager(), Integer.MAX_VALUE, AllowedDataTypes.FIXED_LENGTH);
		dialog.setInitialDataType(initialType);
		tool.showDialog(dialog);
		return dialog.getUserChosenDataType();
	}

	private String prompt(String title, String label, String initialValue) {
		Object value = JOptionPane.showInputDialog(provider.getComponent(), label, title,
			JOptionPane.PLAIN_MESSAGE, null, null, initialValue);
		if (value == null) {
			return null;
		}
		String text = value.toString().trim();
		return text.isEmpty() ? null : text;
	}

	private void exportAllFunctions() {
		Program program = currentProgram;
		if (program == null) {
			return;
		}

		boolean folderMode = EXPORT_PER_FUNCTION.equals(exportMode());
		JFileChooser chooser = new JFileChooser();
		if (folderMode) {
			chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
			chooser.setSelectedFile(new File(safeFileName(program.getName()) + "_decompiled"));
		}
		else {
			chooser.setSelectedFile(new File(safeFileName(program.getName()) + "_decompiled.c"));
		}
		if (chooser.showSaveDialog(provider.getComponent()) != JFileChooser.APPROVE_OPTION) {
			return;
		}

		File output = chooser.getSelectedFile();
		TaskLauncher.launch(new Task("Export all decompiled functions", true, true, true) {
			@Override
			public void run(TaskMonitor monitor) throws CancelledException {
				List<ExportMetadata> metadata = new ArrayList<>();
				boolean success = false;
				try {
					monitor.initialize(program.getFunctionManager().getFunctionCount());
					if (folderMode) {
						Files.createDirectories(output.toPath());
						exportFunctionsToFolder(program, output, metadata, monitor);
					}
					else {
						exportFunctionsToSingleFile(program, output, metadata, monitor);
					}
					if (exportMetadata()) {
						File metadataFile = folderMode ? new File(output, "metadata.json")
								: metadataFileFor(output);
						writeMetadata(program, metadata, metadataFile);
					}
					success = true;
				}
				catch (IOException | RuntimeException e) {
					Swing.runLater(() -> Msg.showError(ParadisePlugin.this,
						provider.getComponent(), "Export Failed", e.getMessage(), e));
				}
				if (success) {
					Swing.runLater(() -> Msg.showInfo(ParadisePlugin.this,
						provider.getComponent(), "Export Complete", "Wrote " + output));
				}
			}
		});
	}

	private void exportFunctionsToSingleFile(Program program, File outputFile,
			List<ExportMetadata> metadata, TaskMonitor monitor) throws IOException, CancelledException {
		try (BufferedWriter writer =
			Files.newBufferedWriter(outputFile.toPath(), StandardCharsets.UTF_8)) {
			if (cleanCMode()) {
				writer.write(cleanCHeader());
				writer.newLine();
				writer.newLine();
			}
			for (Function function : program.getFunctionManager().getFunctions(true)) {
				monitor.checkCancelled();
				monitor.incrementProgress(1);
				monitor.setMessage(function.getName());
				if (function.isExternal()) {
					continue;
				}
				ParadiseDecompileResult result = decompileForExport(program, function, monitor);
				metadata.add(metadataFor(program, function, result));
				writer.write("/* ");
				writer.write(function.getEntryPoint().toString());
				writer.write(" ");
				writer.write(function.getName());
				writer.write(" */");
				writer.newLine();
				writer.write(result.code());
				writer.newLine();
			}
		}
	}

	private void exportFunctionsToFolder(Program program, File outputFolder,
			List<ExportMetadata> metadata, TaskMonitor monitor) throws IOException, CancelledException {
		for (Function function : program.getFunctionManager().getFunctions(true)) {
			monitor.checkCancelled();
			monitor.incrementProgress(1);
			monitor.setMessage(function.getName());
			if (function.isExternal()) {
				continue;
			}
			ParadiseDecompileResult result = decompileForExport(program, function, monitor);
			metadata.add(metadataFor(program, function, result));
			File outputFile = new File(outputFolder,
				safeFileName(function.getEntryPoint() + "_" + function.getName()) + ".c");
			Files.writeString(outputFile.toPath(), codeForExport(result, true),
				StandardCharsets.UTF_8);
		}
	}

	private ParadiseDecompileResult decompileForExport(Program program, Function function,
			TaskMonitor monitor) {
		return engine.decompile(program, function, timeoutSeconds(), false, monitor,
			cleanupOptions(), displayTypeAliases(), cleanLiterals(), showAddressComments());
	}

	private String codeForExport(ParadiseDecompileResult result, boolean includeHeader) {
		if (!includeHeader || !cleanCMode()) {
			return result.code();
		}
		return cleanCHeader() + System.lineSeparator() + System.lineSeparator() + result.code();
	}

	private String cleanCHeader() {
		return "#include <stdint.h>" + System.lineSeparator() + "#include <stdarg.h>" +
			System.lineSeparator() + "#include <stdio.h>" + System.lineSeparator() +
			"#include <string.h>";
	}

	private void registerOptions() {
		ToolOptions toolOptions = options();
		toolOptions.registerOption(OPTION_ENABLE_HOTKEYS, DEFAULT_ENABLE_HOTKEYS, null,
			"Enable Paradise platform-aware decompile, search, copy, Tab, N, Y, semicolon, X, Enter, and history key bindings.");
		toolOptions.registerOption(OPTION_SYNC_LISTING, DEFAULT_SYNC_LISTING, null,
			"Navigate the listing when clicking pseudocode tokens.");
		toolOptions.registerOption(OPTION_FOLLOW_EXTERNAL_LOCATION,
			DEFAULT_FOLLOW_EXTERNAL_LOCATION, null,
			"Update Paradise pseudocode when the Listing or Decompiler location changes.");
		toolOptions.registerOption(OPTION_TIMEOUT_SECONDS, DEFAULT_TIMEOUT_SECONDS, null,
			"Maximum seconds to spend decompiling one function.");
		toolOptions.registerOption(OPTION_FONT_SIZE, DEFAULT_FONT_SIZE, null,
			"Font size used by the Paradise pseudocode provider.");
		toolOptions.registerOption(OPTION_THEME_PRESET, THEME_LIGHT, null,
			"Color preset for the Paradise pseudocode surface.");
		toolOptions.registerOption(OPTION_SHOW_GUTTER, DEFAULT_SHOW_GUTTER, null,
			"Show the pseudocode gutter.");
		toolOptions.registerOption(OPTION_SHOW_LINE_NUMBERS, DEFAULT_SHOW_LINE_NUMBERS, null,
			"Show line numbers in the pseudocode gutter.");
		toolOptions.registerOption(OPTION_SHOW_TOKEN_ADDRESSES, DEFAULT_SHOW_TOKEN_ADDRESSES, null,
			"Show token addresses in the pseudocode gutter.");
		toolOptions.registerOption(OPTION_SHOW_AUX_PANELS, DEFAULT_SHOW_AUX_PANELS, null,
			"Show the Paradise bottom inspection panels.");
		toolOptions.registerOption(OPTION_VIEW_XREFS, DEFAULT_SHOW_AUX_TAB, null,
			"Show the Xrefs bottom panel tab.");
		toolOptions.registerOption(OPTION_VIEW_LOCALS, DEFAULT_SHOW_AUX_TAB, null,
			"Show the Locals bottom panel tab.");
		toolOptions.registerOption(OPTION_VIEW_TRACE, DEFAULT_SHOW_AUX_TAB, null,
			"Show the Trace bottom panel tab.");
		toolOptions.registerOption(OPTION_VIEW_CALLS, DEFAULT_SHOW_AUX_TAB, null,
			"Show the Calls bottom panel tab.");
		toolOptions.registerOption(OPTION_VIEW_STRINGS, DEFAULT_SHOW_AUX_TAB, null,
			"Show the Strings bottom panel tab.");
		toolOptions.registerOption(OPTION_VIEW_DIFF, DEFAULT_SHOW_AUX_TAB, null,
			"Show the Diff bottom panel tab.");
		toolOptions.registerOption(OPTION_VIEW_DRAFTS, DEFAULT_SHOW_AUX_TAB, null,
			"Show the Drafts bottom panel tab.");
		toolOptions.registerOption(OPTION_VIEW_SUGGESTIONS, DEFAULT_SHOW_AUX_TAB, null,
			"Show the Suggestions bottom panel tab.");
		toolOptions.registerOption(OPTION_VIEW_TRIAGE, DEFAULT_SHOW_AUX_TAB, null,
			"Show the Triage bottom panel tab.");
		toolOptions.registerOption(OPTION_VIEW_CLEANUPS, DEFAULT_SHOW_AUX_TAB, null,
			"Show the Cleanups bottom panel tab.");
		toolOptions.registerOption(OPTION_VIEW_FINDS_WINDOW, DEFAULT_SHOW_AUX_TAB, null,
			"Show the Paradise URL/path inspector dockable window.");
		toolOptions.registerOption(OPTION_FIND_MERGE_REPEATED, DEFAULT_FIND_MERGE_REPEATED, null,
			"Merge repeated Paradise Inspector rows and show the total in Count.");
		toolOptions.registerOption(OPTION_FIND_COLUMN_PRIORITY, true, null,
			"Show Priority in the Paradise Inspector tables.");
		toolOptions.registerOption(OPTION_FIND_COLUMN_COUNT, true, null,
			"Show Count in the Paradise Inspector tables.");
		toolOptions.registerOption(OPTION_FIND_COLUMN_KIND, true, null,
			"Show Kind in the Paradise Inspector tables.");
		toolOptions.registerOption(OPTION_FIND_COLUMN_ADDRESS, true, null,
			"Show Address in the Paradise Inspector tables.");
		toolOptions.registerOption(OPTION_FIND_COLUMN_USE, true, null,
			"Show Use in the Paradise Inspector tables.");
		toolOptions.registerOption(OPTION_FIND_COLUMN_SOURCE, true, null,
			"Show Source in the Paradise Inspector tables.");
		toolOptions.registerOption(OPTION_FIND_COLUMN_CHAIN, true, null,
			"Show Decode Chain in the Paradise Inspector tables.");
		toolOptions.registerOption(OPTION_FIND_COLUMN_VALUE, true, null,
			"Show Value in the Paradise Inspector tables.");
		toolOptions.registerOption(OPTION_FIND_COLUMN_EVIDENCE, true, null,
			"Show Evidence in the Paradise Inspector tables.");
		toolOptions.registerOption(OPTION_CURRENT_LINE, DEFAULT_CURRENT_LINE, null,
			"Highlight the current pseudocode line.");
		toolOptions.registerOption(OPTION_BRACE_MATCHING, DEFAULT_BRACE_MATCHING, null,
			"Highlight matching braces and parentheses near the caret.");
		toolOptions.registerOption(OPTION_OPEN_CALLEE_NEW_TAB, DEFAULT_OPEN_CALLEE_NEW_TAB, null,
			"Open double-clicked call targets in new pseudocode tabs.");
		toolOptions.registerOption(OPTION_XREF_OPEN_PSEUDOCODE, DEFAULT_XREF_OPEN_PSEUDOCODE, null,
			"Open the containing function in pseudocode when double-clicking an xref.");
		toolOptions.registerOption(OPTION_HIGHLIGHT_USES, DEFAULT_HIGHLIGHT_USES, null,
			"Highlight all matching uses of the selected pseudocode token.");
		toolOptions.registerOption(OPTION_OPEN_DETECTED_MAIN, DEFAULT_OPEN_DETECTED_MAIN, null,
			"Open, name, and type the user main function behind MSVC CRT startup wrappers.");
		toolOptions.registerOption(OPTION_CLEAN_C, DEFAULT_CLEAN_C, null,
			"Display and export cleaner C using stdint aliases and hidden decompiler warnings.");
		toolOptions.registerOption(OPTION_CLEAN_LITERALS, DEFAULT_CLEAN_LITERALS, null,
			"Display low-risk integer constants as cleaner C literals.");
		toolOptions.registerOption(OPTION_CLEAN_STACK_CANARY, DEFAULT_CLEAN_STACK_CANARY, null,
			"Hide common stack canary setup and check noise in Clean C mode.");
		toolOptions.registerOption(OPTION_CLEAN_LOOPS, DEFAULT_CLEAN_LOOPS, null,
			"Rewrite common while(true) and zero-fill loops in Clean C mode.");
		toolOptions.registerOption(OPTION_CLEAN_CONDITIONS, DEFAULT_CLEAN_CONDITIONS, null,
			"Simplify null and boolean conditions in Clean C mode.");
		toolOptions.registerOption(OPTION_CLEAN_COMPOUND_ASSIGNMENTS,
			DEFAULT_CLEAN_COMPOUND_ASSIGNMENTS, null,
			"Render simple self-assignments as +=, ^=, ++, and similar forms.");
		toolOptions.registerOption(OPTION_CLEAN_CALL_ARGUMENTS, DEFAULT_CLEAN_CALL_ARGUMENTS, null,
			"Trim unused call arguments and normalize common call argument literals.");
		toolOptions.registerOption(OPTION_CLEAN_LOCAL_ALIASES, DEFAULT_CLEAN_LOCAL_ALIASES, null,
			"Display conservative local variable aliases without renaming the Ghidra database.");
		toolOptions.registerOption(OPTION_TYPE_ALIASES, DEFAULT_TYPE_ALIASES, null,
			"Display primitive aliases even when Clean C mode is disabled.");
		toolOptions.registerOption(OPTION_ADDRESS_COMMENTS, DEFAULT_ADDRESS_COMMENTS, null,
			"Show address comments beside function and global tokens.");
		toolOptions.registerOption(OPTION_EXPORT_MODE, EXPORT_SINGLE_FILE, null,
			"Export all functions as one C file or as one C file per function.");
		toolOptions.registerOption(OPTION_EXPORT_METADATA, DEFAULT_EXPORT_METADATA, null,
			"Export metadata JSON with function names, entries, xrefs, and warnings.");
		toolOptions.registerOption(OPTION_DIAGRAM_VIEW_STATE, "", null,
			"Internal persisted Paradise diagram zoom, pan, and collapse state.");
	}

	private void showSettingsDialog() {
		JCheckBox hotkeys = new JCheckBox("Enable hotkeys", hotkeysEnabled());
		JCheckBox syncListing = new JCheckBox("Sync listing on token click", syncListingOnClick());
		JCheckBox followExternal =
			new JCheckBox("Follow Listing/Decompiler location", followExternalLocation());
		JSpinner fontSize = new JSpinner(new SpinnerNumberModel(fontSize(), 8, 48, 1));
		JSpinner timeout = new JSpinner(new SpinnerNumberModel(timeoutSeconds(), 1, 600, 1));
		JComboBox<String> themePreset = new JComboBox<>(new String[] { THEME_LIGHT, THEME_DARK });
		themePreset.setSelectedItem(options().getString(OPTION_THEME_PRESET, THEME_LIGHT));
		JCheckBox gutter = new JCheckBox("Show pseudocode gutter", showGutter());
		JCheckBox lineNumbers = new JCheckBox("Show line numbers", showLineNumbers());
		JCheckBox tokenAddresses = new JCheckBox("Show gutter addresses", showTokenAddresses());
		JCheckBox auxPanels = new JCheckBox("Show analysis panels", showAuxPanels());
		JCheckBox viewXrefs = new JCheckBox("Xrefs", showAuxTab("Xrefs"));
		JCheckBox viewLocals = new JCheckBox("Locals", showAuxTab("Locals"));
		JCheckBox viewTrace = new JCheckBox("Trace", showAuxTab("Trace"));
		JCheckBox viewCalls = new JCheckBox("Calls", showAuxTab("Calls"));
		JCheckBox viewStrings = new JCheckBox("Strings", showAuxTab("Strings"));
		JCheckBox viewDiff = new JCheckBox("Diff", showAuxTab("Diff"));
		JCheckBox viewDrafts = new JCheckBox("Drafts", showAuxTab("Drafts"));
		JCheckBox viewSuggestions = new JCheckBox("Suggestions", showAuxTab("Suggestions"));
		JCheckBox viewTriage = new JCheckBox("Triage", showAuxTab("Triage"));
		JCheckBox viewCleanups = new JCheckBox("Cleanups", showAuxTab("Cleanups"));
		JCheckBox viewFinds = new JCheckBox("URL/path inspector window", showFindsWindow());
		JCheckBox mergeFindRows = new JCheckBox("Merge repeated inspector rows",
			mergeRepeatedFinds());
		JCheckBox findColumnPriority = new JCheckBox("Priority", showFindColumn("Priority"));
		JCheckBox findColumnCount = new JCheckBox("Count", showFindColumn("Count"));
		JCheckBox findColumnKind = new JCheckBox("Kind", showFindColumn("Kind"));
		JCheckBox findColumnAddress = new JCheckBox("Address", showFindColumn("Address"));
		JCheckBox findColumnUse = new JCheckBox("Use", showFindColumn("Use"));
		JCheckBox findColumnSource = new JCheckBox("Source", showFindColumn("Source"));
		JCheckBox findColumnChain = new JCheckBox("Decode Chain", showFindColumn("Decode Chain"));
		JCheckBox findColumnValue = new JCheckBox("Value", showFindColumn("Value"));
		JCheckBox findColumnEvidence = new JCheckBox("Evidence", showFindColumn("Evidence"));
		JCheckBox currentLine = new JCheckBox("Highlight current line", currentLineHighlight());
		JCheckBox braceMatch = new JCheckBox("Highlight matching braces", braceMatching());
		JCheckBox newTabs = new JCheckBox("Open callees in new tabs", openCalleesInNewTabs());
		JCheckBox xrefPseudocode =
			new JCheckBox("Open pseudocode from xrefs", openPseudocodeFromXrefs());
		JCheckBox detectedMain =
			new JCheckBox("Open detected user main", openDetectedMain());
		JComboBox<String> exportMode =
			new JComboBox<>(new String[] { EXPORT_SINGLE_FILE, EXPORT_PER_FUNCTION });
		exportMode.setSelectedItem(exportMode());
		JCheckBox typeAliases = new JCheckBox("Display type aliases", displayTypeAliases());
		JCheckBox cleanC = new JCheckBox("Clean C mode", cleanCMode());
		JCheckBox cleanLiterals = new JCheckBox("Clean integer literals", cleanLiterals());
		JCheckBox stackCanaryCleanup =
			new JCheckBox("Stack canary cleanup", cleanStackCanary());
		JCheckBox loopCleanup = new JCheckBox("Loop cleanup", cleanLoops());
		JCheckBox conditionCleanup = new JCheckBox("Condition cleanup", cleanConditions());
		JCheckBox compoundCleanup =
			new JCheckBox("Compound assignment cleanup", cleanCompoundAssignments());
		JCheckBox callArgumentCleanup =
			new JCheckBox("Call argument cleanup", cleanCallArguments());
		JCheckBox localAliasDisplay =
			new JCheckBox("Local alias display", cleanLocalAliases());
		JCheckBox addressComments = new JCheckBox("Show address comments", showAddressComments());
		JCheckBox highlightUses = new JCheckBox("Highlight matching token uses", highlightUsesEnabled());
		JCheckBox metadata = new JCheckBox("Export metadata JSON", exportMetadata());
		JButton resetLayout = new JButton("Reset Layout");
		resetLayout.addActionListener(e -> {
			themePreset.setSelectedItem(THEME_LIGHT);
			gutter.setSelected(DEFAULT_SHOW_GUTTER);
			lineNumbers.setSelected(DEFAULT_SHOW_LINE_NUMBERS);
			tokenAddresses.setSelected(DEFAULT_SHOW_TOKEN_ADDRESSES);
			auxPanels.setSelected(DEFAULT_SHOW_AUX_PANELS);
			viewXrefs.setSelected(DEFAULT_SHOW_AUX_TAB);
			viewLocals.setSelected(DEFAULT_SHOW_AUX_TAB);
			viewTrace.setSelected(DEFAULT_SHOW_AUX_TAB);
			viewCalls.setSelected(DEFAULT_SHOW_AUX_TAB);
			viewStrings.setSelected(DEFAULT_SHOW_AUX_TAB);
			viewDiff.setSelected(DEFAULT_SHOW_AUX_TAB);
			viewDrafts.setSelected(DEFAULT_SHOW_AUX_TAB);
			viewSuggestions.setSelected(DEFAULT_SHOW_AUX_TAB);
			viewTriage.setSelected(DEFAULT_SHOW_AUX_TAB);
			viewCleanups.setSelected(DEFAULT_SHOW_AUX_TAB);
			viewFinds.setSelected(DEFAULT_SHOW_AUX_TAB);
			mergeFindRows.setSelected(DEFAULT_FIND_MERGE_REPEATED);
			findColumnPriority.setSelected(true);
			findColumnCount.setSelected(true);
			findColumnKind.setSelected(true);
			findColumnAddress.setSelected(true);
			findColumnUse.setSelected(true);
			findColumnSource.setSelected(true);
			findColumnChain.setSelected(true);
			findColumnValue.setSelected(true);
			findColumnEvidence.setSelected(true);
			currentLine.setSelected(DEFAULT_CURRENT_LINE);
			braceMatch.setSelected(DEFAULT_BRACE_MATCHING);
			highlightUses.setSelected(DEFAULT_HIGHLIGHT_USES);
			cleanC.setSelected(DEFAULT_CLEAN_C);
			cleanLiterals.setSelected(DEFAULT_CLEAN_LITERALS);
			stackCanaryCleanup.setSelected(DEFAULT_CLEAN_STACK_CANARY);
			loopCleanup.setSelected(DEFAULT_CLEAN_LOOPS);
			conditionCleanup.setSelected(DEFAULT_CLEAN_CONDITIONS);
			compoundCleanup.setSelected(DEFAULT_CLEAN_COMPOUND_ASSIGNMENTS);
			callArgumentCleanup.setSelected(DEFAULT_CLEAN_CALL_ARGUMENTS);
			localAliasDisplay.setSelected(DEFAULT_CLEAN_LOCAL_ALIASES);
			typeAliases.setSelected(DEFAULT_TYPE_ALIASES);
			newTabs.setSelected(DEFAULT_OPEN_CALLEE_NEW_TAB);
			xrefPseudocode.setSelected(DEFAULT_XREF_OPEN_PSEUDOCODE);
			detectedMain.setSelected(DEFAULT_OPEN_DETECTED_MAIN);
			followExternal.setSelected(DEFAULT_FOLLOW_EXTERNAL_LOCATION);
			provider.resetLayout();
		});

		JPanel generalPanel = settingsPanel();
		GridBagConstraints generalGc = settingsConstraints();
		addSectionHeader(generalPanel, generalGc, "General");
		addOption(generalPanel, generalGc, optionSection("Input and Sync", 2, hotkeys,
			syncListing, followExternal, highlightUses));
		addOption(generalPanel, generalGc, optionSection("Navigation", 2, newTabs,
			xrefPseudocode, detectedMain));
		addOption(generalPanel, generalGc, optionSection("Decompiler", 1,
			labeledField("Timeout seconds:", timeout)));
		addSettingsFiller(generalPanel, generalGc);

		JPanel pseudocodePanel = settingsPanel();
		GridBagConstraints pseudocodeGc = settingsConstraints();
		addSectionHeader(pseudocodePanel, pseudocodeGc, "Pseudocode");
		addOption(pseudocodePanel, pseudocodeGc, optionSection("Appearance", 2,
			labeledField("Theme preset:", themePreset),
			labeledField("Font size:", fontSize)));
		addOption(pseudocodePanel, pseudocodeGc, optionSection("Gutter", 3, gutter,
			lineNumbers, tokenAddresses));
		addOption(pseudocodePanel, pseudocodeGc, optionSection("Highlights", 2, currentLine,
			braceMatch));
		addSettingsFiller(pseudocodePanel, pseudocodeGc);

		JPanel cleanupPanel = settingsPanel();
		GridBagConstraints cleanupGc = settingsConstraints();
		addSectionHeader(cleanupPanel, cleanupGc, "Cleanup");
		addOption(cleanupPanel, cleanupGc, optionSection("Clean C", 2, cleanC, cleanLiterals,
			typeAliases, addressComments));
		addOption(cleanupPanel, cleanupGc, optionSection("Cleanup Rules", 2,
			stackCanaryCleanup, loopCleanup, conditionCleanup, compoundCleanup,
			callArgumentCleanup, localAliasDisplay));
		addSettingsFiller(cleanupPanel, cleanupGc);

		JPanel viewsPanel = settingsPanel();
		GridBagConstraints viewsGc = settingsConstraints();
		addSectionHeader(viewsPanel, viewsGc, "Views");
		addOption(viewsPanel, viewsGc, optionSection("Analysis Pane", 1, auxPanels));
		addOption(viewsPanel, viewsGc, optionSection("Visible Tabs", 3, viewXrefs,
			viewLocals, viewTrace, viewCalls, viewStrings, viewDiff, viewDrafts,
			viewSuggestions, viewTriage, viewCleanups));
		addSettingsFiller(viewsPanel, viewsGc);

		JPanel findsPanel = settingsPanel();
		GridBagConstraints findsGc = settingsConstraints();
		addSectionHeader(findsPanel, findsGc, "Inspector");
		addOption(findsPanel, findsGc, optionSection("Window", 2, viewFinds, mergeFindRows));
		addOption(findsPanel, findsGc, optionSection("Columns", 4, findColumnPriority,
			findColumnCount, findColumnKind, findColumnAddress, findColumnUse, findColumnSource,
			findColumnChain, findColumnValue, findColumnEvidence));
		addSettingsFiller(findsPanel, findsGc);

		JPanel exportPanel = settingsPanel();
		GridBagConstraints exportGc = settingsConstraints();
		addSectionHeader(exportPanel, exportGc, "Export");
		addOption(exportPanel, exportGc, optionSection("Output", 2,
			labeledField("Export mode:", exportMode), metadata));
		addSettingsFiller(exportPanel, exportGc);

		JPanel layoutPanel = settingsPanel();
		GridBagConstraints layoutGc = settingsConstraints();
		addSectionHeader(layoutPanel, layoutGc, "Layout");
		addOption(layoutPanel, layoutGc, optionSection("Window Layout", 1,
			new JLabel("Restore Paradise panes, tabs, theme, and cleanup defaults."),
			resetLayout));
		addSettingsFiller(layoutPanel, layoutGc);

		String[] pageNames = { "General", "Pseudocode", "Views", "Inspector", "Cleanup", "Export",
			"Layout" };
		JList<String> pageList = new JList<>(pageNames);
		pageList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		pageList.setSelectedIndex(0);
		pageList.setFixedCellHeight(34);
		pageList.setBorder(BorderFactory.createEmptyBorder(8, 6, 8, 6));
		pageList.setBackground(new Color(244, 245, 247));
		pageList.setSelectionBackground(new Color(218, 231, 252));
		pageList.setSelectionForeground(new Color(18, 24, 32));
		pageList.setCellRenderer(new DefaultListCellRenderer() {
			@Override
			public java.awt.Component getListCellRendererComponent(JList<?> list, Object value,
					int index, boolean selected, boolean focus) {
				JLabel label = (JLabel) super.getListCellRendererComponent(list, value, index,
					selected, focus);
				label.setBorder(BorderFactory.createEmptyBorder(6, 10, 6, 10));
				label.setOpaque(true);
				if (selected) {
					label.setBackground(new Color(218, 231, 252));
					label.setForeground(new Color(18, 24, 32));
					label.setFont(label.getFont().deriveFont(java.awt.Font.BOLD));
				}
				else {
					label.setBackground(new Color(244, 245, 247));
					label.setForeground(new Color(42, 48, 56));
				}
				return label;
			}
		});

		CardLayout pageLayout = new CardLayout();
		JPanel pageCards = new JPanel(pageLayout);
		pageCards.add(settingsScroll(generalPanel), "General");
		pageCards.add(settingsScroll(pseudocodePanel), "Pseudocode");
		pageCards.add(settingsScroll(viewsPanel), "Views");
		pageCards.add(settingsScroll(findsPanel), "Inspector");
		pageCards.add(settingsScroll(cleanupPanel), "Cleanup");
		pageCards.add(settingsScroll(exportPanel), "Export");
		pageCards.add(settingsScroll(layoutPanel), "Layout");
		pageList.addListSelectionListener(e -> {
			if (!e.getValueIsAdjusting()) {
				pageLayout.show(pageCards, pageList.getSelectedValue());
			}
		});

		JPanel settingsRoot = new JPanel(new BorderLayout());
		settingsRoot.setPreferredSize(new Dimension(760, 470));
		settingsRoot.setMinimumSize(new Dimension(700, 420));
		JLabel title = new JLabel("Paradise Settings");
		title.setFont(title.getFont().deriveFont(java.awt.Font.BOLD, 15f));
		title.setBorder(BorderFactory.createEmptyBorder(0, 2, 10, 0));
		settingsRoot.add(title, BorderLayout.NORTH);
		JScrollPane navigation = new JScrollPane(pageList);
		navigation.setBorder(BorderFactory.createMatteBorder(0, 0, 0, 1,
			new Color(210, 214, 220)));
		navigation.setPreferredSize(new Dimension(150, 1));
		settingsRoot.add(navigation, BorderLayout.WEST);
		settingsRoot.add(pageCards, BorderLayout.CENTER);

		int response = JOptionPane.showConfirmDialog(provider.getComponent(), settingsRoot,
			"Paradise Settings", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
		if (response != JOptionPane.OK_OPTION) {
			return;
		}

		boolean formattingChanged = cleanCMode() != cleanC.isSelected() ||
			cleanLiterals() != cleanLiterals.isSelected() ||
			cleanStackCanary() != stackCanaryCleanup.isSelected() ||
			cleanLoops() != loopCleanup.isSelected() ||
			cleanConditions() != conditionCleanup.isSelected() ||
			cleanCompoundAssignments() != compoundCleanup.isSelected() ||
			cleanCallArguments() != callArgumentCleanup.isSelected() ||
			cleanLocalAliases() != localAliasDisplay.isSelected() ||
			displayTypeAliases() != typeAliases.isSelected() ||
			showAddressComments() != addressComments.isSelected();
		boolean findsMergeChanged = mergeRepeatedFinds() != mergeFindRows.isSelected();
		ToolOptions toolOptions = options();
		toolOptions.setBoolean(OPTION_ENABLE_HOTKEYS, hotkeys.isSelected());
		toolOptions.setBoolean(OPTION_SYNC_LISTING, syncListing.isSelected());
		toolOptions.setBoolean(OPTION_FOLLOW_EXTERNAL_LOCATION, followExternal.isSelected());
		toolOptions.setInt(OPTION_FONT_SIZE, (Integer) fontSize.getValue());
		toolOptions.setInt(OPTION_TIMEOUT_SECONDS, (Integer) timeout.getValue());
		toolOptions.setString(OPTION_THEME_PRESET, Objects.toString(themePreset.getSelectedItem(),
			THEME_LIGHT));
		toolOptions.setBoolean(OPTION_SHOW_GUTTER, gutter.isSelected());
		toolOptions.setBoolean(OPTION_SHOW_LINE_NUMBERS, lineNumbers.isSelected());
		toolOptions.setBoolean(OPTION_SHOW_TOKEN_ADDRESSES, tokenAddresses.isSelected());
		toolOptions.setBoolean(OPTION_SHOW_AUX_PANELS, auxPanels.isSelected());
		toolOptions.setBoolean(OPTION_VIEW_XREFS, viewXrefs.isSelected());
		toolOptions.setBoolean(OPTION_VIEW_LOCALS, viewLocals.isSelected());
		toolOptions.setBoolean(OPTION_VIEW_TRACE, viewTrace.isSelected());
		toolOptions.setBoolean(OPTION_VIEW_CALLS, viewCalls.isSelected());
		toolOptions.setBoolean(OPTION_VIEW_STRINGS, viewStrings.isSelected());
		toolOptions.setBoolean(OPTION_VIEW_DIFF, viewDiff.isSelected());
		toolOptions.setBoolean(OPTION_VIEW_DRAFTS, viewDrafts.isSelected());
		toolOptions.setBoolean(OPTION_VIEW_SUGGESTIONS, viewSuggestions.isSelected());
		toolOptions.setBoolean(OPTION_VIEW_TRIAGE, viewTriage.isSelected());
		toolOptions.setBoolean(OPTION_VIEW_CLEANUPS, viewCleanups.isSelected());
		toolOptions.setBoolean(OPTION_VIEW_FINDS_WINDOW, viewFinds.isSelected());
		toolOptions.setBoolean(OPTION_FIND_MERGE_REPEATED, mergeFindRows.isSelected());
		toolOptions.setBoolean(OPTION_FIND_COLUMN_PRIORITY, findColumnPriority.isSelected());
		toolOptions.setBoolean(OPTION_FIND_COLUMN_COUNT, findColumnCount.isSelected());
		toolOptions.setBoolean(OPTION_FIND_COLUMN_KIND, findColumnKind.isSelected());
		toolOptions.setBoolean(OPTION_FIND_COLUMN_ADDRESS, findColumnAddress.isSelected());
		toolOptions.setBoolean(OPTION_FIND_COLUMN_USE, findColumnUse.isSelected());
		toolOptions.setBoolean(OPTION_FIND_COLUMN_SOURCE, findColumnSource.isSelected());
		toolOptions.setBoolean(OPTION_FIND_COLUMN_CHAIN, findColumnChain.isSelected());
		toolOptions.setBoolean(OPTION_FIND_COLUMN_VALUE, findColumnValue.isSelected());
		toolOptions.setBoolean(OPTION_FIND_COLUMN_EVIDENCE, findColumnEvidence.isSelected());
		toolOptions.setBoolean(OPTION_CURRENT_LINE, currentLine.isSelected());
		toolOptions.setBoolean(OPTION_BRACE_MATCHING, braceMatch.isSelected());
		toolOptions.setBoolean(OPTION_OPEN_CALLEE_NEW_TAB, newTabs.isSelected());
		toolOptions.setBoolean(OPTION_XREF_OPEN_PSEUDOCODE, xrefPseudocode.isSelected());
		toolOptions.setBoolean(OPTION_OPEN_DETECTED_MAIN, detectedMain.isSelected());
		toolOptions.setString(OPTION_EXPORT_MODE, Objects.toString(exportMode.getSelectedItem(),
			EXPORT_SINGLE_FILE));
		toolOptions.setBoolean(OPTION_CLEAN_C, cleanC.isSelected());
		toolOptions.setBoolean(OPTION_CLEAN_LITERALS, cleanLiterals.isSelected());
		toolOptions.setBoolean(OPTION_CLEAN_STACK_CANARY, stackCanaryCleanup.isSelected());
		toolOptions.setBoolean(OPTION_CLEAN_LOOPS, loopCleanup.isSelected());
		toolOptions.setBoolean(OPTION_CLEAN_CONDITIONS, conditionCleanup.isSelected());
		toolOptions.setBoolean(OPTION_CLEAN_COMPOUND_ASSIGNMENTS, compoundCleanup.isSelected());
		toolOptions.setBoolean(OPTION_CLEAN_CALL_ARGUMENTS, callArgumentCleanup.isSelected());
		toolOptions.setBoolean(OPTION_CLEAN_LOCAL_ALIASES, localAliasDisplay.isSelected());
		toolOptions.setBoolean(OPTION_TYPE_ALIASES, typeAliases.isSelected());
		toolOptions.setBoolean(OPTION_ADDRESS_COMMENTS, addressComments.isSelected());
		toolOptions.setBoolean(OPTION_HIGHLIGHT_USES, highlightUses.isSelected());
		toolOptions.setBoolean(OPTION_EXPORT_METADATA, metadata.isSelected());
		provider.applyOptionsToOpenTabs();
		findProvider.setVisible(viewFinds.isSelected());
		findProvider.applyOptions();
		if (findsMergeChanged && findProvider.hasScan()) {
			findProvider.refreshScan();
		}
		if (formattingChanged && provider.currentResult() != null) {
			engine.clearProgramCache(provider.currentResult().program());
			provider.refreshCurrent();
		}
	}

	private void resetParadiseLayoutDefaults() {
		ToolOptions toolOptions = options();
		toolOptions.setString(OPTION_THEME_PRESET, THEME_LIGHT);
		toolOptions.setBoolean(OPTION_SHOW_GUTTER, DEFAULT_SHOW_GUTTER);
		toolOptions.setBoolean(OPTION_SHOW_LINE_NUMBERS, DEFAULT_SHOW_LINE_NUMBERS);
		toolOptions.setBoolean(OPTION_SHOW_TOKEN_ADDRESSES, DEFAULT_SHOW_TOKEN_ADDRESSES);
		toolOptions.setBoolean(OPTION_SHOW_AUX_PANELS, DEFAULT_SHOW_AUX_PANELS);
		toolOptions.setBoolean(OPTION_VIEW_XREFS, DEFAULT_SHOW_AUX_TAB);
		toolOptions.setBoolean(OPTION_VIEW_LOCALS, DEFAULT_SHOW_AUX_TAB);
		toolOptions.setBoolean(OPTION_VIEW_TRACE, DEFAULT_SHOW_AUX_TAB);
		toolOptions.setBoolean(OPTION_VIEW_CALLS, DEFAULT_SHOW_AUX_TAB);
		toolOptions.setBoolean(OPTION_VIEW_STRINGS, DEFAULT_SHOW_AUX_TAB);
		toolOptions.setBoolean(OPTION_VIEW_DIFF, DEFAULT_SHOW_AUX_TAB);
		toolOptions.setBoolean(OPTION_VIEW_DRAFTS, DEFAULT_SHOW_AUX_TAB);
		toolOptions.setBoolean(OPTION_VIEW_SUGGESTIONS, DEFAULT_SHOW_AUX_TAB);
		toolOptions.setBoolean(OPTION_VIEW_TRIAGE, DEFAULT_SHOW_AUX_TAB);
		toolOptions.setBoolean(OPTION_VIEW_CLEANUPS, DEFAULT_SHOW_AUX_TAB);
		toolOptions.setBoolean(OPTION_VIEW_FINDS_WINDOW, DEFAULT_SHOW_AUX_TAB);
		toolOptions.setBoolean(OPTION_FIND_MERGE_REPEATED, DEFAULT_FIND_MERGE_REPEATED);
		toolOptions.setBoolean(OPTION_FIND_COLUMN_PRIORITY, true);
		toolOptions.setBoolean(OPTION_FIND_COLUMN_COUNT, true);
		toolOptions.setBoolean(OPTION_FIND_COLUMN_KIND, true);
		toolOptions.setBoolean(OPTION_FIND_COLUMN_ADDRESS, true);
		toolOptions.setBoolean(OPTION_FIND_COLUMN_USE, true);
		toolOptions.setBoolean(OPTION_FIND_COLUMN_SOURCE, true);
		toolOptions.setBoolean(OPTION_FIND_COLUMN_CHAIN, true);
		toolOptions.setBoolean(OPTION_FIND_COLUMN_VALUE, true);
		toolOptions.setBoolean(OPTION_FIND_COLUMN_EVIDENCE, true);
		toolOptions.setBoolean(OPTION_CURRENT_LINE, DEFAULT_CURRENT_LINE);
		toolOptions.setBoolean(OPTION_BRACE_MATCHING, DEFAULT_BRACE_MATCHING);
		toolOptions.setBoolean(OPTION_HIGHLIGHT_USES, DEFAULT_HIGHLIGHT_USES);
		toolOptions.setBoolean(OPTION_CLEAN_C, DEFAULT_CLEAN_C);
		toolOptions.setBoolean(OPTION_CLEAN_LITERALS, DEFAULT_CLEAN_LITERALS);
		toolOptions.setBoolean(OPTION_CLEAN_STACK_CANARY, DEFAULT_CLEAN_STACK_CANARY);
		toolOptions.setBoolean(OPTION_CLEAN_LOOPS, DEFAULT_CLEAN_LOOPS);
		toolOptions.setBoolean(OPTION_CLEAN_CONDITIONS, DEFAULT_CLEAN_CONDITIONS);
		toolOptions.setBoolean(OPTION_CLEAN_COMPOUND_ASSIGNMENTS,
			DEFAULT_CLEAN_COMPOUND_ASSIGNMENTS);
		toolOptions.setBoolean(OPTION_CLEAN_CALL_ARGUMENTS, DEFAULT_CLEAN_CALL_ARGUMENTS);
		toolOptions.setBoolean(OPTION_CLEAN_LOCAL_ALIASES, DEFAULT_CLEAN_LOCAL_ALIASES);
		toolOptions.setBoolean(OPTION_TYPE_ALIASES, DEFAULT_TYPE_ALIASES);
		toolOptions.setBoolean(OPTION_FOLLOW_EXTERNAL_LOCATION,
			DEFAULT_FOLLOW_EXTERNAL_LOCATION);
		toolOptions.setBoolean(OPTION_OPEN_CALLEE_NEW_TAB, DEFAULT_OPEN_CALLEE_NEW_TAB);
		toolOptions.setBoolean(OPTION_XREF_OPEN_PSEUDOCODE, DEFAULT_XREF_OPEN_PSEUDOCODE);
		toolOptions.setBoolean(OPTION_OPEN_DETECTED_MAIN, DEFAULT_OPEN_DETECTED_MAIN);
		provider.resetLayout();
		provider.applyOptionsToOpenTabs();
		findProvider.setVisible(DEFAULT_SHOW_AUX_TAB);
		findProvider.applyOptions();
		if (findProvider.hasScan()) {
			findProvider.refreshScan();
		}
	}

	private void addOption(JPanel panel, GridBagConstraints gc, JComponent component) {
		gc.gridx = 0;
		gc.gridwidth = 2;
		gc.weightx = 1;
		gc.fill = GridBagConstraints.HORIZONTAL;
		panel.add(component, gc);
		gc.gridy++;
	}

	private void addSectionHeader(JPanel panel, GridBagConstraints gc, String title) {
		JLabel label = new JLabel(title);
		label.setFont(label.getFont().deriveFont(java.awt.Font.BOLD, 18f));
		label.setBorder(BorderFactory.createEmptyBorder(0, 3, 10, 0));
		addOption(panel, gc, label);
	}

	private JPanel settingsPanel() {
		JPanel panel = new JPanel(new GridBagLayout());
		panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
		return panel;
	}

	private JPanel optionSection(String title, int columns, JComponent... components) {
		JPanel panel = new JPanel(new GridBagLayout());
		panel.setBorder(BorderFactory.createCompoundBorder(BorderFactory.createTitledBorder(title),
			BorderFactory.createEmptyBorder(5, 6, 7, 6)));
		GridBagConstraints gc = new GridBagConstraints();
		gc.insets = new Insets(2, 4, 2, 10);
		gc.anchor = GridBagConstraints.WEST;
		gc.fill = GridBagConstraints.HORIZONTAL;
		gc.weightx = 1;
		int safeColumns = Math.max(1, columns);
		for (int i = 0; i < components.length; i++) {
			JComponent component = components[i];
			gc.gridx = i % safeColumns;
			gc.gridy = i / safeColumns;
			panel.add(component, gc);
		}
		for (int i = components.length; i < safeColumns; i++) {
			gc.gridx = i;
			gc.gridy = 0;
			panel.add(Box.createHorizontalStrut(1), gc);
		}
		return panel;
	}

	private JPanel labeledField(String label, JComponent component) {
		JPanel panel = new JPanel(new BorderLayout(8, 0));
		JLabel labelComponent = new JLabel(label);
		labelComponent.setLabelFor(component);
		panel.add(labelComponent, BorderLayout.WEST);
		panel.add(component, BorderLayout.CENTER);
		return panel;
	}

	private JScrollPane settingsScroll(JPanel panel) {
		JScrollPane scrollPane = new JScrollPane(panel);
		scrollPane.setBorder(BorderFactory.createEmptyBorder());
		scrollPane.getVerticalScrollBar().setUnitIncrement(16);
		return scrollPane;
	}

	private GridBagConstraints settingsConstraints() {
		GridBagConstraints gc = new GridBagConstraints();
		gc.gridx = 0;
		gc.gridy = 0;
		gc.anchor = GridBagConstraints.WEST;
		gc.insets = new Insets(3, 3, 3, 3);
		return gc;
	}

	private void addSettingsFiller(JPanel panel, GridBagConstraints gc) {
		gc.gridx = 0;
		gc.gridwidth = 2;
		gc.weightx = 1;
		gc.weighty = 1;
		gc.fill = GridBagConstraints.BOTH;
		panel.add(Box.createGlue(), gc);
		gc.gridy++;
		gc.weighty = 0;
	}

	private ToolOptions options() {
		return tool.getOptions(OPTIONS_TITLE);
	}

	boolean openCalleesInNewTabs() {
		return options().getBoolean(OPTION_OPEN_CALLEE_NEW_TAB, DEFAULT_OPEN_CALLEE_NEW_TAB);
	}

	private boolean openPseudocodeFromXrefs() {
		return options().getBoolean(OPTION_XREF_OPEN_PSEUDOCODE, DEFAULT_XREF_OPEN_PSEUDOCODE);
	}

	private boolean openDetectedMain() {
		return options().getBoolean(OPTION_OPEN_DETECTED_MAIN, DEFAULT_OPEN_DETECTED_MAIN);
	}

	private boolean cleanCMode() {
		return options().getBoolean(OPTION_CLEAN_C, DEFAULT_CLEAN_C);
	}

	private ParadiseCleanupOptions cleanupOptions() {
		return new ParadiseCleanupOptions(cleanCMode(), cleanStackCanary(), cleanLoops(),
			cleanConditions(), cleanCompoundAssignments(), cleanCallArguments(),
			cleanLocalAliases());
	}

	private boolean cleanLiterals() {
		return options().getBoolean(OPTION_CLEAN_LITERALS, DEFAULT_CLEAN_LITERALS);
	}

	private boolean cleanStackCanary() {
		return options().getBoolean(OPTION_CLEAN_STACK_CANARY, DEFAULT_CLEAN_STACK_CANARY);
	}

	private boolean cleanLoops() {
		return options().getBoolean(OPTION_CLEAN_LOOPS, DEFAULT_CLEAN_LOOPS);
	}

	private boolean cleanConditions() {
		return options().getBoolean(OPTION_CLEAN_CONDITIONS, DEFAULT_CLEAN_CONDITIONS);
	}

	private boolean cleanCompoundAssignments() {
		return options().getBoolean(OPTION_CLEAN_COMPOUND_ASSIGNMENTS,
			DEFAULT_CLEAN_COMPOUND_ASSIGNMENTS);
	}

	private boolean cleanCallArguments() {
		return options().getBoolean(OPTION_CLEAN_CALL_ARGUMENTS, DEFAULT_CLEAN_CALL_ARGUMENTS);
	}

	private boolean cleanLocalAliases() {
		return options().getBoolean(OPTION_CLEAN_LOCAL_ALIASES, DEFAULT_CLEAN_LOCAL_ALIASES);
	}

	private boolean displayTypeAliases() {
		return options().getBoolean(OPTION_TYPE_ALIASES, DEFAULT_TYPE_ALIASES);
	}

	private boolean showAddressComments() {
		return options().getBoolean(OPTION_ADDRESS_COMMENTS, DEFAULT_ADDRESS_COMMENTS);
	}

	private String exportMode() {
		return options().getString(OPTION_EXPORT_MODE, EXPORT_SINGLE_FILE);
	}

	private boolean exportMetadata() {
		return options().getBoolean(OPTION_EXPORT_METADATA, DEFAULT_EXPORT_METADATA);
	}

	private Symbol symbolForSpan(ParadiseDecompileResult result, ParadiseTokenSpan span) {
		if (span == null) {
			return null;
		}
		if (span.highSymbol() != null && span.highSymbol().getSymbol() != null) {
			return span.highSymbol().getSymbol();
		}
		Address address = span.address();
		if (address == null) {
			return null;
		}
		return result.program().getSymbolTable().getPrimarySymbol(address);
	}

	private Address xrefTarget(ParadiseDecompileResult result, ParadiseTokenSpan span) {
		if (span == null) {
			return result.function().getEntryPoint();
		}
		Function function = engine.functionForToken(result.program(), span);
		if (function != null) {
			return function.getEntryPoint();
		}
		Symbol symbol = symbolForSpan(result, span);
		if (symbol != null) {
			return symbol.getAddress();
		}
		return span.address();
	}

	private List<ParadiseXrefRow> xrefsTo(Program program, Address target) {
		List<ParadiseXrefRow> rows = new ArrayList<>();
		ReferenceIterator iterator = program.getReferenceManager().getReferencesTo(target);
		while (iterator.hasNext()) {
			Reference reference = iterator.next();
			Address from = reference.getFromAddress();
			Function function = program.getFunctionManager().getFunctionContaining(from);
			rows.add(new ParadiseXrefRow(from, function, reference.getReferenceType().getDisplayString(),
				previewFor(program, from)));
		}
		return rows;
	}

	private String previewFor(Program program, Address address) {
		CodeUnit codeUnit = program.getListing().getCodeUnitContaining(address);
		if (codeUnit == null) {
			return "";
		}
		if (codeUnit instanceof Instruction instruction) {
			StringBuilder builder = new StringBuilder(instruction.getMnemonicString());
			for (int i = 0; i < instruction.getNumOperands(); i++) {
				builder.append(i == 0 ? " " : ", ");
				builder.append(instruction.getDefaultOperandRepresentation(i));
			}
			return builder.toString();
		}
		if (codeUnit instanceof Data data) {
			return data.getMnemonicString() + " " + data.getDefaultValueRepresentation();
		}
		return codeUnit.getMnemonicString();
	}

	private StringInfo findStringForSelection(ParadiseDecompileResult result, ParadiseTokenSpan span) {
		if (result == null || !result.success()) {
			return null;
		}
		Program program = result.program();
		Address address = span == null ? result.function().getEntryPoint() : span.address();
		StringInfo direct = stringAt(program, address);
		if (direct != null) {
			return direct;
		}
		CodeUnit codeUnit =
			address == null ? null : program.getListing().getCodeUnitContaining(address);
		if (codeUnit != null) {
			for (Reference reference : codeUnit.getReferencesFrom()) {
				StringInfo referenced = stringAt(program, reference.getToAddress());
				if (referenced != null) {
					return referenced;
				}
			}
		}
		return null;
	}

	private StringInfo stringAt(Program program, Address address) {
		ParadiseStringUtil.ParadiseString string =
			ParadiseStringUtil.stringAt(program, address);
		return string == null ? null : new StringInfo(string.address(), string.value());
	}

	private Function detectedUserMain(ParadiseDecompileResult result) {
		if (result == null || !result.success()) {
			return null;
		}
		String code = result.code();
		int searchOffset = msvcUserMainSearchOffset(code);
		if (searchOffset < 0) {
			return null;
		}
		for (ParadiseTokenSpan span : result.tokenSpans()) {
			if (span.start() < searchOffset || !isCallText(code, span.start())) {
				continue;
			}
			Function target = engine.functionForToken(result.program(), span);
			if (isDetectedUserMainTarget(result.function(), target)) {
				return target;
			}
		}
		return null;
	}

	private int msvcUserMainSearchOffset(String code) {
		if (code == null || code.isBlank()) {
			return -1;
		}
		String[] requiredMarkers = {
			"__scrt_initialize_crt",
			"__scrt_acquire_startup_lock",
			"_get_initial_narrow_environment",
			"__p___argv",
			"__p___argc"
		};
		int searchOffset = -1;
		for (String marker : requiredMarkers) {
			int index = code.indexOf(marker);
			if (index < 0) {
				return -1;
			}
			searchOffset = Math.max(searchOffset, index + marker.length());
		}
		return searchOffset;
	}

	private boolean isCallText(String code, int start) {
		if (code == null || start < 0 || start >= code.length()) {
			return false;
		}
		int lineEnd = code.indexOf('\n', start);
		if (lineEnd < 0) {
			lineEnd = code.length();
		}
		int paren = code.indexOf('(', start);
		return paren >= start && paren < lineEnd;
	}

	private boolean isDetectedUserMainTarget(Function wrapper, Function target) {
		if (target == null || sameFunction(wrapper, target) || target.isExternal()) {
			return false;
		}
		String name = target.getName();
		return !isRuntimeFunctionName(name);
	}

	private boolean isRuntimeFunctionName(String name) {
		if (name == null) {
			return true;
		}
		return name.startsWith("__scrt_") || name.startsWith("_initterm") ||
			name.startsWith("_get_") || name.startsWith("__p__") ||
			name.startsWith("_register_") || name.equals("exit") || name.equals("_cexit");
	}

	private boolean prepareDetectedUserMain(Function function) {
		Program program = function.getProgram();
		int tx = program.startTransaction("Paradise detect user main");
		boolean commit = false;
		try {
			boolean changed = renameDetectedUserMain(function);
			changed |= applyDetectedUserMainSignature(function);
			commit = changed;
			return changed;
		}
		finally {
			program.endTransaction(tx, commit);
		}
	}

	private boolean renameDetectedUserMain(Function function) {
		if (!isAutoNamedFunction(function) || !isAnalysisOwned(function.getSymbol().getSource())) {
			return false;
		}
		try {
			function.setName("main", SourceType.ANALYSIS);
			return true;
		}
		catch (Exception e) {
			Msg.warn(this, "Could not rename detected user main at " + function.getEntryPoint() +
				": " + e.getMessage());
			return false;
		}
	}

	private boolean applyDetectedUserMainSignature(Function function) {
		if (!isAnalysisOwned(function.getSignatureSource())) {
			return false;
		}
		String name = function.getName();
		String[] signatures = {
			"int " + name + "(int argc, const char **argv, const char **envp)",
			"int " + name + "(int argc, char **argv, char **envp)"
		};
		for (String signature : signatures) {
			if (applyDetectedUserMainSignature(function, signature)) {
				return true;
			}
		}
		return false;
	}

	private boolean applyDetectedUserMainSignature(Function function, String signature) {
		Program program = function.getProgram();
		try {
			FunctionSignatureParser parser =
				new FunctionSignatureParser(program.getDataTypeManager(), null);
			FunctionDefinitionDataType definition = parser.parse(function.getSignature(), signature);
			ApplyFunctionSignatureCmd command =
				new ApplyFunctionSignatureCmd(function.getEntryPoint(), definition,
					SourceType.ANALYSIS);
			if (!command.applyTo(program, TaskMonitor.DUMMY)) {
				Msg.warn(this, "Could not apply detected main signature at " +
					function.getEntryPoint() + ": " + command.getStatusMsg());
				return false;
			}
			return true;
		}
		catch (Exception e) {
			Msg.warn(this, "Could not parse detected main signature at " +
				function.getEntryPoint() + ": " + e.getMessage());
			return false;
		}
	}

	private boolean isAutoNamedFunction(Function function) {
		String name = function.getName();
		return name.startsWith("FUN_") || name.startsWith("sub_") || name.startsWith("LAB_");
	}

	private boolean isAnalysisOwned(SourceType sourceType) {
		return sourceType == null || sourceType.isLowerOrEqualPriorityThan(SourceType.ANALYSIS);
	}

	private Function singleDirectCallTarget(Function function) {
		if (function.isThunk()) {
			Function target = function.getThunkedFunction(true);
			if (target != null) {
				return target;
			}
		}
		Set<Function> targets = new LinkedHashSet<>();
		Program program = function.getProgram();
		for (Instruction instruction : program.getListing().getInstructions(function.getBody(), true)) {
			for (Reference reference : instruction.getReferencesFrom()) {
				if (!reference.getReferenceType().isCall()) {
					continue;
				}
				Function target =
					program.getFunctionManager().getFunctionAt(reference.getToAddress());
				if (target != null && !sameFunction(function, target)) {
					targets.add(target);
				}
			}
		}
		return targets.size() == 1 ? targets.iterator().next() : null;
	}

	private ExportMetadata metadataFor(Program program, Function function,
			ParadiseDecompileResult result) {
		List<String> xrefs = new ArrayList<>();
		ReferenceIterator iterator =
			program.getReferenceManager().getReferencesTo(function.getEntryPoint());
		while (iterator.hasNext()) {
			xrefs.add(iterator.next().getFromAddress().toString());
		}
		return new ExportMetadata(function.getName(), function.getEntryPoint().toString(), xrefs,
			result.message());
	}

	private void writeMetadata(Program program, List<ExportMetadata> metadata, File outputFile)
			throws IOException {
		try (BufferedWriter writer =
			Files.newBufferedWriter(outputFile.toPath(), StandardCharsets.UTF_8)) {
			writer.write("{\n");
			writer.write("  \"program\": \"" + json(program.getName()) + "\",\n");
			writer.write("  \"functions\": [\n");
			for (int i = 0; i < metadata.size(); i++) {
				ExportMetadata entry = metadata.get(i);
				writer.write("    {\n");
				writer.write("      \"name\": \"" + json(entry.name()) + "\",\n");
				writer.write("      \"entry\": \"" + json(entry.entry()) + "\",\n");
				writer.write("      \"xrefs\": [");
				for (int j = 0; j < entry.xrefs().size(); j++) {
					if (j > 0) {
						writer.write(", ");
					}
					writer.write("\"" + json(entry.xrefs().get(j)) + "\"");
				}
				writer.write("],\n");
				writer.write("      \"warning\": ");
				writer.write(entry.warning() == null ? "null" : "\"" + json(entry.warning()) + "\"");
				writer.write("\n    }");
				if (i + 1 < metadata.size()) {
					writer.write(",");
				}
				writer.write("\n");
			}
			writer.write("  ]\n");
			writer.write("}\n");
		}
	}

	private File metadataFileFor(File outputFile) {
		File absolute = outputFile.getAbsoluteFile();
		return new File(absolute.getParentFile(), absolute.getName() + ".metadata.json");
	}

	private String json(String value) {
		return value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n")
				.replace("\r", "\\r").replace("\t", "\\t");
	}

	private boolean sameFunction(Function a, Function b) {
		if (a == null || b == null) {
			return false;
		}
		return a.getProgram() == b.getProgram() && a.getEntryPoint().equals(b.getEntryPoint());
	}

	private String safeFileName(String value) {
		return value.replaceAll("[^A-Za-z0-9._-]+", "_");
	}

	private String preview(String value, int maxLength) {
		if (value == null) {
			return "";
		}
		String oneLine = value.replace('\n', ' ').replace('\r', ' ').replace('\t', ' ');
		return oneLine.length() <= maxLength ? oneLine : oneLine.substring(0, maxLength) + "...";
	}

	private String sanitizeIdentifier(String value, String fallback) {
		String source = value == null || value.isBlank() ? fallback : value;
		String sanitized = source.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9_]+", "_")
				.replaceAll("_+", "_").replaceAll("^_+|_+$", "");
		if (sanitized.isBlank()) {
			sanitized = safeFileName(fallback).toLowerCase(Locale.ROOT);
		}
		if (sanitized.isBlank() || Character.isDigit(sanitized.charAt(0))) {
			sanitized = "str_" + sanitized;
		}
		if (sanitized.length() > 64) {
			sanitized = sanitized.substring(0, 64).replaceAll("_+$", "");
		}
		return sanitized;
	}

	private record StringInfo(Address address, String value) {
	}

	private record ExportMetadata(String name, String entry, List<String> xrefs, String warning) {
	}
}
