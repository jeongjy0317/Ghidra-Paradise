package paradise;

import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.*;
import java.util.*;
import java.util.List;
import java.util.function.BooleanSupplier;
import java.util.function.IntFunction;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.JTableHeader;
import javax.swing.table.TableRowSorter;
import javax.swing.text.*;
import javax.swing.plaf.basic.BasicSplitPaneDivider;
import javax.swing.plaf.basic.BasicSplitPaneUI;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.WindowPosition;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.app.decompiler.ClangToken;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.util.Msg;

final class ParadiseDecompilerProvider extends ComponentProvider {
	private static final int MAC_DECOMPILE_MODIFIERS =
		InputEvent.META_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK;
	private static final Color LIGHT_BG = new Color(255, 255, 248);
	private static final Color LIGHT_GUTTER_BG = new Color(240, 240, 232);
	private static final Color LIGHT_PANEL_BG = new Color(246, 246, 242);
	private static final Color LIGHT_HEADER_BG = new Color(232, 232, 226);
	private static final Color LIGHT_HEADER_FG = new Color(24, 24, 24);
	private static final Color DARK_BG = new Color(28, 30, 32);
	private static final Color DARK_GUTTER_BG = new Color(40, 43, 46);
	private static final Color DARK_PANEL_BG = new Color(38, 40, 42);
	private static final Color DARK_HEADER_BG = new Color(58, 61, 65);
	private static final Color DARK_HEADER_FG = new Color(238, 238, 238);
	private static final Color CURRENT_LINE = new Color(232, 241, 255);
	private static final Color CURRENT_LINE_DARK = new Color(47, 55, 64);
	private static final Color USE_HIGHLIGHT = new Color(255, 238, 170);
	private static final Color TRACE_HIGHLIGHT = new Color(186, 225, 255);
	private static final Color BRACE_HIGHLIGHT = new Color(170, 216, 255);
	private static final Color SEARCH_HIGHLIGHT = new Color(196, 255, 196);
	private static final String FOOTER_TEXT = "Ghidra's Paradise by zer0base";
	private static final Pattern IDENTIFIER_PATTERN = Pattern.compile("[A-Za-z_]\\w*");

	private final ParadisePlugin plugin;
	private final JPanel panel = new JPanel(new BorderLayout());
	private final JPanel mainPanel = new JPanel(new BorderLayout());
	private final JTabbedPane tabs = new JTabbedPane();
	private final JTabbedPane auxTabs = new JTabbedPane();
	private final JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
	private final JLabel statusLabel = new JLabel(FOOTER_TEXT);
	private final JPanel headerPanel = new JPanel(new BorderLayout());
	private final JPanel headerTitleRow = new JPanel(new BorderLayout());
	private final JPanel headerActionRow = new JPanel();
	private final JScrollPane actionScrollPane = new JScrollPane(headerActionRow);
	private final JPanel headerSearchPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 0));
	private final JLabel providerTitleLabel = new JLabel("Paradise Pseudocode");
	private final JLabel functionContextLabel = new JLabel(" ");
	private final JTextField searchField = new JTextField(18);
	private final JLabel searchStatusLabel = new JLabel(" ");
	private final JToggleButton rawToggle = new JToggleButton();
	private final List<AbstractButton> headerButtons = new ArrayList<>();
	private boolean updatingSearchField;
	private final Map<TabKey, PseudocodeTab> tabMap = new LinkedHashMap<>();
	private final Deque<Function> backHistory = new ArrayDeque<>();
	private final Deque<Function> forwardHistory = new ArrayDeque<>();
	private final JPopupMenu popup = new JPopupMenu();

	private final DefaultTableModel xrefsModel =
		model("Direction", "Address", "Function", "Type", "Preview");
	private final DefaultTableModel localsModel =
		model("Kind", "Name", "Type", "Storage", "Source");
	private final DefaultTableModel callsModel =
		model("Direction", "Address", "Function", "Type", "Preview");
	private final DefaultTableModel stringsModel = model("Use", "String", "Preview");
	private final DefaultTableModel cleanupsModel = model("Kind", "Cleanup", "Effect");
	private final DefaultTableModel diffModel = model("Line", "Raw Ghidra", "Paradise Clean C");
	private final DefaultTableModel draftsModel = model("Kind", "Target", "Suggestion");
	private final DefaultTableModel suggestionsModel =
		model("Priority", "Address", "Finding", "Evidence");
	private final DefaultTableModel triageModel =
		model("Entry", "Function", "Score", "Strings", "Calls", "Xrefs", "Hints");
	private final DefaultTableModel traceModel =
		model("Address", "Line", "Role", "Expression", "Value");
	private final JTable xrefsTable = table(xrefsModel);
	private final JTable localsTable = table(localsModel);
	private final JTable callsTable = table(callsModel);
	private final JTable stringsTable = table(stringsModel);
	private final JTable cleanupsTable = table(cleanupsModel);
	private final JTable diffTable = table(diffModel);
	private final JTable draftsTable = table(draftsModel);
	private final JTable suggestionsTable = table(suggestionsModel);
	private final JTable triageTable = table(triageModel);
	private final JTable traceTable = table(traceModel);
	private final JScrollPane xrefsPanel = new JScrollPane(xrefsTable);
	private final JScrollPane localsPanel = new JScrollPane(localsTable);
	private final JScrollPane tracePanel = new JScrollPane(traceTable);
	private final JScrollPane callsPanel = new JScrollPane(callsTable);
	private final JTextField stringsFilterField = new JTextField(18);
	private final JPanel stringsOverviewPanel = filteredTablePanel(stringsTable, stringsFilterField);
	private final Map<ParadiseDecodeUtil.Codec, DefaultTableModel> encodedStringModels =
		new EnumMap<>(ParadiseDecodeUtil.Codec.class);
	private final Map<ParadiseDecodeUtil.Codec, JTable> encodedStringTables =
		new EnumMap<>(ParadiseDecodeUtil.Codec.class);
	private final Map<ParadiseDecodeUtil.Codec, JTextField> encodedStringFilters =
		new EnumMap<>(ParadiseDecodeUtil.Codec.class);
	private final Map<ParadiseDecodeUtil.Codec, JPanel> encodedStringPanels =
		new EnumMap<>(ParadiseDecodeUtil.Codec.class);
	private final JTabbedPane stringsPanel = createStringsPanel();
	private final JScrollPane diffPanel = new JScrollPane(diffTable);
	private final JScrollPane draftsPanel = new JScrollPane(draftsTable);
	private final JScrollPane suggestionsPanel = new JScrollPane(suggestionsTable);
	private final JScrollPane triagePanel = new JScrollPane(triageTable);
	private final JPanel cleanupsPanel = new JPanel(new BorderLayout());
	private final JLabel cleanupsSummaryLabel = new JLabel("No Clean C cleanup data");
	private List<ParadiseXrefRow> xrefRows = List.of();
	private List<CallRow> callRows = List.of();
	private List<StringRow> stringRows = List.of();
	private Map<ParadiseDecodeUtil.Codec, List<EncodedStringRow>> encodedStringRowsByCodec =
		new EnumMap<>(ParadiseDecodeUtil.Codec.class);
	private List<SuggestionRow> suggestionRows = List.of();
	private List<TriageRow> triageRows = List.of();
	private List<TraceRow> traceRows = List.of();

	private JMenuItem renameItem;
	private JMenuItem retypeItem;
	private JMenuItem commentItem;
	private JMenuItem xrefsItem;
	private JMenuItem stringPreviewItem;
	private JMenuItem traceItem;
	private JMenu convertLiteralMenu;
	private JMenu decodeMenu;
	private JMenuItem decodeAutoItem;
	private JMenuItem decodeBase64Item;
	private JMenuItem decodeHexItem;
	private JMenuItem decodeUrlItem;
	private JMenuItem decodeBase32Item;
	private JMenuItem decodeUtf16LeItem;
	private JMenuItem decodeUtf16BeItem;
	private JMenuItem renameFromStringItem;
	private JMenuItem wrapperRenameItem;
	private JMenuItem highlightUsesItem;
	private JMenuItem jumpItem;
	private JMenuItem calleeItem;
	private JMenuItem searchItem;
	private JMenuItem copyIdentifierItem;
	private JMenuItem copyLineItem;
	private JMenuItem refreshItem;
	private JMenuItem exportItem;

	ParadiseDecompilerProvider(ParadisePlugin plugin) {
		super(plugin.getTool(), "Paradise Pseudocode", plugin.getName());
		this.plugin = plugin;
		setTitle("Paradise Pseudocode");
		setWindowMenuGroup("Paradise");
		setDefaultWindowPosition(WindowPosition.RIGHT);
		initEncodedStringViews();
		buildUi();
		createPopup();
		installLocalToolbarActions();
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}

	ParadiseDecompileResult currentResult() {
		PseudocodeTab tab = currentTab();
		return tab == null ? null : tab.result;
	}

	Function currentFunction() {
		ParadiseDecompileResult result = currentResult();
		return result == null ? null : result.function();
	}

	Function displayedFunction() {
		PseudocodeTab tab = currentTab();
		return tab == null ? null : tab.function;
	}

	void showLoading(Function function, boolean addHistory, boolean reuseActiveTab) {
		showLoading(function, addHistory, reuseActiveTab, true);
	}

	void showLoading(Function function, boolean addHistory, boolean reuseActiveTab,
			boolean focusProvider) {
		ParadiseDecompileResult current = currentResult();
		if (addHistory && current != null && current.success() &&
			!sameFunction(current.function(), function)) {
			backHistory.push(current.function());
			forwardHistory.clear();
		}

		PseudocodeTab tab = ensureTab(function, reuseActiveTab);
		tab.function = function;
		tab.result = null;
		tab.displayCode = null;
		tab.displaySpans = List.of();
		tab.literalOverrides.clear();
		tab.lines = List.of();
		tab.traceRows = List.of();
		tab.showRaw = false;
		rawToggle.setSelected(false);
		tabs.setSelectedComponent(tab.panel);
		setVisible(true);
		statusLabel.setText(FOOTER_TEXT);
		updateHeader(function, "Decompiling...");
		applyEditorOptions(tab);
		tab.textPane.setText("/* Decompiling " + function.getName() + " ... */\n");
		updateGutter(tab);
		updateAuxPanels(null);
		tab.textPane.setCaretPosition(0);
		contextChanged();
		if (focusProvider) {
			focusText();
		}
	}

	void showResult(ParadiseDecompileResult result) {
		showResult(result, false);
	}

	void showResult(ParadiseDecompileResult result, boolean reuseActiveTab) {
		showResult(result, reuseActiveTab, true);
	}

	void showResult(ParadiseDecompileResult result, boolean reuseActiveTab, boolean focusProvider) {
		PseudocodeTab tab = ensureTab(result.function(), reuseActiveTab);
		tab.result = result;
		tab.function = result.function();
		tab.literalOverrides.clear();
		tab.displayCode = result.code();
		tab.displaySpans = result.tokenSpans();
		tab.lines = buildLines(result);
		int index = tabs.indexOfComponent(tab.panel);
		if (index >= 0) {
			updateTabTitle(tab, result.function());
		}
		tabs.setSelectedComponent(tab.panel);
		rawToggle.setSelected(tab.showRaw);
		setVisible(true);
		applyEditorOptions(tab);
		render(tab, result);
		updateStatus(result);
		updateAuxPanels(result);
		if (tab.textPane.getDocument().getLength() > 0) {
			tab.textPane.setCaretPosition(Math.min(tab.caretPosition,
				tab.textPane.getDocument().getLength() - 1));
		}
		contextChanged();
		if (focusProvider) {
			focusText();
		}
	}

	boolean revealAddress(Address address) {
		PseudocodeTab tab = currentTab();
		if (tab == null || address == null || tab.textPane.getDocument().getLength() == 0) {
			return false;
		}
		Integer offset = offsetForAddress(tab, address);
		if (offset == null) {
			return false;
		}
		int safeOffset = Math.max(0, Math.min(offset, tab.textPane.getDocument().getLength() - 1));
		tab.textPane.setCaretPosition(safeOffset);
		try {
			Rectangle rect = tab.textPane.modelToView2D(safeOffset).getBounds();
			tab.textPane.scrollRectToVisible(rect);
		}
		catch (BadLocationException e) {
			// Ignore stale offsets after a decompile refresh.
		}
		updateEditorHighlights(tab);
		return true;
	}

	boolean revealUsage(Address address, String rawValue, String value) {
		if (focusStringUsage(address, rawValue)) {
			return true;
		}
		if (!Objects.equals(rawValue, value) && focusStringUsage(address, value)) {
			return true;
		}
		return address != null && revealAddress(address);
	}

	void refreshCurrent() {
		ParadiseDecompileResult result = currentResult();
		if (result != null) {
			plugin.decompileFunction(result.function(), true, false);
		}
	}

	void goBackOrClose() {
		if (!goBack()) {
			setVisible(false);
		}
	}

	boolean goBack() {
		if (backHistory.isEmpty()) {
			return false;
		}
		ParadiseDecompileResult current = currentResult();
		if (current != null && current.success()) {
			forwardHistory.push(current.function());
		}
		plugin.decompileFunction(backHistory.pop(), false, false);
		return true;
	}

	boolean goForward() {
		if (forwardHistory.isEmpty()) {
			return false;
		}
		ParadiseDecompileResult current = currentResult();
		if (current != null && current.success()) {
			backHistory.push(current.function());
		}
		plugin.decompileFunction(forwardHistory.pop(), false, false);
		return true;
	}

	void resetLayout() {
		for (PseudocodeTab tab : new ArrayList<>(tabMap.values())) {
			removeTab(tab);
		}
		backHistory.clear();
		forwardHistory.clear();
		statusLabel.setText(FOOTER_TEXT);
		updateHeader(null, "No function selected");
		updateAuxPanels(null);
		setVisible(false);
	}

	void programClosed(Program program) {
		for (PseudocodeTab tab : new ArrayList<>(tabMap.values())) {
			if (tab.key.program == program) {
				removeTab(tab);
			}
		}
		backHistory.removeIf(f -> f.getProgram() == program);
		forwardHistory.removeIf(f -> f.getProgram() == program);
		updateStatus(currentResult());
		updateAuxPanels(currentResult());
	}

	void focusText() {
		SwingUtilities.invokeLater(() -> {
			PseudocodeTab tab = currentTab();
			if (tab != null) {
				tab.textPane.requestFocusInWindow();
			}
		});
	}

	boolean hasFocusInProvider() {
		return SwingUtilities.isDescendingFrom(
			KeyboardFocusManager.getCurrentKeyboardFocusManager().getFocusOwner(), panel);
	}

	ParadiseTokenSpan selectedSpan() {
		PseudocodeTab tab = currentTab();
		if (tab == null || tab.result == null || tab.displaySpans.isEmpty()) {
			return null;
		}
		int docLength = tab.textPane.getDocument().getLength();
		if (docLength == 0) {
			return null;
		}
		int pos = Math.min(tab.textPane.getCaretPosition(), docLength - 1);
		ParadiseTokenSpan span = tokenAt(tab.displaySpans, pos);
		if (span == null && pos > 0) {
			span = tokenAt(tab.displaySpans, pos - 1);
		}
		return span;
	}

	void highlightUses() {
		updateEditorHighlights(currentTab());
	}

	private ParadiseTokenSpan tokenAt(List<ParadiseTokenSpan> spans, int offset) {
		for (ParadiseTokenSpan span : spans) {
			if (span.contains(offset)) {
				return span;
			}
		}
		return null;
	}

	void applyOptionsToOpenTabs() {
		rebuildAuxTabs();
		styleAuxiliaryUi();
		for (PseudocodeTab tab : tabMap.values()) {
			applyEditorOptions(tab);
			updateGutter(tab);
			updateEditorHighlights(tab);
		}
		boolean showAux = plugin.showAuxPanels() && auxTabs.getTabCount() > 0;
		auxTabs.setVisible(showAux);
		splitPane.setDividerLocation(showAux ? 0.72 : 1.0);
	}

	void showXrefsRows(Address target, List<ParadiseXrefRow> rows) {
		xrefRows = List.copyOf(rows);
		fill(xrefsModel);
		for (ParadiseXrefRow row : rows) {
			xrefsModel.addRow(new Object[] { "to " + target, row.from(), row.functionName(),
				row.type(), row.preview() });
		}
		selectAuxTab("Xrefs");
	}

	void searchInCurrentTab() {
		PseudocodeTab tab = currentTab();
		if (tab == null) {
			return;
		}
		String fieldQuery = searchField.getText().trim();
		if (!fieldQuery.isEmpty()) {
			setSearch(tab, fieldQuery, true, true);
			focusSearchField();
			return;
		}
		String initial = selectedTextOrToken(tab);
		if (initial != null && !initial.isBlank()) {
			String query = initial.trim();
			setSearchFieldText(query);
			setSearch(tab, query, true, false);
		}
		focusSearchField();
	}

	void findNextInCurrentTab() {
		PseudocodeTab tab = currentTab();
		if (tab == null) {
			return;
		}
		String fieldQuery = searchField.getText().trim();
		if (!fieldQuery.isEmpty() && !fieldQuery.equals(tab.searchText)) {
			setSearch(tab, fieldQuery, true, true);
			return;
		}
		if (tab.searchText == null || tab.searchText.isBlank()) {
			searchInCurrentTab();
			return;
		}
		findNext(tab, true);
	}

	private void searchFromField() {
		searchFromField(true);
	}

	private void searchFromField(boolean jumpToMatch) {
		PseudocodeTab tab = currentTab();
		if (tab == null) {
			return;
		}
		String query = searchField.getText().trim();
		if (query.isEmpty()) {
			clearSearch(jumpToMatch);
			return;
		}
		setSearch(tab, query, jumpToMatch, true);
	}

	private void setSearch(PseudocodeTab tab, String query, boolean jumpToMatch,
			boolean focusMatch) {
		tab.searchText = query;
		setSearchFieldText(query);
		int matches = highlightSearch(tab);
		updateSearchStatus(matches, query);
		if (jumpToMatch) {
			findNext(tab, focusMatch);
		}
	}

	private void clearSearch() {
		clearSearch(true);
	}

	private void clearSearch(boolean refocusText) {
		PseudocodeTab tab = currentTab();
		if (tab == null) {
			return;
		}
		tab.searchText = null;
		setSearchFieldText("");
		clearSearchHighlights(tab);
		updateSearchStatus(0, "");
		if (refocusText) {
			focusText();
		}
	}

	private void focusSearchField() {
		SwingUtilities.invokeLater(() -> {
			searchField.requestFocusInWindow();
			searchField.selectAll();
		});
	}

	void smartCopy() {
		PseudocodeTab tab = currentTab();
		if (tab == null) {
			return;
		}
		String selected = tab.textPane.getSelectedText();
		if (selected != null && !selected.isEmpty()) {
			copyText(selected);
			return;
		}
		copyCurrentLine();
	}

	void copyIdentifier() {
		ParadiseTokenSpan span = selectedSpan();
		if (span != null && span.token().getText() != null) {
			copyText(span.token().getText());
		}
	}

	void copyCurrentLine() {
		PseudocodeTab tab = currentTab();
		if (tab == null) {
			return;
		}
		int caret = tab.textPane.getCaretPosition();
		PseudocodeLine line = lineAt(tab, caret);
		if (line == null) {
			return;
		}
		copyText(tab.textPane.getText().substring(line.start(), line.end()));
	}

	private void buildUi() {
		ToolTipManager.sharedInstance().setInitialDelay(250);
		functionContextLabel.setFont(functionContextLabel.getFont().deriveFont(Font.BOLD, 12f));
		functionContextLabel.setHorizontalAlignment(SwingConstants.LEFT);
		functionContextLabel.setBorder(BorderFactory.createEmptyBorder(3, 8, 3, 8));

		searchField.putClientProperty("JTextField.placeholderText", "Find");
		searchField.setToolTipText("Search pseudocode. Press Enter to find next.");
		searchField.addActionListener(e -> searchFromField());
		searchField.getDocument().addDocumentListener(new DocumentListener() {
			@Override
			public void insertUpdate(DocumentEvent e) {
				searchTextChanged();
			}

			@Override
			public void removeUpdate(DocumentEvent e) {
				searchTextChanged();
			}

			@Override
			public void changedUpdate(DocumentEvent e) {
				searchTextChanged();
			}
		});

		tabs.addChangeListener(e -> {
			PseudocodeTab tab = currentTab();
			updateStatus(tab == null ? null : tab.result);
			setSearchFieldText(tab == null || tab.searchText == null ? "" : tab.searchText);
			rawToggle.setSelected(tab != null && tab.showRaw);
			updateAuxPanels(currentResult());
			updateEditorHighlights(tab);
			updateTraceSelectionForCaret(tab);
			contextChanged();
		});
		tabs.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (SwingUtilities.isMiddleMouseButton(e)) {
					int index = tabs.indexAtLocation(e.getX(), e.getY());
					if (index >= 0) {
						java.awt.Component component = tabs.getComponentAt(index);
						for (PseudocodeTab tab : new ArrayList<>(tabMap.values())) {
							if (tab.panel == component) {
								removeTab(tab);
								break;
							}
						}
					}
				}
			}
		});

		headerSearchPanel.setVisible(false);
		headerPanel.add(functionContextLabel, BorderLayout.CENTER);
		headerPanel.add(compactSearchPanel(), BorderLayout.EAST);

		createCleanupsPanel();
		rebuildAuxTabs();
		installTableNavigation();
		styleAuxiliaryUi();

		splitPane.setUI(new DottedSplitPaneUi());
		splitPane.setDividerSize(11);
		splitPane.setBorder(BorderFactory.createEmptyBorder());
		splitPane.setTopComponent(tabs);
		splitPane.setBottomComponent(auxTabs);
		splitPane.setResizeWeight(0.72);
		splitPane.setDividerLocation(0.72);
		auxTabs.setVisible(plugin.showAuxPanels() && auxTabs.getTabCount() > 0);

		mainPanel.add(splitPane, BorderLayout.CENTER);

		panel.add(headerPanel, BorderLayout.NORTH);
		panel.add(mainPanel, BorderLayout.CENTER);
		panel.add(statusLabel, BorderLayout.SOUTH);
	}

	private void installLocalToolbarActions() {
		addToolbarAction("Disasm", ToolbarGlyph.DISASM, "01_navigation", "010",
			() -> currentResult() != null, () -> plugin.jumpToDisassembly(selectedSpan()));
		addToolbarAction("Graph", ToolbarGlyph.GRAPH, "01_navigation", "020",
			() -> currentResult() != null || displayedFunction() != null,
			() -> plugin.openFunctionDiagram());
		addToolbarAction("Back", ToolbarGlyph.BACK, "02_history", "010",
			() -> !backHistory.isEmpty(), () -> goBack());
		addToolbarAction("Forward", ToolbarGlyph.FORWARD, "02_history", "020",
			() -> !forwardHistory.isEmpty(), () -> goForward());
		addToolbarAction("Refresh", ToolbarGlyph.REFRESH, "02_history", "030",
			() -> currentResult() != null, () -> refreshCurrent());
		addToolbarAction("Raw", ToolbarGlyph.RAW, "02_history", "040",
			() -> currentResult() != null && currentResult().success(), () -> toggleRawClean());
		addToolbarAction("Rename", ToolbarGlyph.RENAME, "03_edit", "010",
			() -> currentResult() != null && currentResult().success(),
			() -> plugin.renameSelectedToken(selectedSpan()));
		addToolbarAction("Type", ToolbarGlyph.TYPE, "03_edit", "020",
			() -> currentResult() != null && currentResult().success(),
			() -> plugin.retypeSelectedToken(selectedSpan()));
		addToolbarAction("Comment", ToolbarGlyph.COMMENT, "03_edit", "030",
			() -> currentResult() != null && currentResult().success(),
			() -> plugin.editComment(selectedSpan()));
		addToolbarAction("Draft", ToolbarGlyph.DRAFT, "03_edit", "040",
			() -> currentResult() != null && currentResult().success(),
			() -> plugin.applyDraftComment());
		addToolbarAction("Xrefs", ToolbarGlyph.XREFS, "04_inspect", "010",
			() -> currentResult() != null && currentResult().success(),
			() -> plugin.showXrefs(selectedSpan()));
		addToolbarAction("Follow", ToolbarGlyph.FOLLOW, "04_inspect", "020",
			() -> plugin.canOpenCallee(selectedSpan()), () -> plugin.openCalleeOrJump(selectedSpan()));
		addToolbarAction("Uses", ToolbarGlyph.USES, "04_inspect", "030",
			() -> selectedSpan() != null, () -> highlightUses());
		addToolbarAction("Trace", ToolbarGlyph.TRACE, "04_inspect", "040",
			() -> traceableSelectedVariable(currentTab()) != null, () -> traceSelectedVariable());
		addToolbarAction("Copy", ToolbarGlyph.COPY, "05_output", "010",
			() -> currentResult() != null, () -> smartCopy());
		addToolbarAction("Export", ToolbarGlyph.EXPORT, "05_output", "020",
			() -> currentResult() != null, () -> plugin.exportCurrentFunction());
	}

	private void addToolbarAction(String name, ToolbarGlyph glyph, String group, String subgroup,
			BooleanSupplier enabled, Runnable handler) {
		DockingAction action = new DockingAction("Paradise " + name, plugin.getName()) {
			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return enabled.getAsBoolean();
			}

			@Override
			public void actionPerformed(ActionContext context) {
				handler.run();
			}
		};
		action.setToolBarData(new ToolBarData(toolbarIcon(glyph), group, subgroup));
		action.setDescription(name);
		action.markHelpUnnecessary();
		addLocalAction(action);
	}

	private JComponent createCleanupsPanel() {
		cleanupsSummaryLabel.setBorder(BorderFactory.createEmptyBorder(5, 8, 5, 8));
		cleanupsSummaryLabel.setFont(cleanupsSummaryLabel.getFont().deriveFont(Font.BOLD));
		cleanupsPanel.add(cleanupsSummaryLabel, BorderLayout.NORTH);
		cleanupsPanel.add(new JScrollPane(cleanupsTable), BorderLayout.CENTER);
		return cleanupsPanel;
	}

	private void initEncodedStringViews() {
		for (ParadiseDecodeUtil.Codec codec : ParadiseDecodeUtil.Codec.stringTabs()) {
			DefaultTableModel model =
				model("Use", "String", "Chain", "Decoded", "Kind", "Confidence");
			JTable table = table(model);
			JTextField filter = new JTextField(18);
			encodedStringModels.put(codec, model);
			encodedStringTables.put(codec, table);
			encodedStringFilters.put(codec, filter);
			encodedStringPanels.put(codec, filteredTablePanel(table, filter));
		}
	}

	private JTabbedPane createStringsPanel() {
		JTabbedPane pane = new JTabbedPane();
		pane.addTab("Overview", stringsOverviewPanel);
		return pane;
	}

	private void rebuildStringsPanelTabs() {
		String selected = stringsPanel.getSelectedIndex() >= 0
				? stringsPanel.getTitleAt(stringsPanel.getSelectedIndex())
				: null;
		stringsPanel.removeAll();
		stringsPanel.addTab("Overview", stringsOverviewPanel);
		for (ParadiseDecodeUtil.Codec codec : ParadiseDecodeUtil.Codec.stringTabs()) {
			List<EncodedStringRow> rows =
				encodedStringRowsByCodec.getOrDefault(codec, List.of());
			if (!rows.isEmpty()) {
				stringsPanel.addTab(codec.tabTitle(), encodedStringPanels.get(codec));
			}
		}
		if (selected != null) {
			for (int i = 0; i < stringsPanel.getTabCount(); i++) {
				if (selected.equals(stringsPanel.getTitleAt(i))) {
					stringsPanel.setSelectedIndex(i);
					break;
				}
			}
		}
		boolean dark = plugin.darkTheme();
		styleTabbedPane(stringsPanel, dark, dark ? DARK_PANEL_BG : LIGHT_PANEL_BG,
			dark ? DARK_HEADER_FG : LIGHT_HEADER_FG);
	}

	private JPanel filteredTablePanel(JTable table, JTextField filterField) {
		installTextFilter(table, filterField);
		JPanel wrapper = new JPanel(new BorderLayout(0, 4));
		JPanel filterPanel = new JPanel(new BorderLayout(4, 0));
		filterPanel.setBorder(BorderFactory.createEmptyBorder(4, 4, 0, 4));
		filterPanel.add(new JLabel("Filter"), BorderLayout.WEST);
		filterPanel.add(filterField, BorderLayout.CENTER);
		wrapper.add(filterPanel, BorderLayout.NORTH);
		wrapper.add(new JScrollPane(table), BorderLayout.CENTER);
		return wrapper;
	}

	private void installTextFilter(JTable table, JTextField filterField) {
		TableRowSorter<DefaultTableModel> sorter =
			new TableRowSorter<>((DefaultTableModel) table.getModel());
		table.setRowSorter(sorter);
		filterField.getDocument().addDocumentListener(new DocumentListener() {
			@Override
			public void insertUpdate(DocumentEvent e) {
				apply();
			}

			@Override
			public void removeUpdate(DocumentEvent e) {
				apply();
			}

			@Override
			public void changedUpdate(DocumentEvent e) {
				apply();
			}

			private void apply() {
				String text = filterField.getText();
				sorter.setRowFilter(text == null || text.isBlank() ? null
						: RowFilter.regexFilter("(?i)" + Pattern.quote(text)));
			}
		});
	}

	private void rebuildAuxTabs() {
		String selected = auxTabs.getSelectedIndex() >= 0 ? auxTabs.getTitleAt(auxTabs.getSelectedIndex())
				: null;
		auxTabs.removeAll();
		addAuxTab("Xrefs", xrefsPanel);
		addAuxTab("Locals", localsPanel);
		addAuxTab("Trace", tracePanel);
		addAuxTab("Calls", callsPanel);
		addAuxTab("Strings", stringsPanel);
		addAuxTab("Diff", diffPanel);
		addAuxTab("Drafts", draftsPanel);
		addAuxTab("Suggestions", suggestionsPanel);
		addAuxTab("Triage", triagePanel);
		addAuxTab("Cleanups", cleanupsPanel);
		if (selected != null) {
			selectAuxTabIfPresent(selected);
		}
		auxTabs.setVisible(plugin.showAuxPanels() && auxTabs.getTabCount() > 0);
	}

	private void addAuxTab(String title, JComponent component) {
		if (plugin.showAuxTab(title)) {
			auxTabs.addTab(title, component);
		}
	}

	private JButton button(String text, ActionListener listener) {
		return actionButton(text, null, listener);
	}

	private JButton iconButton(ToolbarGlyph glyph, String tooltip, ActionListener listener) {
		JButton button = new JButton(toolbarIcon(glyph));
		button.addActionListener(listener);
		button.setToolTipText(tooltip);
		configureIconButton(button);
		headerButtons.add(button);
		return button;
	}

	private Icon toolbarIcon(ToolbarGlyph glyph) {
		return new ToolbarIcon(glyph);
	}

	private void configureIconButton(AbstractButton button) {
		Dimension size = new Dimension(24, 22);
		button.setFocusable(false);
		button.setText(null);
		button.setMargin(new Insets(0, 0, 0, 0));
		button.setHorizontalAlignment(SwingConstants.CENTER);
		button.setVerticalAlignment(SwingConstants.CENTER);
		button.setAlignmentY(Component.CENTER_ALIGNMENT);
		button.setPreferredSize(size);
		button.setMinimumSize(size);
		button.setMaximumSize(size);
		button.setOpaque(true);
		button.setContentAreaFilled(true);
	}

	private JButton actionButton(String text, String tooltip, ActionListener listener) {
		JButton button = new JButton(text);
		button.addActionListener(listener);
		button.setFocusable(false);
		button.setMargin(new Insets(2, 7, 2, 7));
		button.setToolTipText(tooltip);
		button.setHorizontalAlignment(SwingConstants.CENTER);
		button.setAlignmentY(Component.CENTER_ALIGNMENT);
		headerButtons.add(button);
		return button;
	}

	private void toggleRawClean() {
		PseudocodeTab tab = currentTab();
		if (tab == null || tab.result == null) {
			rawToggle.setSelected(false);
			return;
		}
		tab.showRaw = !tab.showRaw;
		rawToggle.setSelected(tab.showRaw);
		render(tab, tab.result);
		updateStatus(tab.result);
		updateAuxPanels(tab.result);
		contextChanged();
		focusText();
	}

	private JPanel compactSearchPanel() {
		JButton findButton = iconButton(ToolbarGlyph.FIND, "Find - find text in pseudocode",
			e -> searchFromField());
		JButton nextButton = iconButton(ToolbarGlyph.NEXT, "Next - find next match (F3)",
			e -> findNextInCurrentTab());
		JButton clearButton = iconButton(ToolbarGlyph.CLEAR,
			"Clear - clear active search highlight", e -> clearSearch());
		int height = Math.max(providerTitleLabel.getPreferredSize().height,
			findButton.getPreferredSize().height);
		Dimension fieldSize = new Dimension(118, height);
		searchField.setPreferredSize(fieldSize);
		searchField.setMinimumSize(fieldSize);
		searchField.setMaximumSize(fieldSize);
		searchStatusLabel.setPreferredSize(new Dimension(70, height));
		headerSearchPanel.setBorder(BorderFactory.createEmptyBorder());
		headerSearchPanel.add(searchField);
		headerSearchPanel.add(findButton);
		headerSearchPanel.add(nextButton);
		headerSearchPanel.add(clearButton);
		headerSearchPanel.add(searchStatusLabel);
		return headerSearchPanel;
	}

	private void searchTextChanged() {
		if (updatingSearchField) {
			return;
		}
		SwingUtilities.invokeLater(() -> searchFromField(false));
	}

	private void createPopup() {
		renameItem = item("Rename", e -> plugin.renameSelectedToken(selectedSpan()));
		retypeItem = item("Set type / Signature", e -> plugin.retypeSelectedToken(selectedSpan()));
		commentItem = item("Comment", e -> plugin.editComment(selectedSpan()));
		JMenuItem draftItem = item("Draft Comment", e -> plugin.applyDraftComment());
		xrefsItem = item("Xrefs", e -> plugin.showXrefs(selectedSpan()));
		stringPreviewItem = item("String Preview", e -> plugin.showStringPreview(selectedSpan()));
		traceItem = item("Trace Variable", e -> traceSelectedVariable());
		convertLiteralMenu = new JMenu("Convert Literal");
		convertLiteralMenu.add(item("Hex", e -> convertSelectedLiteral(LiteralFormat.HEX)));
		convertLiteralMenu.add(item("Unsigned decimal",
			e -> convertSelectedLiteral(LiteralFormat.UNSIGNED_DECIMAL)));
		convertLiteralMenu.add(item("Signed decimal",
			e -> convertSelectedLiteral(LiteralFormat.SIGNED_DECIMAL)));
		convertLiteralMenu.add(item("Binary", e -> convertSelectedLiteral(LiteralFormat.BINARY)));
		convertLiteralMenu.add(item("Character",
			e -> convertSelectedLiteral(LiteralFormat.CHARACTER)));
		convertLiteralMenu.addSeparator();
		convertLiteralMenu.add(item("Reset", e -> resetSelectedLiteral()));
		decodeMenu = new JMenu("Decode from...");
		decodeAutoItem = item("Auto", e -> decodeSelected(ParadiseDecodeUtil.Codec.AUTO));
		decodeBase64Item = item("Base64", e -> decodeSelected(ParadiseDecodeUtil.Codec.BASE64));
		decodeHexItem = item("Hex", e -> decodeSelected(ParadiseDecodeUtil.Codec.HEX));
		decodeUrlItem = item("URL percent", e -> decodeSelected(ParadiseDecodeUtil.Codec.URL));
		decodeBase32Item = item("Base32", e -> decodeSelected(ParadiseDecodeUtil.Codec.BASE32));
		decodeUtf16LeItem = item("UTF-16LE", e -> decodeSelected(ParadiseDecodeUtil.Codec.UTF16_LE));
		decodeUtf16BeItem = item("UTF-16BE", e -> decodeSelected(ParadiseDecodeUtil.Codec.UTF16_BE));
		decodeMenu.add(decodeAutoItem);
		decodeMenu.addSeparator();
		decodeMenu.add(decodeBase64Item);
		decodeMenu.add(decodeHexItem);
		decodeMenu.add(decodeUrlItem);
		decodeMenu.add(decodeBase32Item);
		decodeMenu.add(decodeUtf16LeItem);
		decodeMenu.add(decodeUtf16BeItem);
		renameFromStringItem =
			item("Rename Function From String", e -> plugin.renameFromSelectedString(selectedSpan()));
		wrapperRenameItem =
			item("Rename Wrapper From Target", e -> plugin.renameWrapperFromTarget(currentFunction()));
		highlightUsesItem = item("Highlight Uses", e -> highlightUses());
		jumpItem = item("Jump to disasm", e -> plugin.jumpToDisassembly(selectedSpan()));
		calleeItem = item("Follow call", e -> plugin.openCalleeOrJump(selectedSpan()));
		searchItem = item("Search", e -> searchInCurrentTab());
		copyIdentifierItem = item("Copy Identifier", e -> copyIdentifier());
		copyLineItem = item("Copy Line", e -> copyCurrentLine());
		refreshItem = item("Refresh", e -> refreshCurrent());
		exportItem = item("Export Function", e -> plugin.exportCurrentFunction());

		popup.add(renameItem);
		popup.add(retypeItem);
		popup.add(commentItem);
		popup.add(draftItem);
		popup.addSeparator();
		popup.add(xrefsItem);
		popup.add(jumpItem);
		popup.add(calleeItem);
		popup.add(traceItem);
		popup.add(convertLiteralMenu);
		popup.add(decodeMenu);
		popup.addSeparator();
		popup.add(stringPreviewItem);
		popup.add(renameFromStringItem);
		popup.add(wrapperRenameItem);
		popup.add(highlightUsesItem);
		popup.addSeparator();
		popup.add(searchItem);
		popup.add(copyIdentifierItem);
		popup.add(copyLineItem);
		popup.add(item("Copy Selection", e -> currentTextPane().copy()));
		popup.add(item("Copy Function", e -> copyAll()));
		popup.addSeparator();
		popup.add(refreshItem);
		popup.add(exportItem);
	}

	private JMenuItem item(String text, ActionListener listener) {
		JMenuItem item = new JMenuItem(text);
		item.addActionListener(listener);
		return item;
	}

	private PseudocodeTab ensureTab(Function function, boolean reuseActiveTab) {
		TabKey key = new TabKey(function);
		PseudocodeTab existing = tabMap.get(key);
		if (existing != null) {
			return existing;
		}

		PseudocodeTab current = currentTab();
		if (reuseActiveTab && current != null) {
			tabMap.remove(current.key);
			current.function = function;
			current.result = null;
			current.key = new TabKey(function);
			current.tracedVariable = null;
			current.traceRows = List.of();
			tabMap.put(current.key, current);
			int index = tabs.indexOfComponent(current.panel);
			if (index >= 0) {
				updateTabTitle(current, function);
			}
			return current;
		}

		NoWrapTextPane textPane = createTextPane();
		JTextArea gutter = new JTextArea();
		gutter.setEditable(false);
		gutter.setFocusable(false);
		gutter.setBorder(BorderFactory.createEmptyBorder(0, 4, 0, 8));

		JPanel tabPanel = new JPanel(new BorderLayout());
		JScrollPane scrollPane = new JScrollPane(textPane);
		scrollPane.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
		scrollPane.setRowHeaderView(gutter);
		tabPanel.add(scrollPane, BorderLayout.CENTER);

		PseudocodeTab tab = new PseudocodeTab(key, function, tabPanel, textPane, gutter);
		tabMap.put(key, tab);
		tabs.addTab(tabTitle(function), tabPanel);
		updateTabTitle(tab, function);
		applyEditorOptions(tab);
		return tab;
	}

	private NoWrapTextPane createTextPane() {
		NoWrapTextPane textPane = new NoWrapTextPane();
		textPane.setEditable(false);
		textPane.setFocusTraversalKeysEnabled(false);
		textPane.setBorder(BorderFactory.createEmptyBorder(0, 6, 0, 24));

		textPane.addCaretListener(e -> {
			PseudocodeTab tab = currentTab();
			if (tab != null && textPane == tab.textPane) {
				tab.caretPosition = textPane.getCaretPosition();
				updateEditorHighlights(tab);
				updateTraceSelectionForCaret(tab);
				contextChanged();
			}
		});
		textPane.addMouseListener(new MouseAdapter() {
			@Override
			public void mousePressed(MouseEvent e) {
				handlePopup(e, textPane);
			}

			@Override
			public void mouseReleased(MouseEvent e) {
				handlePopup(e, textPane);
			}

			@Override
			public void mouseClicked(MouseEvent e) {
				if (!SwingUtilities.isLeftMouseButton(e)) {
					return;
				}
				setCaretFromPoint(textPane, e.getPoint());
				ParadiseTokenSpan span = selectedSpan();
				if (e.getClickCount() >= 2) {
					plugin.openCalleeOrJump(span);
				}
				else if (span != null && plugin.syncListingOnClick()) {
					plugin.navigateTo(span.address());
				}
			}
		});

		installKeyBindings(textPane);
		return textPane;
	}

	private void installKeyBindings(JTextPane textPane) {
		InputMap inputMap = textPane.getInputMap(JComponent.WHEN_FOCUSED);
		ActionMap actionMap = textPane.getActionMap();

		bind(inputMap, actionMap, KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), "paradise.escape",
			() -> goBackOrClose());
		bind(inputMap, actionMap,
			KeyStroke.getKeyStroke(decompileKeyCode(), decompileKeyModifiers()), "paradise.refresh",
			() -> refreshCurrent());
		bind(inputMap, actionMap, KeyStroke.getKeyStroke(KeyEvent.VK_TAB, 0), "paradise.toggle",
			() -> plugin.togglePseudocode());
		bind(inputMap, actionMap, KeyStroke.getKeyStroke(KeyEvent.VK_N, 0), "paradise.rename",
			() -> plugin.renameSelectedToken(selectedSpan()));
		bind(inputMap, actionMap, KeyStroke.getKeyStroke(KeyEvent.VK_Y, 0), "paradise.retype",
			() -> plugin.retypeSelectedToken(selectedSpan()));
		bind(inputMap, actionMap, KeyStroke.getKeyStroke(KeyEvent.VK_SEMICOLON, 0),
			"paradise.comment", () -> plugin.editComment(selectedSpan()));
		bind(inputMap, actionMap, KeyStroke.getKeyStroke(KeyEvent.VK_X, 0), "paradise.xrefs",
			() -> plugin.showXrefs(selectedSpan()));
		bind(inputMap, actionMap, KeyStroke.getKeyStroke(KeyEvent.VK_T, 0), "paradise.trace",
			() -> traceSelectedVariable());
		bind(inputMap, actionMap, KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, 0), "paradise.enter",
			() -> plugin.openCalleeOrJump(selectedSpan()));
		bind(inputMap, actionMap, KeyStroke.getKeyStroke(KeyEvent.VK_SPACE, 0), "paradise.jump",
			() -> plugin.jumpToDisassembly(selectedSpan()));
		bind(inputMap, actionMap, KeyStroke.getKeyStroke(KeyEvent.VK_G, 0), "paradise.goto",
			() -> promptGoTo());
		bind(inputMap, actionMap, KeyStroke.getKeyStroke(KeyEvent.VK_SLASH, 0), "paradise.search",
			() -> searchInCurrentTab());
		bind(inputMap, actionMap, KeyStroke.getKeyStroke(KeyEvent.VK_F, menuShortcutModifiers()),
			"paradise.ctrl.search", () -> searchInCurrentTab());
		bind(inputMap, actionMap, KeyStroke.getKeyStroke(KeyEvent.VK_F3, 0), "paradise.find.next",
			() -> findNextInCurrentTab());
		bind(inputMap, actionMap, KeyStroke.getKeyStroke(KeyEvent.VK_C, menuShortcutModifiers()),
			"paradise.copy", () -> smartCopy());
		bind(inputMap, actionMap, KeyStroke.getKeyStroke(KeyEvent.VK_A, menuShortcutModifiers()),
			"paradise.copy.function", () -> copyAll());
		bind(inputMap, actionMap, KeyStroke.getKeyStroke(KeyEvent.VK_LEFT, historyKeyModifiers()),
			"paradise.back", () -> goBack());
		bind(inputMap, actionMap, KeyStroke.getKeyStroke(KeyEvent.VK_RIGHT, historyKeyModifiers()),
			"paradise.forward", () -> goForward());
	}

	private void bind(InputMap inputMap, ActionMap actionMap, KeyStroke keyStroke, String id,
			Runnable runnable) {
		inputMap.put(keyStroke, id);
		actionMap.put(id, new AbstractAction() {
			@Override
			public void actionPerformed(ActionEvent e) {
				if (plugin.hotkeysEnabled()) {
					runnable.run();
				}
			}
		});
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

	private void render(PseudocodeTab tab, ParadiseDecompileResult result) {
		RenderedDisplay display = displayFor(tab, result);
		tab.displayCode = display.code();
		tab.displaySpans = display.spans();
		tab.lines = buildLines(display.code(), display.spans());
		StyledDocument document = tab.textPane.getStyledDocument();
		try {
			document.remove(0, document.getLength());
			document.insertString(0, display.code(), styleFor(ClangToken.DEFAULT_COLOR));
			if (!result.success()) {
				document.setCharacterAttributes(0, document.getLength(), errorStyle(), false);
				return;
			}
			applyFallbackSyntax(document, display.code());
			for (ParadiseTokenSpan span : display.spans()) {
				document.setCharacterAttributes(span.start(), span.length(),
					styleFor(span.syntaxType()), false);
			}
		}
		catch (BadLocationException e) {
			tab.textPane.setText(display.code());
		}
		finally {
			clearAllHighlights(tab);
			updateGutter(tab);
			highlightSearch(tab);
			rebuildTrace(tab);
			updateEditorHighlights(tab);
			updateTraceSelectionForCaret(tab);
		}
	}

	private void applyFallbackSyntax(StyledDocument document, String code)
			throws BadLocationException {
		applyFallbackPattern(document, code,
			Pattern.compile("\"(?:\\\\.|[^\"\\\\])*\"|'(?:\\\\.|[^'\\\\])+'"),
			ClangToken.CONST_COLOR);
		applyFallbackPattern(document, code,
			Pattern.compile("\\b(?:0x[0-9a-fA-F]+|\\d+)\\b"), ClangToken.CONST_COLOR);
		applyFallbackPattern(document, code,
			Pattern.compile("\\b(?:bool|char|double|float|int|int\\d+_t|uint\\d+_t|int8_t|int16_t|int32_t|int64_t|uint8_t|uint16_t|uint32_t|uint64_t|long|short|size_t|uintptr_t|void)\\b"),
			ClangToken.TYPE_COLOR);
		applyFallbackPattern(document, code,
			Pattern.compile("\\b[A-Za-z_]\\w*(?=\\s*\\()"), ClangToken.FUNCTION_COLOR);
		applyFallbackPattern(document, code,
			Pattern.compile("\\b(?:break|case|continue|default|do|else|for|goto|if|return|sizeof|switch|while)\\b"),
			ClangToken.KEYWORD_COLOR);
		applyFallbackPattern(document, code,
			Pattern.compile("(?s)/\\*.*?\\*/|(?m)//.*$"), ClangToken.COMMENT_COLOR);
	}

	private void applyFallbackPattern(StyledDocument document, String code, Pattern pattern,
			int syntaxType) throws BadLocationException {
		Matcher matcher = pattern.matcher(code);
		AttributeSet style = styleFor(syntaxType);
		while (matcher.find()) {
			document.setCharacterAttributes(matcher.start(), matcher.end() - matcher.start(), style,
				false);
		}
	}

	private RenderedDisplay displayFor(PseudocodeTab tab, ParadiseDecompileResult result) {
		String code = tab.showRaw ? result.rawCode() : result.code();
		List<ParadiseTokenSpan> sourceSpans =
			tab.showRaw ? result.rawTokenSpans() : result.tokenSpans();
		if (sourceSpans.isEmpty() || tab.literalOverrides.isEmpty()) {
			return new RenderedDisplay(code, sourceSpans);
		}
		StringBuilder builder = new StringBuilder(code.length());
		List<ParadiseTokenSpan> spans = new ArrayList<>();
		int sourceOffset = 0;
		for (ParadiseTokenSpan span : sourceSpans) {
			if (span.start() < sourceOffset || span.end() > code.length()) {
				continue;
			}
			builder.append(code, sourceOffset, span.start());
			String text = tab.literalOverrides.get(span.token());
			if (text == null) {
				text = code.substring(span.start(), span.end());
			}
			int start = builder.length();
			builder.append(text);
			int end = builder.length();
			spans.add(new ParadiseTokenSpan(start, end, span.token(), span.minAddress(),
				span.maxAddress(), span.highSymbol(), span.syntaxType()));
			sourceOffset = span.end();
		}
		builder.append(code, sourceOffset, code.length());
		return new RenderedDisplay(builder.toString(), List.copyOf(spans));
	}

	private AttributeSet styleFor(int syntaxType) {
		SimpleAttributeSet style = new SimpleAttributeSet();
		StyleConstants.setForeground(style, colorFor(syntaxType));
		if (syntaxType == ClangToken.FUNCTION_COLOR || syntaxType == ClangToken.KEYWORD_COLOR) {
			StyleConstants.setBold(style, true);
		}
		if (syntaxType == ClangToken.COMMENT_COLOR) {
			StyleConstants.setItalic(style, true);
		}
		return style;
	}

	private AttributeSet errorStyle() {
		SimpleAttributeSet style = new SimpleAttributeSet();
		StyleConstants.setForeground(style, plugin.darkTheme() ? new Color(255, 125, 125)
				: new Color(150, 35, 35));
		return style;
	}

	private Color colorFor(int syntaxType) {
		if (plugin.darkTheme()) {
			return switch (syntaxType) {
				case ClangToken.KEYWORD_COLOR -> new Color(198, 120, 221);
				case ClangToken.COMMENT_COLOR -> new Color(112, 139, 91);
				case ClangToken.TYPE_COLOR -> new Color(86, 182, 194);
				case ClangToken.FUNCTION_COLOR -> new Color(97, 175, 239);
				case ClangToken.VARIABLE_COLOR -> new Color(220, 223, 228);
				case ClangToken.CONST_COLOR -> new Color(209, 154, 102);
				case ClangToken.PARAMETER_COLOR -> new Color(229, 192, 123);
				case ClangToken.GLOBAL_COLOR -> new Color(224, 172, 105);
				case ClangToken.ERROR_COLOR -> new Color(255, 110, 110);
				default -> new Color(220, 223, 228);
			};
		}
		return switch (syntaxType) {
			case ClangToken.KEYWORD_COLOR -> new Color(127, 0, 85);
			case ClangToken.COMMENT_COLOR -> new Color(63, 127, 95);
			case ClangToken.TYPE_COLOR -> new Color(0, 78, 130);
			case ClangToken.FUNCTION_COLOR -> new Color(40, 86, 160);
			case ClangToken.VARIABLE_COLOR -> new Color(20, 20, 20);
			case ClangToken.CONST_COLOR -> new Color(142, 84, 0);
			case ClangToken.PARAMETER_COLOR -> new Color(88, 70, 150);
			case ClangToken.GLOBAL_COLOR -> new Color(130, 70, 20);
			case ClangToken.ERROR_COLOR -> new Color(170, 30, 30);
			default -> Color.BLACK;
		};
	}

	private void updateEditorHighlights(PseudocodeTab tab) {
		if (tab == null) {
			return;
		}
		clearTransientHighlights(tab);
		if (tab.textPane.getDocument().getLength() == 0) {
			return;
		}
		if (plugin.currentLineHighlight()) {
			highlightCurrentLine(tab);
		}
		ParadiseTokenSpan span = selectedSpan();
		if (span != null && span.length() > 0 && tab.result != null) {
			List<ParadiseTokenSpan> spans = plugin.highlightUsesEnabled() ? matchingSpans(tab, span)
					: List.of(span);
			for (ParadiseTokenSpan use : spans) {
				addHighlight(tab, use.start(), use.end(), USE_HIGHLIGHT, tab.useHighlightTags);
			}
		}
		highlightTracedVariable(tab);
		if (plugin.braceMatching()) {
			highlightMatchingBrace(tab);
		}
	}

	private void highlightTracedVariable(PseudocodeTab tab) {
		if (tab.tracedVariable == null || tab.tracedVariable.isBlank()) {
			return;
		}
		Pattern pattern = identifierPattern(tab.tracedVariable);
		Matcher matcher = pattern.matcher(tab.textPane.getText());
		while (matcher.find()) {
			addHighlight(tab, matcher.start(), matcher.end(), TRACE_HIGHLIGHT,
				tab.traceHighlightTags);
		}
	}

	private void highlightCurrentLine(PseudocodeTab tab) {
		PseudocodeLine line = lineAt(tab, tab.textPane.getCaretPosition());
		if (line == null) {
			return;
		}
		int end = Math.min(tab.textPane.getDocument().getLength(),
			Math.max(line.start() + 1, line.end() + 1));
		addHighlight(tab, line.start(), end,
			plugin.darkTheme() ? CURRENT_LINE_DARK : CURRENT_LINE, tab.lineHighlightTags);
	}

	private void highlightMatchingBrace(PseudocodeTab tab) {
		String text = tab.textPane.getText();
		int caret = Math.min(tab.textPane.getCaretPosition(), text.length() - 1);
		if (caret < 0) {
			return;
		}
		int pos = isBrace(text.charAt(caret)) ? caret
				: caret > 0 && isBrace(text.charAt(caret - 1)) ? caret - 1 : -1;
		if (pos < 0) {
			return;
		}
		int match = matchingBrace(text, pos);
		if (match >= 0) {
			addHighlight(tab, pos, pos + 1, BRACE_HIGHLIGHT, tab.braceHighlightTags);
			addHighlight(tab, match, match + 1, BRACE_HIGHLIGHT, tab.braceHighlightTags);
		}
	}

	private int highlightSearch(PseudocodeTab tab) {
		clearSearchHighlights(tab);
		if (tab.searchText == null || tab.searchText.isBlank()) {
			return 0;
		}
		String text = tab.textPane.getText().toLowerCase(Locale.ROOT);
		String query = tab.searchText.toLowerCase(Locale.ROOT);
		int index = text.indexOf(query);
		int count = 0;
		while (index >= 0) {
			addHighlight(tab, index, index + query.length(), SEARCH_HIGHLIGHT, tab.searchHighlightTags);
			count++;
			index = text.indexOf(query, index + Math.max(1, query.length()));
		}
		return count;
	}

	private void addHighlight(PseudocodeTab tab, int start, int end, Color color, List<Object> tags) {
		try {
			Object tag = tab.textPane.getHighlighter()
					.addHighlight(start, end, new DefaultHighlighter.DefaultHighlightPainter(color));
			tags.add(tag);
		}
		catch (BadLocationException e) {
			// Ignore stale offsets after a decompile refresh.
		}
	}

	private List<ParadiseTokenSpan> matchingSpans(PseudocodeTab tab, ParadiseTokenSpan selected) {
		List<ParadiseTokenSpan> matches = new ArrayList<>();
		for (ParadiseTokenSpan matchSpan : tab.displaySpans) {
			if (sameUse(selected, matchSpan)) {
				matches.add(matchSpan);
			}
		}
		return matches;
	}

	private boolean sameUse(ParadiseTokenSpan a, ParadiseTokenSpan b) {
		if (a == null || b == null) {
			return false;
		}
		if (a.highSymbol() != null && b.highSymbol() != null) {
			return Objects.equals(a.highSymbol().getName(), b.highSymbol().getName());
		}
		return a.syntaxType() == b.syntaxType() && Objects.equals(a.token().getText(), b.token().getText());
	}

	private void clearTransientHighlights(PseudocodeTab tab) {
		clearTags(tab, tab.lineHighlightTags);
		clearTags(tab, tab.useHighlightTags);
		clearTags(tab, tab.traceHighlightTags);
		clearTags(tab, tab.braceHighlightTags);
	}

	private void clearSearchHighlights(PseudocodeTab tab) {
		clearTags(tab, tab.searchHighlightTags);
	}

	private void clearAllHighlights(PseudocodeTab tab) {
		clearTransientHighlights(tab);
		clearSearchHighlights(tab);
	}

	private void clearTags(PseudocodeTab tab, List<Object> tags) {
		for (Object tag : tags) {
			tab.textPane.getHighlighter().removeHighlight(tag);
		}
		tags.clear();
	}

	private void handlePopup(MouseEvent e, JTextPane textPane) {
		if (!e.isPopupTrigger()) {
			return;
		}
		setCaretFromPoint(textPane, e.getPoint());
		refreshPopupState();
		popup.show(e.getComponent(), e.getX(), e.getY());
	}

	private void refreshPopupState() {
		ParadiseTokenSpan span = selectedSpan();
		boolean hasResult = currentResult() != null && currentResult().success();
		boolean hasSpan = span != null;
		renameItem.setEnabled(hasResult);
		retypeItem.setEnabled(hasResult);
		commentItem.setEnabled(hasResult);
		xrefsItem.setEnabled(hasResult);
		stringPreviewItem.setEnabled(hasResult);
		traceItem.setEnabled(hasResult && traceableSelectedVariable(currentTab()) != null);
		convertLiteralMenu.setEnabled(hasResult && literalValue(span) != null);
		String decodeSource = hasResult ? selectedDecodeSource() : null;
		Set<ParadiseDecodeUtil.Codec> codecs =
			decodeSource == null ? Set.of() : ParadiseDecodeUtil.availableCodecs(decodeSource);
		decodeMenu.setEnabled(!codecs.isEmpty());
		decodeAutoItem.setEnabled(!codecs.isEmpty());
		decodeBase64Item.setEnabled(codecs.contains(ParadiseDecodeUtil.Codec.BASE64));
		decodeHexItem.setEnabled(codecs.contains(ParadiseDecodeUtil.Codec.HEX));
		decodeUrlItem.setEnabled(codecs.contains(ParadiseDecodeUtil.Codec.URL));
		decodeBase32Item.setEnabled(codecs.contains(ParadiseDecodeUtil.Codec.BASE32));
		decodeUtf16LeItem.setEnabled(codecs.contains(ParadiseDecodeUtil.Codec.UTF16_LE));
		decodeUtf16BeItem.setEnabled(codecs.contains(ParadiseDecodeUtil.Codec.UTF16_BE));
		renameFromStringItem.setEnabled(hasResult);
		wrapperRenameItem.setEnabled(hasResult && currentFunction() != null);
		highlightUsesItem.setEnabled(hasSpan);
		jumpItem.setEnabled(hasSpan && addressOf(span) != null);
		calleeItem.setEnabled(plugin.canOpenCallee(span));
		searchItem.setEnabled(currentResult() != null);
		copyIdentifierItem.setEnabled(hasSpan);
		copyLineItem.setEnabled(currentResult() != null);
		refreshItem.setEnabled(currentResult() != null);
		exportItem.setEnabled(currentResult() != null);
	}

	private void convertSelectedLiteral(LiteralFormat format) {
		PseudocodeTab tab = currentTab();
		ParadiseTokenSpan span = selectedSpan();
		LiteralValue value = literalValue(span);
		if (tab == null || tab.result == null || span == null || value == null) {
			return;
		}
		String converted = literalText(value, format);
		if (converted == null) {
			Msg.showInfo(this, panel, "Convert Literal",
				"That value cannot be represented as a compact character literal.");
			return;
		}
		tab.literalOverrides.put(span.token(), converted);
		render(tab, tab.result);
		selectToken(tab, span.token());
	}

	private void resetSelectedLiteral() {
		PseudocodeTab tab = currentTab();
		ParadiseTokenSpan span = selectedSpan();
		if (tab == null || tab.result == null || span == null) {
			return;
		}
		tab.literalOverrides.remove(span.token());
		render(tab, tab.result);
		selectToken(tab, span.token());
	}

	private void decodeSelected(ParadiseDecodeUtil.Codec codec) {
		String source = selectedDecodeSource();
		List<ParadiseDecodeUtil.Result> decoded =
			ParadiseDecodeUtil.resultsForSelection(source, codec);
		if (source == null || decoded.isEmpty()) {
			Msg.showInfo(this, panel, "Decode from",
				"Select an encoded string literal or encoded text first.");
			return;
		}

		JTextArea output = new JTextArea(decodeDialogText(decoded), 10, 78);
		output.setEditable(false);
		output.setLineWrap(true);
		output.setWrapStyleWord(true);
		output.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
		JPanel content = new JPanel(new BorderLayout(0, 8));
		content.add(new JLabel(decodeDialogHeader(decoded)), BorderLayout.NORTH);
		content.add(new JScrollPane(output), BorderLayout.CENTER);
		JOptionPane.showMessageDialog(panel, content, "Decode from " + codec.displayName(),
			JOptionPane.INFORMATION_MESSAGE);
	}

	private String selectedDecodeSource() {
		PseudocodeTab tab = currentTab();
		if (tab == null || tab.result == null) {
			return null;
		}
		String text = selectedTextOrToken(tab);
		if (text == null) {
			return null;
		}
		text = text.trim();
		if (text.isEmpty()) {
			return null;
		}
		if (isQuotedStringLiteral(text)) {
			return cStringLiteralValue(text);
		}
		return text;
	}

	private void selectToken(PseudocodeTab tab, ClangToken token) {
		for (ParadiseTokenSpan span : tab.displaySpans) {
			if (span.token() == token) {
				selectRange(tab, span.start(), span.end());
				return;
			}
		}
	}

	private void selectRange(PseudocodeTab tab, int start, int end) {
		if (tab == null || tab.textPane.getDocument().getLength() == 0) {
			return;
		}
		int length = tab.textPane.getDocument().getLength();
		int safeStart = Math.max(0, Math.min(start, length - 1));
		int safeEnd = Math.max(safeStart, Math.min(end, length));
		tab.textPane.setCaretPosition(safeStart);
		tab.textPane.moveCaretPosition(safeEnd);
		try {
			Rectangle rect = tab.textPane.modelToView2D(safeStart).getBounds();
			tab.textPane.scrollRectToVisible(rect);
		}
		catch (BadLocationException e) {
			// Ignore stale offsets after refresh.
		}
		updateEditorHighlights(tab);
	}

	private LiteralValue literalValue(ParadiseTokenSpan span) {
		if (span == null || span.token() == null) {
			return null;
		}
		String text = span.token().getText();
		if (text == null || text.isBlank() || text.indexOf('\'') >= 0 ||
			text.indexOf('"') >= 0 || text.indexOf('.') >= 0) {
			return null;
		}
		try {
			Scalar scalar = span.token().getScalar();
			if (scalar != null) {
				return new LiteralValue(scalar.getUnsignedValue(), scalar.getSignedValue(),
					normalizeBitLength(scalar.bitLength()));
			}
		}
		catch (RuntimeException e) {
			// Fall back to text parsing.
		}
		return parseIntegerLiteral(text);
	}

	private LiteralValue parseIntegerLiteral(String text) {
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
		int bitLength = Long.SIZE;
		if (lower.startsWith("0x")) {
			radix = 16;
			digits = body.substring(2);
			bitLength = normalizeBitLength(Math.max(1, digits.length()) * 4);
		}
		else if (lower.startsWith("0b")) {
			radix = 2;
			digits = body.substring(2);
			bitLength = normalizeBitLength(Math.max(1, digits.length()));
		}
		else if (body.length() > 1 && body.charAt(0) == '0') {
			radix = 8;
			digits = body.substring(1);
			bitLength = normalizeBitLength(Math.max(1, digits.length()) * 3);
		}
		if (digits.isEmpty() || !validDigits(digits, radix)) {
			return null;
		}
		try {
			long unsigned = Long.parseUnsignedLong(digits, radix);
			if (negative) {
				unsigned = -unsigned;
			}
			return new LiteralValue(unsigned, signedValue(unsigned, bitLength), bitLength);
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

	private int normalizeBitLength(int bits) {
		if (bits <= Byte.SIZE) {
			return Byte.SIZE;
		}
		if (bits <= Short.SIZE) {
			return Short.SIZE;
		}
		if (bits <= Integer.SIZE) {
			return Integer.SIZE;
		}
		return Long.SIZE;
	}

	private long signedValue(long unsigned, int bitLength) {
		if (bitLength >= Long.SIZE) {
			return unsigned;
		}
		long signBit = 1L << (bitLength - 1);
		long mask = (1L << bitLength) - 1;
		long value = unsigned & mask;
		return (value & signBit) == 0 ? value : value | ~mask;
	}

	private String literalText(LiteralValue value, LiteralFormat format) {
		return switch (format) {
			case HEX -> "0x" + Long.toHexString(maskedValue(value));
			case UNSIGNED_DECIMAL -> Long.toUnsignedString(maskedValue(value));
			case SIGNED_DECIMAL -> Long.toString(value.signedValue());
			case BINARY -> "0b" + Long.toBinaryString(maskedValue(value));
			case CHARACTER -> characterLiteral(value.unsignedValue());
		};
	}

	private long maskedValue(LiteralValue value) {
		int bitLength = value.bitLength();
		if (bitLength >= Long.SIZE) {
			return value.unsignedValue();
		}
		return value.unsignedValue() & ((1L << bitLength) - 1);
	}

	private String characterLiteral(long value) {
		if (value < 0 || value > 0xffff) {
			return null;
		}
		int c = (int) value;
		return switch (c) {
			case 0 -> "'\\0'";
			case '\t' -> "'\\t'";
			case '\n' -> "'\\n'";
			case '\r' -> "'\\r'";
			case '\'' -> "'\\''";
			case '\\' -> "'\\\\'";
			default -> c >= 0x20 && c <= 0x7e ? "'" + (char) c + "'"
					: c <= 0xff ? "'\\x" + Integer.toHexString(c) + "'"
							: "L'\\x" + Integer.toHexString(c) + "'";
		};
	}

	private void setCaretFromPoint(JTextPane textPane, Point point) {
		int pos = textPane.viewToModel2D(point);
		if (pos >= 0) {
			textPane.setCaretPosition(pos);
		}
	}

	private Address addressOf(ParadiseTokenSpan span) {
		return span == null ? null : span.address();
	}

	private void updateStatus(ParadiseDecompileResult result) {
		statusLabel.setText(FOOTER_TEXT);
		if (result == null) {
			updateHeader(null, "No function selected");
			return;
		}
		Function function = result.function();
		PseudocodeTab tab = currentTab();
		String state = result.success() && tab != null && tab.showRaw ? "Raw" :
			result.success() ? "Ready" : "Decompile failed";
		updateHeader(function, state);
	}

	private void updateHeader(Function function, String state) {
		setTitle("Paradise Pseudocode");
		setSubTitle("");
		boolean hasResult = currentResult() != null;
		headerSearchPanel.setVisible(hasResult);
		if (function == null) {
			providerTitleLabel.setText("Paradise Pseudocode");
			functionContextLabel.setText(state == null || state.isBlank() ? "No function selected"
					: state);
			return;
		}
		String subtitle = function.getName() + " @ " + function.getEntryPoint() +
			(state == null || state.isBlank() ? "" : " | " + state);
		providerTitleLabel.setText(subtitle);
		functionContextLabel.setText(subtitle);
	}

	private void copyAll() {
		PseudocodeTab tab = currentTab();
		String text = tab == null || tab.displayCode == null ? currentTextPane().getText()
				: tab.displayCode;
		copyText(text);
	}

	private void copyText(String text) {
		Toolkit.getDefaultToolkit()
				.getSystemClipboard()
				.setContents(new StringSelection(text == null ? "" : text), null);
	}

	private JTextPane currentTextPane() {
		PseudocodeTab tab = currentTab();
		if (tab != null) {
			return tab.textPane;
		}
		return new JTextPane();
	}

	private void setSearchFieldText(String text) {
		String value = text == null ? "" : text;
		if (value.equals(searchField.getText())) {
			return;
		}
		updatingSearchField = true;
		try {
			searchField.setText(value);
		}
		finally {
			updatingSearchField = false;
		}
	}

	private PseudocodeTab currentTab() {
		int index = tabs.getSelectedIndex();
		if (index < 0) {
			return null;
		}
		java.awt.Component component = tabs.getComponentAt(index);
		for (PseudocodeTab tab : tabMap.values()) {
			if (tab.panel == component) {
				return tab;
			}
		}
		return null;
	}

	private void updateTabTitle(PseudocodeTab tab, Function function) {
		int index = tabs.indexOfComponent(tab.panel);
		if (index < 0) {
			return;
		}
		String title = tabTitle(function);
		tabs.setTitleAt(index, title);
		tabs.setToolTipTextAt(index, function.getName() + " @ " + function.getEntryPoint());
		tabs.setTabComponentAt(index, closeableTabComponent(tab, title));
	}

	private JComponent closeableTabComponent(PseudocodeTab tab, String title) {
		JPanel tabComponent = new JPanel(new FlowLayout(FlowLayout.CENTER, 3, 0));
		tabComponent.setOpaque(false);
		JLabel label = new JLabel(title);
		JButton closeButton = new JButton("x");
		closeButton.setFocusable(false);
		closeButton.setMargin(new Insets(0, 2, 0, 2));
		closeButton.setBorder(BorderFactory.createEmptyBorder(0, 3, 0, 3));
		closeButton.setContentAreaFilled(false);
		closeButton.setToolTipText("Close " + title);
		closeButton.addActionListener(e -> closeTab(tab));
		MouseAdapter selector = new MouseAdapter() {
			@Override
			public void mousePressed(MouseEvent e) {
				if (tabs.indexOfComponent(tab.panel) >= 0) {
					tabs.setSelectedComponent(tab.panel);
				}
			}
		};
		tabComponent.addMouseListener(selector);
		label.addMouseListener(selector);
		tabComponent.add(label);
		tabComponent.add(closeButton);
		return tabComponent;
	}

	private void removeTab(PseudocodeTab tab) {
		tabMap.remove(tab.key);
		tabs.remove(tab.panel);
	}

	private void closeTab(PseudocodeTab tab) {
		if (tab == null || tabs.indexOfComponent(tab.panel) < 0) {
			return;
		}
		removeTab(tab);
		updateStatus(currentResult());
		updateAuxPanels(currentResult());
		contextChanged();
	}

	private String tabTitle(Function function) {
		return function.getName();
	}

	private void applyEditorOptions(PseudocodeTab tab) {
		Font font = new Font(Font.MONOSPACED, Font.PLAIN, plugin.fontSize());
		tab.textPane.setFont(font);
		tab.gutter.setFont(font);
		tab.textPane.setBackground(plugin.darkTheme() ? DARK_BG : LIGHT_BG);
		tab.textPane.setForeground(plugin.darkTheme() ? new Color(220, 223, 228) : Color.BLACK);
		tab.gutter.setBackground(plugin.darkTheme() ? DARK_GUTTER_BG : LIGHT_GUTTER_BG);
		tab.gutter.setForeground(plugin.darkTheme() ? new Color(155, 163, 175) : new Color(90, 90, 90));
		tab.gutter.setVisible(plugin.showGutter());
	}

	private void styleAuxiliaryUi() {
		boolean dark = plugin.darkTheme();
		Color panelBg = dark ? DARK_PANEL_BG : LIGHT_PANEL_BG;
		Color text = dark ? DARK_HEADER_FG : LIGHT_HEADER_FG;
		panel.setBackground(panelBg);
		mainPanel.setBackground(panelBg);
		headerPanel.setBackground(panelBg);
		headerTitleRow.setBackground(panelBg);
		headerActionRow.setBackground(panelBg);
		headerSearchPanel.setBackground(panelBg);
		cleanupsPanel.setBackground(panelBg);
		actionScrollPane.setBackground(panelBg);
		actionScrollPane.getViewport().setBackground(panelBg);
		actionScrollPane.setBorder(BorderFactory.createMatteBorder(1, 0, 1, 0,
			dark ? new Color(74, 78, 84) : new Color(200, 200, 194)));
		providerTitleLabel.setForeground(text);
		functionContextLabel.setForeground(dark ? new Color(190, 198, 208) : new Color(75, 75, 75));
		for (java.awt.Component component : headerActionRow.getComponents()) {
			if (component instanceof JComponent jComponent) {
				jComponent.setBackground(panelBg);
			}
		}
		searchField.setBackground(dark ? new Color(45, 48, 52) : Color.WHITE);
		searchField.setForeground(text);
		searchField.setCaretColor(text);
		searchStatusLabel.setForeground(dark ? new Color(190, 198, 208) : new Color(75, 75, 75));
		styleFilterPanel(stringsOverviewPanel, dark, panelBg, text);
		styleFilterField(stringsFilterField, dark, text);
		for (ParadiseDecodeUtil.Codec codec : ParadiseDecodeUtil.Codec.stringTabs()) {
			styleFilterPanel(encodedStringPanels.get(codec), dark, panelBg, text);
			styleFilterField(encodedStringFilters.get(codec), dark, text);
		}
		cleanupsSummaryLabel.setBackground(panelBg);
		cleanupsSummaryLabel.setForeground(text);
		cleanupsSummaryLabel.setOpaque(true);
		splitPane.setBackground(panelBg);
		statusLabel.setForeground(text);
		statusLabel.setBackground(panelBg);
		for (AbstractButton button : headerButtons) {
			button.setBackground(dark ? new Color(54, 57, 62) : new Color(244, 244, 240));
			button.setForeground(text);
			button.setBorder(BorderFactory.createCompoundBorder(
				BorderFactory.createLineBorder(dark ? new Color(82, 86, 92) : new Color(190, 190, 184)),
				BorderFactory.createEmptyBorder(2, 6, 2, 6)));
		}
		styleTabbedPane(tabs, dark, panelBg, text);
		styleTabbedPane(auxTabs, dark, panelBg, text);
		styleTabbedPane(stringsPanel, dark, panelBg, text);
		styleTable(xrefsTable, dark);
		styleTable(localsTable, dark);
		styleTable(callsTable, dark);
		styleTable(stringsTable, dark);
		for (JTable table : encodedStringTables.values()) {
			styleTable(table, dark);
		}
		styleTable(diffTable, dark);
		styleTable(draftsTable, dark);
		styleTable(suggestionsTable, dark);
		styleTable(triageTable, dark);
		styleTable(traceTable, dark);
		styleTable(cleanupsTable, dark);
		setColumnWidth(stringsTable, 0, 92);
		for (JTable table : encodedStringTables.values()) {
			setColumnWidth(table, 0, 92);
			setColumnWidth(table, 2, 150);
			setColumnWidth(table, 4, 64);
			setColumnWidth(table, 5, 78);
		}
		setColumnWidth(diffTable, 0, 52);
		setColumnWidth(draftsTable, 0, 78);
		setColumnWidth(draftsTable, 1, 118);
		setColumnWidth(suggestionsTable, 0, 64);
		setColumnWidth(suggestionsTable, 1, 92);
		setColumnWidth(suggestionsTable, 2, 190);
		setColumnWidth(triageTable, 0, 92);
		setColumnWidth(triageTable, 2, 52);
		setColumnWidth(triageTable, 3, 64);
		setColumnWidth(triageTable, 4, 52);
		setColumnWidth(triageTable, 5, 52);
		setColumnWidth(traceTable, 0, 92);
		setColumnWidth(traceTable, 1, 48);
		setColumnWidth(traceTable, 2, 88);
		setColumnWidth(cleanupsTable, 0, 118);
	}

	private void setColumnWidth(JTable table, int column, int width) {
		if (table.getColumnModel().getColumnCount() <= column) {
			return;
		}
		table.getColumnModel().getColumn(column).setMinWidth(width);
		table.getColumnModel().getColumn(column).setPreferredWidth(width);
		table.getColumnModel().getColumn(column).setMaxWidth(width);
	}

	private void styleFilterField(JTextField field, boolean dark, Color text) {
		if (field == null) {
			return;
		}
		field.setBackground(dark ? new Color(45, 48, 52) : Color.WHITE);
		field.setForeground(text);
		field.setCaretColor(text);
	}

	private void styleFilterPanel(JPanel panel, boolean dark, Color panelBg, Color text) {
		if (panel == null) {
			return;
		}
		panel.setBackground(panelBg);
		for (java.awt.Component component : panel.getComponents()) {
			if (component instanceof JPanel childPanel) {
				childPanel.setBackground(panelBg);
				for (java.awt.Component child : childPanel.getComponents()) {
					if (child instanceof JLabel label) {
						label.setForeground(text);
					}
				}
			}
			else if (component instanceof JScrollPane scrollPane) {
				scrollPane.getViewport().setBackground(dark ? DARK_PANEL_BG : LIGHT_PANEL_BG);
			}
		}
	}

	private void styleTabbedPane(JTabbedPane tabbedPane, boolean dark, Color background,
			Color foreground) {
		tabbedPane.setBackground(background);
		tabbedPane.setForeground(foreground);
		for (int i = 0; i < tabbedPane.getTabCount(); i++) {
			tabbedPane.setBackgroundAt(i, background);
			tabbedPane.setForegroundAt(i, foreground);
		}
	}

	private void styleTable(JTable table, boolean dark) {
		Color background = dark ? DARK_BG : Color.WHITE;
		Color foreground = dark ? DARK_HEADER_FG : LIGHT_HEADER_FG;
		Color grid = dark ? new Color(72, 76, 82) : new Color(210, 210, 205);
		Color selectionBg = dark ? new Color(68, 91, 120) : new Color(204, 226, 255);
		Color selectionFg = dark ? Color.WHITE : Color.BLACK;
		table.setBackground(background);
		table.setForeground(foreground);
		table.setGridColor(grid);
		table.setSelectionBackground(selectionBg);
		table.setSelectionForeground(selectionFg);
		table.setFont(new Font(Font.MONOSPACED, Font.PLAIN, Math.max(11, plugin.fontSize() - 1)));
		table.setRowHeight(Math.max(18, plugin.fontSize() + 6));
		table.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
			@Override
			public java.awt.Component getTableCellRendererComponent(JTable table, Object value,
					boolean selected, boolean focused, int row, int column) {
				JLabel label = (JLabel) super.getTableCellRendererComponent(table, value, selected,
					focused, row, column);
				label.setOpaque(true);
				label.setBackground(selected ? selectionBg : background);
				label.setForeground(selected ? selectionFg : foreground);
				label.setBorder(BorderFactory.createEmptyBorder(1, 4, 1, 4));
				return label;
			}
		});

		JTableHeader header = table.getTableHeader();
		Color headerBg = dark ? DARK_HEADER_BG : LIGHT_HEADER_BG;
		Color headerFg = dark ? DARK_HEADER_FG : LIGHT_HEADER_FG;
		header.setOpaque(true);
		header.setBackground(headerBg);
		header.setForeground(headerFg);
		header.setFont(table.getFont().deriveFont(Font.BOLD));
		header.setDefaultRenderer(new DefaultTableCellRenderer() {
			@Override
			public java.awt.Component getTableCellRendererComponent(JTable table, Object value,
					boolean selected, boolean focused, int row, int column) {
				JLabel label = (JLabel) super.getTableCellRendererComponent(table, value, selected,
					focused, row, column);
				label.setOpaque(true);
				label.setBackground(headerBg);
				label.setForeground(headerFg);
				label.setFont(table.getFont().deriveFont(Font.BOLD));
				label.setBorder(BorderFactory.createEmptyBorder(2, 4, 2, 4));
				return label;
			}
		});
		header.repaint();
	}

	private void updateGutter(PseudocodeTab tab) {
		if (!plugin.showGutter()) {
			tab.gutter.setText("");
			return;
		}
		List<PseudocodeLine> lines = tab.lines.isEmpty() ? buildLinesFromText(tab.textPane.getText())
				: tab.lines;
		StringBuilder builder = new StringBuilder();
		for (PseudocodeLine line : lines) {
			if (plugin.showLineNumbers()) {
				builder.append(String.format("%4d", line.number()));
			}
			if (plugin.showTokenAddresses()) {
				builder.append(" ");
				builder.append(line.address() == null ? "        " : line.address().toString());
			}
			builder.append(System.lineSeparator());
		}
		tab.gutter.setText(builder.toString());
		tab.gutter.setCaretPosition(0);
	}

	private List<PseudocodeLine> buildLines(ParadiseDecompileResult result) {
		return buildLines(result.code(), result.tokenSpans());
	}

	private List<PseudocodeLine> buildLines(String code, List<ParadiseTokenSpan> spans) {
		List<PseudocodeLine> lines = buildLinesFromText(code);
		if (spans.isEmpty()) {
			return lines;
		}
		List<PseudocodeLine> enriched = new ArrayList<>();
		for (PseudocodeLine line : lines) {
			Address address = null;
			for (ParadiseTokenSpan span : spans) {
				if (span.end() <= line.start()) {
					continue;
				}
				if (span.start() >= line.end()) {
					break;
				}
				address = span.address();
				if (address != null) {
					break;
				}
			}
			enriched.add(new PseudocodeLine(line.number(), line.start(), line.end(), address));
		}
		return enriched;
	}

	private List<PseudocodeLine> buildLinesFromText(String text) {
		List<PseudocodeLine> lines = new ArrayList<>();
		int start = 0;
		int number = 1;
		while (start <= text.length()) {
			int newline = text.indexOf('\n', start);
			int end = newline < 0 ? text.length() : newline;
			lines.add(new PseudocodeLine(number++, start, end, null));
			if (newline < 0) {
				break;
			}
			start = newline + 1;
		}
		return lines;
	}

	private PseudocodeLine lineAt(PseudocodeTab tab, int offset) {
		for (PseudocodeLine line : tab.lines) {
			if (line.start() <= offset && offset <= line.end()) {
				return line;
			}
		}
		if (!tab.lines.isEmpty()) {
			return tab.lines.get(tab.lines.size() - 1);
		}
		return null;
	}

	private Integer offsetForAddress(PseudocodeTab tab, Address address) {
		for (ParadiseTokenSpan span : tab.displaySpans) {
			if (spanContainsAddress(span, address)) {
				return span.start();
			}
		}
		for (PseudocodeLine line : tab.lines) {
			if (address.equals(line.address())) {
				return line.start();
			}
		}
		return null;
	}

	private boolean spanContainsAddress(ParadiseTokenSpan span, Address address) {
		Address min = span.minAddress();
		Address max = span.maxAddress();
		if (min == null && max == null) {
			return false;
		}
		if (address.equals(min) || address.equals(max)) {
			return true;
		}
		if (min == null || max == null ||
			!Objects.equals(address.getAddressSpace(), min.getAddressSpace()) ||
			!Objects.equals(address.getAddressSpace(), max.getAddressSpace())) {
			return false;
		}
		Address low = min.compareTo(max) <= 0 ? min : max;
		Address high = min.compareTo(max) <= 0 ? max : min;
		return address.compareTo(low) >= 0 && address.compareTo(high) <= 0;
	}

	private void updateAuxPanels(ParadiseDecompileResult result) {
		fill(xrefsModel);
		fill(localsModel);
		fill(callsModel);
		fill(stringsModel);
		for (DefaultTableModel model : encodedStringModels.values()) {
			fill(model);
		}
		fill(cleanupsModel);
		fill(diffModel);
		fill(draftsModel);
		fill(suggestionsModel);
		fill(triageModel);
		fill(traceModel);
		cleanupsSummaryLabel.setText("No Clean C cleanup data");
		xrefRows = List.of();
		callRows = List.of();
		stringRows = List.of();
		encodedStringRowsByCodec = new EnumMap<>(ParadiseDecodeUtil.Codec.class);
		suggestionRows = List.of();
		triageRows = List.of();
		traceRows = List.of();
		if (result == null) {
			rebuildStringsPanelTabs();
			return;
		}
		updateXrefsPanel(result);
		updateLocalsPanel(result);
		updateCallsPanel(result);
		updateStringsPanel(result);
		updateDiffPanel(result);
		updateDraftsPanel(result);
		updateTriagePanel(result);
		updateSuggestionsPanel(result);
		updateCleanupsPanel(result);
		updateTracePanel(currentTab());
	}

	private void updateXrefsPanel(ParadiseDecompileResult result) {
		List<ParadiseXrefRow> rows = xrefsTo(result.program(), result.function().getEntryPoint());
		xrefRows = rows;
		for (ParadiseXrefRow row : rows) {
			xrefsModel.addRow(new Object[] { "caller", row.from(), row.functionName(), row.type(),
				row.preview() });
		}
	}

	private void updateLocalsPanel(ParadiseDecompileResult result) {
		Function function = result.function();
		for (Parameter parameter : function.getParameters()) {
			localsModel.addRow(new Object[] { "param", parameter.getName(),
				parameter.getDataType().getDisplayName(), parameter.getVariableStorage(),
				parameter.getSource() });
		}
		for (Variable variable : function.getLocalVariables()) {
			localsModel.addRow(new Object[] { "local", variable.getName(),
				variable.getDataType().getDisplayName(), variable.getVariableStorage(),
				variable.getSource() });
		}
		HighFunction highFunction = result.highFunction();
		if (highFunction == null || highFunction.getLocalSymbolMap() == null) {
			return;
		}
		Iterator<HighSymbol> iterator = highFunction.getLocalSymbolMap().getSymbols();
		while (iterator.hasNext()) {
			HighSymbol symbol = iterator.next();
			localsModel.addRow(new Object[] { symbol.isParameter() ? "high param" : "high local",
				symbol.getName(), symbol.getDataType().getDisplayName(), symbol.getStorage(),
				symbol.isNameLocked() || symbol.isTypeLocked() ? "locked" : "decompiler" });
		}
	}

	private void updateCallsPanel(ParadiseDecompileResult result) {
		List<CallRow> rows = new ArrayList<>();
		Program program = result.program();
		Function function = result.function();
		for (Instruction instruction : program.getListing().getInstructions(function.getBody(), true)) {
			for (Reference reference : instruction.getReferencesFrom()) {
				if (!reference.getReferenceType().isCall()) {
					continue;
				}
				Function target = program.getFunctionManager().getFunctionAt(reference.getToAddress());
				rows.add(new CallRow("callee", reference.getToAddress(), target,
					reference.getReferenceType().getDisplayString(), previewFor(program,
						instruction.getAddress())));
			}
		}
		ReferenceIterator iterator =
			program.getReferenceManager().getReferencesTo(function.getEntryPoint());
		while (iterator.hasNext()) {
			Reference reference = iterator.next();
			if (!reference.getReferenceType().isCall()) {
				continue;
			}
			Function caller =
				program.getFunctionManager().getFunctionContaining(reference.getFromAddress());
			rows.add(new CallRow("caller", reference.getFromAddress(), caller,
				reference.getReferenceType().getDisplayString(), previewFor(program,
					reference.getFromAddress())));
		}
		callRows = rows;
		for (CallRow row : rows) {
			callsModel.addRow(new Object[] { row.direction(), row.address(), row.functionName(),
				row.type(), row.preview() });
		}
	}

	private void updateStringsPanel(ParadiseDecompileResult result) {
		Map<String, StringRow> rows = new LinkedHashMap<>();
		Program program = result.program();
		for (Instruction instruction : program.getListing().getInstructions(result.function().getBody(),
			true)) {
			for (Reference reference : instruction.getReferencesFrom()) {
				StringRow row = stringRow(program, instruction.getAddress(), reference.getToAddress());
				if (row != null) {
					addStringRow(rows, row);
				}
			}
		}
		addRenderedStringRows(rows, result);
		stringRows = List.copyOf(rows.values());
		for (StringRow row : stringRows) {
			stringsModel.addRow(new Object[] { row.useAddress(), row.stringAddress(),
				preview(row.value(), 200) });
		}
		encodedStringRowsByCodec = encodedStringRows(stringRows);
		for (Map.Entry<ParadiseDecodeUtil.Codec, List<EncodedStringRow>> entry :
				encodedStringRowsByCodec.entrySet()) {
			DefaultTableModel model = encodedStringModels.get(entry.getKey());
			if (model == null) {
				continue;
			}
			for (EncodedStringRow row : entry.getValue()) {
				model.addRow(new Object[] { row.useAddress(), row.encodedPreview(), row.chain(),
					row.decodedPreview(), row.kind(), row.confidence() });
			}
		}
		rebuildStringsPanelTabs();
	}

	private void updateDiffPanel(ParadiseDecompileResult result) {
		String[] rawLines = result.rawCode() == null ? new String[0] : result.rawCode().split("\\R", -1);
		String[] cleanLines = result.code() == null ? new String[0] : result.code().split("\\R", -1);
		int count = Math.max(rawLines.length, cleanLines.length);
		for (int i = 0; i < count; i++) {
			String raw = i < rawLines.length ? rawLines[i] : "";
			String clean = i < cleanLines.length ? cleanLines[i] : "";
			if (!Objects.equals(raw, clean)) {
				diffModel.addRow(new Object[] { i + 1, raw, clean });
			}
		}
		if (diffModel.getRowCount() == 0) {
			diffModel.addRow(new Object[] { "", "No raw/clean differences", "" });
		}
	}

	private void updateDraftsPanel(ParadiseDecompileResult result) {
		draftsModel.addRow(new Object[] { "comment", result.function().getName(),
			draftComment(result) });
		for (String hint : typeRecoveryHints(result)) {
			draftsModel.addRow(new Object[] { "type hint", result.function().getName(), hint });
		}
		for (String cleanup : result.cleanups()) {
			if (cleanup.toLowerCase(Locale.ROOT).contains("varargs")) {
				draftsModel.addRow(new Object[] { "signature", result.function().getName(),
					"Consider variadic signature for wrapper-like function." });
			}
		}
	}

	String draftComment(ParadiseDecompileResult result) {
		if (result == null || result.function() == null) {
			return "";
		}
		StringBuilder builder = new StringBuilder();
		builder.append("Paradise draft: ");
		List<String> calls = calledFunctionNames(result);
		List<String> strings = renderedStrings(result, 3);
		if (!calls.isEmpty()) {
			builder.append("calls ").append(String.join(", ", calls.subList(0,
				Math.min(4, calls.size()))));
		}
		if (!strings.isEmpty()) {
			if (!calls.isEmpty()) {
				builder.append("; ");
			}
			builder.append("uses strings ").append(String.join(", ", strings));
		}
		if (result.code().contains("fread(") && result.code().contains("fwrite(")) {
			if (!calls.isEmpty() || !strings.isEmpty()) {
				builder.append("; ");
			}
			builder.append("processes file data in a byte loop");
		}
		if (builder.toString().equals("Paradise draft: ")) {
			builder.append("review ").append(result.function().getName()).append(" behavior.");
		}
		return builder.toString();
	}

	private List<String> typeRecoveryHints(ParadiseDecompileResult result) {
		List<String> hints = new ArrayList<>();
		String code = result.code();
		if (code.contains("fopen(") || code.contains("fread(") || code.contains("fwrite(")) {
			hints.add("FILE stream locals detected; consider naming input/output stream variables.");
		}
		if (code.matches("(?s).*\\b(?:uint8_t|byte|char)\\s+\\w+\\s*\\[.*")) {
			hints.add("Byte/char buffer local detected; inspect whether it is a string or raw buffer.");
		}
		if (code.contains("% 4") || code.contains("%4")) {
			hints.add("Modulo-4 index pattern detected; possible 4-byte key or rolling table.");
		}
		if (code.contains("va_start(")) {
			hints.add("Variadic wrapper detected; verify printf/scanf-like format argument.");
		}
		if (hints.isEmpty()) {
			hints.add("No strong local type hints detected.");
		}
		return hints;
	}

	private void updateTriagePanel(ParadiseDecompileResult result) {
		Program program = result.program();
		List<TriageRow> rows = new ArrayList<>();
		for (Function function : program.getFunctionManager().getFunctions(true)) {
			if (function.isExternal()) {
				continue;
			}
			int strings = functionStringCount(program, function);
			int calls = functionCallCount(program, function);
			int xrefs = xrefsTo(program, function.getEntryPoint()).size();
			String hints = triageHints(function, strings, calls, xrefs);
			int score = strings * 3 + calls * 2 + xrefs;
			rows.add(new TriageRow(function, score, strings, calls, xrefs, hints));
		}
		rows.sort(Comparator.comparingInt(TriageRow::score).reversed()
				.thenComparing(row -> row.function().getEntryPoint()));
		triageRows = rows;
		for (TriageRow row : rows) {
			triageModel.addRow(new Object[] { row.function().getEntryPoint(),
				row.function().getName(), row.score(), row.strings(), row.calls(),
				row.xrefs(), row.hints() });
		}
	}

	private void updateSuggestionsPanel(ParadiseDecompileResult result) {
		List<SuggestionRow> rows = new ArrayList<>();
		Program program = result.program();
		for (Instruction instruction : program.getListing().getInstructions(result.function().getBody(),
			true)) {
			String mnemonic = instruction.getMnemonicString().toLowerCase(Locale.ROOT);
			String text = previewFor(program, instruction.getAddress());
			if (mnemonic.equals("xor")) {
				rows.add(suggestion(instruction.getAddress(), "XOR operation suspected",
					text));
			}
			else if (mnemonic.matches("rol|ror|shl|shr|sal|sar")) {
				rows.add(suggestion(instruction.getAddress(), "Bit shift/rotate suspected",
					text));
			}
			else if (mnemonic.equals("cmp") || mnemonic.equals("test")) {
				rows.add(suggestion(instruction.getAddress(), "Branch condition source",
					text));
			}
			else if (instruction.getFlowType().isCall()) {
				String target = callTargetName(program, instruction);
				String lowerTarget = target.toLowerCase(Locale.ROOT);
				if (lowerTarget.matches(".*(crypt|encrypt|decrypt|hash|sha|md5|aes|rc4|xor).*")) {
					rows.add(suggestion(instruction.getAddress(),
						"Crypto-related call suspected", text));
				}
				else if (lowerTarget.matches(".*(fopen|fread|fwrite|read|write|open|close).*")) {
					rows.add(suggestion(instruction.getAddress(), "File I/O call", text));
				}
				else if (lowerTarget.matches(".*(strcpy|strncpy|strcat|sprintf|gets|scanf).*")) {
					rows.add(suggestion(instruction.getAddress(),
						"Potentially risky string/input call", text));
				}
			}
			for (Reference reference : instruction.getReferencesFrom()) {
				ParadiseStringUtil.ParadiseString string =
					ParadiseStringUtil.stringAt(program, reference.getToAddress());
				if (string != null) {
					rows.add(suggestion(instruction.getAddress(), "String reference",
						"\"" + previewString(string.value(), 100) + "\""));
				}
			}
		}
		if (result.code().contains("% 4") || result.code().contains("%4")) {
			rows.add(suggestion(result.function().getEntryPoint(), "Modulo key/index pattern",
				"Clean C contains modulo-4 indexing."));
		}
		if (result.code().contains("while (fread(")) {
			rows.add(suggestion(result.function().getEntryPoint(), "Byte processing loop",
				"Clean C loop reads one byte at a time."));
		}
		if (rows.isEmpty()) {
			rows.add(suggestion(result.function().getEntryPoint(), "No strong findings",
				"No suspicious instruction-level pattern detected."));
		}
		rows.sort(Comparator.comparingInt(SuggestionRow::priority)
				.thenComparing(SuggestionRow::address)
				.thenComparing(SuggestionRow::finding));
		suggestionRows = rows;
		for (SuggestionRow row : rows) {
			suggestionsModel.addRow(new Object[] { row.priority(), row.address(), row.finding(),
				row.evidence() });
		}
	}

	private SuggestionRow suggestion(Address address, String finding, String evidence) {
		return new SuggestionRow(suggestionPriority(finding, evidence), address, finding, evidence);
	}

	private int suggestionPriority(String finding, String evidence) {
		String text = (finding + " " + evidence).toLowerCase(Locale.ROOT);
		if (text.contains("crypto") || text.contains("xor") || text.contains("modulo key") ||
			text.contains("byte processing")) {
			return 2;
		}
		if (text.contains("risky") || text.contains("branch condition")) {
			return 3;
		}
		if (text.contains("file i/o") || text.contains("string reference")) {
			return 4;
		}
		if (text.contains("shift") || text.contains("rotate")) {
			return 5;
		}
		return 9;
	}

	private void updateCleanupsPanel(ParadiseDecompileResult result) {
		List<String> cleanups = result.cleanups();
		if (cleanups.isEmpty()) {
			cleanupsSummaryLabel.setText("No Clean C cleanup rules applied for " +
				result.function().getName());
			cleanupsModel.addRow(new Object[] { "none", "No cleanup rules were applied",
				"Raw Ghidra output already matches the enabled rules." });
			return;
		}
		cleanupsSummaryLabel.setText(cleanups.size() + " Clean C cleanup rule" +
			(cleanups.size() == 1 ? "" : "s") + " applied for " + result.function().getName());
		for (String cleanup : cleanups) {
			cleanupsModel.addRow(new Object[] { cleanupKind(cleanup), cleanup,
				cleanupEffect(cleanup) });
		}
	}

	private String cleanupKind(String cleanup) {
		String text = cleanup.toLowerCase(Locale.ROOT);
		if (text.contains("varargs") || text.contains("wrapper") || text.contains("printf") ||
			text.contains("scanf")) {
			return "call cleanup";
		}
		if (text.contains("loop") || text.contains("while") || text.contains("for")) {
			return "flow cleanup";
		}
		if (text.contains("cast") || text.contains("literal") || text.contains("expression") ||
			text.contains("index")) {
			return "expression";
		}
		if (text.contains("comment") || text.contains("string")) {
			return "annotation";
		}
		if (text.contains("type") || text.contains("signature")) {
			return "type display";
		}
		return "display";
	}

	private String cleanupEffect(String cleanup) {
		String text = cleanup.toLowerCase(Locale.ROOT);
		if (text.contains("varargs")) {
			return "Hides va_list/local_res noise and displays variadic-style calls.";
		}
		if (text.contains("loop")) {
			return "Makes recovered control flow closer to structured pseudocode.";
		}
		if (text.contains("cast")) {
			return "Removes redundant casts from the visible expression.";
		}
		if (text.contains("literal")) {
			return "Normalizes numeric constants for easier reading.";
		}
		if (text.contains("index")) {
			return "Simplifies array or pointer indexing syntax.";
		}
		if (text.contains("comment") || text.contains("string")) {
			return "Adds display-only context from known comments or strings.";
		}
		return "Display/export cleanup only; no Ghidra database change.";
	}

	private void traceSelectedVariable() {
		PseudocodeTab tab = currentTab();
		String variable = traceableSelectedVariable(tab);
		if (tab == null || tab.result == null || variable == null) {
			Msg.showInfo(this, panel, "Trace Variable",
				"Select a pseudocode variable, parameter, or local first.");
			return;
		}
		tab.tracedVariable = variable;
		rebuildTrace(tab);
		selectAuxTab("Trace");
		updateEditorHighlights(tab);
		updateTraceSelectionForCaret(tab);
		if (tab.traceRows.isEmpty()) {
			Msg.showInfo(this, panel, "Trace Variable",
				"No visible uses of " + variable + " were found in this pseudocode view.");
		}
	}

	private String traceableSelectedVariable(PseudocodeTab tab) {
		if (tab == null || tab.result == null) {
			return null;
		}
		String identifier = firstIdentifier(tab.textPane.getSelectedText());
		if (isTraceableIdentifier(identifier)) {
			return identifier;
		}
		identifier = identifierAtCaret(tab);
		if (isTraceableIdentifier(identifier)) {
			return identifier;
		}
		ParadiseTokenSpan span = selectedSpan();
		String text = span == null || span.token() == null ? null : span.token().getText();
		identifier = firstIdentifier(text);
		if (isTraceableIdentifier(identifier)) {
			return identifier;
		}
		identifier = nearestTraceableIdentifierOnLine(tab);
		return isTraceableIdentifier(identifier) ? identifier : null;
	}

	private String identifierAtCaret(PseudocodeTab tab) {
		String text = tab.textPane.getText();
		if (text.isEmpty()) {
			return null;
		}
		int pos = Math.max(0, Math.min(tab.textPane.getCaretPosition(), text.length() - 1));
		if (!isIdentifierPart(text.charAt(pos)) && pos > 0 && isIdentifierPart(text.charAt(pos - 1))) {
			pos--;
		}
		if (!isIdentifierPart(text.charAt(pos))) {
			return null;
		}
		int start = pos;
		while (start > 0 && isIdentifierPart(text.charAt(start - 1))) {
			start--;
		}
		int end = pos + 1;
		while (end < text.length() && isIdentifierPart(text.charAt(end))) {
			end++;
		}
		return text.substring(start, end);
	}

	private boolean isIdentifierPart(char c) {
		return Character.isLetterOrDigit(c) || c == '_';
	}

	private String nearestTraceableIdentifierOnLine(PseudocodeTab tab) {
		PseudocodeLine line = lineAt(tab, tab.textPane.getCaretPosition());
		if (line == null) {
			return null;
		}
		String text = lineText(tab.textPane.getText(), line);
		Set<String> locals = traceableVariableNames(tab.result);
		Matcher matcher = IDENTIFIER_PATTERN.matcher(text);
		String fallback = null;
		while (matcher.find()) {
			String identifier = matcher.group();
			if (!isTraceableIdentifier(identifier)) {
				continue;
			}
			if (locals.contains(identifier)) {
				return identifier;
			}
			if (fallback == null && looksLikeLocalIdentifier(identifier)) {
				fallback = identifier;
			}
		}
		return fallback;
	}

	private Set<String> traceableVariableNames(ParadiseDecompileResult result) {
		Set<String> names = new LinkedHashSet<>();
		if (result == null || result.function() == null) {
			return names;
		}
		for (Parameter parameter : result.function().getParameters()) {
			names.add(parameter.getName());
		}
		for (Variable variable : result.function().getLocalVariables()) {
			names.add(variable.getName());
		}
		HighFunction highFunction = result.highFunction();
		if (highFunction != null && highFunction.getLocalSymbolMap() != null) {
			Iterator<HighSymbol> iterator = highFunction.getLocalSymbolMap().getSymbols();
			while (iterator.hasNext()) {
				names.add(iterator.next().getName());
			}
		}
		return names;
	}

	private boolean looksLikeLocalIdentifier(String identifier) {
		return identifier.matches("(?:local|param|uVar|iVar|bVar|cVar|sVar|lVar|puVar|pcVar|pbVar|in_FS_OFFSET)_?.*") ||
			identifier.matches("[A-Za-z_]\\w*_(?:\\d|[0-9a-fA-F])\\w*");
	}

	private String firstIdentifier(String text) {
		if (text == null) {
			return null;
		}
		Matcher matcher = IDENTIFIER_PATTERN.matcher(text);
		return matcher.find() ? matcher.group() : null;
	}

	private boolean isTraceableIdentifier(String identifier) {
		return identifier != null && IDENTIFIER_PATTERN.matcher(identifier).matches() &&
			!isCKeyword(identifier) && !isTypeIdentifier(identifier);
	}

	private boolean isTypeIdentifier(String identifier) {
		return identifier.matches("(?:u?int(?:8|16|32|64)?_t|size_t|ssize_t|uintptr_t|intptr_t|FILE|bool|byte|undefined\\w*)") ||
			identifier.matches("_[A-Z]+");
	}

	private boolean isCKeyword(String identifier) {
		return switch (identifier) {
			case "auto", "break", "case", "char", "const", "continue", "default", "do",
				"double", "else", "enum", "extern", "float", "for", "goto", "if", "inline",
				"int", "long", "register", "restrict", "return", "short", "signed", "sizeof",
				"static", "struct", "switch", "typedef", "union", "unsigned", "void",
				"volatile", "while", "bool", "true", "false", "NULL" -> true;
			default -> false;
		};
	}

	private void rebuildTrace(PseudocodeTab tab) {
		if (tab == null || tab.result == null || tab.tracedVariable == null ||
			tab.tracedVariable.isBlank()) {
			if (tab == currentTab()) {
				updateTracePanel(tab);
			}
			return;
		}
		tab.traceRows = traceRowsFor(tab, tab.tracedVariable);
		if (tab == currentTab()) {
			updateTracePanel(tab);
		}
	}

	private void updateTracePanel(PseudocodeTab tab) {
		fill(traceModel);
		traceRows = tab == null ? List.of() : tab.traceRows;
		for (TraceRow row : traceRows) {
			traceModel.addRow(new Object[] {
				row.address() == null ? "" : row.address(),
				row.lineNumber(),
				row.role(),
				row.expression(),
				row.value()
			});
		}
	}

	private List<TraceRow> traceRowsFor(PseudocodeTab tab, String variable) {
		String text = tab.textPane.getText();
		Pattern identifier = identifierPattern(variable);
		TraceState state = new TraceState();
		List<TraceRow> rows = new ArrayList<>();
		List<PseudocodeLine> lines = tab.lines.isEmpty() ? buildLinesFromText(text) : tab.lines;
		for (PseudocodeLine line : lines) {
			String expression = lineText(text, line).trim();
			if (expression.isEmpty() || !identifier.matcher(expression).find()) {
				continue;
			}
			String role = traceRole(variable, expression);
			String value = traceValue(variable, expression, role, state);
			rows.add(new TraceRow(line.address(), line.number(), line.start(), line.end(), role,
				expression, value));
		}
		return List.copyOf(rows);
	}

	private String traceRole(String variable, String expression) {
		String clean = stripTrailingComment(expression).trim();
		if (isDeclarationOf(variable, clean)) {
			return assignmentRhs(variable, clean) == null ? "declaration" : "init";
		}
		if (matches(clean, "(?:\\+\\+|--)\\s*" + quotedIdentifier(variable) + "\\b") ||
			matches(clean, quotedIdentifier(variable) + "\\s*(?:\\+\\+|--)")) {
			return "update";
		}
		if (matches(clean, quotedIdentifier(variable) + "\\s*(?:<<|>>|[+\\-*/%&|^])?=")) {
			return clean.contains("^=") || clean.contains("&=") || clean.contains("|=") ?
				"transform" : "assign";
		}
		if (matches(clean, "\\[[^\\]]*" + quotedIdentifier(variable) + "[^\\]]*\\]") ||
			matches(clean, quotedIdentifier(variable) + "\\s*%")) {
			return "index";
		}
		if (clean.startsWith("if ") || clean.startsWith("if(") || clean.startsWith("while ") ||
			clean.startsWith("while(") || clean.startsWith("for ") || clean.startsWith("for(")) {
			return "condition";
		}
		if (matches(clean, "&\\s*" + quotedIdentifier(variable) + "\\b")) {
			return "address arg";
		}
		if (matches(clean, "\\w+\\s*\\([^;]*" + quotedIdentifier(variable) + "[^;]*\\)")) {
			return "argument";
		}
		return "use";
	}

	private String traceValue(String variable, String expression, String role, TraceState state) {
		String clean = stripTrailingComment(expression).trim();
		if ("declaration".equals(role)) {
			state.clear();
			return "declared; value unknown";
		}
		String increment = incrementOperator(variable, clean);
		if (increment != null) {
			return applyIncrement(variable, increment, state);
		}
		CompoundUpdate compound = compoundUpdate(variable, clean);
		if (compound != null) {
			return applyUpdate(variable, compound.operator(), compound.rhs(), state);
		}
		String rhs = assignmentRhs(variable, clean);
		if (rhs != null) {
			return applyAssignment(variable, rhs, state);
		}
		String modulo = moduloValue(variable, clean, state);
		if (modulo != null) {
			return modulo;
		}
		if (matches(clean, "&\\s*" + quotedIdentifier(variable) + "\\b")) {
			return callByAddressValue(variable, clean, state);
		}
		if (state.numericValue != null) {
			return variable + " = " + state.numericValue;
		}
		if (state.symbolicValue != null) {
			return variable + " = " + state.symbolicValue;
		}
		return "unknown";
	}

	private String applyAssignment(String variable, String rhs, TraceState state) {
		String normalized = normalizeTraceExpression(rhs);
		Long literal = parseTraceInteger(normalized);
		if (literal != null) {
			state.numericValue = literal;
			state.symbolicValue = Long.toString(literal);
			return variable + " = " + literal;
		}
		DirectUpdate update = directUpdate(variable, normalized);
		if (update != null) {
			return applyUpdate(variable, update.operator(), update.rhs(), state);
		}
		state.numericValue = null;
		state.symbolicValue = normalized;
		return variable + " = " + normalized;
	}

	private String applyIncrement(String variable, String operator, TraceState state) {
		return applyUpdate(variable, operator.equals("++") ? "+" : "-", "1", state);
	}

	private String applyUpdate(String variable, String operator, String rhs, TraceState state) {
		String normalizedRhs = normalizeTraceExpression(rhs);
		Long rhsValue = parseTraceInteger(normalizedRhs);
		Long before = state.numericValue;
		if (before != null && rhsValue != null) {
			Long after = evaluateBinary(before, operator, rhsValue);
			if (after != null) {
				state.numericValue = after;
				state.symbolicValue = Long.toString(after);
				return variable + " = " + before + " " + operator + " " + rhsValue + " = " + after;
			}
		}
		String previous = state.symbolicValue == null ? variable : state.symbolicValue;
		String value = previous + " " + operator + " " + normalizedRhs;
		state.numericValue = null;
		state.symbolicValue = value;
		return variable + " = " + value;
	}

	private Long evaluateBinary(long left, String operator, long right) {
		return switch (operator) {
			case "+" -> left + right;
			case "-" -> left - right;
			case "*" -> left * right;
			case "/" -> right == 0 ? null : left / right;
			case "%" -> right == 0 ? null : left % right;
			case "^" -> left ^ right;
			case "&" -> left & right;
			case "|" -> left | right;
			case "<<" -> right < 0 || right >= Long.SIZE ? null : left << right;
			case ">>" -> right < 0 || right >= Long.SIZE ? null : left >> right;
			default -> null;
		};
	}

	private String moduloValue(String variable, String expression, TraceState state) {
		Matcher matcher = Pattern.compile(quotedIdentifier(variable) + "\\s*%\\s*(" +
			integerLiteralRegex() + ")").matcher(expression);
		if (!matcher.find()) {
			return null;
		}
		Long divisor = parseTraceInteger(matcher.group(1));
		if (divisor == null || divisor == 0) {
			return variable + " % " + matcher.group(1) + " = unknown";
		}
		if (state.numericValue != null) {
			return variable + " = " + state.numericValue + "; " + variable + " % " + divisor +
				" = " + Math.floorMod(state.numericValue, divisor);
		}
		return variable + " % " + divisor + " = 0.." + (Math.abs(divisor) - 1) + " repeating";
	}

	private String callByAddressValue(String variable, String expression, TraceState state) {
		String call = firstCallName(expression);
		String prefix = call == null ? "passed by address" : "passed by address to " + call;
		if (call != null && call.toLowerCase(Locale.ROOT).matches(".*(read|scanf|gets|recv).*")) {
			state.clear();
			return prefix + "; value may be written by the call";
		}
		if (state.numericValue != null) {
			return prefix + "; current " + variable + " = " + state.numericValue;
		}
		if (state.symbolicValue != null) {
			return prefix + "; current " + variable + " = " + state.symbolicValue;
		}
		return prefix + "; value unknown";
	}

	private Pattern identifierPattern(String identifier) {
		return Pattern.compile("\\b" + Pattern.quote(identifier) + "\\b");
	}

	private String quotedIdentifier(String identifier) {
		return "\\b" + Pattern.quote(identifier) + "\\b";
	}

	private boolean isDeclarationOf(String variable, String expression) {
		if (!matches(expression, quotedIdentifier(variable) + "\\s*(?:\\[.*\\])?\\s*(?:=|;)")) {
			return false;
		}
		String prefix = expression.substring(0, expression.indexOf(variable)).trim();
		return prefix.matches(".*\\b(?:bool|byte|char|double|float|int|int\\d+_t|uint\\d+_t|long|short|size_t|FILE|undefined\\w*|_BYTE|_DWORD|_QWORD)\\b.*");
	}

	private String assignmentRhs(String variable, String expression) {
		Matcher matcher = Pattern.compile(quotedIdentifier(variable) + "\\s*=\\s*(?!=)(.+)")
				.matcher(expression);
		if (!matcher.find()) {
			return null;
		}
		String rhs = matcher.group(1).trim();
		rhs = rhs.replaceFirst(";\\s*$", "").trim();
		rhs = rhs.replaceFirst("\\)\\s*(?:==|!=|<=|>=|<|>).*", ")").trim();
		rhs = rhs.replaceFirst("\\{\\s*$", "").trim();
		return trimOuterParens(rhs);
	}

	private CompoundUpdate compoundUpdate(String variable, String expression) {
		Matcher matcher = Pattern.compile(quotedIdentifier(variable) +
			"\\s*(<<|>>|[+\\-*/%&|^])=\\s*(.+)").matcher(expression);
		if (!matcher.find()) {
			return null;
		}
		String rhs = matcher.group(2).replaceFirst(";\\s*$", "").trim();
		return new CompoundUpdate(matcher.group(1), trimOuterParens(rhs));
	}

	private DirectUpdate directUpdate(String variable, String expression) {
		Matcher matcher = Pattern.compile(quotedIdentifier(variable) +
			"\\s*(<<|>>|[+\\-*/%&|^])\\s*(.+)").matcher(trimOuterParens(expression));
		if (!matcher.matches()) {
			return null;
		}
		return new DirectUpdate(matcher.group(1), trimOuterParens(matcher.group(2).trim()));
	}

	private String incrementOperator(String variable, String expression) {
		if (matches(expression, "(?:\\+\\+\\s*" + quotedIdentifier(variable) + "|" +
			quotedIdentifier(variable) + "\\s*\\+\\+)")) {
			return "++";
		}
		if (matches(expression, "(?:--\\s*" + quotedIdentifier(variable) + "|" +
			quotedIdentifier(variable) + "\\s*--)")) {
			return "--";
		}
		return null;
	}

	private String firstCallName(String expression) {
		Matcher matcher = Pattern.compile("\\b([A-Za-z_]\\w*)\\s*\\(").matcher(expression);
		return matcher.find() ? matcher.group(1) : null;
	}

	private String normalizeTraceExpression(String expression) {
		String normalized = trimOuterParens(expression.trim());
		Matcher matcher = Pattern.compile(integerLiteralRegex()).matcher(normalized);
		StringBuffer buffer = new StringBuffer();
		while (matcher.find()) {
			Long value = parseTraceInteger(matcher.group());
			if (value == null) {
				continue;
			}
			matcher.appendReplacement(buffer, Matcher.quoteReplacement(Long.toString(value)));
		}
		matcher.appendTail(buffer);
		return buffer.toString();
	}

	private Long parseTraceInteger(String text) {
		if (text == null) {
			return null;
		}
		String trimmed = trimOuterParens(text.trim());
		if (trimmed.startsWith("(uint") || trimmed.startsWith("(int") ||
			trimmed.startsWith("(long") || trimmed.startsWith("(char")) {
			int castEnd = trimmed.indexOf(')');
			if (castEnd >= 0 && castEnd + 1 < trimmed.length()) {
				trimmed = trimOuterParens(trimmed.substring(castEnd + 1).trim());
			}
		}
		LiteralValue value = parseIntegerLiteral(trimmed);
		return value == null ? null : value.signedValue();
	}

	private String trimOuterParens(String text) {
		String value = text;
		while (value.length() >= 2 && value.charAt(0) == '(' &&
			matchingOuterParen(value)) {
			value = value.substring(1, value.length() - 1).trim();
		}
		return value;
	}

	private boolean matchingOuterParen(String text) {
		int depth = 0;
		for (int i = 0; i < text.length(); i++) {
			char c = text.charAt(i);
			if (c == '(') {
				depth++;
			}
			else if (c == ')') {
				depth--;
				if (depth == 0 && i != text.length() - 1) {
					return false;
				}
			}
		}
		return depth == 0;
	}

	private String integerLiteralRegex() {
		return "(?<![A-Za-z_])[-+]?(?:0x[0-9a-fA-F]+|0b[01]+|\\d+)[uUlL]*\\b";
	}

	private String stripTrailingComment(String expression) {
		int comment = expression.indexOf("//");
		return comment < 0 ? expression : expression.substring(0, comment);
	}

	private boolean matches(String text, String regex) {
		return Pattern.compile(regex).matcher(text).find();
	}

	private String lineText(String text, PseudocodeLine line) {
		int start = Math.max(0, Math.min(line.start(), text.length()));
		int end = Math.max(start, Math.min(line.end(), text.length()));
		return text.substring(start, end);
	}

	private void updateTraceSelectionForCaret(PseudocodeTab tab) {
		if (tab == null || tab != currentTab() || tab.traceRows.isEmpty()) {
			return;
		}
		if (traceRows != tab.traceRows) {
			updateTracePanel(tab);
		}
		PseudocodeLine line = lineAt(tab, tab.textPane.getCaretPosition());
		if (line == null) {
			return;
		}
		int modelRow = traceRowForLine(tab, line);
		if (modelRow < 0) {
			return;
		}
		int viewRow = traceTable.convertRowIndexToView(modelRow);
		if (viewRow < 0) {
			return;
		}
		if (traceTable.getSelectedRow() != viewRow) {
			traceTable.getSelectionModel().setSelectionInterval(viewRow, viewRow);
		}
		Rectangle rect = traceTable.getCellRect(viewRow, 0, true);
		traceTable.scrollRectToVisible(rect);
	}

	private int traceRowForLine(PseudocodeTab tab, PseudocodeLine line) {
		for (int i = 0; i < tab.traceRows.size(); i++) {
			TraceRow row = tab.traceRows.get(i);
			if (row.lineNumber() == line.number()) {
				return i;
			}
		}
		if (line.address() != null) {
			for (int i = 0; i < tab.traceRows.size(); i++) {
				if (line.address().equals(tab.traceRows.get(i).address())) {
					return i;
				}
			}
		}
		int nearest = -1;
		for (int i = 0; i < tab.traceRows.size(); i++) {
			if (tab.traceRows.get(i).startOffset() <= line.start()) {
				nearest = i;
			}
			else {
				break;
			}
		}
		return nearest;
	}

	private void revealTraceRow(TraceRow row) {
		PseudocodeTab tab = currentTab();
		if (tab == null || row == null) {
			return;
		}
		if (row.address() != null && revealAddress(row.address())) {
			return;
		}
		int offset = Math.max(0,
			Math.min(row.startOffset(), Math.max(0, tab.textPane.getDocument().getLength() - 1)));
		tab.textPane.setCaretPosition(offset);
		try {
			Rectangle rect = tab.textPane.modelToView2D(offset).getBounds();
			tab.textPane.scrollRectToVisible(rect);
		}
		catch (BadLocationException e) {
			// Ignore stale offsets after refresh.
		}
		tab.textPane.requestFocusInWindow();
	}

	private List<String> calledFunctionNames(ParadiseDecompileResult result) {
		List<String> names = new ArrayList<>();
		Program program = result.program();
		for (Instruction instruction : program.getListing().getInstructions(result.function().getBody(),
			true)) {
			for (Reference reference : instruction.getReferencesFrom()) {
				if (!reference.getReferenceType().isCall()) {
					continue;
				}
				Function target =
					program.getFunctionManager().getFunctionAt(reference.getToAddress());
				String name = target == null ? reference.getToAddress().toString() : target.getName();
				if (!names.contains(name)) {
					names.add(name);
				}
			}
		}
		return names;
	}

	private List<String> renderedStrings(ParadiseDecompileResult result, int max) {
		List<String> strings = new ArrayList<>();
		Matcher matcher = Pattern.compile("\"(?:\\\\.|[^\"\\\\])*\"").matcher(result.code());
		while (matcher.find() && strings.size() < max) {
			String value = matcher.group();
			if (!strings.contains(value)) {
				strings.add(value);
			}
		}
		return strings;
	}

	private int functionStringCount(Program program, Function function) {
		Set<Address> strings = new HashSet<>();
		for (Instruction instruction : program.getListing().getInstructions(function.getBody(), true)) {
			for (Reference reference : instruction.getReferencesFrom()) {
				if (ParadiseStringUtil.stringAt(program, reference.getToAddress()) != null) {
					strings.add(reference.getToAddress());
				}
			}
		}
		return strings.size();
	}

	private int functionCallCount(Program program, Function function) {
		int calls = 0;
		for (Instruction instruction : program.getListing().getInstructions(function.getBody(), true)) {
			if (instruction.getFlowType().isCall()) {
				calls++;
			}
		}
		return calls;
	}

	private String triageHints(Function function, int strings, int calls, int xrefs) {
		List<String> hints = new ArrayList<>();
		String name = function.getName().toLowerCase(Locale.ROOT);
		if (name.equals("main") || name.contains("main")) {
			hints.add("entry logic");
		}
		if (strings > 0) {
			hints.add("strings");
		}
		if (calls > 6) {
			hints.add("call-heavy");
		}
		if (xrefs == 0) {
			hints.add("orphan/export");
		}
		return hints.isEmpty() ? "review" : String.join(", ", hints);
	}

	private List<ParadiseXrefRow> xrefsTo(Program program, Address target) {
		List<ParadiseXrefRow> rows = new ArrayList<>();
		ReferenceIterator iterator = program.getReferenceManager().getReferencesTo(target);
		while (iterator.hasNext()) {
			Reference reference = iterator.next();
			Address from = reference.getFromAddress();
			Function function = program.getFunctionManager().getFunctionContaining(from);
			rows.add(new ParadiseXrefRow(from, function,
				reference.getReferenceType().getDisplayString(), previewFor(program, from)));
		}
		return rows;
	}

	private StringRow stringRow(Program program, Address useAddress, Address stringAddress) {
		ParadiseStringUtil.ParadiseString string =
			ParadiseStringUtil.stringAt(program, stringAddress);
		return string == null ? null : new StringRow(useAddress, string.address(),
			string.value());
	}

	private void addRenderedStringRows(Map<String, StringRow> rows, ParadiseDecompileResult result) {
		String code = result.code();
		if (code == null || code.isEmpty()) {
			return;
		}
		for (ParadiseTokenSpan span : result.tokenSpans()) {
			if (span.start() < 0 || span.end() > code.length() || span.start() >= span.end()) {
				continue;
			}
			String text = code.substring(span.start(), span.end()).trim();
			if (!isQuotedStringLiteral(text)) {
				continue;
			}
			String value = cStringLiteralValue(text);
			if (value == null || value.isBlank()) {
				continue;
			}
			addStringRow(rows, new StringRow(span.address(), span.address(), value));
		}
	}

	private void addStringRow(Map<String, StringRow> rows, StringRow row) {
		String key = Objects.toString(row.stringAddress(), "") + "\u0000" + row.value();
		rows.putIfAbsent(key, row);
	}

	private Map<ParadiseDecodeUtil.Codec, List<EncodedStringRow>> encodedStringRows(
			List<StringRow> rows) {
		Map<ParadiseDecodeUtil.Codec, List<EncodedStringRow>> matches =
			new EnumMap<>(ParadiseDecodeUtil.Codec.class);
		Set<String> seen = new HashSet<>();
		for (StringRow row : rows) {
			for (ParadiseDecodeUtil.Result result : ParadiseDecodeUtil.results(row.value(), true)) {
				String key = Objects.toString(row.stringAddress(), "") + "\u0000" + row.value() +
					"\u0000" + result.chain();
				if (seen.add(key)) {
					EncodedStringRow encodedRow =
						new EncodedStringRow(row.useAddress(), row.stringAddress(), row.value(),
							preview(row.value(), 200), result.chain(),
							result.decodedPreview(), result.kind(), result.confidence());
					matches.computeIfAbsent(result.codec(), ignored -> new ArrayList<>())
							.add(encodedRow);
				}
			}
		}
		return matches;
	}

	private String decodeDialogHeader(List<ParadiseDecodeUtil.Result> results) {
		if (results.size() == 1) {
			ParadiseDecodeUtil.Result result = results.get(0);
			return result.chain() + " -> " + result.kind() + " (" + result.confidence() + "%)";
		}
		return results.size() + " decode matches";
	}

	private String decodeDialogText(List<ParadiseDecodeUtil.Result> results) {
		if (results.size() == 1) {
			return results.get(0).decodedDisplay();
		}
		StringBuilder builder = new StringBuilder();
		for (ParadiseDecodeUtil.Result result : results) {
			if (builder.length() > 0) {
				builder.append(System.lineSeparator()).append(System.lineSeparator());
			}
			builder.append('[').append(result.confidence()).append("%] ")
				.append(result.chain()).append(" -> ").append(result.kind())
				.append(System.lineSeparator()).append(result.decodedPreview());
		}
		return builder.toString();
	}

	private int hexNibble(char c) {
		return ParadiseDecodeUtil.hexNibble(c);
	}

	private boolean isQuotedStringLiteral(String text) {
		return text.length() >= 2 && text.charAt(0) == '"' && text.charAt(text.length() - 1) == '"';
	}

	private String cStringLiteralValue(String text) {
		StringBuilder builder = new StringBuilder();
		for (int i = 1; i < text.length() - 1; i++) {
			char c = text.charAt(i);
			if (c != '\\' || i + 1 >= text.length() - 1) {
				builder.append(c);
				continue;
			}
			char escaped = text.charAt(++i);
			switch (escaped) {
				case 'n' -> builder.append('\n');
				case 'r' -> builder.append('\r');
				case 't' -> builder.append('\t');
				case '0' -> {
					int value = 0;
					int digits = 1;
					while (i + 1 < text.length() - 1 && digits < 3) {
						char next = text.charAt(i + 1);
						if (next < '0' || next > '7') {
							break;
						}
						value = (value << 3) | (next - '0');
						i++;
						digits++;
					}
					builder.append((char) value);
				}
				case '\\' -> builder.append('\\');
				case '"' -> builder.append('"');
				case 'x' -> {
					int value = 0;
					int digits = 0;
					while (i + 1 < text.length() - 1 && digits < 2) {
						int nibble = hexNibble(text.charAt(i + 1));
						if (nibble < 0) {
							break;
						}
						value = (value << 4) | nibble;
						i++;
						digits++;
					}
					builder.append(digits == 0 ? 'x' : (char) value);
				}
				case 'u' -> {
					if (i + 4 < text.length() - 1) {
						String hex = text.substring(i + 1, i + 5);
						if (hex.matches("[0-9A-Fa-f]{4}")) {
							builder.append((char) Integer.parseInt(hex, 16));
							i += 4;
						}
						else {
							builder.append('u');
						}
					}
					else {
						builder.append('u');
					}
				}
				default -> {
					if (escaped >= '1' && escaped <= '7') {
						int value = escaped - '0';
						int digits = 1;
						while (i + 1 < text.length() - 1 && digits < 3) {
							char next = text.charAt(i + 1);
							if (next < '0' || next > '7') {
								break;
							}
							value = (value << 3) | (next - '0');
							i++;
							digits++;
						}
						builder.append((char) value);
					}
					else {
						builder.append(escaped);
					}
				}
			}
		}
		return builder.toString();
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

	private String callTargetName(Program program, Instruction instruction) {
		for (Reference reference : instruction.getReferencesFrom()) {
			if (!reference.getReferenceType().isCall()) {
				continue;
			}
			Function target = program.getFunctionManager().getFunctionAt(reference.getToAddress());
			return target == null ? reference.getToAddress().toString() : target.getName();
		}
		Address[] flows = instruction.getFlows();
		if (flows.length == 0) {
			return "";
		}
		Function target = program.getFunctionManager().getFunctionAt(flows[0]);
		return target == null ? flows[0].toString() : target.getName();
	}

	private String previewString(String value, int maxLength) {
		if (value == null) {
			return "";
		}
		String oneLine = value.replace('\n', ' ').replace('\r', ' ').replace('\t', ' ');
		return oneLine.length() <= maxLength ? oneLine
				: oneLine.substring(0, Math.max(0, maxLength - 3)) + "...";
	}

	private void installTableNavigation() {
		xrefsTable.addMouseListener(tableDoubleClick(() -> {
			int row = selectedModelRow(xrefsTable);
			if (row >= 0 && row < xrefRows.size()) {
				ParadiseXrefRow xref = xrefRows.get(row);
				plugin.navigateTo(xref.from());
				if (plugin.openPseudocodeFromXrefsSetting() && xref.function() != null) {
					plugin.decompileFunction(xref.function(), false, true);
				}
			}
		}));
		callsTable.addMouseListener(tableDoubleClick(() -> {
			int row = selectedModelRow(callsTable);
			if (row >= 0 && row < callRows.size()) {
				CallRow call = callRows.get(row);
				plugin.navigateTo(call.address());
				if (call.function() != null) {
					plugin.decompileFunction(call.function(), false, true);
				}
			}
		}));
		stringsTable.addMouseListener(tableDoubleClick(() -> {
			int row = selectedModelRow(stringsTable);
			if (row >= 0 && row < stringRows.size()) {
				plugin.navigateTo(stringRows.get(row).stringAddress());
			}
		}));
		installStringTablePopup(stringsTable,
			row -> row >= 0 && row < stringRows.size() ? stringRows.get(row) : null);
		for (ParadiseDecodeUtil.Codec codec : ParadiseDecodeUtil.Codec.stringTabs()) {
			JTable table = encodedStringTables.get(codec);
			if (table == null) {
				continue;
			}
			table.addMouseListener(tableDoubleClick(() -> {
				int row = selectedModelRow(table);
				List<EncodedStringRow> rows =
					encodedStringRowsByCodec.getOrDefault(codec, List.of());
				if (row >= 0 && row < rows.size()) {
					plugin.navigateTo(rows.get(row).stringAddress());
				}
			}));
			installStringTablePopup(table, row -> {
				List<EncodedStringRow> rows =
					encodedStringRowsByCodec.getOrDefault(codec, List.of());
				if (row < 0 || row >= rows.size()) {
					return null;
				}
				EncodedStringRow encoded = rows.get(row);
				return new StringRow(encoded.useAddress(), encoded.stringAddress(), encoded.value());
			});
		}
		triageTable.addMouseListener(tableDoubleClick(() -> {
			int row = selectedModelRow(triageTable);
			if (row >= 0 && row < triageRows.size()) {
				Function function = triageRows.get(row).function();
				plugin.navigateTo(function.getEntryPoint());
				plugin.decompileFunction(function, false, true);
			}
		}));
		draftsTable.addMouseListener(tableDoubleClick(() -> {
			int row = selectedModelRow(draftsTable);
			if (row >= 0 && "comment".equals(Objects.toString(draftsModel.getValueAt(row, 0), ""))) {
				plugin.applyDraftComment();
			}
		}));
		suggestionsTable.addMouseListener(tableDoubleClick(() -> {
			int row = selectedModelRow(suggestionsTable);
			if (row >= 0 && row < suggestionRows.size()) {
				plugin.navigateTo(suggestionRows.get(row).address());
				revealAddress(suggestionRows.get(row).address());
			}
		}));
		localsTable.addMouseListener(tableDoubleClick(() -> {
			int row = selectedModelRow(localsTable);
			if (row >= 0) {
				String name = Objects.toString(localsModel.getValueAt(row, 1), "");
				moveCaretToText(name);
			}
		}));
		traceTable.addMouseListener(tableDoubleClick(() -> {
			int row = selectedModelRow(traceTable);
			if (row >= 0 && row < traceRows.size()) {
				revealTraceRow(traceRows.get(row));
			}
		}));
	}

	private void installStringTablePopup(JTable table, IntFunction<StringRow> rowGetter) {
		JPopupMenu tablePopup = new JPopupMenu();
		tablePopup.add(item("Goto usage", e -> {
			StringRow row = rowGetter.apply(selectedModelRow(table));
			if (row != null) {
				gotoStringUsage(row);
			}
		}));
		tablePopup.add(item("Goto string", e -> {
			StringRow row = rowGetter.apply(selectedModelRow(table));
			if (row != null) {
				plugin.navigateTo(row.stringAddress());
			}
		}));
		table.addMouseListener(new MouseAdapter() {
			@Override
			public void mousePressed(MouseEvent e) {
				handleTablePopup(e);
			}

			@Override
			public void mouseReleased(MouseEvent e) {
				handleTablePopup(e);
			}

			private void handleTablePopup(MouseEvent e) {
				if (!e.isPopupTrigger()) {
					return;
				}
				int row = table.rowAtPoint(e.getPoint());
				if (row >= 0) {
					table.setRowSelectionInterval(row, row);
				}
				tablePopup.show(e.getComponent(), e.getX(), e.getY());
			}
		});
	}

	private void gotoStringUsage(StringRow row) {
		if (row.useAddress() != null) {
			plugin.navigateTo(row.useAddress());
		}
		if (!focusStringUsage(row.useAddress(), row.value())) {
			Msg.showInfo(this, panel, "Goto usage",
				"No pseudocode usage is visible for the selected string.");
		}
	}

	private boolean focusStringUsage(Address useAddress, String value) {
		PseudocodeTab tab = currentTab();
		if (tab == null || tab.result == null) {
			return false;
		}
		if (useAddress != null) {
			for (ParadiseTokenSpan span : tab.displaySpans) {
				if (useAddress.equals(span.address())) {
					selectRange(tab, span.start(), span.end());
					focusText();
					return true;
				}
			}
		}
		if (value == null || value.isBlank()) {
			return false;
		}
		String text = tab.textPane.getText();
		for (String searchValue : usageSearchValues(value)) {
			int index = text.indexOf(searchValue);
			int matchLength = searchValue.length();
			if (index < 0) {
				String preview = previewString(searchValue, Math.min(searchValue.length(), 80));
				index = preview.isBlank() ? -1 : text.indexOf(preview);
				matchLength = preview.length();
			}
			if (index >= 0) {
				selectRange(tab, index, index + Math.min(matchLength, text.length() - index));
				focusText();
				return true;
			}
		}
		return false;
	}

	private List<String> usageSearchValues(String value) {
		List<String> values = new ArrayList<>();
		addSearchValue(values, value);
		addSearchValue(values, cEscapedSearchValue(value));
		return values;
	}

	private void addSearchValue(List<String> values, String value) {
		if (value != null && !value.isBlank() && !values.contains(value)) {
			values.add(value);
		}
	}

	private String cEscapedSearchValue(String value) {
		if (value == null) {
			return "";
		}
		return value.replace("\\", "\\\\")
				.replace("\"", "\\\"")
				.replace("\n", "\\n")
				.replace("\r", "\\r")
				.replace("\t", "\\t");
	}

	private MouseAdapter tableDoubleClick(Runnable runnable) {
		return new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (e.getClickCount() >= 2) {
					runnable.run();
				}
			}
		};
	}

	private int selectedModelRow(JTable table) {
		int viewRow = table.getSelectedRow();
		return viewRow < 0 ? -1 : table.convertRowIndexToModel(viewRow);
	}

	private DefaultTableModel model(String... columns) {
		return new DefaultTableModel(columns, 0) {
			@Override
			public boolean isCellEditable(int row, int column) {
				return false;
			}
		};
	}

	private JTable table(DefaultTableModel model) {
		JTable table = new JTable(model);
		table.setAutoCreateRowSorter(true);
		table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		return table;
	}

	private void fill(DefaultTableModel model) {
		model.setRowCount(0);
	}

	private void selectAuxTab(String title) {
		if (!selectAuxTabIfPresent(title)) {
			return;
		}
		auxTabs.setVisible(plugin.showAuxPanels());
	}

	private boolean selectAuxTabIfPresent(String title) {
		for (int i = 0; i < auxTabs.getTabCount(); i++) {
			if (title.equals(auxTabs.getTitleAt(i))) {
				auxTabs.setSelectedIndex(i);
				return true;
			}
		}
		return false;
	}

	void promptGoTo() {
		String text = JOptionPane.showInputDialog(panel, "Address or symbol:");
		if (text != null && !text.isBlank()) {
			plugin.goToAddressOrSymbol(text.trim());
		}
	}

	private boolean findNext(PseudocodeTab tab, boolean focusMatch) {
		if (tab.searchText == null || tab.searchText.isBlank()) {
			return false;
		}
		String text = tab.textPane.getText().toLowerCase(Locale.ROOT);
		String query = tab.searchText.toLowerCase(Locale.ROOT);
		int start = Math.min(tab.textPane.getCaretPosition() + 1, text.length());
		int index = text.indexOf(query, start);
		if (index < 0) {
			index = text.indexOf(query);
		}
		if (index >= 0) {
			tab.textPane.setCaretPosition(index);
			tab.textPane.moveCaretPosition(index + query.length());
			try {
				Rectangle rect = tab.textPane.modelToView2D(index).getBounds();
				tab.textPane.scrollRectToVisible(rect);
			}
			catch (BadLocationException e) {
				// Ignore stale offsets after edits or refreshes.
			}
			if (focusMatch) {
				focusText();
			}
			return true;
		}
		searchStatusLabel.setText("0 matches");
		return false;
	}

	private void updateSearchStatus(int matches, String query) {
		if (query == null || query.isBlank()) {
			searchStatusLabel.setText(" ");
			return;
		}
		searchStatusLabel.setText(matches == 1 ? "1 match" : matches + " matches");
	}

	private String selectedTextOrToken(PseudocodeTab tab) {
		String selected = tab.textPane.getSelectedText();
		if (selected != null && !selected.isBlank()) {
			return selected;
		}
		ParadiseTokenSpan span = selectedSpan();
		return span == null ? "" : span.token().getText();
	}

	private void moveCaretToText(String text) {
		PseudocodeTab tab = currentTab();
		if (tab == null || text == null || text.isBlank()) {
			return;
		}
		int index = tab.textPane.getText().indexOf(text);
		if (index >= 0) {
			tab.textPane.setCaretPosition(index);
			tab.textPane.moveCaretPosition(index + text.length());
			tab.textPane.requestFocusInWindow();
		}
	}

	private boolean isBrace(char c) {
		return c == '(' || c == ')' || c == '{' || c == '}' || c == '[' || c == ']';
	}

	private int matchingBrace(String text, int pos) {
		char open = text.charAt(pos);
		char close;
		int direction;
		if (open == '(') {
			close = ')';
			direction = 1;
		}
		else if (open == '{') {
			close = '}';
			direction = 1;
		}
		else if (open == '[') {
			close = ']';
			direction = 1;
		}
		else if (open == ')') {
			close = '(';
			direction = -1;
		}
		else if (open == '}') {
			close = '{';
			direction = -1;
		}
		else if (open == ']') {
			close = '[';
			direction = -1;
		}
		else {
			return -1;
		}
		int depth = 0;
		for (int i = pos; i >= 0 && i < text.length(); i += direction) {
			char c = text.charAt(i);
			if (c == open) {
				depth++;
			}
			else if (c == close) {
				depth--;
				if (depth == 0) {
					return i;
				}
			}
		}
		return -1;
	}

	private String preview(String value, int maxLength) {
		if (value == null) {
			return "";
		}
		String oneLine = value.replace('\n', ' ').replace('\r', ' ').replace('\t', ' ');
		return oneLine.length() <= maxLength ? oneLine : oneLine.substring(0, maxLength) + "...";
	}

	private boolean sameFunction(Function a, Function b) {
		if (a == null || b == null) {
			return false;
		}
		return a.getProgram() == b.getProgram() && a.getEntryPoint().equals(b.getEntryPoint());
	}

	private static final class NoWrapTextPane extends JTextPane {
		@Override
		public boolean getScrollableTracksViewportWidth() {
			Container parent = getParent();
			return parent != null && getUI().getPreferredSize(this).width <= parent.getSize().width;
		}
	}

	private static final class ToolbarIcon implements Icon {
		private static final int SIZE = 16;
		private final ToolbarGlyph glyph;

		private ToolbarIcon(ToolbarGlyph glyph) {
			this.glyph = glyph;
		}

		@Override
		public int getIconWidth() {
			return SIZE;
		}

		@Override
		public int getIconHeight() {
			return SIZE;
		}

		@Override
		public void paintIcon(Component component, Graphics graphics, int x, int y) {
			Graphics2D g = (Graphics2D) graphics.create();
			try {
				g.translate(x, y);
				g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
				g.setStroke(new BasicStroke(1.5f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
				Color baseForeground = component == null || component.getForeground() == null ?
					new Color(42, 58, 74) : component.getForeground();
				Color fg = component == null || component.isEnabled() ? baseForeground
						: new Color(145, 145, 145);
				Color blue = component == null || component.isEnabled() ? new Color(42, 121, 190)
						: new Color(150, 165, 178);
				Color green = component == null || component.isEnabled() ? new Color(38, 145, 89)
						: new Color(145, 165, 150);
				Color orange = component == null || component.isEnabled() ? new Color(190, 123, 36)
						: new Color(170, 156, 136);
				Color red = component == null || component.isEnabled() ? new Color(190, 55, 55)
						: new Color(170, 140, 140);
				switch (glyph) {
					case DISASM -> paintDocument(g, fg, blue);
					case GRAPH -> paintGraph(g, fg, green, blue);
					case BACK -> paintArrow(g, fg, true);
					case FORWARD -> paintArrow(g, fg, false);
					case REFRESH -> paintRefresh(g, blue);
					case RAW -> paintRaw(g, fg, orange);
					case RENAME -> paintPencil(g, fg, orange);
					case TYPE -> paintType(g, fg, blue);
					case COMMENT -> paintComment(g, fg, new Color(214, 235, 255));
					case DRAFT -> paintDraft(g, fg, orange);
					case XREFS -> paintXrefs(g, fg, blue);
					case FOLLOW -> paintFollow(g, fg, green);
					case USES -> paintUses(g, fg, orange);
					case TRACE -> paintTrace(g, fg, green, blue);
					case COPY -> paintCopy(g, fg, blue);
					case EXPORT -> paintExport(g, fg, green);
					case CLOSE -> paintClose(g, red);
					case FIND -> paintFind(g, fg, blue);
					case NEXT -> paintNext(g, fg, blue);
					case CLEAR -> paintClear(g, fg, red);
				}
			}
			finally {
				g.dispose();
			}
		}

		private void paintDocument(Graphics2D g, Color fg, Color blue) {
			g.setColor(Color.WHITE);
			g.fillRoundRect(3, 2, 10, 12, 1, 1);
			g.setColor(fg);
			g.drawRoundRect(3, 2, 10, 12, 1, 1);
			g.setColor(blue);
			g.drawLine(5, 5, 11, 5);
			g.drawLine(5, 8, 11, 8);
			g.drawLine(5, 11, 9, 11);
		}

		private void paintGraph(Graphics2D g, Color fg, Color green, Color blue) {
			g.setColor(fg);
			g.drawLine(5, 5, 11, 5);
			g.drawLine(8, 7, 8, 11);
			g.drawLine(5, 11, 11, 11);
			g.setColor(green);
			g.fillRect(2, 2, 5, 5);
			g.fillRect(9, 2, 5, 5);
			g.setColor(blue);
			g.fillRect(2, 9, 5, 5);
			g.fillRect(9, 9, 5, 5);
			g.setColor(fg);
			g.drawRect(2, 2, 5, 5);
			g.drawRect(9, 2, 5, 5);
			g.drawRect(2, 9, 5, 5);
			g.drawRect(9, 9, 5, 5);
		}

		private void paintArrow(Graphics2D g, Color fg, boolean left) {
			g.setColor(fg);
			if (left) {
				g.drawLine(4, 8, 13, 8);
				g.drawLine(4, 8, 8, 4);
				g.drawLine(4, 8, 8, 12);
			}
			else {
				g.drawLine(3, 8, 12, 8);
				g.drawLine(12, 8, 8, 4);
				g.drawLine(12, 8, 8, 12);
			}
		}

		private void paintRefresh(Graphics2D g, Color blue) {
			g.setColor(blue);
			g.drawArc(3, 3, 10, 10, 35, 265);
			g.drawLine(12, 3, 12, 7);
			g.drawLine(12, 3, 8, 3);
		}

		private void paintRaw(Graphics2D g, Color fg, Color orange) {
			g.setColor(orange);
			g.drawString("C", 4, 12);
			g.setColor(fg);
			g.drawLine(11, 4, 13, 4);
			g.drawLine(13, 4, 13, 12);
			g.drawLine(13, 12, 11, 12);
		}

		private void paintPencil(Graphics2D g, Color fg, Color orange) {
			g.setColor(orange);
			g.drawLine(4, 12, 11, 5);
			g.setColor(fg);
			g.drawLine(3, 13, 5, 11);
			g.drawLine(10, 4, 12, 6);
			g.drawLine(3, 13, 7, 12);
		}

		private void paintType(Graphics2D g, Color fg, Color blue) {
			g.setColor(blue);
			g.drawLine(3, 4, 13, 4);
			g.setColor(fg);
			g.drawLine(8, 4, 8, 13);
			g.drawLine(5, 13, 11, 13);
		}

		private void paintComment(Graphics2D g, Color fg, Color fill) {
			g.setColor(fill);
			g.fillRoundRect(3, 3, 10, 8, 3, 3);
			g.setColor(fg);
			g.drawRoundRect(3, 3, 10, 8, 3, 3);
			g.drawLine(6, 11, 4, 14);
			g.drawLine(5, 6, 11, 6);
			g.drawLine(5, 8, 9, 8);
		}

		private void paintDraft(Graphics2D g, Color fg, Color orange) {
			paintDocument(g, fg, new Color(130, 170, 205));
			g.setColor(orange);
			g.drawLine(11, 2, 12, 5);
			g.drawLine(12, 5, 15, 6);
			g.drawLine(12, 5, 10, 8);
		}

		private void paintXrefs(Graphics2D g, Color fg, Color blue) {
			g.setColor(blue);
			g.drawOval(2, 2, 5, 5);
			g.drawOval(9, 2, 5, 5);
			g.drawOval(5, 10, 5, 5);
			g.setColor(fg);
			g.drawLine(6, 6, 9, 9);
			g.drawLine(10, 6, 8, 10);
		}

		private void paintFollow(Graphics2D g, Color fg, Color green) {
			g.setColor(fg);
			g.drawRect(9, 3, 5, 10);
			g.setColor(green);
			g.drawLine(2, 8, 11, 8);
			g.drawLine(11, 8, 8, 5);
			g.drawLine(11, 8, 8, 11);
		}

		private void paintUses(Graphics2D g, Color fg, Color orange) {
			g.setColor(orange);
			g.drawOval(3, 3, 10, 10);
			g.drawOval(6, 6, 4, 4);
			g.setColor(fg);
			g.drawLine(8, 1, 8, 4);
			g.drawLine(8, 12, 8, 15);
			g.drawLine(1, 8, 4, 8);
			g.drawLine(12, 8, 15, 8);
		}

		private void paintTrace(Graphics2D g, Color fg, Color green, Color blue) {
			g.setColor(fg);
			g.drawLine(4, 4, 8, 8);
			g.drawLine(8, 8, 12, 5);
			g.drawLine(8, 8, 11, 12);
			g.setColor(green);
			g.fillOval(2, 2, 5, 5);
			g.setColor(blue);
			g.fillOval(6, 6, 5, 5);
			g.setColor(green);
			g.fillOval(10, 10, 5, 5);
		}

		private void paintCopy(Graphics2D g, Color fg, Color blue) {
			g.setColor(new Color(224, 238, 255));
			g.fillRect(5, 3, 8, 10);
			g.setColor(blue);
			g.drawRect(5, 3, 8, 10);
			g.setColor(Color.WHITE);
			g.fillRect(2, 6, 8, 8);
			g.setColor(fg);
			g.drawRect(2, 6, 8, 8);
		}

		private void paintExport(Graphics2D g, Color fg, Color green) {
			g.setColor(green);
			g.drawLine(8, 2, 8, 10);
			g.drawLine(8, 10, 5, 7);
			g.drawLine(8, 10, 11, 7);
			g.setColor(fg);
			g.drawLine(3, 13, 13, 13);
			g.drawLine(3, 10, 3, 13);
			g.drawLine(13, 10, 13, 13);
		}

		private void paintClose(Graphics2D g, Color red) {
			g.setColor(red);
			g.drawLine(4, 4, 12, 12);
			g.drawLine(12, 4, 4, 12);
		}

		private void paintFind(Graphics2D g, Color fg, Color blue) {
			g.setColor(blue);
			g.drawOval(3, 3, 7, 7);
			g.setColor(fg);
			g.drawLine(9, 9, 13, 13);
		}

		private void paintNext(Graphics2D g, Color fg, Color blue) {
			g.setColor(blue);
			g.drawLine(8, 3, 8, 12);
			g.drawLine(8, 12, 4, 8);
			g.drawLine(8, 12, 12, 8);
			g.setColor(fg);
			g.drawLine(4, 14, 12, 14);
		}

		private void paintClear(Graphics2D g, Color fg, Color red) {
			g.setColor(fg);
			g.drawRoundRect(3, 5, 8, 7, 2, 2);
			g.drawLine(5, 12, 12, 12);
			g.setColor(red);
			g.drawLine(10, 3, 14, 7);
			g.drawLine(14, 3, 10, 7);
		}
	}

	private final class DottedSplitPaneUi extends BasicSplitPaneUI {
		@Override
		public BasicSplitPaneDivider createDefaultDivider() {
			return new BasicSplitPaneDivider(this) {
				@Override
				public void paint(Graphics g) {
					Graphics2D g2 = (Graphics2D) g.create();
					try {
						boolean dark = plugin.darkTheme();
						Color background = dark ? new Color(50, 53, 57) : new Color(225, 225, 218);
						Color border = dark ? new Color(76, 81, 88) : new Color(185, 185, 178);
						Color dot = dark ? new Color(142, 149, 160) : new Color(110, 110, 104);
						int width = getWidth();
						int height = getHeight();
						g2.setColor(background);
						g2.fillRect(0, 0, width, height);
						g2.setColor(border);
						g2.drawLine(0, 0, width, 0);
						g2.drawLine(0, height - 1, width, height - 1);
						g2.setColor(dot);
						int cx = width / 2;
						int cy = height / 2;
						if (ParadiseDecompilerProvider.this.splitPane.getOrientation() ==
							JSplitPane.VERTICAL_SPLIT) {
							for (int dx = -7; dx <= 7; dx += 7) {
								g2.fillOval(cx + dx - 2, cy - 2, 4, 4);
							}
						}
						else {
							for (int dy = -7; dy <= 7; dy += 7) {
								g2.fillOval(cx - 2, cy + dy - 2, 4, 4);
							}
						}
					}
					finally {
						g2.dispose();
					}
				}
			};
		}
	}

	private static final class PseudocodeTab {
		private TabKey key;
		private Function function;
		private final JPanel panel;
		private final NoWrapTextPane textPane;
		private final JTextArea gutter;
		private final List<Object> lineHighlightTags = new ArrayList<>();
		private final List<Object> useHighlightTags = new ArrayList<>();
		private final List<Object> traceHighlightTags = new ArrayList<>();
		private final List<Object> braceHighlightTags = new ArrayList<>();
		private final List<Object> searchHighlightTags = new ArrayList<>();
		private final Map<ClangToken, String> literalOverrides = new IdentityHashMap<>();
		private List<PseudocodeLine> lines = List.of();
		private List<ParadiseTokenSpan> displaySpans = List.of();
		private List<TraceRow> traceRows = List.of();
		private ParadiseDecompileResult result;
		private String displayCode;
		private boolean showRaw;
		private int caretPosition;
		private String searchText;
		private String tracedVariable;

		private PseudocodeTab(TabKey key, Function function, JPanel panel, NoWrapTextPane textPane,
				JTextArea gutter) {
			this.key = key;
			this.function = function;
			this.panel = panel;
			this.textPane = textPane;
			this.gutter = gutter;
		}
	}

	private record PseudocodeLine(int number, int start, int end, Address address) {
	}

	private record RenderedDisplay(String code, List<ParadiseTokenSpan> spans) {
	}

	private record LiteralValue(long unsignedValue, long signedValue, int bitLength) {
	}

	private enum LiteralFormat {
		HEX,
		UNSIGNED_DECIMAL,
		SIGNED_DECIMAL,
		BINARY,
		CHARACTER
	}

	private enum ToolbarGlyph {
		DISASM,
		GRAPH,
		BACK,
		FORWARD,
		REFRESH,
		RAW,
		RENAME,
		TYPE,
		COMMENT,
		DRAFT,
		XREFS,
		FOLLOW,
		USES,
		TRACE,
		COPY,
		EXPORT,
		CLOSE,
		FIND,
		NEXT,
		CLEAR
	}

	private record CallRow(String direction, Address address, Function function, String type,
			String preview) {
		private String functionName() {
			return function == null ? "" : function.getName();
		}
	}

	private record StringRow(Address useAddress, Address stringAddress, String value) {
	}

	private record EncodedStringRow(Address useAddress, Address stringAddress, String value,
			String encodedPreview, String chain, String decodedPreview, String kind, int confidence) {
	}

	private record SuggestionRow(int priority, Address address, String finding, String evidence) {
	}

	private record TriageRow(Function function, int score, int strings, int calls, int xrefs,
			String hints) {
	}

	private record TraceRow(Address address, int lineNumber, int startOffset, int endOffset,
			String role, String expression, String value) {
	}

	private record CompoundUpdate(String operator, String rhs) {
	}

	private record DirectUpdate(String operator, String rhs) {
	}

	private static final class TraceState {
		private Long numericValue;
		private String symbolicValue;

		private void clear() {
			numericValue = null;
			symbolicValue = null;
		}
	}

	private static final class TabKey {
		private final Program program;
		private final Address entry;

		private TabKey(Function function) {
			this.program = function.getProgram();
			this.entry = function.getEntryPoint();
		}

		@Override
		public int hashCode() {
			return 31 * System.identityHashCode(program) + entry.hashCode();
		}

		@Override
		public boolean equals(Object obj) {
			if (!(obj instanceof TabKey other)) {
				return false;
			}
			return program == other.program && entry.equals(other.entry);
		}
	}
}
