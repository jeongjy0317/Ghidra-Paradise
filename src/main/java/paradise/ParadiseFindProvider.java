package paradise;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Graphics;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.BooleanSupplier;
import java.util.regex.Pattern;

import javax.swing.AbstractAction;
import javax.swing.BorderFactory;
import javax.swing.Icon;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.KeyStroke;
import javax.swing.RowFilter;
import javax.swing.SwingUtilities;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.JTableHeader;
import javax.swing.table.TableColumn;
import javax.swing.table.TableRowSorter;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.WindowPosition;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.Swing;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskLauncher;

final class ParadiseFindProvider extends ComponentProvider {
	private static final ColumnSpec[] COLUMNS = {
		new ColumnSpec("Priority", 52),
		new ColumnSpec("Count", 52),
		new ColumnSpec("Kind", 92),
		new ColumnSpec("Address", 92),
		new ColumnSpec("Use", 92),
		new ColumnSpec("Source", 64),
		new ColumnSpec("Decode Chain", 118),
		new ColumnSpec("Value", 360),
		new ColumnSpec("Evidence", 320)
	};

	private final ParadisePlugin plugin;
	private final JPanel panel = new JPanel(new BorderLayout());
	private final JLabel titleLabel = new JLabel("Paradise Inspector");
	private final JLabel statusLabel = new JLabel("No scan yet");
	private final JTabbedPane tabs = new JTabbedPane();
	private final DefaultTableModel overviewModel = model();
	private final DefaultTableModel urlModel = model();
	private final DefaultTableModel pathModel = model();
	private final DefaultTableModel shellModel = model();
	private final Map<JTable, List<TableColumn>> tableColumns = new LinkedHashMap<>();
	private final JTable overviewTable = table(overviewModel);
	private final JTable urlTable = table(urlModel);
	private final JTable pathTable = table(pathModel);
	private final JTable shellTable = table(shellModel);
	private final JTextField overviewFilter = new JTextField(18);
	private final JTextField urlFilter = new JTextField(18);
	private final JTextField pathFilter = new JTextField(18);
	private final JTextField shellFilter = new JTextField(18);
	private List<ParadiseFindScanner.Row> overviewRows = List.of();
	private List<ParadiseFindScanner.Row> urlRows = List.of();
	private List<ParadiseFindScanner.Row> pathRows = List.of();
	private List<ParadiseFindScanner.Row> shellRows = List.of();
	private Program lastProgram;
	private Function lastFunction;
	private boolean lastWholeProgram;

	ParadiseFindProvider(ParadisePlugin plugin) {
		super(plugin.getTool(), "Paradise Inspector", plugin.getName());
		this.plugin = plugin;
		setTitle("Paradise Inspector");
		setWindowMenuGroup("Paradise");
		setDefaultWindowPosition(WindowPosition.RIGHT);
		buildUi();
		installLocalToolbarActions();
		installNavigation();
		applyOptions();
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}

	void programClosed(Program program) {
		if (program != null && program == lastProgram) {
			lastProgram = null;
			lastFunction = null;
			lastWholeProgram = false;
			showRows(List.of(), "No scan yet");
		}
	}

	void applyOptions() {
		applyColumnOptions(overviewTable);
		applyColumnOptions(urlTable);
		applyColumnOptions(pathTable);
		applyColumnOptions(shellTable);
	}

	boolean hasScan() {
		return lastProgram != null || lastFunction != null || !overviewRows.isEmpty();
	}

	void scanActiveFunction() {
		Function function = plugin.activeFunctionForFinds();
		if (function == null) {
			Msg.showInfo(this, panel, "Paradise Inspector",
				"Place the cursor inside a function first.");
			return;
		}
		scanFunction(function);
	}

	void scanWholeProgram() {
		Program program = plugin.activeProgramForFinds();
		if (program == null) {
			Msg.showInfo(this, panel, "Paradise Inspector", "Open a program first.");
			return;
		}
		scanProgram(program);
	}

	void refreshScan() {
		if (lastWholeProgram && lastProgram != null) {
			scanProgram(lastProgram);
			return;
		}
		if (lastFunction != null) {
			scanFunction(lastFunction);
			return;
		}
		scanActiveFunction();
	}

	private void scanFunction(Function function) {
		lastProgram = function.getProgram();
		lastFunction = function;
		lastWholeProgram = false;
		setVisible(true);
		statusLabel.setText("Scanning function " + function.getName() + "...");
		TaskLauncher.launchNonModal("Paradise scan function inspector", monitor -> {
			List<ParadiseFindScanner.Row> rows;
			try {
				rows = ParadiseFindScanner.scanFunction(function, plugin.mergeRepeatedFinds(),
					monitor);
			}
			catch (CancelledException e) {
				return;
			}
			Swing.runLater(() -> showRows(rows,
				function.getName() + " @ " + function.getEntryPoint() + ": " + rows.size() +
					" items"));
		});
	}

	private void scanProgram(Program program) {
		lastProgram = program;
		lastFunction = null;
		lastWholeProgram = true;
		setVisible(true);
		statusLabel.setText("Scanning whole program...");
		TaskLauncher.launchNonModal("Paradise scan program inspector", monitor -> {
			List<ParadiseFindScanner.Row> rows;
			try {
				rows = ParadiseFindScanner.scanProgram(program, plugin.mergeRepeatedFinds(),
					monitor);
			}
			catch (CancelledException e) {
				return;
			}
			Swing.runLater(() -> showRows(rows, program.getName() + ": " + rows.size() +
				" items"));
		});
	}

	private void showRows(List<ParadiseFindScanner.Row> rows, String status) {
		overviewRows = List.copyOf(rows);
		urlRows = rows.stream().filter(row -> row.kind().equals("URL")).toList();
		shellRows = rows.stream().filter(row -> row.kind().equals("Shell")).toList();
		pathRows = rows.stream().filter(row -> !row.kind().equals("URL") &&
			!row.kind().equals("Shell")).toList();
		fill(overviewModel, overviewRows);
		fill(urlModel, urlRows);
		fill(pathModel, pathRows);
		fill(shellModel, shellRows);
		statusLabel.setText(status);
		contextChanged();
	}

	private void buildUi() {
		JPanel header = new JPanel(new BorderLayout());
		header.setBorder(BorderFactory.createEmptyBorder(3, 8, 3, 8));
		titleLabel.setFont(titleLabel.getFont().deriveFont(java.awt.Font.BOLD, 13f));
		header.add(titleLabel, BorderLayout.WEST);
		tabs.addTab("Overview", filteredTablePanel(overviewTable, overviewFilter));
		tabs.addTab("URLs", filteredTablePanel(urlTable, urlFilter));
		tabs.addTab("Paths", filteredTablePanel(pathTable, pathFilter));
		tabs.addTab("Shell", filteredTablePanel(shellTable, shellFilter));
		panel.add(header, BorderLayout.NORTH);
		panel.add(tabs, BorderLayout.CENTER);
		panel.add(statusLabel, BorderLayout.SOUTH);
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
		filterField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
			@Override
			public void insertUpdate(javax.swing.event.DocumentEvent e) {
				apply();
			}

			@Override
			public void removeUpdate(javax.swing.event.DocumentEvent e) {
				apply();
			}

			@Override
			public void changedUpdate(javax.swing.event.DocumentEvent e) {
				apply();
			}

			private void apply() {
				String text = filterField.getText();
				sorter.setRowFilter(text == null || text.isBlank() ? null
						: RowFilter.regexFilter("(?i)" + Pattern.quote(text)));
			}
		});
	}

	private void installLocalToolbarActions() {
		addToolbarAction("Scan Function", FindGlyph.FUNCTION, "01_scan", "010",
			() -> plugin.activeFunctionForFinds() != null, this::scanActiveFunction);
		addToolbarAction("Scan Binary", FindGlyph.PROGRAM, "01_scan", "020",
			() -> plugin.activeProgramForFinds() != null, this::scanWholeProgram);
		addToolbarAction("Refresh", FindGlyph.REFRESH, "01_scan", "030",
			() -> lastProgram != null || plugin.activeProgramForFinds() != null, this::refreshScan);
		addToolbarAction("Goto Usage", FindGlyph.USAGE, "02_nav", "010",
			() -> selectedRow() != null, this::gotoUsage);
		addToolbarAction("Goto String", FindGlyph.STRING, "02_nav", "020",
			() -> selectedRow() != null, this::gotoString);
		addToolbarAction("Copy", FindGlyph.COPY, "03_output", "010",
			() -> selectedRow() != null, this::copySelected);
		addToolbarAction("Export CSV", FindGlyph.EXPORT, "03_output", "020",
			() -> !overviewRows.isEmpty(), this::exportCsv);
	}

	private void addToolbarAction(String name, FindGlyph glyph, String group, String subgroup,
			BooleanSupplier enabled, Runnable handler) {
		DockingAction action = new DockingAction("Paradise Inspector " + name, plugin.getName()) {
			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return enabled.getAsBoolean();
			}

			@Override
			public void actionPerformed(ActionContext context) {
				handler.run();
			}
		};
		action.setToolBarData(new ToolBarData(new FindIcon(glyph), group, subgroup));
		action.setDescription(name);
		action.markHelpUnnecessary();
		addLocalAction(action);
	}

	private void installNavigation() {
		installTableNavigation(overviewTable);
		installTableNavigation(urlTable);
		installTableNavigation(pathTable);
		installTableNavigation(shellTable);
	}

	private void installTableNavigation(JTable table) {
		JPopupMenu popup = new JPopupMenu();
		popup.add(item("Goto usage", this::gotoUsage));
		popup.add(item("Goto string", this::gotoString));
		popup.addSeparator();
		popup.add(item("Copy value", this::copySelected));
		table.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (e.getClickCount() == 2 && SwingUtilities.isLeftMouseButton(e)) {
					gotoUsage();
				}
			}

			@Override
			public void mousePressed(MouseEvent e) {
				handlePopup(e);
			}

			@Override
			public void mouseReleased(MouseEvent e) {
				handlePopup(e);
			}

			private void handlePopup(MouseEvent e) {
				if (!e.isPopupTrigger()) {
					return;
				}
				int row = table.rowAtPoint(e.getPoint());
				if (row >= 0) {
					table.setRowSelectionInterval(row, row);
				}
				popup.show(e.getComponent(), e.getX(), e.getY());
			}
		});
		table.getInputMap().put(KeyStroke.getKeyStroke("ENTER"), "gotoUsage");
		table.getActionMap().put("gotoUsage", new AbstractAction() {
			@Override
			public void actionPerformed(ActionEvent e) {
				gotoUsage();
			}
		});
	}

	private JMenuItem item(String text, Runnable action) {
		JMenuItem item = new JMenuItem(text);
		item.addActionListener(e -> action.run());
		return item;
	}

	private ParadiseFindScanner.Row selectedRow() {
		JTable table = selectedTable();
		List<ParadiseFindScanner.Row> rows = selectedRows();
		int viewRow = table.getSelectedRow();
		if (viewRow < 0) {
			return null;
		}
		int row = table.convertRowIndexToModel(viewRow);
		return row >= 0 && row < rows.size() ? rows.get(row) : null;
	}

	private JTable selectedTable() {
		return switch (tabs.getSelectedIndex()) {
			case 1 -> urlTable;
			case 2 -> pathTable;
			case 3 -> shellTable;
			default -> overviewTable;
		};
	}

	private List<ParadiseFindScanner.Row> selectedRows() {
		return switch (tabs.getSelectedIndex()) {
			case 1 -> urlRows;
			case 2 -> pathRows;
			case 3 -> shellRows;
			default -> overviewRows;
		};
	}

	private void gotoUsage() {
		ParadiseFindScanner.Row row = selectedRow();
		if (row == null) {
			return;
		}
		Address address = row.useAddress() != null ? row.useAddress() : row.textAddress();
		if (address != null) {
			plugin.navigateTo(address);
			plugin.focusPseudocodeUsage(address, row.rawValue(), row.value());
		}
	}

	private void gotoString() {
		ParadiseFindScanner.Row row = selectedRow();
		if (row != null && row.textAddress() != null) {
			plugin.navigateTo(row.textAddress());
		}
	}

	private void copySelected() {
		ParadiseFindScanner.Row row = selectedRow();
		if (row == null) {
			return;
		}
		Toolkit.getDefaultToolkit().getSystemClipboard()
				.setContents(new StringSelection(row.value()), null);
	}

	private void exportCsv() {
		JFileChooser chooser = new JFileChooser();
		chooser.setSelectedFile(new File("paradise_inspector.csv"));
		if (chooser.showSaveDialog(panel) != JFileChooser.APPROVE_OPTION) {
			return;
		}
		try (BufferedWriter writer =
			Files.newBufferedWriter(chooser.getSelectedFile().toPath(), StandardCharsets.UTF_8)) {
			writer.write("Priority,Count,Kind,Address,Use,Source,Decode Chain,Value,Evidence");
			writer.newLine();
			for (ParadiseFindScanner.Row row : overviewRows) {
				writer.write(csv(row.priority()));
				writer.write(',');
				writer.write(csv(row.count()));
				writer.write(',');
				writer.write(csv(row.kind()));
				writer.write(',');
				writer.write(csv(row.textAddress()));
				writer.write(',');
				writer.write(csv(row.useAddress()));
				writer.write(',');
				writer.write(csv(row.source()));
				writer.write(',');
				writer.write(csv(row.chain()));
				writer.write(',');
				writer.write(csv(row.value()));
				writer.write(',');
				writer.write(csv(row.evidence()));
				writer.newLine();
			}
		}
		catch (IOException e) {
			Msg.showError(this, panel, "Export Failed", e.getMessage(), e);
		}
	}

	private String csv(Object value) {
		String text = Objects.toString(value, "");
		return "\"" + text.replace("\"", "\"\"") + "\"";
	}

	private DefaultTableModel model() {
		String[] headers = new String[COLUMNS.length];
		for (int i = 0; i < COLUMNS.length; i++) {
			headers[i] = COLUMNS[i].title();
		}
		return new DefaultTableModel(headers, 0) {
			@Override
			public boolean isCellEditable(int row, int column) {
				return false;
			}
		};
	}

	private JTable table(DefaultTableModel model) {
		JTable table = new JTable(model);
		table.setAutoCreateRowSorter(true);
		table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
		table.setFillsViewportHeight(true);
		table.setRowHeight(20);
		JTableHeader header = table.getTableHeader();
		header.setReorderingAllowed(false);
		Color tableBg = Color.WHITE;
		Color tableFg = new Color(24, 24, 24);
		Color headerBg = new Color(232, 232, 226);
		Color headerFg = new Color(24, 24, 24);
		Color selectionBg = new Color(204, 226, 255);
		Color selectionFg = Color.BLACK;
		table.setBackground(tableBg);
		table.setForeground(tableFg);
		table.setGridColor(new Color(210, 210, 205));
		table.setSelectionBackground(selectionBg);
		table.setSelectionForeground(selectionFg);
		table.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
			@Override
			public Component getTableCellRendererComponent(JTable table, Object value,
					boolean selected, boolean focus, int row, int column) {
				Component component =
					super.getTableCellRendererComponent(table, value, selected, focus, row, column);
				if (!selected) {
					component.setBackground(row % 2 == 0 ? new Color(248, 248, 244)
							: new Color(255, 255, 252));
					component.setForeground(tableFg);
				}
				else {
					component.setBackground(selectionBg);
					component.setForeground(selectionFg);
				}
				return component;
			}
		});
		header.setOpaque(true);
		header.setBackground(headerBg);
		header.setForeground(headerFg);
		header.setFont(table.getFont().deriveFont(java.awt.Font.BOLD));
		header.setDefaultRenderer(new DefaultTableCellRenderer() {
			@Override
			public Component getTableCellRendererComponent(JTable table, Object value,
					boolean selected, boolean focus, int row, int column) {
				JLabel label = (JLabel) super.getTableCellRendererComponent(table, value, selected,
					focus, row, column);
				label.setOpaque(true);
				label.setBackground(headerBg);
				label.setForeground(headerFg);
				label.setFont(table.getFont().deriveFont(java.awt.Font.BOLD));
				label.setBorder(BorderFactory.createEmptyBorder(2, 4, 2, 4));
				return label;
			}
		});
		for (int i = 0; i < COLUMNS.length; i++) {
			setColumnWidth(table, i, COLUMNS[i].width());
		}
		List<TableColumn> columns = new ArrayList<>();
		for (int i = 0; i < table.getColumnModel().getColumnCount(); i++) {
			columns.add(table.getColumnModel().getColumn(i));
		}
		tableColumns.put(table, columns);
		return table;
	}

	private void applyColumnOptions(JTable table) {
		List<TableColumn> columns = tableColumns.get(table);
		if (columns == null || columns.isEmpty()) {
			return;
		}
		while (table.getColumnModel().getColumnCount() > 0) {
			table.getColumnModel().removeColumn(table.getColumnModel().getColumn(0));
		}
		boolean added = false;
		for (int i = 0; i < COLUMNS.length; i++) {
			if (plugin.showFindColumn(COLUMNS[i].title())) {
				table.getColumnModel().addColumn(columns.get(i));
				added = true;
			}
		}
		if (!added) {
			table.getColumnModel().addColumn(columns.get(7));
		}
		table.repaint();
	}

	private void fill(DefaultTableModel model, List<ParadiseFindScanner.Row> rows) {
		model.setRowCount(0);
		for (ParadiseFindScanner.Row row : rows) {
			model.addRow(new Object[] { row.priority(), row.count(), row.kind(),
				row.textAddress(), row.useAddress(), row.source(), row.chain(), row.value(),
				row.evidence() });
		}
	}

	private void setColumnWidth(JTable table, int column, int width) {
		table.getColumnModel().getColumn(column).setPreferredWidth(width);
		table.getColumnModel().getColumn(column).setMinWidth(Math.min(width, 40));
	}

	private record ColumnSpec(String title, int width) {
	}

	private enum FindGlyph {
		FUNCTION,
		PROGRAM,
		REFRESH,
		USAGE,
		STRING,
		COPY,
		EXPORT
	}

	private static final class FindIcon implements Icon {
		private final FindGlyph glyph;

		private FindIcon(FindGlyph glyph) {
			this.glyph = glyph;
		}

		@Override
		public int getIconWidth() {
			return 16;
		}

		@Override
		public int getIconHeight() {
			return 16;
		}

		@Override
		public void paintIcon(Component c, Graphics g, int x, int y) {
			g.setColor(new Color(250, 250, 250));
			g.fillRect(x, y, 15, 15);
			g.setColor(new Color(118, 126, 135));
			g.drawRect(x, y, 15, 15);
			g.setColor(color());
			switch (glyph) {
				case FUNCTION -> {
					g.drawString("f", x + 5, y + 12);
				}
				case PROGRAM -> {
					g.drawRect(x + 4, y + 4, 7, 7);
					g.drawLine(x + 2, y + 7, x + 13, y + 7);
				}
				case REFRESH -> {
					g.drawArc(x + 3, y + 3, 9, 9, 35, 280);
					g.drawLine(x + 11, y + 3, x + 13, y + 3);
				}
				case USAGE -> {
					g.drawLine(x + 4, y + 8, x + 12, y + 8);
					g.drawLine(x + 9, y + 5, x + 12, y + 8);
					g.drawLine(x + 9, y + 11, x + 12, y + 8);
				}
				case STRING -> {
					g.drawString("s", x + 5, y + 12);
				}
				case COPY -> {
					g.drawRect(x + 4, y + 3, 7, 8);
					g.drawRect(x + 2, y + 5, 7, 8);
				}
				case EXPORT -> {
					g.drawLine(x + 8, y + 3, x + 8, y + 10);
					g.drawLine(x + 5, y + 7, x + 8, y + 10);
					g.drawLine(x + 11, y + 7, x + 8, y + 10);
					g.drawLine(x + 4, y + 13, x + 12, y + 13);
				}
			}
		}

		private Color color() {
			return switch (glyph) {
				case FUNCTION -> new Color(52, 125, 220);
				case PROGRAM -> new Color(37, 150, 110);
				case REFRESH -> new Color(40, 120, 200);
				case USAGE -> new Color(218, 126, 24);
				case STRING -> new Color(142, 82, 175);
				case COPY -> new Color(80, 90, 105);
				case EXPORT -> new Color(33, 145, 80);
			};
		}
	}
}
