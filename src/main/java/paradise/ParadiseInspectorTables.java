package paradise;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;
import java.util.regex.Pattern;

import javax.swing.AbstractAction;
import javax.swing.BorderFactory;
import javax.swing.JComponent;
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

final class ParadiseInspectorTables {
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
	private static final TabSpec[] TABS = {
		new TabSpec("Overview", row -> true),
		new TabSpec("URLs", row -> row.kind().equals("URL")),
		new TabSpec("Paths", ParadiseInspectorTables::isPathRow),
		new TabSpec("Registry", row -> row.kind().equals("Registry")),
		new TabSpec("Shell", row -> row.kind().equals("Shell")),
		new TabSpec("Execute", row -> row.kind().equals("Execute"))
	};

	private final Predicate<String> columnVisible;
	private final Runnable selectionChanged;
	private final Runnable gotoUsage;
	private final Runnable gotoString;
	private final Runnable copySelected;
	private final JTabbedPane tabs = new JTabbedPane();
	private final JTextField filterField = new JTextField(18);
	private final List<TabState> states = new ArrayList<>();
	private final Map<JTable, List<TableColumn>> tableColumns = new LinkedHashMap<>();
	private final Map<JTable, TableRowSorter<DefaultTableModel>> tableSorters =
		new LinkedHashMap<>();

	ParadiseInspectorTables(Predicate<String> columnVisible, Runnable selectionChanged,
			Runnable gotoUsage, Runnable gotoString, Runnable copySelected) {
		this.columnVisible = columnVisible;
		this.selectionChanged = selectionChanged;
		this.gotoUsage = gotoUsage;
		this.gotoString = gotoString;
		this.copySelected = copySelected;
		for (TabSpec spec : TABS) {
			DefaultTableModel model = model();
			JTable table = table(model);
			TabState state = new TabState(spec, model, table);
			states.add(state);
			tabs.addTab(spec.title(), tablePanel(table));
			installTableNavigation(table);
		}
		tabs.addChangeListener(e -> selectionChanged.run());
	}

	JTabbedPane tabs() {
		return tabs;
	}

	JPanel compactFilterPanel() {
		filterField.putClientProperty("JTextField.placeholderText", "Filter");
		filterField.setToolTipText("Filter Inspector rows");
		Dimension fieldSize = new Dimension(160, 22);
		filterField.setPreferredSize(fieldSize);
		filterField.setMinimumSize(fieldSize);
		filterField.addActionListener(e -> applyTableFilter());
		filterField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
			@Override
			public void insertUpdate(javax.swing.event.DocumentEvent e) {
				applyTableFilter();
			}

			@Override
			public void removeUpdate(javax.swing.event.DocumentEvent e) {
				applyTableFilter();
			}

			@Override
			public void changedUpdate(javax.swing.event.DocumentEvent e) {
				applyTableFilter();
			}
		});
		JPanel filterPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 0));
		filterPanel.setBorder(BorderFactory.createEmptyBorder());
		filterPanel.add(filterField);
		return filterPanel;
	}

	void applyColumnOptions() {
		for (TabState state : states) {
			applyColumnOptions(state.table());
		}
	}

	void showRows(List<ParadiseFindScanner.Row> rows) {
		for (TabState state : states) {
			state.setRows(rows.stream().filter(state.spec().filter()).toList());
			fill(state.model(), state.rows());
		}
	}

	boolean hasRows() {
		return !overviewRows().isEmpty();
	}

	List<ParadiseFindScanner.Row> overviewRows() {
		return states.isEmpty() ? List.of() : states.get(0).rows();
	}

	ParadiseFindScanner.Row selectedRow() {
		TabState state = selectedState();
		if (state == null) {
			return null;
		}
		JTable table = state.table();
		int viewRow = table.getSelectedRow();
		if (viewRow < 0) {
			return null;
		}
		int row = table.convertRowIndexToModel(viewRow);
		return row >= 0 && row < state.rows().size() ? state.rows().get(row) : null;
	}

	private TabState selectedState() {
		int index = tabs.getSelectedIndex();
		return index >= 0 && index < states.size() ? states.get(index) : null;
	}

	private static boolean isPathRow(ParadiseFindScanner.Row row) {
		return !row.kind().equals("URL") && !row.kind().equals("Registry") &&
			!row.kind().equals("Shell") && !row.kind().equals("Execute");
	}

	private JPanel tablePanel(JTable table) {
		installTableFilter(table);
		JPanel wrapper = new JPanel(new BorderLayout());
		wrapper.add(new JScrollPane(table), BorderLayout.CENTER);
		return wrapper;
	}

	private void installTableFilter(JTable table) {
		TableRowSorter<DefaultTableModel> sorter =
			new TableRowSorter<>((DefaultTableModel) table.getModel());
		table.setRowSorter(sorter);
		tableSorters.put(table, sorter);
	}

	private void applyTableFilter() {
		String text = filterField.getText();
		RowFilter<DefaultTableModel, Object> filter = text == null || text.isBlank() ? null
				: RowFilter.regexFilter("(?i)" + Pattern.quote(text));
		for (TableRowSorter<DefaultTableModel> sorter : tableSorters.values()) {
			sorter.setRowFilter(filter);
		}
	}

	private void installTableNavigation(JTable table) {
		JPopupMenu popup = new JPopupMenu();
		popup.add(item("Goto usage", gotoUsage));
		popup.add(item("Goto string", gotoString));
		popup.addSeparator();
		popup.add(item("Copy value", copySelected));
		table.getSelectionModel().addListSelectionListener(e -> {
			if (!e.getValueIsAdjusting()) {
				selectionChanged.run();
			}
		});
		table.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (e.getClickCount() == 2 && SwingUtilities.isLeftMouseButton(e)) {
					gotoUsage.run();
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
				gotoUsage.run();
			}
		});
	}

	private JMenuItem item(String text, Runnable action) {
		JMenuItem item = new JMenuItem(text);
		item.addActionListener(e -> action.run());
		return item;
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
		Color tableFg = new Color(24, 24, 24);
		Color headerBg = new Color(232, 232, 226);
		Color headerFg = new Color(24, 24, 24);
		Color selectionBg = new Color(204, 226, 255);
		Color selectionFg = Color.BLACK;
		table.setBackground(Color.WHITE);
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
			if (columnVisible.test(COLUMNS[i].title())) {
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

	private record TabSpec(String title, Predicate<ParadiseFindScanner.Row> filter) {
	}

	private static final class TabState {
		private final TabSpec spec;
		private final DefaultTableModel model;
		private final JTable table;
		private List<ParadiseFindScanner.Row> rows = List.of();

		private TabState(TabSpec spec, DefaultTableModel model, JTable table) {
			this.spec = spec;
			this.model = model;
			this.table = table;
		}

		private TabSpec spec() {
			return spec;
		}

		private DefaultTableModel model() {
			return model;
		}

		private JTable table() {
			return table;
		}

		private List<ParadiseFindScanner.Row> rows() {
			return rows;
		}

		private void setRows(List<ParadiseFindScanner.Row> rows) {
			this.rows = List.copyOf(rows);
		}
	}
}
