package paradise;

import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.function.Consumer;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableColumn;

import ghidra.program.model.address.Address;

final class ParadiseInspectorDetails {
	private static final String SCREEN_CARD = "screen";
	private static final String TEXT_CARD = "text";
	private static final Color PAGE_BACKGROUND = new Color(244, 245, 247);

	private final Consumer<Address> navigateTo;
	private final Consumer<String> copyText;
	private final CardLayout layout = new CardLayout();
	private final JPanel cards = new JPanel(layout);
	private final JTabbedPane tabs = new JTabbedPane();
	private final JTextArea area = new JTextArea("Select an Inspector row to view details.");

	ParadiseInspectorDetails(Consumer<Address> navigateTo, Consumer<String> copyText) {
		this.navigateTo = navigateTo;
		this.copyText = copyText;
		area.setEditable(false);
		area.setRows(7);
		area.setLineWrap(true);
		area.setWrapStyleWord(false);
		area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, area.getFont().getSize()));
	}

	JPanel panel() {
		JPanel panel = new JPanel(new BorderLayout());
		JLabel label = new JLabel("Details");
		label.setBorder(BorderFactory.createEmptyBorder(2, 4, 2, 4));
		label.setFont(label.getFont().deriveFont(Font.BOLD));
		panel.add(label, BorderLayout.NORTH);
		cards.add(tabs, SCREEN_CARD);
		cards.add(new JScrollPane(area), TEXT_CARD);
		panel.add(cards, BorderLayout.CENTER);
		return panel;
	}

	void showScreen(boolean screen) {
		layout.show(cards, screen ? SCREEN_CARD : TEXT_CARD);
	}

	void update(ParadiseFindScanner.Row row) {
		area.setText(row == null ? "Select an Inspector row to view details." : detailText(row));
		area.setCaretPosition(0);
		tabs.removeAll();
		if (row == null) {
			JPanel page = detailPage();
			addDetailSection(page, "Details",
				List.<Object[]>of(new Object[] { "Status",
					"Select an Inspector row to view details." }));
			finishDetailPage(page);
			tabs.addTab("Overview", detailScroll(page));
			return;
		}
		fillDetailScreen(row);
	}

	private String detailText(ParadiseFindScanner.Row row) {
		StringBuilder builder = new StringBuilder();
		appendDetail(builder, "Kind", row.kind());
		appendDetail(builder, "Priority", row.priority());
		appendDetail(builder, "Count", row.count());
		appendDetail(builder, "Address", row.textAddress());
		appendDetail(builder, "Use", row.useAddress());
		appendDetail(builder, "Source", row.source());
		appendDetail(builder, "Decode Chain", row.chain());
		appendDetail(builder, "Evidence", row.evidence());
		builder.append('\n');
		appendDetail(builder, "Value", row.value());
		if (!Objects.equals(row.rawValue(), row.value())) {
			appendDetail(builder, "Original", row.rawValue());
		}
		builder.append('\n').append("Usages").append('\n');
		List<ParadiseFindScanner.Usage> usages = row.usages();
		if (usages.isEmpty()) {
			builder.append("  none\n");
			return builder.toString();
		}
		for (int i = 0; i < usages.size(); i++) {
			ParadiseFindScanner.Usage usage = usages.get(i);
			builder.append("  #").append(i + 1).append('\n');
			appendDetail(builder, "    Use", usage.useAddress());
			appendDetail(builder, "    String", usage.textAddress());
			appendDetail(builder, "    Source", usage.source());
			appendDetail(builder, "    Decode Chain", usage.chain());
			appendDetail(builder, "    Evidence", usage.evidence());
			appendDetail(builder, "    Original", usage.rawValue());
		}
		return builder.toString();
	}

	private void appendDetail(StringBuilder builder, String label, Object value) {
		builder.append(label).append(": ").append(Objects.toString(value, "")).append('\n');
	}

	private void fillDetailScreen(ParadiseFindScanner.Row row) {
		JPanel overviewPage = detailPage();
		JPanel valuePage = detailPage();
		JPanel sourcePage = detailPage();
		JPanel usePage = detailPage();
		addDetailHeader(overviewPage, "Overview");
		addDetailSection(overviewPage, "Summary", List.of(
			new Object[] { "Brief", brief(row) },
			new Object[] { "Kind", row.kind() },
			new Object[] { "Priority", row.priority() },
			new Object[] { "Count", row.count() },
			new Object[] { "Address", row.textAddress() },
			new Object[] { "Use", row.useAddress() },
			new Object[] { "Value", row.value() }));
		addDetailHeader(sourcePage, "Source");
		addDetailSection(sourcePage, "Encoding Info", List.of(
			new Object[] { "Source", row.source() },
			new Object[] { "Decode Chain", row.chain() },
			new Object[] { "Steps", decodeStepCount(row.chain()) },
			new Object[] { "Evidence", row.evidence() }));
		addDetailSection(sourcePage, "Locations", List.of(
			new Object[] { "String", row.textAddress() },
			new Object[] { "Use", row.useAddress() }));
		addDetailSection(sourcePage, "Raw Data", List.<Object[]>of(
			new Object[] { "Original", row.rawValue() }));
		List<Object[]> valueRows = new ArrayList<>();
		valueRows.add(new Object[] { "Value", row.value() });
		if (!Objects.equals(row.rawValue(), row.value())) {
			valueRows.add(new Object[] { "Original", row.rawValue() });
		}
		addDetailHeader(valuePage, "Value");
		addDetailSection(valuePage, "Decoded Text", valueRows, true);
		List<ParadiseFindScanner.Usage> usages = row.usages();
		addDetailHeader(usePage, "Use");
		if (usages.isEmpty()) {
			addDetailSection(usePage, "Use", List.<Object[]>of(new Object[] { "Status",
				"No recorded uses" }));
		}
		else {
			for (int i = 0; i < usages.size(); i++) {
				ParadiseFindScanner.Usage usage = usages.get(i);
				addDetailSection(usePage, "Use #" + (i + 1), List.of(
					new Object[] { "Use", usage.useAddress() },
					new Object[] { "String", usage.textAddress() },
					new Object[] { "Source", usage.source() },
					new Object[] { "Decode Chain", usage.chain() },
					new Object[] { "Evidence", usage.evidence() },
					new Object[] { "Original", usage.rawValue() }));
			}
		}
		finishDetailPage(overviewPage);
		finishDetailPage(valuePage);
		finishDetailPage(sourcePage);
		finishDetailPage(usePage);
		tabs.addTab("Overview", detailScroll(overviewPage));
		tabs.addTab("Value", detailScroll(valuePage));
		tabs.addTab("Source", detailScroll(sourcePage));
		tabs.addTab("Use", detailScroll(usePage));
	}

	private String brief(ParadiseFindScanner.Row row) {
		String source = row.source() == null || row.source().isBlank() ? "raw" : row.source();
		String chain = row.chain() == null || row.chain().isBlank() ? "no decode chain" : row.chain();
		return row.kind() + " finding from " + source + " data, " + chain + ".";
	}

	private int decodeStepCount(String chain) {
		if (chain == null || chain.isBlank()) {
			return 0;
		}
		int count = 1;
		for (int i = 0; i < chain.length(); i++) {
			if (chain.charAt(i) == '>') {
				count++;
			}
		}
		return count;
	}

	private JPanel detailPage() {
		JPanel page = new JPanel();
		page.setLayout(new BoxLayout(page, BoxLayout.Y_AXIS));
		page.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));
		page.setBackground(PAGE_BACKGROUND);
		return page;
	}

	private JScrollPane detailScroll(JPanel page) {
		JScrollPane scrollPane = new JScrollPane(page);
		scrollPane.setBorder(BorderFactory.createEmptyBorder());
		scrollPane.getVerticalScrollBar().setUnitIncrement(16);
		scrollPane.getViewport().setBackground(PAGE_BACKGROUND);
		return scrollPane;
	}

	private void addDetailHeader(JPanel page, String title) {
		JLabel label = new JLabel(title);
		label.setFont(label.getFont().deriveFont(Font.BOLD, 15f));
		label.setBorder(BorderFactory.createEmptyBorder(4, 3, 4, 0));
		label.setAlignmentX(Component.LEFT_ALIGNMENT);
		page.add(label);
	}

	private void addDetailSection(JPanel page, String title, List<Object[]> rows) {
		addDetailSection(page, title, rows, false);
	}

	private void addDetailSection(JPanel page, String title, List<Object[]> rows,
			boolean copyValues) {
		JPanel section = new JPanel(new BorderLayout());
		section.setBorder(BorderFactory.createCompoundBorder(
			BorderFactory.createTitledBorder(title),
			BorderFactory.createEmptyBorder(5, 6, 7, 6)));
		section.setAlignmentX(Component.LEFT_ALIGNMENT);
		section.setBackground(PAGE_BACKGROUND);
		JTable table = detailTable(rows, copyValues);
		section.add(table.getTableHeader(), BorderLayout.NORTH);
		section.add(table, BorderLayout.CENTER);
		installDetailTableSizing(table, section);
		page.add(section);
		page.add(Box.createVerticalStrut(6));
	}

	private JTable detailTable(List<Object[]> rows, boolean copyValues) {
		DefaultTableModel model = new DefaultTableModel(new String[] { "Field", "Value", "" }, 0) {
			@Override
			public boolean isCellEditable(int row, int column) {
				return false;
			}
		};
		for (Object[] row : rows) {
			Object value = row.length > 1 ? row[1] : "";
			Address address = value instanceof Address found ? found : null;
			model.addRow(new Object[] { Objects.toString(row[0], ""), Objects.toString(value, ""),
				copyValues ? Objects.toString(value, "") : address });
		}
		JTable table = new JTable(model);
		table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
		table.setFillsViewportHeight(false);
		table.setRowHeight(22);
		table.setShowGrid(true);
		table.setGridColor(new Color(210, 210, 205));
		table.setBackground(Color.WHITE);
		table.setForeground(new Color(24, 24, 24));
		table.setSelectionBackground(new Color(204, 226, 255));
		table.setSelectionForeground(Color.BLACK);
		table.getTableHeader().setReorderingAllowed(false);
		table.getTableHeader().setBackground(new Color(232, 232, 226));
		table.getTableHeader().setForeground(new Color(24, 24, 24));
		table.getTableHeader().setFont(table.getFont().deriveFont(Font.BOLD));
		TableColumn fieldColumn = table.getColumnModel().getColumn(0);
		TableColumn valueColumn = table.getColumnModel().getColumn(1);
		TableColumn actionColumn = table.getColumnModel().getColumn(2);
		fieldColumn.setPreferredWidth(150);
		fieldColumn.setMinWidth(96);
		fieldColumn.setMaxWidth(220);
		valueColumn.setPreferredWidth(640);
		valueColumn.setMinWidth(160);
		actionColumn.setPreferredWidth(78);
		actionColumn.setMinWidth(72);
		actionColumn.setMaxWidth(86);
		table.getColumnModel().getColumn(0).setCellRenderer(new DetailFieldRenderer());
		table.getColumnModel().getColumn(1).setCellRenderer(new DetailValueRenderer());
		table.getColumnModel().getColumn(2).setCellRenderer(copyValues ? new DetailCopyRenderer()
				: new DetailGotoRenderer());
		table.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				int viewColumn = table.columnAtPoint(e.getPoint());
				int viewRow = table.rowAtPoint(e.getPoint());
				if (viewRow < 0 || viewColumn < 0 ||
					table.convertColumnIndexToModel(viewColumn) != 2) {
					return;
				}
				Object action = model.getValueAt(table.convertRowIndexToModel(viewRow), 2);
				if (copyValues && action instanceof String value) {
					copyText.accept(value);
				}
				else if (action instanceof Address address) {
					navigateTo.accept(address);
				}
			}
		});
		table.setPreferredScrollableViewportSize(new Dimension(1,
			table.getTableHeader().getPreferredSize().height + table.getRowHeight() *
				Math.max(1, rows.size())));
		return table;
	}

	private void installDetailTableSizing(JTable table, JPanel section) {
		Runnable sync = () -> syncDetailTableSize(table, section);
		table.addComponentListener(new ComponentAdapter() {
			@Override
			public void componentResized(ComponentEvent e) {
				sync.run();
			}
		});
		section.addComponentListener(new ComponentAdapter() {
			@Override
			public void componentResized(ComponentEvent e) {
				sync.run();
			}
		});
		SwingUtilities.invokeLater(sync);
	}

	private void syncDetailTableSize(JTable table, JPanel section) {
		int valueWidth = Math.max(80, table.getColumnModel().getColumn(1).getWidth() - 18);
		JTextArea measure = new JTextArea();
		measure.setLineWrap(true);
		measure.setWrapStyleWord(false);
		measure.setFont(new Font(Font.MONOSPACED, Font.PLAIN, table.getFont().getSize()));
		for (int row = 0; row < table.getRowCount(); row++) {
			measure.setText(Objects.toString(table.getValueAt(row, 1), ""));
			measure.setSize(new Dimension(valueWidth, Short.MAX_VALUE));
			int height = Math.max(22, measure.getPreferredSize().height + 8);
			if (table.getRowHeight(row) != height) {
				table.setRowHeight(row, height);
			}
		}
		int bodyHeight = 0;
		for (int row = 0; row < table.getRowCount(); row++) {
			bodyHeight += table.getRowHeight(row);
		}
		table.setPreferredSize(new Dimension(table.getPreferredSize().width, bodyHeight));
		int tableHeight = table.getTableHeader().getPreferredSize().height + bodyHeight;
		int sectionHeight = tableHeight + section.getInsets().top + section.getInsets().bottom;
		section.setPreferredSize(new Dimension(section.getPreferredSize().width, sectionHeight));
		section.setMaximumSize(new Dimension(Integer.MAX_VALUE, sectionHeight));
		refreshComponentTree(section);
	}

	private void refreshComponentTree(JComponent component) {
		try {
			JComponent.class.getMethod("re" + "val" + "date").invoke(component);
		}
		catch (ReflectiveOperationException | SecurityException e) {
			component.doLayout();
		}
		component.repaint();
	}

	private void finishDetailPage(JPanel page) {
		page.add(Box.createVerticalGlue());
		if (page.getParent() != null) {
			page.getParent().doLayout();
		}
		page.repaint();
	}

	private static final class DetailFieldRenderer extends DefaultTableCellRenderer {
		@Override
		public Component getTableCellRendererComponent(JTable table, Object value,
				boolean selected, boolean focus, int row, int column) {
			JLabel label = (JLabel) super.getTableCellRendererComponent(table, value, selected,
				focus, row, column);
			label.setBorder(BorderFactory.createEmptyBorder(2, 8, 2, 8));
			label.setFont(label.getFont().deriveFont(Font.BOLD));
			return label;
		}
	}

	private static final class DetailValueRenderer extends JTextArea implements TableCellRenderer {
		private DetailValueRenderer() {
			setLineWrap(true);
			setWrapStyleWord(false);
			setOpaque(true);
			setBorder(BorderFactory.createEmptyBorder(2, 8, 2, 8));
			setFont(new Font(Font.MONOSPACED, Font.PLAIN, getFont().getSize()));
		}

		@Override
		public Component getTableCellRendererComponent(JTable table, Object value,
				boolean selected, boolean focus, int row, int column) {
			setText(Objects.toString(value, ""));
			if (selected) {
				setBackground(table.getSelectionBackground());
				setForeground(table.getSelectionForeground());
			}
			else {
				setBackground(row % 2 == 0 ? new Color(248, 248, 244)
						: new Color(255, 255, 252));
				setForeground(table.getForeground());
			}
			return this;
		}
	}

	private static final class DetailGotoRenderer extends JButton implements TableCellRenderer {
		private DetailGotoRenderer() {
			setText("Goto");
			setFocusable(false);
		}

		@Override
		public Component getTableCellRendererComponent(JTable table, Object value,
				boolean selected, boolean focus, int row, int column) {
			setText(value instanceof Address ? "Goto" : "");
			setEnabled(value instanceof Address);
			return this;
		}
	}

	private static final class DetailCopyRenderer extends JButton implements TableCellRenderer {
		private DetailCopyRenderer() {
			setText("Copy");
			setFocusable(false);
		}

		@Override
		public Component getTableCellRendererComponent(JTable table, Object value,
				boolean selected, boolean focus, int row, int column) {
			setText(value instanceof String && !((String) value).isEmpty() ? "Copy" : "");
			setEnabled(value instanceof String && !((String) value).isEmpty());
			return this;
		}
	}
}
