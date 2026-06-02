package paradise;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Graphics;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;
import java.util.Objects;
import java.util.function.BooleanSupplier;

import javax.swing.BorderFactory;
import javax.swing.Icon;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JSplitPane;

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
	private final ParadisePlugin plugin;
	private final JPanel panel = new JPanel(new BorderLayout());
	private final JLabel titleLabel = new JLabel("Paradise Inspector");
	private final JLabel statusLabel = new JLabel("No scan yet");
	private final JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
	private final ParadiseInspectorTables inspectorTables;
	private final ParadiseInspectorDetails inspectorDetails;
	private Program lastProgram;
	private Function lastFunction;
	private boolean lastWholeProgram;

	ParadiseFindProvider(ParadisePlugin plugin) {
		super(plugin.getTool(), "Paradise Inspector", plugin.getName());
		this.plugin = plugin;
		inspectorTables = new ParadiseInspectorTables(plugin::showFindColumn, this::updateDetail,
			this::gotoUsage, this::gotoString, this::copySelected);
		inspectorDetails = new ParadiseInspectorDetails(this::gotoAddress, this::copyText);
		setTitle("Paradise Inspector");
		setWindowMenuGroup("Paradise");
		setDefaultWindowPosition(WindowPosition.RIGHT);
		buildUi();
		installLocalToolbarActions();
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
		inspectorTables.applyColumnOptions();
		inspectorDetails.showScreen(plugin.inspectorDetailsScreen());
		updateDetail();
	}

	boolean hasScan() {
		return lastProgram != null || lastFunction != null || inspectorTables.hasRows();
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
		inspectorTables.showRows(rows);
		statusLabel.setText(status);
		updateDetail();
		contextChanged();
	}

	private void buildUi() {
		JPanel header = new JPanel(new BorderLayout());
		header.setBorder(BorderFactory.createEmptyBorder(3, 8, 3, 8));
		titleLabel.setFont(titleLabel.getFont().deriveFont(java.awt.Font.BOLD, 13f));
		header.add(titleLabel, BorderLayout.WEST);
		header.add(inspectorTables.compactFilterPanel(), BorderLayout.EAST);
		splitPane.setUI(new ParadiseDottedSplitPaneUi(plugin::darkTheme));
		splitPane.setBorder(BorderFactory.createEmptyBorder());
		splitPane.setTopComponent(inspectorTables.tabs());
		splitPane.setBottomComponent(inspectorDetails.panel());
		splitPane.setResizeWeight(0.78);
		splitPane.setDividerSize(11);
		panel.add(header, BorderLayout.NORTH);
		panel.add(splitPane, BorderLayout.CENTER);
		panel.add(statusLabel, BorderLayout.SOUTH);
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
				() -> !inspectorTables.overviewRows().isEmpty(), this::exportCsv);
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

	private ParadiseFindScanner.Row selectedRow() {
		return inspectorTables.selectedRow();
	}

	private void updateDetail() {
		inspectorDetails.update(selectedRow());
	}

	private void gotoAddress(Address address) {
		if (address != null) {
			plugin.navigateTo(address);
		}
	}

	private void copyText(String value) {
		Toolkit.getDefaultToolkit().getSystemClipboard()
				.setContents(new StringSelection(Objects.toString(value, "")), null);
	}

	private void gotoUsage() {
		ParadiseFindScanner.Row row = selectedRow();
		if (row == null) {
			return;
		}
		Address address = row.useAddress() != null ? row.useAddress() : row.textAddress();
		if (address != null) {
			plugin.navigateTo(address);
		}
		plugin.focusPseudocodeUsage(address, row.rawValue(), row.value());
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
			for (ParadiseFindScanner.Row row : inspectorTables.overviewRows()) {
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
