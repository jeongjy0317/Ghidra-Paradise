package paradise;

import java.awt.BasicStroke;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.Point;
import java.awt.RenderingHints;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.MouseWheelEvent;
import java.awt.geom.AffineTransform;
import java.awt.geom.Path2D;
import java.awt.geom.Point2D;
import java.awt.geom.Rectangle2D;
import java.awt.image.BufferedImage;
import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Queue;
import java.util.Set;
import java.util.TreeMap;
import java.util.function.BooleanSupplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.imageio.ImageIO;
import javax.swing.AbstractAction;
import javax.swing.BorderFactory;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.Icon;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JSlider;
import javax.swing.JTextField;
import javax.swing.KeyStroke;
import javax.swing.SwingUtilities;
import javax.swing.ToolTipManager;
import javax.swing.filechooser.FileNameExtensionFilter;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.WindowPosition;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.lang.Register;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.Msg;
import ghidra.util.Swing;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;

final class ParadiseGraphProvider extends ComponentProvider {
	private final ParadisePlugin plugin;
	private final JPanel panel = new JPanel(new BorderLayout());
	private final JLabel titleLabel = new JLabel("Paradise Diagram");
	private final JLabel statusLabel = new JLabel(" ");
	private final JTextField searchField = new JTextField(14);
	private final JSlider zoomSlider = new JSlider(25, 280, 100);
	private final GraphCanvas canvas = new GraphCanvas();
	private ParadiseGraph graph;
	private boolean updatingZoomSlider;
	private String graphStateKey;

	ParadiseGraphProvider(ParadisePlugin plugin) {
		super(plugin.getTool(), "Paradise Diagram", plugin.getName());
		this.plugin = plugin;
		setTitle("Paradise Diagram");
		setWindowMenuGroup("Paradise");
		setDefaultWindowPosition(WindowPosition.RIGHT);
		buildUi();
		installLocalToolbarActions();
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}

	void showGraph(Function function) {
		if (function == null) {
			Msg.showInfo(this, panel, "Paradise Diagram", "No function selected.");
			return;
		}
		setTitle("Paradise Diagram");
		setSubTitle("");
		setVisible(true);
		titleLabel.setText(function.getName() + " @ " + function.getEntryPoint());
		statusLabel.setText("Building graph...");
		TaskLauncher.launchNonModal("Build Diagram " + function.getName(), monitor -> {
			try {
				ParadiseGraph built = ParadiseGraphBuilder.build(function, monitor);
				Swing.runLater(() -> showGraph(built));
			}
			catch (CancelledException e) {
				Swing.runLater(() -> statusLabel.setText("Graph build cancelled."));
			}
			catch (RuntimeException e) {
				Swing.runLater(() -> {
					statusLabel.setText("Graph build failed.");
					Msg.showError(this, panel, "Paradise Diagram", e.getMessage(), e);
				});
			}
		});
	}

	void showGraph(Program program) {
		if (program == null) {
			Msg.showInfo(this, panel, "Paradise Diagram", "No program selected.");
			return;
		}
		setTitle("Paradise Diagram");
		setSubTitle("");
		setVisible(true);
		titleLabel.setText(program.getName() + " call graph");
		statusLabel.setText("Building binary graph...");
		TaskLauncher.launchNonModal("Build Binary Diagram " + program.getName(), monitor -> {
			try {
				ParadiseGraph built = ParadiseGraphBuilder.build(program, monitor);
				Swing.runLater(() -> showGraph(built));
			}
			catch (CancelledException e) {
				Swing.runLater(() -> statusLabel.setText("Graph build cancelled."));
			}
			catch (RuntimeException e) {
				Swing.runLater(() -> {
					statusLabel.setText("Graph build failed.");
					Msg.showError(this, panel, "Paradise Diagram", e.getMessage(), e);
				});
			}
		});
	}

	void programClosed(Program program) {
		if (graph != null && graph.program() == program) {
			canvas.saveViewState();
			graph = null;
			canvas.setGraph(null);
			titleLabel.setText("Paradise Diagram");
			statusLabel.setText(" ");
			contextChanged();
		}
	}

	void revealAddress(Address address) {
		if (address == null || graph == null || !isVisible()) {
			return;
		}
		canvas.selectAddress(address, true);
	}

	private void showGraph(ParadiseGraph graph) {
		canvas.saveViewState();
		this.graph = graph;
		graphStateKey = graphStateKey(graph);
		titleLabel.setText(graph.title());
		String nodeText = graph.function() == null ? " functions, " : " blocks, ";
		statusLabel.setText(graph.blocks().size() + nodeText + graph.edges().size() + " edges");
		searchField.setText("");
		canvas.setGraph(graph);
		contextChanged();
	}

	private String graphStateKey(ParadiseGraph graph) {
		if (graph == null || graph.program() == null) {
			return "";
		}
		String subject = graph.function() == null ? "binary" : graph.function().getEntryPoint().toString();
		return graph.program().getName() + ":" + subject;
	}

	private void buildUi() {
		JPanel header = new JPanel(new BorderLayout());
		header.setBorder(BorderFactory.createEmptyBorder(3, 8, 3, 8));
		titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD, 13f));
		header.add(titleLabel, BorderLayout.WEST);
		zoomSlider.setFocusable(false);
		zoomSlider.addChangeListener(e -> {
			if (!updatingZoomSlider) {
				canvas.setZoomPercent(zoomSlider.getValue());
			}
		});
		searchField.addActionListener(e -> canvas.setSearchQuery(searchField.getText(), true));

		panel.add(header, BorderLayout.NORTH);
		panel.add(canvas, BorderLayout.CENTER);
		panel.add(statusLabel, BorderLayout.SOUTH);
	}

	private void installLocalToolbarActions() {
		addToolbarAction("Fit", GraphGlyph.FIT, "01_view", "010", () -> graph != null,
			() -> canvas.fitToView());
		addToolbarAction("100%", GraphGlyph.ACTUAL_SIZE, "01_view", "020", () -> graph != null,
			() -> canvas.resetZoom());
		addToolbarAction("Zoom In", GraphGlyph.ZOOM_IN, "01_view", "030", () -> graph != null,
			() -> canvas.zoomBy(1.18));
		addToolbarAction("Zoom Out", GraphGlyph.ZOOM_OUT, "01_view", "040", () -> graph != null,
			() -> canvas.zoomBy(1.0 / 1.18));
		addToolbarAction("Search", GraphGlyph.SEARCH, "02_search", "010", () -> graph != null,
			() -> searchGraph());
		addToolbarAction("Next Match", GraphGlyph.NEXT, "02_search", "020", () -> graph != null,
			() -> selectNextGraphMatch());
		addToolbarAction("Collapse", GraphGlyph.COLLAPSE, "03_graph", "010", () -> graph != null,
			() -> canvas.toggleSelectedBlockCollapse());
		addToolbarAction("Pseudocode", GraphGlyph.PSEUDOCODE, "04_navigation", "010",
			() -> graph != null, () -> openPseudocode());
		addToolbarAction("Disasm", GraphGlyph.DISASM, "04_navigation", "020", () -> graph != null,
			() -> jumpToDisassembly());
		addToolbarAction("Copy", GraphGlyph.COPY, "05_output", "010", () -> graph != null,
			() -> canvas.copySelectedBlock());
		addToolbarAction("Export", GraphGlyph.EXPORT, "05_output", "020", () -> graph != null,
			() -> canvas.exportGraph());
	}

	private void addToolbarAction(String name, GraphGlyph glyph, String group, String subgroup,
			BooleanSupplier enabled, Runnable handler) {
		DockingAction action = new DockingAction("Paradise Diagram " + name, plugin.getName()) {
			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return enabled.getAsBoolean();
			}

			@Override
			public void actionPerformed(ActionContext context) {
				handler.run();
			}
		};
		action.setToolBarData(new ToolBarData(new GraphToolbarIcon(glyph), group, subgroup));
		action.setDescription(name);
		action.markHelpUnnecessary();
		addLocalAction(action);
	}

	private void searchGraph() {
		if (graph == null) {
			return;
		}
		String query = JOptionPane.showInputDialog(panel, "Find diagram text:",
			searchField.getText());
		if (query == null) {
			return;
		}
		searchField.setText(query);
		canvas.setSearchQuery(query, true);
	}

	private void selectNextGraphMatch() {
		if (graph == null) {
			return;
		}
		if (searchField.getText().isBlank()) {
			searchGraph();
			return;
		}
		canvas.setSearchQuery(searchField.getText(), false);
		canvas.selectNextSearchMatch();
	}

	private void openPseudocode() {
		Function function = graph == null ? null : graph.function();
		if (function == null && graph != null) {
			Address address = canvas.selectedAddress();
			if (address == null) {
				address = graph.entryPoint();
			}
			if (address != null) {
				function = graph.program().getFunctionManager().getFunctionAt(address);
				if (function == null) {
					function = graph.program().getFunctionManager().getFunctionContaining(address);
				}
			}
		}
		if (function != null) {
			plugin.decompileFunction(function, false, true);
		}
	}

	private void jumpToDisassembly() {
		Address address = canvas.selectedAddress();
		if (address == null && graph != null && graph.function() != null) {
			address = graph.function().getEntryPoint();
		}
		if (address == null && graph != null) {
			address = graph.entryPoint();
		}
		if (address != null) {
			plugin.navigateTo(address);
		}
	}

	private void activateLine(ParadiseGraphLine line) {
		if (line == null) {
			return;
		}
		if (line.callTarget() != null && graph != null) {
			Function target = graph.program().getFunctionManager()
					.getFunctionAt(line.callTarget());
			if (target != null && (graph.function() == null || !target.equals(graph.function()))) {
				plugin.decompileFunction(target, false, true, !plugin.openCalleesInNewTabs());
				return;
			}
		}
		if (line.address() != null) {
			plugin.navigateTo(line.address());
		}
	}

	private final class GraphCanvas extends JComponent {
		private static final int TITLE_HEIGHT = 18;
		private static final int BLOCK_PAD_X = 10;
		private static final int BLOCK_PAD_Y = 8;
		private static final int LAYER_GAP = 80;
		private static final int COLUMN_GAP = 54;
		private static final double EDGE_LANE_GAP = 14.0;

		private final Font codeFont = new Font(Font.MONOSPACED, Font.PLAIN, 13);
		private final JPopupMenu popup = new JPopupMenu();
		private double scale = 1.0;
		private double offsetX = 48.0;
		private double offsetY = 48.0;
		private Point dragStart;
		private double dragOffsetX;
		private double dragOffsetY;
		private ParadiseGraphBlock selectedBlock;
		private ParadiseGraphLine selectedLine;
		private ParadiseGraphEdge hoveredEdge;
		private String searchQuery = "";
		private int searchMatchIndex = -1;
		private boolean suppressStateSave;

		GraphCanvas() {
			setOpaque(true);
			setBackground(new Color(160, 160, 160));
			setFocusable(true);
			buildPopup();
			MouseAdapter mouse = new MouseAdapter() {
				@Override
				public void mousePressed(MouseEvent e) {
					requestFocusInWindow();
					if (showPopup(e)) {
						return;
					}
					selectAt(e.getPoint(), e.getClickCount());
					dragStart = e.getPoint();
					dragOffsetX = offsetX;
					dragOffsetY = offsetY;
				}

				@Override
				public void mouseReleased(MouseEvent e) {
					showPopup(e);
					dragStart = null;
				}

				@Override
				public void mouseDragged(MouseEvent e) {
					if (dragStart == null || SwingUtilities.isRightMouseButton(e)) {
						return;
					}
					offsetX = dragOffsetX + e.getX() - dragStart.x;
					offsetY = dragOffsetY + e.getY() - dragStart.y;
					saveViewState();
					repaint();
				}

				@Override
				public void mouseMoved(MouseEvent e) {
					updateHoveredEdge(e.getPoint());
				}

				@Override
				public void mouseExited(MouseEvent e) {
					clearHoveredEdge();
				}

				@Override
				public void mouseWheelMoved(MouseWheelEvent e) {
					if (e.isControlDown() || e.isMetaDown()) {
						zoomAt(e.getPoint(), wheelZoomFactor(e));
						return;
					}
					panFromWheel(e);
				}
			};
			addMouseListener(mouse);
			addMouseMotionListener(mouse);
			addMouseWheelListener(mouse);
			installTrackpadZoomSupport();
			installKeyBindings();
			setToolTipText("");
			ToolTipManager.sharedInstance().registerComponent(this);
		}

		void setGraph(ParadiseGraph graph) {
			selectedBlock = null;
			selectedLine = null;
			hoveredEdge = null;
			searchQuery = "";
			searchMatchIndex = -1;
			layoutGraph(graph);
			suppressStateSave = true;
			if (getWidth() <= 1 || getHeight() <= 1) {
				resetZoom();
				SwingUtilities.invokeLater(() -> {
					suppressStateSave = true;
					fitToView();
					suppressStateSave = false;
					restoreViewState(plugin.diagramViewState(graphStateKey));
					repaint();
				});
			}
			else {
				fitToView();
			}
			suppressStateSave = false;
			restoreViewState(plugin.diagramViewState(graphStateKey));
			repaint();
		}

		void fitToView() {
			if (graph == null || graph.layoutSize().width <= 0 || graph.layoutSize().height <= 0) {
				return;
			}
			int width = Math.max(1, getWidth() - 72);
			int height = Math.max(1, getHeight() - 72);
			scale = Math.max(0.25, Math.min(1.6,
				Math.min(width / (double) graph.layoutSize().width,
					height / (double) graph.layoutSize().height)));
			offsetX = Math.max(24, (getWidth() - graph.layoutSize().width * scale) / 2.0);
			offsetY = Math.max(24, (getHeight() - graph.layoutSize().height * scale) / 2.0);
			syncZoomSlider();
			saveViewState();
			repaint();
		}

		void resetZoom() {
			scale = 1.0;
			offsetX = 48.0;
			offsetY = 48.0;
			syncZoomSlider();
			saveViewState();
			repaint();
		}

		void zoomBy(double factor) {
			Point pivot = new Point(Math.max(0, getWidth() / 2), Math.max(0, getHeight() / 2));
			zoomAt(pivot, factor);
			saveViewState();
		}

		void setZoomPercent(int percent) {
			double oldScale = scale;
			scale = Math.max(0.25, Math.min(2.8, percent / 100.0));
			double actual = scale / oldScale;
			Point pivot = new Point(Math.max(0, getWidth() / 2), Math.max(0, getHeight() / 2));
			offsetX = pivot.x - (pivot.x - offsetX) * actual;
			offsetY = pivot.y - (pivot.y - offsetY) * actual;
			saveViewState();
			repaint();
		}

		void panFromWheel(MouseWheelEvent e) {
			double amount = e.getPreciseWheelRotation() * 48.0;
			if (e.isShiftDown()) {
				offsetX -= amount;
			}
			else {
				offsetY -= amount;
			}
			saveViewState();
			repaint();
		}

		void setSearchQuery(String query, boolean selectFirst) {
			searchQuery = query == null ? "" : query.strip().toLowerCase(Locale.ROOT);
			searchMatchIndex = -1;
			int count = searchMatches().size();
			if (selectFirst && count > 0) {
				selectNextSearchMatch();
			}
			else {
				statusLabel.setText(count == 0 && !searchQuery.isBlank() ? "No diagram matches"
						: count + " diagram matches");
				repaint();
			}
		}

		void selectNextSearchMatch() {
			List<GraphMatch> matches = searchMatches();
			if (matches.isEmpty()) {
				statusLabel.setText(searchQuery.isBlank() ? " " : "No diagram matches");
				repaint();
				return;
			}
			searchMatchIndex = (searchMatchIndex + 1) % matches.size();
			GraphMatch match = matches.get(searchMatchIndex);
			selectedBlock = match.block();
			selectedLine = match.line();
			centerBlock(selectedBlock);
			statusLabel.setText("Diagram match " + (searchMatchIndex + 1) + " of " +
				matches.size());
			repaint();
		}

		void toggleSelectedBlockCollapse() {
			if (selectedBlock == null) {
				return;
			}
			selectedBlock.setCollapsed(!selectedBlock.collapsed());
			layoutGraph(graph);
			centerBlock(selectedBlock);
			saveViewState();
			repaint();
		}

		private double wheelZoomFactor(MouseWheelEvent e) {
			return Math.pow(1.12, -e.getPreciseWheelRotation());
		}

		private void installTrackpadZoomSupport() {
			try {
				Class<?> gestureUtilities =
					Class.forName("com.apple.eawt.event.GestureUtilities");
				Class<?> gestureListener =
					Class.forName("com.apple.eawt.event.GestureListener");
				Class<?> magnificationListener =
					Class.forName("com.apple.eawt.event.MagnificationListener");
				Object listener = Proxy.newProxyInstance(
					magnificationListener.getClassLoader(),
					new Class<?>[] { magnificationListener },
					(proxy, method, args) -> handleGestureInvocation(proxy, method, args));
				Method addGestureListener = gestureUtilities.getMethod("addGestureListenerTo",
					JComponent.class, gestureListener);
				addGestureListener.invoke(null, this, listener);
			}
			catch (ReflectiveOperationException | LinkageError e) {
				// Non-macOS runtimes and older JDKs do not expose Apple gesture events.
			}
		}

		private Object handleGestureInvocation(Object proxy, Method method, Object[] args) {
			if (method.getDeclaringClass() == Object.class) {
				return switch (method.getName()) {
					case "toString" -> "ParadiseGraphMagnificationListener";
					case "hashCode" -> System.identityHashCode(proxy);
					case "equals" -> proxy == (args == null || args.length == 0 ? null : args[0]);
					default -> null;
				};
			}
			if ("magnify".equals(method.getName()) && args != null && args.length > 0) {
				handleTrackpadMagnification(args[0]);
			}
			return null;
		}

		private void handleTrackpadMagnification(Object event) {
			try {
				Method getMagnification = event.getClass().getMethod("getMagnification");
				double magnification = ((Number) getMagnification.invoke(event)).doubleValue();
				if (!Double.isFinite(magnification) || Math.abs(magnification) < 0.001) {
					return;
				}
				double factor = Math.max(0.2, Math.min(5.0, 1.0 + magnification));
				zoomAt(trackpadZoomPoint(), factor);
			}
			catch (ReflectiveOperationException | ClassCastException e) {
				// Ignore malformed gesture events.
			}
		}

		private Point trackpadZoomPoint() {
			Point point = getMousePosition();
			if (point != null) {
				return point;
			}
			return new Point(Math.max(0, getWidth() / 2), Math.max(0, getHeight() / 2));
		}

		private void installKeyBindings() {
			bindKey(KeyStroke.getKeyStroke(KeyEvent.VK_LEFT, 0), "graph-left",
				() -> moveSelection(-1, 0));
			bindKey(KeyStroke.getKeyStroke(KeyEvent.VK_RIGHT, 0), "graph-right",
				() -> moveSelection(1, 0));
			bindKey(KeyStroke.getKeyStroke(KeyEvent.VK_UP, 0), "graph-up",
				() -> moveSelection(0, -1));
			bindKey(KeyStroke.getKeyStroke(KeyEvent.VK_DOWN, 0), "graph-down",
				() -> moveSelection(0, 1));
			bindKey(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, 0), "graph-open",
				ParadiseGraphProvider.this::openPseudocode);
			bindKey(KeyStroke.getKeyStroke(KeyEvent.VK_F, 0), "graph-fit", this::fitToView);
			bindKey(KeyStroke.getKeyStroke(KeyEvent.VK_0, 0), "graph-reset", this::resetZoom);
			bindKey(KeyStroke.getKeyStroke(KeyEvent.VK_C, 0), "graph-collapse",
				this::toggleSelectedBlockCollapse);
			bindKey(KeyStroke.getKeyStroke(KeyEvent.VK_SLASH, 0), "graph-search",
				ParadiseGraphProvider.this::searchGraph);
			bindKey(KeyStroke.getKeyStroke(KeyEvent.VK_N, 0), "graph-next-match",
				this::selectNextSearchMatch);
		}

		private void bindKey(KeyStroke keyStroke, String actionName, Runnable action) {
			getInputMap(WHEN_FOCUSED).put(keyStroke, actionName);
			getActionMap().put(actionName, new AbstractAction() {
				@Override
				public void actionPerformed(ActionEvent e) {
					action.run();
				}
			});
		}

		Address selectedAddress() {
			if (selectedLine != null && selectedLine.address() != null) {
				return selectedLine.address();
			}
			return selectedBlock == null ? null : selectedBlock.start();
		}

		void selectAddress(Address address, boolean center) {
			if (graph == null || address == null || graph.program() == null ||
				!Objects.equals(graph.program().getAddressFactory().getDefaultAddressSpace(),
					address.getAddressSpace())) {
				return;
			}
			ParadiseGraphBlock block = graph.blockAt(address);
			ParadiseGraphLine line = null;
			if (block == null) {
				for (ParadiseGraphBlock graphBlock : graph.blocks()) {
					for (ParadiseGraphLine graphLine : graphBlock.lines()) {
						if (address.equals(graphLine.address())) {
							block = graphBlock;
							line = graphLine;
							break;
						}
					}
					if (block != null) {
						break;
					}
				}
			}
			if (block == null) {
				return;
			}
			if (line == null) {
				for (ParadiseGraphLine graphLine : block.lines()) {
					if (address.equals(graphLine.address())) {
						line = graphLine;
						break;
					}
				}
			}
			selectedBlock = block;
			selectedLine = block.collapsed() ? null : line;
			if (center) {
				centerBlock(block);
			}
			repaint();
		}

		void copySelectedBlock() {
			if (selectedBlock == null) {
				return;
			}
			StringBuilder builder = new StringBuilder();
			for (ParadiseGraphLine line : selectedBlock.lines()) {
				builder.append(line.text()).append(System.lineSeparator());
			}
			Toolkit.getDefaultToolkit().getSystemClipboard()
					.setContents(new StringSelection(builder.toString()), null);
		}

		void exportGraph() {
			if (graph == null) {
				return;
			}
			JFileChooser chooser = new JFileChooser();
			chooser.setDialogTitle("Export Paradise Diagram");
			chooser.setFileFilter(new FileNameExtensionFilter("PNG or SVG", "png", "svg"));
			chooser.setSelectedFile(new File(defaultExportName() + ".png"));
			if (chooser.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) {
				return;
			}
			File file = chooser.getSelectedFile();
			String name = file.getName().toLowerCase(Locale.ROOT);
			try {
				if (name.endsWith(".svg")) {
					exportSvg(file);
				}
				else {
					if (!name.endsWith(".png")) {
						file = new File(file.getParentFile(), file.getName() + ".png");
					}
					exportPng(file);
				}
				statusLabel.setText("Exported " + file.getName());
			}
			catch (IOException e) {
				Msg.showError(this, panel, "Export Diagram", "Could not export diagram.", e);
			}
		}

		private String defaultExportName() {
			String title = graph == null ? "paradise_diagram" : graph.title();
			String safe = title.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9._-]+", "_")
					.replaceAll("_+", "_").replaceAll("^_+|_+$", "");
			return safe.isBlank() ? "paradise_diagram" : safe;
		}

		private void exportPng(File file) throws IOException {
			int pad = 48;
			int width = Math.max(1, graph.layoutSize().width + pad * 2);
			int height = Math.max(1, graph.layoutSize().height + pad * 2);
			BufferedImage image = new BufferedImage(width, height, BufferedImage.TYPE_INT_ARGB);
			Graphics2D g2 = image.createGraphics();
			double oldScale = scale;
			try {
				scale = 1.0;
				g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING,
					RenderingHints.VALUE_ANTIALIAS_ON);
				g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING,
					RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
				g2.setColor(new Color(168, 168, 168));
				g2.fillRect(0, 0, width, height);
				g2.translate(pad, pad);
				drawEdges(g2);
				drawBlocks(g2);
			}
			finally {
				scale = oldScale;
				g2.dispose();
			}
			ImageIO.write(image, "png", file);
		}

		private void exportSvg(File file) throws IOException {
			int pad = 48;
			int width = Math.max(1, graph.layoutSize().width + pad * 2);
			int height = Math.max(1, graph.layoutSize().height + pad * 2);
			try (BufferedWriter writer =
				Files.newBufferedWriter(file.toPath(), StandardCharsets.UTF_8)) {
				writer.write("<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"" + width +
					"\" height=\"" + height + "\" viewBox=\"0 0 " + width + " " + height +
					"\">\n");
				writer.write("<rect width=\"100%\" height=\"100%\" fill=\"#a8a8a8\"/>\n");
				writer.write("<g transform=\"translate(" + pad + " " + pad +
					")\" font-family=\"Menlo,Consolas,monospace\" font-size=\"13\">\n");
				for (ParadiseGraphEdge edge : graph.edges()) {
					writer.write("<polyline points=\"");
					for (Point2D.Double point : edge.points()) {
						writer.write(point.x + "," + point.y + " ");
					}
					writer.write("\" fill=\"none\" stroke=\"" + colorHex(edgeColor(edge.kind())) +
						"\" stroke-width=\"2\"/>\n");
				}
				for (ParadiseGraphBlock block : graph.blocks()) {
					Rectangle2D.Double b = block.bounds();
					writer.write("<rect x=\"" + b.x + "\" y=\"" + b.y + "\" width=\"" +
						b.width + "\" height=\"" + b.height + "\" fill=\"#222\" stroke=\"#000\"/>\n");
					writer.write("<rect x=\"" + (b.x + 1) + "\" y=\"" + (b.y + 1) +
						"\" width=\"" + (b.width - 2) + "\" height=\"" + (TITLE_HEIGHT - 1) +
						"\" fill=\"#e0e0e0\"/>\n");
					double textY = b.y + TITLE_HEIGHT + BLOCK_PAD_Y + 12;
					for (ParadiseGraphLine line : visibleLines(block)) {
						writer.write("<text x=\"" + (b.x + BLOCK_PAD_X) + "\" y=\"" + textY +
							"\" fill=\"#e6e6e6\">" + xmlEscape(line.text()) + "</text>\n");
						textY += 16;
					}
				}
				writer.write("</g>\n</svg>\n");
			}
		}

		private String colorHex(Color color) {
			return String.format("#%02x%02x%02x", color.getRed(), color.getGreen(),
				color.getBlue());
		}

		private String xmlEscape(String text) {
			return text == null ? "" : text.replace("&", "&amp;").replace("<", "&lt;")
					.replace(">", "&gt;").replace("\"", "&quot;");
		}

		private void centerBlock(ParadiseGraphBlock block) {
			if (block == null) {
				return;
			}
			Rectangle2D.Double bounds = block.bounds();
			offsetX = getWidth() / 2.0 - bounds.getCenterX() * scale;
			offsetY = getHeight() / 2.0 - bounds.getCenterY() * scale;
		}

		private void syncZoomSlider() {
			updatingZoomSlider = true;
			try {
				zoomSlider.setValue((int) Math.round(scale * 100.0));
			}
			finally {
				updatingZoomSlider = false;
			}
		}

		private void saveViewState() {
			if (suppressStateSave || graph == null || graphStateKey == null ||
				graphStateKey.isBlank()) {
				return;
			}
			StringBuilder collapsed = new StringBuilder();
			for (ParadiseGraphBlock block : graph.blocks()) {
				if (!block.collapsed()) {
					continue;
				}
				if (!collapsed.isEmpty()) {
					collapsed.append(',');
				}
				collapsed.append(block.start());
			}
			String state = String.format(Locale.ROOT, "%.4f,%.2f,%.2f;%s", scale, offsetX,
				offsetY, collapsed);
			plugin.setDiagramViewState(graphStateKey, state);
		}

		private void restoreViewState(String state) {
			if (graph == null || state == null || state.isBlank()) {
				return;
			}
			String[] parts = state.split(";", 2);
			String[] view = parts[0].split(",");
			if (view.length < 3) {
				return;
			}
			try {
				Set<String> collapsed = new HashSet<>();
				if (parts.length > 1 && !parts[1].isBlank()) {
					for (String address : parts[1].split(",")) {
						collapsed.add(address);
					}
				}
				for (ParadiseGraphBlock block : graph.blocks()) {
					block.setCollapsed(collapsed.contains(block.start().toString()));
				}
				layoutGraph(graph);
				scale = Math.max(0.25, Math.min(2.8, Double.parseDouble(view[0])));
				offsetX = Double.parseDouble(view[1]);
				offsetY = Double.parseDouble(view[2]);
				syncZoomSlider();
			}
			catch (RuntimeException e) {
				// Ignore stale or incompatible persisted view state.
			}
		}

		private void moveSelection(int dx, int dy) {
			if (graph == null || graph.blocks().isEmpty()) {
				return;
			}
			if (selectedBlock == null) {
				selectedBlock = graph.blocks().get(0);
				centerBlock(selectedBlock);
				repaint();
				return;
			}
			ParadiseGraphBlock best = null;
			double bestScore = Double.POSITIVE_INFINITY;
			double cx = selectedBlock.bounds().getCenterX();
			double cy = selectedBlock.bounds().getCenterY();
			for (ParadiseGraphBlock block : graph.blocks()) {
				if (block == selectedBlock) {
					continue;
				}
				double bx = block.bounds().getCenterX();
				double by = block.bounds().getCenterY();
				double vx = bx - cx;
				double vy = by - cy;
				if ((dx < 0 && vx >= -1) || (dx > 0 && vx <= 1) ||
					(dy < 0 && vy >= -1) || (dy > 0 && vy <= 1)) {
					continue;
				}
				double primary = dx == 0 ? Math.abs(vy) : Math.abs(vx);
				double secondary = dx == 0 ? Math.abs(vx) : Math.abs(vy);
				double score = primary * 10.0 + secondary;
				if (score < bestScore) {
					bestScore = score;
					best = block;
				}
			}
			if (best != null) {
				selectedBlock = best;
				selectedLine = null;
				centerBlock(best);
				repaint();
			}
		}

		@Override
		protected void paintComponent(Graphics g) {
			super.paintComponent(g);
			Graphics2D g2 = (Graphics2D) g.create();
			try {
				g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING,
					RenderingHints.VALUE_ANTIALIAS_ON);
				g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING,
					RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
				g2.setColor(new Color(168, 168, 168));
				g2.fillRect(0, 0, getWidth(), getHeight());
				if (graph == null) {
					g2.setColor(new Color(40, 40, 40));
					g2.drawString("Open a function diagram from Paradise > Diagram.", 18, 28);
					return;
				}
				AffineTransform old = g2.getTransform();
				g2.translate(offsetX, offsetY);
				g2.scale(scale, scale);
				drawEdges(g2);
				drawBlocks(g2);
				g2.setTransform(old);
				drawMinimap(g2);
			}
			finally {
				g2.dispose();
			}
		}

		private void drawEdges(Graphics2D g2) {
			for (ParadiseGraphEdge edge : graph.edges()) {
				if (edge != hoveredEdge && !isSelectedPathEdge(edge)) {
					drawEdge(g2, edge, false, false);
				}
			}
			for (ParadiseGraphEdge edge : graph.edges()) {
				if (edge != hoveredEdge && isSelectedPathEdge(edge)) {
					drawEdge(g2, edge, false, true);
				}
			}
			if (hoveredEdge != null) {
				drawEdge(g2, hoveredEdge, true, isSelectedPathEdge(hoveredEdge));
			}
		}

		private void drawEdge(Graphics2D g2, ParadiseGraphEdge edge, boolean hovered,
				boolean selectedPath) {
			List<Point2D.Double> points = edge.points();
			if (points.size() < 2) {
				return;
			}
			Path2D path = edgePath(points);
			Color color = edgeColor(edge.kind());
			if (hovered || selectedPath) {
				g2.setColor(new Color(255, 238, 120, 190));
				g2.setStroke(new BasicStroke(hovered ? 7.0f : 5.0f, BasicStroke.CAP_ROUND,
					BasicStroke.JOIN_ROUND));
				g2.draw(path);
			}
			g2.setColor(color);
			g2.setStroke(new BasicStroke(hovered ? 3.4f : selectedPath ? 2.8f : 2.0f, BasicStroke.CAP_ROUND,
				BasicStroke.JOIN_ROUND));
			g2.draw(path);
			drawArrow(g2, points.get(points.size() - 2), points.get(points.size() - 1), color,
				hovered);
			drawEdgeLabel(g2, edge, points, color);
		}

		private Path2D edgePath(List<Point2D.Double> points) {
			Path2D path = new Path2D.Double();
			Point2D.Double first = points.get(0);
			path.moveTo(first.x, first.y);
			for (int i = 1; i < points.size(); i++) {
				Point2D.Double point = points.get(i);
				path.lineTo(point.x, point.y);
			}
			return path;
		}

		private void drawArrow(Graphics2D g2, Point2D.Double from, Point2D.Double to, Color color,
				boolean hovered) {
			double angle = Math.atan2(to.y - from.y, to.x - from.x);
			Path2D arrow = arrowShape(to, angle, hovered ? 11 : 8);
			if (hovered) {
				g2.setColor(new Color(255, 238, 120, 190));
				g2.fill(arrowShape(to, angle, 14));
			}
			g2.setColor(color);
			g2.fill(arrow);
		}

		private Path2D arrowShape(Point2D.Double to, double angle, int size) {
			Path2D arrow = new Path2D.Double();
			arrow.moveTo(to.x, to.y);
			arrow.lineTo(to.x - size * Math.cos(angle - Math.PI / 6),
				to.y - size * Math.sin(angle - Math.PI / 6));
			arrow.lineTo(to.x - size * Math.cos(angle + Math.PI / 6),
				to.y - size * Math.sin(angle + Math.PI / 6));
			arrow.closePath();
			return arrow;
		}

		private void drawEdgeLabel(Graphics2D g2, ParadiseGraphEdge edge,
				List<Point2D.Double> points, Color color) {
			String label = edgeLabel(edge.kind());
			if (label.isEmpty() || points.size() < 2 || scale < 0.45) {
				return;
			}
			Point2D.Double midpoint = points.get(points.size() / 2);
			Font oldFont = g2.getFont();
			g2.setFont(codeFont.deriveFont(Font.BOLD, 10f));
			FontMetrics metrics = g2.getFontMetrics();
			double width = metrics.stringWidth(label) + 8;
			double height = metrics.getHeight();
			double x = midpoint.x - width / 2.0;
			double y = midpoint.y - height / 2.0;
			g2.setColor(new Color(40, 40, 40, 210));
			g2.fill(new Rectangle2D.Double(x, y, width, height));
			g2.setColor(color);
			g2.drawString(label, (float) (x + 4), (float) (y + metrics.getAscent()));
			g2.setFont(oldFont);
		}

		private String edgeLabel(ParadiseGraphEdgeKind kind) {
			return switch (kind) {
				case TRUE_BRANCH -> "true";
				case FALSE_BRANCH -> "false";
				case BACK_EDGE -> "back";
				case JUMP -> "jmp";
			};
		}

		private boolean isSelectedPathEdge(ParadiseGraphEdge edge) {
			return selectedBlock != null && (edge.source() == selectedBlock ||
				edge.target() == selectedBlock);
		}

		private void drawBlocks(Graphics2D g2) {
			g2.setFont(codeFont);
			FontMetrics metrics = g2.getFontMetrics();
			for (ParadiseGraphBlock block : graph.blocks()) {
				Rectangle2D.Double bounds = block.bounds();
				g2.setColor(new Color(88, 88, 88, 90));
				g2.fill(new Rectangle2D.Double(bounds.x + 4, bounds.y + 4, bounds.width,
					bounds.height));
				g2.setColor(Color.BLACK);
				g2.fill(bounds);
				g2.setColor(new Color(34, 34, 34));
				g2.fill(new Rectangle2D.Double(bounds.x + 1, bounds.y + TITLE_HEIGHT,
					bounds.width - 2, bounds.height - TITLE_HEIGHT - 1));
				g2.setColor(new Color(224, 224, 224));
				g2.fill(new Rectangle2D.Double(bounds.x + 1, bounds.y + 1, bounds.width - 2,
					TITLE_HEIGHT - 1));
				drawTitleIcons(g2, bounds);
				Color border = selectedBlock == block ? new Color(255, 220, 90)
						: blockMatches(block) ? new Color(84, 210, 230) : Color.BLACK;
				g2.setColor(border);
				g2.setStroke(new BasicStroke(selectedBlock == block || blockMatches(block) ? 2.2f : 1.1f));
				g2.draw(bounds);

				double textX = bounds.x + BLOCK_PAD_X;
				double textY = bounds.y + TITLE_HEIGHT + BLOCK_PAD_Y + metrics.getAscent();
				List<ParadiseGraphLine> lines = visibleLines(block);
				for (int i = 0; i < lines.size(); i++) {
					ParadiseGraphLine line = lines.get(i);
					if (line == selectedLine) {
						g2.setColor(new Color(58, 62, 68));
						g2.fill(new Rectangle2D.Double(bounds.x + 1, textY - metrics.getAscent(),
							bounds.width - 2, metrics.getHeight()));
					}
					else if (lineMatches(line)) {
						g2.setColor(new Color(40, 88, 98));
						g2.fill(new Rectangle2D.Double(bounds.x + 1, textY - metrics.getAscent(),
							bounds.width - 2, metrics.getHeight()));
					}
					drawLine(g2, line.text(), textX, textY);
					textY += metrics.getHeight();
				}
			}
		}

		private void drawTitleIcons(Graphics2D g2, Rectangle2D.Double bounds) {
			int x = (int) bounds.x + 5;
			int y = (int) bounds.y + 4;
			Color[] colors = { new Color(200, 40, 52), new Color(235, 210, 76),
				new Color(56, 176, 212) };
			for (Color color : colors) {
				g2.setColor(color);
				g2.fillOval(x, y, 8, 8);
				g2.setColor(Color.BLACK);
				g2.drawOval(x, y, 8, 8);
				x += 13;
			}
		}

		private void drawLine(Graphics2D g2, String text, double x, double y) {
			if (text.isBlank()) {
				return;
			}
			if (text.startsWith(";")) {
				drawSegment(g2, text, x, y, new Color(214, 161, 214));
				return;
			}
			if (text.endsWith(":") || text.endsWith("proc near") || text.endsWith("endp")) {
				drawSegment(g2, text, x, y, new Color(255, 232, 0));
				return;
			}
			int comment = text.indexOf(" ; ");
			String code = comment >= 0 ? text.substring(0, comment) : text;
			String suffix = comment >= 0 ? text.substring(comment) : "";
			double currentX = drawColoredCode(g2, code, x, y);
			if (!suffix.isEmpty()) {
				drawComment(g2, suffix, currentX, y);
			}
		}

		private void drawComment(Graphics2D g2, String text, double x, double y) {
			Matcher matcher = Pattern.compile("( ; )([A-Za-z_][A-Za-z0-9_]*)(?=\\s*(?:\"|;|$))")
					.matcher(text);
			int index = 0;
			double currentX = x;
			while (matcher.find()) {
				if (matcher.start() > index) {
					currentX = drawSegment(g2, text.substring(index, matcher.start()), currentX, y,
						new Color(128, 128, 128));
				}
				currentX = drawSegment(g2, matcher.group(1), currentX, y,
					new Color(128, 128, 128));
				currentX = drawSegment(g2, matcher.group(2), currentX, y,
					new Color(214, 161, 214));
				index = matcher.end();
			}
			if (index < text.length()) {
				drawSegment(g2, text.substring(index), currentX, y, new Color(128, 128, 128));
			}
		}

		private double drawColoredCode(Graphics2D g2, String text, double x, double y) {
			Matcher matcher = Pattern.compile(
				"\"(?:\\\\.|[^\"\\\\])*\"|-?0x[0-9a-fA-F]+|-?[0-9a-fA-F]+h\\b|\\b\\d+\\b|\\b[A-Za-z_][A-Za-z0-9_@$?.]*\\b")
					.matcher(text);
			int index = 0;
			double currentX = x;
			while (matcher.find()) {
				if (matcher.start() > index) {
					currentX = drawSegment(g2, text.substring(index, matcher.start()), currentX, y,
						new Color(230, 230, 230));
				}
				String token = matcher.group();
				currentX = drawSegment(g2, token, currentX, y, tokenColor(token));
				index = matcher.end();
			}
			if (index < text.length()) {
				currentX = drawSegment(g2, text.substring(index), currentX, y,
					new Color(230, 230, 230));
			}
			return currentX;
		}

		private Color tokenColor(String token) {
			if (token.startsWith("\"")) {
				return new Color(150, 150, 150);
			}
			if (token.matches("-?0x[0-9a-fA-F]+|-?[0-9a-fA-F]+h|\\d+")) {
				return new Color(255, 120, 100);
			}
			if (token.matches("(?i)(je|jz)")) {
				return new Color(36, 178, 55);
			}
			if (token.matches("(?i)(jne|jnz)")) {
				return new Color(220, 40, 44);
			}
			if (token.matches("(?i)jmp")) {
				return new Color(50, 96, 220);
			}
			if (graph != null && graph.frameNames().contains(token)) {
				return new Color(255, 138, 0);
			}
			if (token.matches("(?i)(r[a-z0-9]+|e[a-z0-9]+|[abcd][lh]|[re]?[abcd]x|[er]?[sd]i|[er]?[sb]p|[er]?[sc]x|[er]?[sd]x|[cdefgs]s)")) {
				return new Color(117, 222, 224);
			}
			if (token.matches("(var|arg|local|param)_[0-9A-Za-z_]+")) {
				return new Color(255, 138, 0);
			}
			if (token.startsWith("__") || token.startsWith("_") || isKnownImport(token)) {
				return new Color(0, 220, 220);
			}
			if (token.startsWith("FUN_") || token.startsWith("DAT_") ||
				token.startsWith("LAB_") || token.startsWith("loc_") ||
				token.startsWith("locret_") || token.startsWith("a") ||
				token.startsWith("Buffer") || token.startsWith("StackCookie") ||
				token.startsWith("sub_")) {
				return new Color(255, 232, 0);
			}
			return new Color(230, 230, 230);
		}

		private boolean isKnownImport(String token) {
			return token.matches("(puts|printf|scanf|gets|memset|memcpy|strlen|strcmp|strncmp|malloc|free|exit|abort)");
		}

		private double drawSegment(Graphics2D g2, String text, double x, double y, Color color) {
			g2.setColor(color);
			g2.drawString(text, (float) x, (float) y);
			return x + g2.getFontMetrics().stringWidth(text);
		}

		private Color edgeColor(ParadiseGraphEdgeKind kind) {
			return switch (kind) {
				case TRUE_BRANCH -> new Color(36, 178, 55);
				case FALSE_BRANCH -> new Color(220, 40, 44);
				case BACK_EDGE -> new Color(50, 96, 220);
				default -> new Color(50, 96, 220);
			};
		}

		private boolean showPopup(MouseEvent e) {
			if (!e.isPopupTrigger()) {
				return false;
			}
			selectAt(e.getPoint(), 1);
			popup.show(this, e.getX(), e.getY());
			return true;
		}

		private void selectAt(Point point, int clickCount) {
			Point2D.Double graphPoint = screenToGraph(point);
			selectedBlock = null;
			selectedLine = null;
			if (graph != null) {
				for (ParadiseGraphBlock block : graph.blocks()) {
					if (!block.bounds().contains(graphPoint)) {
						continue;
					}
					selectedBlock = block;
					selectedLine = lineAt(block, graphPoint);
					if (selectedLine != null && selectedLine.address() != null) {
						if (plugin.syncListingOnClick()) {
							plugin.navigateTo(selectedLine.address());
						}
						plugin.focusPseudocodeAt(selectedLine.address());
					}
					if (clickCount >= 2) {
						activateLine(selectedLine);
					}
					break;
				}
			}
			repaint();
		}

		private void updateHoveredEdge(Point point) {
			ParadiseGraphEdge edge = edgeAt(screenToGraph(point), Math.max(7.0, 7.0 / scale));
			if (edge == hoveredEdge) {
				return;
			}
			hoveredEdge = edge;
			repaint();
		}

		private void clearHoveredEdge() {
			if (hoveredEdge == null) {
				return;
			}
			hoveredEdge = null;
			repaint();
		}

		private ParadiseGraphEdge edgeAt(Point2D.Double point, double tolerance) {
			if (graph == null) {
				return null;
			}
			ParadiseGraphEdge nearest = null;
			double best = tolerance;
			for (ParadiseGraphEdge edge : graph.edges()) {
				double distance = distanceToEdge(point, edge);
				if (distance <= best) {
					best = distance;
					nearest = edge;
				}
			}
			return nearest;
		}

		private double distanceToEdge(Point2D.Double point, ParadiseGraphEdge edge) {
			List<Point2D.Double> points = edge.points();
			if (points.size() < 2) {
				return Double.POSITIVE_INFINITY;
			}
			double distance = Double.POSITIVE_INFINITY;
			for (int i = 1; i < points.size(); i++) {
				distance = Math.min(distance,
					distanceToSegment(point, points.get(i - 1), points.get(i)));
			}
			return distance;
		}

		private double distanceToSegment(Point2D.Double point, Point2D.Double a,
				Point2D.Double b) {
			double dx = b.x - a.x;
			double dy = b.y - a.y;
			double lengthSquared = dx * dx + dy * dy;
			if (lengthSquared == 0) {
				return point.distance(a);
			}
			double t = ((point.x - a.x) * dx + (point.y - a.y) * dy) / lengthSquared;
			t = Math.max(0.0, Math.min(1.0, t));
			double x = a.x + t * dx;
			double y = a.y + t * dy;
			return point.distance(x, y);
		}

		private List<ParadiseGraphLine> visibleLines(ParadiseGraphBlock block) {
			if (!block.collapsed()) {
				return block.lines();
			}
			return List.of(new ParadiseGraphLine("... " + block.lines().size() + " lines",
				block.start(), null, null));
		}

		private boolean blockMatches(ParadiseGraphBlock block) {
			if (searchQuery.isBlank()) {
				return false;
			}
			for (ParadiseGraphLine line : block.lines()) {
				if (lineMatches(line)) {
					return true;
				}
			}
			return false;
		}

		private boolean lineMatches(ParadiseGraphLine line) {
			return !searchQuery.isBlank() && line != null &&
				line.text().toLowerCase(Locale.ROOT).contains(searchQuery);
		}

		private List<GraphMatch> searchMatches() {
			List<GraphMatch> matches = new ArrayList<>();
			if (graph == null || searchQuery.isBlank()) {
				return matches;
			}
			for (ParadiseGraphBlock block : graph.blocks()) {
				for (ParadiseGraphLine line : block.lines()) {
					if (lineMatches(line)) {
						matches.add(new GraphMatch(block, line));
					}
				}
			}
			return matches;
		}

		private void drawMinimap(Graphics2D g2) {
			if (graph == null || graph.layoutSize().width <= 0 || graph.layoutSize().height <= 0 ||
				getWidth() < 260 || getHeight() < 220) {
				return;
			}
			int width = Math.min(190, Math.max(120, getWidth() / 5));
			int height = Math.min(150, Math.max(90, getHeight() / 5));
			int x = getWidth() - width - 14;
			int y = 14;
			double sx = width / (double) graph.layoutSize().width;
			double sy = height / (double) graph.layoutSize().height;
			double miniScale = Math.min(sx, sy);
			int graphWidth = (int) Math.round(graph.layoutSize().width * miniScale);
			int graphHeight = (int) Math.round(graph.layoutSize().height * miniScale);
			int gx = x + (width - graphWidth) / 2;
			int gy = y + (height - graphHeight) / 2;
			g2.setColor(new Color(36, 36, 36, 190));
			g2.fillRoundRect(x, y, width, height, 6, 6);
			g2.setColor(new Color(210, 210, 210, 190));
			g2.drawRoundRect(x, y, width, height, 6, 6);
			for (ParadiseGraphEdge edge : graph.edges()) {
				g2.setColor(new Color(70, 110, 220, 130));
				for (int i = 1; i < edge.points().size(); i++) {
					Point2D.Double a = edge.points().get(i - 1);
					Point2D.Double b = edge.points().get(i);
					g2.drawLine((int) (gx + a.x * miniScale), (int) (gy + a.y * miniScale),
						(int) (gx + b.x * miniScale), (int) (gy + b.y * miniScale));
				}
			}
			for (ParadiseGraphBlock block : graph.blocks()) {
				Rectangle2D.Double bounds = block.bounds();
				g2.setColor(block == selectedBlock ? new Color(255, 220, 90, 220)
						: new Color(25, 25, 25, 220));
				g2.fill(new Rectangle2D.Double(gx + bounds.x * miniScale,
					gy + bounds.y * miniScale, Math.max(3, bounds.width * miniScale),
					Math.max(3, bounds.height * miniScale)));
			}
			double vx = -offsetX / scale;
			double vy = -offsetY / scale;
			double vw = getWidth() / scale;
			double vh = getHeight() / scale;
			g2.setColor(new Color(255, 255, 255, 170));
			g2.draw(new Rectangle2D.Double(gx + vx * miniScale, gy + vy * miniScale,
				vw * miniScale, vh * miniScale));
		}

		private ParadiseGraphLine lineAt(ParadiseGraphBlock block, Point2D.Double point) {
			FontMetrics metrics = getFontMetrics(codeFont);
			double y = block.bounds().y + TITLE_HEIGHT + BLOCK_PAD_Y;
			int index = (int) ((point.y - y) / metrics.getHeight());
			List<ParadiseGraphLine> lines = visibleLines(block);
			if (index < 0 || index >= lines.size()) {
				return null;
			}
			return lines.get(index);
		}

		@Override
		public String getToolTipText(MouseEvent event) {
			if (graph == null || event == null) {
				return null;
			}
			Point2D.Double graphPoint = screenToGraph(event.getPoint());
			for (ParadiseGraphBlock block : graph.blocks()) {
				if (!block.bounds().contains(graphPoint)) {
					continue;
				}
				ParadiseGraphLine line = lineAt(block, graphPoint);
				if (line == null) {
					return block.start().toString();
				}
				if (line.callTarget() != null) {
					Function function = graph.program().getFunctionManager()
							.getFunctionAt(line.callTarget());
					if (function != null) {
						return "<html><b>" + htmlEscape(function.getName()) + "</b><br><code>" +
							htmlEscape(function.getPrototypeString(false, true)) + "</code></html>";
					}
				}
				return "<html><code>" + htmlEscape(line.text()) + "</code></html>";
			}
			ParadiseGraphEdge edge = edgeAt(graphPoint, Math.max(7.0, 7.0 / scale));
			return edge == null ? null : edgeLabel(edge.kind()) + " edge";
		}

		private Point2D.Double screenToGraph(Point point) {
			return new Point2D.Double((point.x - offsetX) / scale, (point.y - offsetY) / scale);
		}

		private void zoomAt(Point point, double factor) {
			double oldScale = scale;
			scale = Math.max(0.25, Math.min(2.8, scale * factor));
			double actual = scale / oldScale;
			offsetX = point.x - (point.x - offsetX) * actual;
			offsetY = point.y - (point.y - offsetY) * actual;
			syncZoomSlider();
			repaint();
		}

		private String htmlEscape(String text) {
			return text == null ? "" : text.replace("&", "&amp;").replace("<", "&lt;")
					.replace(">", "&gt;").replace("\"", "&quot;");
		}

		private final class GraphMatch {
			private final ParadiseGraphBlock block;
			private final ParadiseGraphLine line;

			private GraphMatch(ParadiseGraphBlock block, ParadiseGraphLine line) {
				this.block = block;
				this.line = line;
			}

			private ParadiseGraphBlock block() {
				return block;
			}

			private ParadiseGraphLine line() {
				return line;
			}
		}

		private void buildPopup() {
			popup.add(item("Open Pseudocode", e -> openPseudocode()));
			popup.add(item("Jump to Disassembly", e -> jumpToDisassembly()));
			popup.add(item("Copy Block Text", e -> copySelectedBlock()));
			popup.add(item("Collapse/Expand Block", e -> toggleSelectedBlockCollapse()));
			popup.add(item("Export Diagram", e -> exportGraph()));
			popup.addSeparator();
			popup.add(item("Fit to View", e -> fitToView()));
			popup.add(item("Reset Zoom", e -> resetZoom()));
		}

		private JMenuItem item(String text, ActionListener listener) {
			JMenuItem item = new JMenuItem(text);
			item.addActionListener(listener);
			return item;
		}

		private void layoutGraph(ParadiseGraph graph) {
			if (graph == null) {
				return;
			}
			FontMetrics metrics = getFontMetrics(codeFont);
			for (ParadiseGraphBlock block : graph.blocks()) {
				int maxChars = 18;
				for (ParadiseGraphLine line : visibleLines(block)) {
					maxChars = Math.max(maxChars, line.text().length());
				}
				double width = Math.max(190, maxChars * metrics.charWidth('m') + BLOCK_PAD_X * 2);
				double height = TITLE_HEIGHT + BLOCK_PAD_Y * 2 +
					visibleLines(block).size() * metrics.getHeight();
				block.setSize(width, height);
			}

			assignLayers(graph);
			Map<Integer, List<ParadiseGraphBlock>> byLayer = layers(graph);
			positionTreeRows(graph, byLayer);
			routeEdges(graph);
		}

		private Map<Integer, List<ParadiseGraphBlock>> layers(ParadiseGraph graph) {
			Map<Integer, List<ParadiseGraphBlock>> byLayer = new TreeMap<>();
			for (ParadiseGraphBlock block : graph.blocks()) {
				byLayer.computeIfAbsent(block.layer(), l -> new ArrayList<>()).add(block);
			}
			return byLayer;
		}

		private void positionTreeRows(ParadiseGraph graph,
				Map<Integer, List<ParadiseGraphBlock>> byLayer) {
			Map<ParadiseGraphBlock, Double> centers = new HashMap<>();
			double y = 24;
			double minX = Double.POSITIVE_INFINITY;
			double maxX = Double.NEGATIVE_INFINITY;

			for (Map.Entry<Integer, List<ParadiseGraphBlock>> entry : byLayer.entrySet()) {
				List<ParadiseGraphBlock> row = entry.getValue();
				Map<ParadiseGraphBlock, Double> desiredCenters =
					desiredCentersForLayer(graph, row, centers, entry.getKey());
				sortTreeRow(row, desiredCenters);
				positionRow(row, desiredCenters, y, centers);
				for (ParadiseGraphBlock block : row) {
					minX = Math.min(minX, block.bounds().x);
					maxX = Math.max(maxX, block.bounds().getMaxX());
				}
				y += rowHeight(row) + LAYER_GAP;
			}

			if (!Double.isFinite(minX)) {
				graph.layoutSize().setSize(1, 1);
				return;
			}
			double shift = minX < 24 ? 24 - minX : 0;
			if (shift > 0) {
				for (ParadiseGraphBlock block : graph.blocks()) {
					block.bounds().x += shift;
				}
				maxX += shift;
			}
			graph.layoutSize().setSize((int) Math.ceil(maxX + 64), (int) Math.ceil(y + 24));
		}

		private Map<ParadiseGraphBlock, Double> desiredCentersForLayer(ParadiseGraph graph,
				List<ParadiseGraphBlock> row, Map<ParadiseGraphBlock, Double> centers,
				int layer) {
			Map<ParadiseGraphBlock, List<Double>> desired = new HashMap<>();
			Set<ParadiseGraphBlock> rowSet = new HashSet<>(row);
			List<ParadiseGraphBlock> parents = new ArrayList<>(centers.keySet());
			parents.sort(Comparator.comparingDouble(centers::get));
			for (ParadiseGraphBlock parent : parents) {
				List<ParadiseGraphEdge> children = outgoingChildrenOnLayer(graph, parent, rowSet, layer);
				if (children.isEmpty()) {
					continue;
				}
				double groupWidth = groupWidth(children);
				double x = centers.get(parent) - groupWidth / 2.0;
				for (ParadiseGraphEdge edge : children) {
					ParadiseGraphBlock child = edge.target();
					double childCenter = x + child.bounds().width / 2.0;
					desired.computeIfAbsent(child, b -> new ArrayList<>()).add(childCenter);
					x += child.bounds().width + COLUMN_GAP;
				}
			}

			Map<ParadiseGraphBlock, Double> averaged = new HashMap<>();
			for (Map.Entry<ParadiseGraphBlock, List<Double>> entry : desired.entrySet()) {
				double sum = 0;
				for (double value : entry.getValue()) {
					sum += value;
				}
				averaged.put(entry.getKey(), sum / entry.getValue().size());
			}
			return averaged;
		}

		private List<ParadiseGraphEdge> outgoingChildrenOnLayer(ParadiseGraph graph,
				ParadiseGraphBlock parent, Set<ParadiseGraphBlock> rowSet, int layer) {
			List<ParadiseGraphEdge> children = new ArrayList<>();
			for (ParadiseGraphEdge edge : graph.outgoing(parent)) {
				if (rowSet.contains(edge.target()) && edge.target().layer() == layer) {
					children.add(edge);
				}
			}
			children.sort(Comparator
					.comparingInt((ParadiseGraphEdge edge) -> edgeOrder(edge.kind()))
					.thenComparing(edge -> edge.target().start()));
			return children;
		}

		private double groupWidth(List<ParadiseGraphEdge> children) {
			double width = -COLUMN_GAP;
			for (ParadiseGraphEdge edge : children) {
				width += edge.target().bounds().width + COLUMN_GAP;
			}
			return Math.max(0, width);
		}

		private int edgeOrder(ParadiseGraphEdgeKind kind) {
			return switch (kind) {
				case FALSE_BRANCH -> 0;
				case TRUE_BRANCH -> 1;
				default -> 2;
			};
		}

		private void sortTreeRow(List<ParadiseGraphBlock> row,
				Map<ParadiseGraphBlock, Double> desiredCenters) {
			row.sort(Comparator
					.comparingDouble((ParadiseGraphBlock block) ->
						desiredCenters.getOrDefault(block, Double.POSITIVE_INFINITY))
					.thenComparingInt(block -> branchOrderForBlock(block, desiredCenters))
					.thenComparing(ParadiseGraphBlock::start));
		}

		private int branchOrderForBlock(ParadiseGraphBlock block,
				Map<ParadiseGraphBlock, Double> desiredCenters) {
			return desiredCenters.containsKey(block) ? 0 : 1;
		}

		private void positionRow(List<ParadiseGraphBlock> row,
				Map<ParadiseGraphBlock, Double> desiredCenters, double y,
				Map<ParadiseGraphBlock, Double> centers) {
			double cursor = 0;
			for (ParadiseGraphBlock block : row) {
				double desiredCenter = desiredCenters.getOrDefault(block,
					cursor + block.bounds().width / 2.0);
				double x = desiredCenter - block.bounds().width / 2.0;
				if (x < cursor) {
					x = cursor;
				}
				block.bounds().x = x;
				block.bounds().y = y;
				centers.put(block, block.bounds().getCenterX());
				cursor = block.bounds().getMaxX() + COLUMN_GAP;
			}
		}

		private double rowHeight(List<ParadiseGraphBlock> row) {
			double height = 0;
			for (ParadiseGraphBlock block : row) {
				height = Math.max(height, block.bounds().height);
			}
			return height;
		}

		private void assignLayers(ParadiseGraph graph) {
			for (ParadiseGraphBlock block : graph.blocks()) {
				block.setLayer(-1);
			}
			ParadiseGraphBlock entry = graph.blockAt(graph.entryPoint());
			if (entry == null && !graph.blocks().isEmpty()) {
				entry = graph.blocks().get(0);
			}
			Queue<ParadiseGraphBlock> queue = new ArrayDeque<>();
			if (entry != null) {
				entry.setLayer(0);
				queue.add(entry);
			}
			while (!queue.isEmpty()) {
				ParadiseGraphBlock block = queue.remove();
				for (ParadiseGraphEdge edge : graph.outgoing(block)) {
					if (isLoopLatchEdge(graph, edge) && edge.target().layer() >= 0) {
						continue;
					}
					ParadiseGraphBlock target = edge.target();
					if (target.layer() >= 0) {
						continue;
					}
					target.setLayer(block.layer() + 1);
					queue.add(target);
				}
			}
			int layer = 0;
			for (ParadiseGraphBlock block : graph.blocks()) {
				if (block.layer() < 0) {
					block.setLayer(++layer);
				}
				layer = Math.max(layer, block.layer());
			}
			normalizeLoopHeaderLayers(graph);
		}

		private boolean isLoopLatchEdge(ParadiseGraph graph, ParadiseGraphEdge edge) {
			for (ParadiseGraphEdge reverse : graph.outgoing(edge.target())) {
				FlowType flowType = reverse.flowType();
				if (reverse.target() == edge.source() && flowType != null &&
					flowType.isConditional()) {
					return true;
				}
			}
			return false;
		}

		private void normalizeLoopHeaderLayers(ParadiseGraph graph) {
			for (ParadiseGraphEdge edge : graph.edges()) {
				if (!isConditionalBlock(graph, edge.source()) ||
					!canReach(graph, edge.target(), edge.source())) {
					continue;
				}
				ParadiseGraphBlock header = edge.source();
				ParadiseGraphBlock body = edge.target();
				int headerLayer = loopHeaderLayer(graph, header, body);
				header.setLayer(headerLayer);
				body.setLayer(headerLayer + 1);
				for (ParadiseGraphEdge sibling : graph.outgoing(header)) {
					if (sibling.target() == body || isLoopLatchEdge(graph, sibling)) {
						continue;
					}
					sibling.target().setLayer(headerLayer + 1);
				}
			}
		}

		private int loopHeaderLayer(ParadiseGraph graph, ParadiseGraphBlock header,
				ParadiseGraphBlock body) {
			int layer = 0;
			for (ParadiseGraphEdge incoming : graph.edges()) {
				if (incoming.target() != header || incoming.source() == body) {
					continue;
				}
				if (canReach(graph, body, incoming.source())) {
					continue;
				}
				layer = Math.max(layer, incoming.source().layer() + 1);
			}
			return Math.max(0, layer);
		}

		private boolean canReach(ParadiseGraph graph, ParadiseGraphBlock start,
				ParadiseGraphBlock goal) {
			if (start == goal) {
				return true;
			}
			Set<ParadiseGraphBlock> seen = new HashSet<>();
			Queue<ParadiseGraphBlock> queue = new ArrayDeque<>();
			queue.add(start);
			seen.add(start);
			while (!queue.isEmpty()) {
				ParadiseGraphBlock block = queue.remove();
				for (ParadiseGraphEdge edge : graph.outgoing(block)) {
					if (edge.target() == goal) {
						return true;
					}
					if (seen.add(edge.target())) {
						queue.add(edge.target());
					}
				}
			}
			return false;
		}

		private boolean isConditionalBlock(ParadiseGraph graph, ParadiseGraphBlock block) {
			ParadiseGraphLine last = block.lastInstruction();
			if (last == null || last.address() == null) {
				return false;
			}
			CodeUnit codeUnit = graph.program().getListing()
					.getCodeUnitAt(last.address());
			if (codeUnit instanceof Instruction instruction) {
				FlowType flowType = instruction.getFlowType();
				if (flowType != null && flowType.isConditional()) {
					return true;
				}
				String mnemonic = instruction.getMnemonicString();
				return mnemonic != null && mnemonic.toLowerCase(Locale.ROOT).startsWith("j") &&
					!mnemonic.equalsIgnoreCase("jmp");
			}
			return false;
		}

		private void routeEdges(ParadiseGraph graph) {
			Map<ParadiseGraphBlock, Integer> outgoingIndex = new HashMap<>();
			Map<ParadiseGraphBlock, Integer> incomingIndex = new HashMap<>();
			for (ParadiseGraphEdge edge : graph.edges()) {
				edge.points().clear();
				Rectangle2D.Double source = edge.source().bounds();
				Rectangle2D.Double target = edge.target().bounds();
				double sourceLane = sourceLane(edge, outgoingIndex);
				double targetLane = targetLane(edge, incomingIndex);
				if (edge.source().layer() >= edge.target().layer()) {
					double x = Math.max(source.getMaxX(), target.getMaxX()) + 28 +
						Math.abs(sourceLane - targetLane);
					double sy = source.getCenterY() + sourceLane;
					double ty = target.getCenterY() + targetLane;
					edge.points().add(new Point2D.Double(source.getMaxX(), sy));
					edge.points().add(new Point2D.Double(x, sy));
					edge.points().add(new Point2D.Double(x, ty));
					edge.points().add(new Point2D.Double(target.getMaxX(), ty));
					continue;
				}
				double sx = source.getCenterX() + sourceLane;
				double sy = source.getMaxY();
				double tx = target.getCenterX() + targetLane;
				double ty = target.getMinY();
				double midY = sy + Math.max(24, (ty - sy) / 2);
				edge.points().add(new Point2D.Double(sx, sy));
				edge.points().add(new Point2D.Double(sx, midY));
				edge.points().add(new Point2D.Double(tx, midY));
				edge.points().add(new Point2D.Double(tx, ty));
			}
		}

		private double sourceLane(ParadiseGraphEdge edge,
				Map<ParadiseGraphBlock, Integer> outgoingIndex) {
			int total = graph == null ? 1 : graph.outgoing(edge.source()).size();
			int index = outgoingIndex.merge(edge.source(), 1, Integer::sum) - 1;
			if (edge.kind() == ParadiseGraphEdgeKind.FALSE_BRANCH) {
				return -EDGE_LANE_GAP;
			}
			if (edge.kind() == ParadiseGraphEdgeKind.TRUE_BRANCH) {
				return EDGE_LANE_GAP;
			}
			return laneOffset(index, total);
		}

		private double targetLane(ParadiseGraphEdge edge,
				Map<ParadiseGraphBlock, Integer> incomingIndex) {
			int total = graph == null ? 1 : graph.incoming(edge.target()).size();
			int index = incomingIndex.merge(edge.target(), 1, Integer::sum) - 1;
			if (edge.kind() == ParadiseGraphEdgeKind.FALSE_BRANCH) {
				return -EDGE_LANE_GAP;
			}
			if (edge.kind() == ParadiseGraphEdgeKind.TRUE_BRANCH) {
				return EDGE_LANE_GAP;
			}
			return laneOffset(index, total);
		}

		private double laneOffset(int index, int total) {
			if (total <= 1) {
				return 0.0;
			}
			return (index - (total - 1) / 2.0) * EDGE_LANE_GAP;
		}
	}

	private enum GraphGlyph {
		FIT,
		ACTUAL_SIZE,
		ZOOM_IN,
		ZOOM_OUT,
		SEARCH,
		NEXT,
		COLLAPSE,
		PSEUDOCODE,
		DISASM,
		COPY,
		EXPORT
	}

	private static final class GraphToolbarIcon implements Icon {
		private static final int SIZE = 16;
		private final GraphGlyph glyph;

		private GraphToolbarIcon(GraphGlyph glyph) {
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
		public void paintIcon(java.awt.Component component, Graphics graphics, int x, int y) {
			Graphics2D g = (Graphics2D) graphics.create();
			try {
				g.translate(x, y);
				g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
				g.setStroke(new BasicStroke(1.5f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
				Color fg = component == null || component.getForeground() == null ?
					new Color(42, 58, 74) : component.getForeground();
				if (component != null && !component.isEnabled()) {
					fg = new Color(145, 145, 145);
				}
				Color blue = component == null || component.isEnabled() ? new Color(42, 121, 190)
						: new Color(150, 165, 178);
				Color green = component == null || component.isEnabled() ? new Color(38, 145, 89)
						: new Color(145, 165, 150);
				Color orange = component == null || component.isEnabled() ? new Color(190, 123, 36)
						: new Color(170, 156, 136);
				switch (glyph) {
					case FIT -> paintFit(g, fg, blue);
					case ACTUAL_SIZE -> paintActualSize(g, fg);
					case ZOOM_IN -> paintZoom(g, fg, blue, true);
					case ZOOM_OUT -> paintZoom(g, fg, blue, false);
					case SEARCH -> paintSearch(g, fg, blue);
					case NEXT -> paintNext(g, fg, blue);
					case COLLAPSE -> paintCollapse(g, fg, orange);
					case PSEUDOCODE -> paintDocument(g, fg, blue);
					case DISASM -> paintDisasm(g, fg, orange);
					case COPY -> paintCopy(g, fg, blue);
					case EXPORT -> paintExport(g, fg, green);
				}
			}
			finally {
				g.dispose();
			}
		}

		private void paintFit(Graphics2D g, Color fg, Color blue) {
			g.setColor(blue);
			g.drawRect(3, 3, 10, 10);
			g.setColor(fg);
			g.drawLine(1, 5, 5, 5);
			g.drawLine(5, 1, 5, 5);
			g.drawLine(11, 1, 11, 5);
			g.drawLine(11, 5, 15, 5);
			g.drawLine(1, 11, 5, 11);
			g.drawLine(5, 11, 5, 15);
			g.drawLine(11, 11, 15, 11);
			g.drawLine(11, 11, 11, 15);
		}

		private void paintActualSize(Graphics2D g, Color fg) {
			g.setColor(fg);
			g.drawString("1", 4, 12);
			g.drawLine(9, 4, 13, 4);
			g.drawLine(13, 4, 13, 12);
			g.drawLine(13, 12, 9, 12);
		}

		private void paintZoom(Graphics2D g, Color fg, Color blue, boolean plus) {
			paintSearch(g, fg, blue);
			g.setColor(fg);
			g.drawLine(5, 6, 9, 6);
			if (plus) {
				g.drawLine(7, 4, 7, 8);
			}
		}

		private void paintSearch(Graphics2D g, Color fg, Color blue) {
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

		private void paintCollapse(Graphics2D g, Color fg, Color orange) {
			g.setColor(orange);
			g.drawRect(3, 4, 10, 8);
			g.setColor(fg);
			g.drawLine(5, 8, 11, 8);
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

		private void paintDisasm(Graphics2D g, Color fg, Color orange) {
			g.setColor(orange);
			g.drawString("A", 3, 12);
			g.setColor(fg);
			g.drawLine(10, 4, 14, 4);
			g.drawLine(10, 8, 14, 8);
			g.drawLine(10, 12, 14, 12);
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
	}
}

final class ParadiseGraphBuilder {
	private ParadiseGraphBuilder() {
	}

	static ParadiseGraph build(Program program, TaskMonitor monitor) throws CancelledException {
		Map<Function, ParadiseGraphBlock> byFunction = new LinkedHashMap<>();
		Map<Address, ParadiseGraphBlock> byStart = new LinkedHashMap<>();
		int id = 0;
		for (Function function : program.getFunctionManager().getFunctions(true)) {
			monitor.checkCancelled();
			if (function.isExternal()) {
				continue;
			}
			ParadiseGraphBlock block =
				new ParadiseGraphBlock(id++, function.getEntryPoint(), functionNodeLines(function));
			byFunction.put(function, block);
			byStart.put(function.getEntryPoint(), block);
		}
		List<ParadiseGraphBlock> blocks = new ArrayList<>(byFunction.values());
		List<ParadiseGraphEdge> edges = callGraphEdges(program, byFunction, monitor);
		Address entryPoint = graphEntryPoint(program, blocks);
		return new ParadiseGraph(program, null, program.getName() + " call graph", entryPoint,
			blocks, edges, byStart, new Dimension(1, 1), Set.of());
	}

	static ParadiseGraph build(Function function, TaskMonitor monitor) throws CancelledException {
		Program program = function.getProgram();
		BasicBlockModel blockModel = new BasicBlockModel(program);
		CodeBlockIterator iterator = blockModel.getCodeBlocksContaining(function.getBody(), monitor);
		Map<CodeBlock, ParadiseGraphBlock> byCodeBlock = new LinkedHashMap<>();
		Map<Address, ParadiseGraphBlock> byStart = new HashMap<>();
		FrameDisplay frameDisplay = frameDisplay(function);
		int id = 0;
		while (iterator.hasNext()) {
			monitor.checkCancelled();
			CodeBlock codeBlock = iterator.next();
			Address start = codeBlock.getFirstStartAddress();
			ParadiseGraphBlock existing = byStart.get(start);
			if (existing != null) {
				byCodeBlock.put(codeBlock, existing);
				continue;
			}
			ParadiseGraphBlock block = new ParadiseGraphBlock(id++, codeBlock.getFirstStartAddress(),
				linesFor(function, codeBlock, frameDisplay));
			byCodeBlock.put(codeBlock, block);
			byStart.put(block.start(), block);
		}
		List<ParadiseGraphBlock> blocks = new ArrayList<>(new LinkedHashSet<>(byCodeBlock.values()));
		blocks.sort(Comparator.comparing(ParadiseGraphBlock::start));
		Map<Address, ParadiseGraphBlock> sortedByStart = new LinkedHashMap<>();
		for (ParadiseGraphBlock block : blocks) {
			sortedByStart.put(block.start(), block);
		}
		List<ParadiseGraphEdge> edges = edgesFor(byCodeBlock, sortedByStart, monitor);
		appendExitFooters(function, blocks, edges);
		return new ParadiseGraph(function.getProgram(), function,
			function.getName() + " @ " + function.getEntryPoint(), function.getEntryPoint(),
			blocks, edges, sortedByStart, new Dimension(1, 1), frameDisplay.names());
	}

	private static List<ParadiseGraphLine> functionNodeLines(Function function) {
		List<ParadiseGraphLine> lines = new ArrayList<>();
		lines.add(new ParadiseGraphLine(function.getName() + " proc near",
			function.getEntryPoint(), function.getEntryPoint(), null));
		lines.add(new ParadiseGraphLine("; entry " + function.getEntryPoint(),
			function.getEntryPoint(), null, null));
		return lines;
	}

	private static List<ParadiseGraphEdge> callGraphEdges(Program program,
			Map<Function, ParadiseGraphBlock> byFunction, TaskMonitor monitor)
			throws CancelledException {
		List<ParadiseGraphEdge> edges = new ArrayList<>();
		Set<String> seen = new HashSet<>();
		for (Map.Entry<Function, ParadiseGraphBlock> entry : byFunction.entrySet()) {
			monitor.checkCancelled();
			Function caller = entry.getKey();
			InstructionIterator instructions =
				program.getListing().getInstructions(caller.getBody(), true);
			while (instructions.hasNext()) {
				monitor.checkCancelled();
				Instruction instruction = instructions.next();
				if (!instruction.getFlowType().isCall()) {
					continue;
				}
				for (Function callee : calleesFor(program, caller, instruction)) {
					ParadiseGraphBlock target = byFunction.get(callee);
					if (target == null) {
						continue;
					}
					String key = caller.getEntryPoint() + "->" + callee.getEntryPoint();
					if (seen.add(key)) {
						edges.add(new ParadiseGraphEdge(entry.getValue(), target,
							instruction.getFlowType(), ParadiseGraphEdgeKind.JUMP));
					}
				}
			}
		}
		return edges;
	}

	private static Set<Function> calleesFor(Program program, Function caller,
			Instruction instruction) {
		Set<Function> callees = new LinkedHashSet<>();
		for (Reference reference : instruction.getReferencesFrom()) {
			if (reference.getReferenceType().isCall()) {
				addCallee(program, caller, reference.getToAddress(), callees);
			}
		}
		for (Address flow : instruction.getFlows()) {
			addCallee(program, caller, flow, callees);
		}
		return callees;
	}

	private static void addCallee(Program program, Function caller, Address address,
			Set<Function> callees) {
		if (address == null) {
			return;
		}
		Function callee = program.getFunctionManager().getFunctionAt(address);
		if (callee == null) {
			callee = program.getFunctionManager().getFunctionContaining(address);
		}
		if (callee == null || callee.isExternal() || callee.equals(caller)) {
			return;
		}
		callees.add(callee);
	}

	private static Address graphEntryPoint(Program program, List<ParadiseGraphBlock> blocks) {
		Function entry = program.getFunctionManager().getFunctionAt(program.getImageBase());
		if (entry != null) {
			return entry.getEntryPoint();
		}
		for (ParadiseGraphBlock block : blocks) {
			if ("entry".equalsIgnoreCase(symbolNameFor(program, block.start())) ||
				"main".equalsIgnoreCase(symbolNameFor(program, block.start()))) {
				return block.start();
			}
		}
		return blocks.isEmpty() ? program.getImageBase() : blocks.get(0).start();
	}

	private static void appendExitFooters(Function function, List<ParadiseGraphBlock> blocks,
			List<ParadiseGraphEdge> edges) {
		Set<ParadiseGraphBlock> sources = new HashSet<>();
		for (ParadiseGraphEdge edge : edges) {
			sources.add(edge.source());
		}
		for (ParadiseGraphBlock block : blocks) {
			if (sources.contains(block)) {
				continue;
			}
			if (!isReturnBlock(function, block)) {
				continue;
			}
			block.lines().add(new ParadiseGraphLine("", null, null, null));
			block.lines().add(new ParadiseGraphLine(function.getName() + " endp", null, null, null));
		}
	}

	private static boolean isReturnBlock(Function function, ParadiseGraphBlock block) {
		ParadiseGraphLine last = block.lastInstruction();
		if (last == null || last.address() == null) {
			return false;
		}
		CodeUnit codeUnit = function.getProgram().getListing().getCodeUnitAt(last.address());
		if (codeUnit instanceof Instruction instruction) {
			return instruction.getMnemonicString().equalsIgnoreCase("ret");
		}
		return false;
	}

	private static List<ParadiseGraphEdge> edgesFor(Map<CodeBlock, ParadiseGraphBlock> byCodeBlock,
			Map<Address, ParadiseGraphBlock> byStart, TaskMonitor monitor)
			throws CancelledException {
		List<ParadiseGraphEdge> edges = new ArrayList<>();
		Set<String> seenEdges = new HashSet<>();
		for (Map.Entry<CodeBlock, ParadiseGraphBlock> entry : byCodeBlock.entrySet()) {
			CodeBlockReferenceIterator destinations = entry.getKey().getDestinations(monitor);
			Set<ParadiseGraphBlock> seen = new HashSet<>();
			while (destinations.hasNext()) {
				monitor.checkCancelled();
				CodeBlockReference reference = destinations.next();
				CodeBlock destinationBlock = reference.getDestinationBlock();
				if (destinationBlock == null) {
					continue;
				}
				ParadiseGraphBlock target =
					byStart.get(destinationBlock.getFirstStartAddress());
				if (target == null || !seen.add(target)) {
					continue;
				}
				String key = entry.getValue().id() + ":" + target.id();
				if (!seenEdges.add(key)) {
					continue;
				}
				edges.add(new ParadiseGraphEdge(entry.getValue(), target, reference.getFlowType(),
					edgeKind(reference, entry.getValue())));
			}
		}
		return edges;
	}

	private static ParadiseGraphEdgeKind edgeKind(CodeBlockReference reference,
			ParadiseGraphBlock source) {
		FlowType flowType = reference.getFlowType();
		ParadiseGraphLine lastInstruction = source.lastInstruction();
		String mnemonic = branchMnemonic(lastInstruction);
		if ((flowType != null && flowType.isConditional()) || isConditionalJump(mnemonic)) {
			boolean fallthroughEdge = lastInstruction != null &&
				Objects.equals(reference.getDestinationAddress(), lastInstruction.fallthrough());
			return fallthroughEdge ? ParadiseGraphEdgeKind.FALSE_BRANCH
					: ParadiseGraphEdgeKind.TRUE_BRANCH;
		}
		return ParadiseGraphEdgeKind.JUMP;
	}

	private static String branchMnemonic(ParadiseGraphLine line) {
		if (line == null || line.text() == null) {
			return "";
		}
		String text = line.text().stripLeading();
		int end = 0;
		while (end < text.length() && !Character.isWhitespace(text.charAt(end))) {
			end++;
		}
		return text.substring(0, end).toLowerCase(Locale.ROOT);
	}

	private static boolean isConditionalJump(String mnemonic) {
		return mnemonic.startsWith("j") && !mnemonic.equals("jmp");
	}

	private static FrameDisplay frameDisplay(Function function) {
		int framePointerBias = framePointerBias(function);
		Map<Integer, String> rawStackNames = new HashMap<>();
		Map<Integer, String> displayStackNames = new HashMap<>();
		List<FrameDeclaration> declarations = new ArrayList<>();
		for (Variable variable : function.getLocalVariables()) {
			if (variable == null || !variable.hasStackStorage()) {
				continue;
			}
			String name = variable.getName();
			if (name == null || name.isBlank()) {
				continue;
			}
			int offset;
			try {
				offset = variable.getStackOffset();
			}
			catch (RuntimeException e) {
				continue;
			}
			int displayOffset = offset + framePointerBias;
			rawStackNames.putIfAbsent(offset, name);
			displayStackNames.putIfAbsent(displayOffset, name);
			declarations.add(new FrameDeclaration(name, pointerType(variable.getLength()),
				displayOffset));
		}
		declarations.sort(Comparator.comparingInt(FrameDeclaration::offset));
		List<String> lines = new ArrayList<>();
		for (FrameDeclaration declaration : declarations) {
			lines.add(String.format("%s= %s %s", declaration.name(), declaration.pointerType(),
				stackOffsetText(declaration.offset())));
		}
		return new FrameDisplay(Map.copyOf(rawStackNames), Map.copyOf(displayStackNames),
			List.copyOf(lines));
	}

	private static int framePointerBias(Function function) {
		if (!hasRbpFramePointer(function)) {
			return 0;
		}
		return Math.max(0, function.getProgram().getDefaultPointerSize());
	}

	private static boolean hasRbpFramePointer(Function function) {
		Listing listing = function.getProgram().getListing();
		InstructionIterator instructions = listing.getInstructions(function.getBody(), true);
		int checked = 0;
		boolean sawPushRbp = false;
		while (instructions.hasNext() && checked++ < 8) {
			Instruction instruction = instructions.next();
			String text = instruction.toString().toLowerCase(Locale.ROOT);
			if (text.matches("push\\s+rbp\\b.*")) {
				sawPushRbp = true;
				continue;
			}
			if (sawPushRbp && text.matches("mov\\s+rbp\\s*,\\s*rsp\\b.*")) {
				return true;
			}
		}
		return false;
	}

	private static String pointerType(int length) {
		return switch (length) {
			case 1 -> "byte ptr";
			case 2 -> "word ptr";
			case 4 -> "dword ptr";
			case 8 -> "qword ptr";
			case 16 -> "xmmword ptr";
			default -> length <= 0 ? "ptr" : length + " byte ptr";
		};
	}

	private static String stackOffsetText(int offset) {
		if (offset == 0) {
			return "0";
		}
		String sign = offset < 0 ? "-" : "";
		int value = Math.abs(offset);
		if (value < 10) {
			return sign + value;
		}
		return sign + Integer.toHexString(value).toUpperCase(Locale.ROOT) + "h";
	}

	private static List<ParadiseGraphLine> linesFor(Function function, CodeBlock block,
			FrameDisplay frameDisplay) {
		List<ParadiseGraphLine> lines = new ArrayList<>();
		if (block.getFirstStartAddress().equals(function.getEntryPoint())) {
			lines.add(new ParadiseGraphLine("; " + function.getPrototypeString(false, true), null,
				null, null));
			lines.add(new ParadiseGraphLine(function.getName() + " proc near", function.getEntryPoint(),
				null, null));
			lines.add(new ParadiseGraphLine("", null, null, null));
			for (String declaration : frameDisplay.declarations()) {
				lines.add(new ParadiseGraphLine(declaration, null, null, null));
			}
			if (!frameDisplay.declarations().isEmpty()) {
				lines.add(new ParadiseGraphLine("", null, null, null));
			}
		}
		else {
			String label = labelFor(function, block);
			lines.add(new ParadiseGraphLine(label + ":", block.getFirstStartAddress(), null, null));
		}

		Listing listing = function.getProgram().getListing();
		InstructionIterator instructions =
			listing.getInstructions((AddressSetView) block, true);
		List<Instruction> blockInstructions = new ArrayList<>();
		while (instructions.hasNext()) {
			Instruction instruction = instructions.next();
			if (!function.getBody().contains(instruction.getAddress())) {
				continue;
			}
			blockInstructions.add(instruction);
		}
		Map<Address, String> argumentComments =
			callArgumentComments(function.getProgram(), blockInstructions);
		for (Instruction instruction : blockInstructions) {
			lines.add(lineFor(function.getProgram(), instruction, frameDisplay,
				argumentComments.get(instruction.getAddress())));
		}
		return lines;
	}

	private static ParadiseGraphLine lineFor(Program program, Instruction instruction,
			FrameDisplay frameDisplay, String argumentComment) {
		StringBuilder builder = new StringBuilder();
		String mnemonic = instruction.getMnemonicString().toLowerCase(Locale.ROOT);
		builder.append(String.format("%-7s", mnemonic));
		List<String> operands = operandsFor(program, instruction, frameDisplay);
		builder.append(String.join(", ", operands));
		List<String> comments = new ArrayList<>();
		String comment = listingComment(instruction);
		if (comment != null && !comment.isBlank()) {
			addLineComment(comments, comment);
		}
		String stringComment = stringComment(program, instruction);
		if (argumentComment != null && !argumentComment.isBlank() && stringComment != null) {
			addLineComment(comments, argumentCommentWithString(argumentComment, stringComment));
		}
		else {
			addLineComment(comments, argumentComment);
			addLineComment(comments, stringComment);
		}
		if (!comments.isEmpty()) {
			builder.append(" ; ").append(String.join(" ; ", comments));
		}
		Address callTarget = null;
		if (instruction.getFlowType().isCall()) {
			Address[] flows = instruction.getFlows();
			if (flows.length > 0 && program.getFunctionManager().getFunctionAt(flows[0]) != null) {
				callTarget = flows[0];
			}
		}
		return new ParadiseGraphLine(builder.toString(), instruction.getAddress(), callTarget,
			instruction.getFallThrough());
	}

	private static String argumentCommentWithString(String argumentComment, String stringComment) {
		List<String> parts = new ArrayList<>(List.of(argumentComment.split("\\s+;\\s+")));
		if (parts.isEmpty()) {
			return argumentComment + " " + stringComment;
		}
		int last = parts.size() - 1;
		parts.set(last, parts.get(last) + " " + stringComment);
		return String.join(" ; ", parts);
	}

	private static void addLineComment(List<String> comments, String comment) {
		if (comment == null || comment.isBlank() || hasEquivalentComment(comments, comment)) {
			return;
		}
		comments.add(comment);
	}

	private static Map<Address, String> callArgumentComments(Program program,
			List<Instruction> instructions) {
		Map<Address, String> comments = new HashMap<>();
		for (int i = 0; i < instructions.size(); i++) {
			Instruction call = instructions.get(i);
			if (!call.getFlowType().isCall()) {
				continue;
			}
			Function callee = callTargetFunction(program, call);
			List<String> parameterNames = parameterNames(callee);
			List<String> argumentRegisters = argumentRegistersFor(program, callee);
			if (parameterNames.isEmpty() || argumentRegisters.isEmpty()) {
				continue;
			}
			Map<String, String> pending = new LinkedHashMap<>();
			int count = Math.min(parameterNames.size(), argumentRegisters.size());
			for (int index = 0; index < count; index++) {
				String name = parameterNames.get(index);
				if (name != null && !name.isBlank()) {
					pending.put(argumentRegisters.get(index), name);
				}
			}
			annotateCallSetup(instructions, i, pending, comments);
		}
		return comments;
	}

	private static void annotateCallSetup(List<Instruction> instructions, int callIndex,
			Map<String, String> pending, Map<Address, String> comments) {
		if (pending.isEmpty()) {
			return;
		}
		int inspected = 0;
		for (int i = callIndex - 1; i >= 0 && inspected++ < 16 && !pending.isEmpty(); i--) {
			Instruction instruction = instructions.get(i);
			FlowType flowType = instruction.getFlowType();
			if (flowType != null && (flowType.isCall() || flowType.isJump())) {
				break;
			}
			String destination = destinationRegister(instruction);
			if (destination == null) {
				continue;
			}
			String comment = pending.remove(destination);
			if (comment != null) {
				addInstructionComment(comments, instruction.getAddress(), comment);
			}
		}
	}

	private static void addInstructionComment(Map<Address, String> comments, Address address,
			String comment) {
		if (address == null || comment == null || comment.isBlank()) {
			return;
		}
		String existing = comments.get(address);
		if (existing == null || existing.isBlank()) {
			comments.put(address, comment);
			return;
		}
		List<String> parts = new ArrayList<>(List.of(existing.split("\\s+;\\s+")));
		addLineComment(parts, comment);
		comments.put(address, String.join(" ; ", parts));
	}

	private static Function callTargetFunction(Program program, Instruction instruction) {
		for (Reference reference : instruction.getReferencesFrom()) {
			if (!reference.getReferenceType().isCall()) {
				continue;
			}
			Function function = functionAtOrContaining(program, reference.getToAddress());
			if (function != null) {
				return resolvedThunk(function);
			}
		}
		for (Address flow : instruction.getFlows()) {
			Function function = functionAtOrContaining(program, flow);
			if (function != null) {
				return resolvedThunk(function);
			}
		}
		return null;
	}

	private static Function functionAtOrContaining(Program program, Address address) {
		if (program == null || address == null) {
			return null;
		}
		Function function = program.getFunctionManager().getFunctionAt(address);
		return function != null ? function : program.getFunctionManager().getFunctionContaining(address);
	}

	private static Function resolvedThunk(Function function) {
		if (function == null || !function.isThunk()) {
			return function;
		}
		Function thunked = function.getThunkedFunction(true);
		return thunked == null ? function : thunked;
	}

	private static List<String> parameterNames(Function function) {
		if (function == null) {
			return List.of();
		}
		List<String> names = new ArrayList<>();
		try {
			for (Parameter parameter : function.getParameters()) {
				if (parameter == null || parameter.isAutoParameter()) {
					continue;
				}
				names.add(displayParameterName(parameter.getName()));
			}
		}
		catch (RuntimeException e) {
			return List.of();
		}
		return names;
	}

	private static String displayParameterName(String name) {
		if (name == null) {
			return null;
		}
		String display = name.strip().replaceFirst("^_+", "");
		display = display.replaceAll("[^A-Za-z0-9_]+", "_").replaceAll("_+", "_")
				.replaceAll("^_+|_+$", "");
		if (display.isBlank()) {
			return null;
		}
		String lower = display.toLowerCase(Locale.ROOT);
		if (lower.matches("(param|arg)_?\\d+") || lower.matches("a\\d+")) {
			return null;
		}
		return display;
	}

	private static List<String> argumentRegistersFor(Program program, Function callee) {
		if (program == null || program.getDefaultPointerSize() != 8) {
			return List.of();
		}
		return usesWindowsX64CallingConvention(program, callee)
				? List.of("rcx", "rdx", "r8", "r9")
				: List.of("rdi", "rsi", "rdx", "rcx", "r8", "r9");
	}

	private static boolean usesWindowsX64CallingConvention(Program program, Function callee) {
		String callingConvention = callee == null ? "" :
			Objects.toString(callee.getCallingConventionName(), "");
		String executableFormat = Objects.toString(program.getExecutableFormat(), "");
		String combined = (callingConvention + " " + executableFormat).toLowerCase(Locale.ROOT);
		return combined.contains("fastcall") || combined.contains("windows") ||
			combined.contains("portable executable") || combined.matches(".*\\bpe\\b.*");
	}

	private static String destinationRegister(Instruction instruction) {
		if (instruction == null || instruction.getNumOperands() <= 0) {
			return null;
		}
		Register register = instruction.getRegister(0);
		if (register != null) {
			return canonicalRegister(register.getName());
		}
		for (Object object : instruction.getOpObjects(0)) {
			if (object instanceof Register operandRegister) {
				return canonicalRegister(operandRegister.getName());
			}
		}
		return null;
	}

	private static String canonicalRegister(String registerName) {
		if (registerName == null) {
			return null;
		}
		String name = registerName.toLowerCase(Locale.ROOT);
		return switch (name) {
			case "edi", "di", "dil" -> "rdi";
			case "esi", "si", "sil" -> "rsi";
			case "edx", "dx", "dl", "dh" -> "rdx";
			case "ecx", "cx", "cl", "ch" -> "rcx";
			case "r8d", "r8w", "r8b" -> "r8";
			case "r9d", "r9w", "r9b" -> "r9";
			case "eax", "ax", "al", "ah" -> "rax";
			case "ebx", "bx", "bl", "bh" -> "rbx";
			case "esp", "sp", "spl" -> "rsp";
			case "ebp", "bp", "bpl" -> "rbp";
			default -> name;
		};
	}

	private static String listingComment(Instruction instruction) {
		List<String> comments = new ArrayList<>();
		CommentType[] order = {
			CommentType.EOL,
			CommentType.REPEATABLE,
			CommentType.PLATE,
			CommentType.PRE,
			CommentType.POST
		};
		for (CommentType type : order) {
			String comment = normalizeComment(instruction.getComment(type));
			if (comment == null || hasEquivalentComment(comments, comment)) {
				continue;
			}
			comments.add(comment);
		}
		return comments.isEmpty() ? null : String.join(" | ", comments);
	}

	private static String normalizeComment(String comment) {
		if (comment == null) {
			return null;
		}
		String normalized = comment.strip().replace('\r', '\n')
				.replaceAll("\\s*\\n\\s*", " ")
				.replaceAll("\\s+", " ");
		if (normalized.isBlank()) {
			return null;
		}
		return previewComment(normalized, 120);
	}

	private static boolean hasEquivalentComment(List<String> comments, String comment) {
		for (String existing : comments) {
			if (existing.equals(comment) || existing.contains(comment) || comment.contains(existing)) {
				return true;
			}
		}
		return false;
	}

	private static String previewComment(String value, int maxLength) {
		if (value.length() <= maxLength) {
			return value;
		}
		return value.substring(0, Math.max(0, maxLength - 3)).stripTrailing() + "...";
	}

	private static List<String> operandsFor(Program program, Instruction instruction,
			FrameDisplay frameDisplay) {
		Address[] flows = instruction.getFlows();
		FlowType flowType = instruction.getFlowType();
		if (flows.length > 0 && flowType.isCall()) {
			return List.of(symbolNameFor(program, flows[0]));
		}
		if (flows.length > 0 && flowType.isJump()) {
			return List.of("short " + labelForAddress(program, flows[0], false));
		}

		List<String> operands = new ArrayList<>();
		for (int i = 0; i < instruction.getNumOperands(); i++) {
			operands.add(normalizeOperand(instruction.getDefaultOperandRepresentation(i),
				frameDisplay));
		}
		return operands;
	}

	private static String normalizeOperand(String operand, FrameDisplay frameDisplay) {
		if (operand == null) {
			return "";
		}
		String normalized = operand.toLowerCase(Locale.ROOT)
				.replace(" + -", "-")
				.replace(" + ", "+")
				.replace(" - ", "-");
		normalized = normalized.replaceAll("\\b([a-z][a-z0-9]*)=>[^,\\s\\]]+", "$1");
		normalized = applyStackNames(normalized, frameDisplay);
		return simplifyHexConstants(normalized);
	}

	private static String applyStackNames(String operand, FrameDisplay frameDisplay) {
		Matcher matcher = Pattern.compile("\\[(r[bs]p)([+-])0x([0-9a-f]+)\\]")
				.matcher(operand);
		StringBuffer buffer = new StringBuffer();
		while (matcher.find()) {
			int value;
			try {
				value = Integer.parseUnsignedInt(matcher.group(3), 16);
			}
			catch (NumberFormatException e) {
				continue;
			}
			int offset = matcher.group(2).equals("-") ? -value : value;
			String name = frameDisplay.nameForOffset(matcher.group(1), offset);
			if (name == null) {
				continue;
			}
			matcher.appendReplacement(buffer,
				Matcher.quoteReplacement("[" + matcher.group(1) + "+" + name + "]"));
		}
		matcher.appendTail(buffer);
		return buffer.toString();
	}

	private static String simplifyHexConstants(String operand) {
		Matcher matcher = Pattern.compile("(?<![A-Za-z0-9_])0x([0-9a-f]+)(?![A-Za-z0-9_])")
				.matcher(operand);
		StringBuffer buffer = new StringBuffer();
		while (matcher.find()) {
			long value;
			try {
				value = Long.parseUnsignedLong(matcher.group(1), 16);
			}
			catch (NumberFormatException e) {
				continue;
			}
			if (looksLikeAddress(value)) {
				continue;
			}
			matcher.appendReplacement(buffer, Long.toUnsignedString(value));
		}
		matcher.appendTail(buffer);
		return buffer.toString();
	}

	private static boolean looksLikeAddress(long value) {
		return Long.compareUnsigned(value, 0x1000L) >= 0;
	}

	private static String stringComment(Program program, Instruction instruction) {
		for (Reference reference : instruction.getReferencesFrom()) {
			if (reference.getReferenceType().isCall()) {
				continue;
			}
			ParadiseStringUtil.ParadiseString string =
				ParadiseStringUtil.stringAt(program, reference.getToAddress());
			if (string != null) {
				return "\"" + escapeStringPreview(string.value(), 120) + "\"";
			}
		}
		return null;
	}

	private static String escapeStringPreview(String value, int maxLength) {
		StringBuilder builder = new StringBuilder();
		if (value == null) {
			return "";
		}
		for (int i = 0; i < value.length() && builder.length() < maxLength; i++) {
			char c = value.charAt(i);
			switch (c) {
				case '\n' -> builder.append("\\n");
				case '\r' -> builder.append("\\r");
				case '\t' -> builder.append("\\t");
				case '"' -> builder.append("\\\"");
				case '\\' -> builder.append("\\\\");
				default -> builder.append(c);
			}
		}
		if (builder.length() >= maxLength && value.length() > maxLength) {
			builder.append("...");
		}
		return builder.toString();
	}

	private static String labelFor(Function function, CodeBlock block) {
		return labelForAddress(function.getProgram(), block.getFirstStartAddress(),
			blockEndsWithRet(function, block));
	}

	private static String labelForAddress(Program program, Address address, boolean returnLabel) {
		CodeUnit codeUnit = program.getListing().getCodeUnitAt(address);
		Symbol symbol = codeUnit == null ? null : codeUnit.getPrimarySymbol();
		if (symbol != null && symbol.getName() != null && !symbol.getName().isBlank() &&
			!isDefaultBlockLabel(symbol.getName())) {
			return symbol.getName();
		}
		return (returnLabel ? "locret_" : "loc_") + addressSuffix(program, address);
	}

	private static boolean isDefaultBlockLabel(String name) {
		return name.startsWith("LAB_") || name.startsWith("loc_") || name.startsWith("locret_");
	}

	private static String symbolNameFor(Program program, Address address) {
		Function function = program.getFunctionManager().getFunctionAt(address);
		if (function != null && function.getName() != null && !function.getName().isBlank()) {
			return function.getName();
		}
		Symbol symbol = program.getSymbolTable().getPrimarySymbol(address);
		if (symbol != null && symbol.getName() != null && !symbol.getName().isBlank()) {
			return symbol.getName();
		}
		return "0x" + addressSuffix(program, address);
	}

	private static String addressSuffix(Program program, Address address) {
		String text = address.toString();
		if (text.startsWith("00")) {
			try {
				Address imageBase = program.getImageBase();
				if (imageBase != null &&
					Objects.equals(imageBase.getAddressSpace(), address.getAddressSpace()) &&
					address.compareTo(imageBase) >= 0) {
					long relative = address.subtract(imageBase);
					if (relative >= 0) {
						return Long.toHexString(relative).toUpperCase(Locale.ROOT);
					}
				}
			}
			catch (RuntimeException e) {
				// Fall back to the address text below.
			}
		}
		String stripped = text.replaceFirst("^0+", "");
		return (stripped.isEmpty() ? "0" : stripped).toUpperCase(Locale.ROOT);
	}

	private static boolean blockEndsWithRet(Function function, CodeBlock block) {
		Listing listing = function.getProgram().getListing();
		InstructionIterator instructions = listing.getInstructions((AddressSetView) block, true);
		Instruction last = null;
		while (instructions.hasNext()) {
			Instruction instruction = instructions.next();
			if (function.getBody().contains(instruction.getAddress())) {
				last = instruction;
			}
		}
		return last != null && last.getMnemonicString().equalsIgnoreCase("ret");
	}
}

record FrameDisplay(Map<Integer, String> rawStackNames, Map<Integer, String> displayStackNames,
		List<String> declarations) {
	String nameForOffset(String baseRegister, int offset) {
		if ("rbp".equals(baseRegister)) {
			return displayStackNames.get(offset);
		}
		return rawStackNames.get(offset);
	}

	Set<String> names() {
		return Set.copyOf(displayStackNames.values());
	}
}

record FrameDeclaration(String name, String pointerType, int offset) {
}

final class ParadiseGraph {
	private final Program program;
	private final Function function;
	private final String title;
	private final Address entryPoint;
	private final List<ParadiseGraphBlock> blocks;
	private final List<ParadiseGraphEdge> edges;
	private final Map<Address, ParadiseGraphBlock> blocksByStart;
	private final Dimension layoutSize;
	private final Set<String> frameNames;
	private final Map<ParadiseGraphBlock, List<ParadiseGraphEdge>> outgoing = new HashMap<>();
	private final Map<ParadiseGraphBlock, List<ParadiseGraphEdge>> incoming = new HashMap<>();

	ParadiseGraph(Program program, Function function, String title, Address entryPoint,
			List<ParadiseGraphBlock> blocks, List<ParadiseGraphEdge> edges,
			Map<Address, ParadiseGraphBlock> blocksByStart, Dimension layoutSize,
			Set<String> frameNames) {
		this.program = program;
		this.function = function;
		this.title = title;
		this.entryPoint = entryPoint;
		this.blocks = blocks;
		this.edges = edges;
		this.blocksByStart = blocksByStart;
		this.layoutSize = layoutSize;
		this.frameNames = frameNames;
		for (ParadiseGraphEdge edge : edges) {
			outgoing.computeIfAbsent(edge.source(), b -> new ArrayList<>()).add(edge);
			incoming.computeIfAbsent(edge.target(), b -> new ArrayList<>()).add(edge);
		}
	}

	Program program() {
		return program;
	}

	Function function() {
		return function;
	}

	String title() {
		return title;
	}

	Address entryPoint() {
		return entryPoint;
	}

	List<ParadiseGraphBlock> blocks() {
		return blocks;
	}

	List<ParadiseGraphEdge> edges() {
		return edges;
	}

	Dimension layoutSize() {
		return layoutSize;
	}

	Set<String> frameNames() {
		return frameNames;
	}

	ParadiseGraphBlock blockAt(Address address) {
		return blocksByStart.get(address);
	}

	Collection<ParadiseGraphEdge> outgoing(ParadiseGraphBlock block) {
		return outgoing.getOrDefault(block, List.of());
	}

	Collection<ParadiseGraphEdge> incoming(ParadiseGraphBlock block) {
		return incoming.getOrDefault(block, List.of());
	}
}

final class ParadiseGraphBlock {
	private final int id;
	private final Address start;
	private final List<ParadiseGraphLine> lines;
	private final Rectangle2D.Double bounds = new Rectangle2D.Double();
	private int layer = -1;
	private boolean collapsed;

	ParadiseGraphBlock(int id, Address start, List<ParadiseGraphLine> lines) {
		this.id = id;
		this.start = start;
		this.lines = lines;
	}

	int id() {
		return id;
	}

	Address start() {
		return start;
	}

	List<ParadiseGraphLine> lines() {
		return lines;
	}

	Rectangle2D.Double bounds() {
		return bounds;
	}

	int layer() {
		return layer;
	}

	void setLayer(int layer) {
		this.layer = layer;
	}

	boolean collapsed() {
		return collapsed;
	}

	void setCollapsed(boolean collapsed) {
		this.collapsed = collapsed;
	}

	void setSize(double width, double height) {
		bounds.width = width;
		bounds.height = height;
	}

	ParadiseGraphLine lastInstruction() {
		for (int i = lines.size() - 1; i >= 0; i--) {
			ParadiseGraphLine line = lines.get(i);
			if (line.address() != null) {
				return line;
			}
		}
		return null;
	}
}

final class ParadiseGraphEdge {
	private final ParadiseGraphBlock source;
	private final ParadiseGraphBlock target;
	private final FlowType flowType;
	private ParadiseGraphEdgeKind kind;
	private final List<Point2D.Double> points = new ArrayList<>();

	ParadiseGraphEdge(ParadiseGraphBlock source, ParadiseGraphBlock target, FlowType flowType,
			ParadiseGraphEdgeKind kind) {
		this.source = source;
		this.target = target;
		this.flowType = flowType;
		this.kind = kind;
	}

	ParadiseGraphBlock source() {
		return source;
	}

	ParadiseGraphBlock target() {
		return target;
	}

	FlowType flowType() {
		return flowType;
	}

	ParadiseGraphEdgeKind kind() {
		return kind;
	}

	List<Point2D.Double> points() {
		return points;
	}
}

record ParadiseGraphLine(String text, Address address, Address callTarget, Address fallthrough) {
}

enum ParadiseGraphEdgeKind {
	TRUE_BRANCH,
	FALSE_BRANCH,
	JUMP,
	BACK_EDGE
}
