package paradise;

import java.awt.Color;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.util.function.BooleanSupplier;

import javax.swing.JSplitPane;
import javax.swing.plaf.basic.BasicSplitPaneDivider;
import javax.swing.plaf.basic.BasicSplitPaneUI;

final class ParadiseDottedSplitPaneUi extends BasicSplitPaneUI {
	private final BooleanSupplier darkTheme;

	ParadiseDottedSplitPaneUi(BooleanSupplier darkTheme) {
		this.darkTheme = darkTheme;
	}

	@Override
	public BasicSplitPaneDivider createDefaultDivider() {
		return new BasicSplitPaneDivider(this) {
			@Override
			public void paint(Graphics g) {
				Graphics2D g2 = (Graphics2D) g.create();
				try {
					boolean dark = darkTheme != null && darkTheme.getAsBoolean();
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
					if (ParadiseDottedSplitPaneUi.this.splitPane != null &&
						ParadiseDottedSplitPaneUi.this.splitPane.getOrientation() ==
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
