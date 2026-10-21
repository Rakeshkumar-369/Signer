package in.signer.agent.ui;

import java.awt.BasicStroke;
import java.awt.Color;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.image.BufferedImage;

/** Programmatically drawn application icon (pen nib + check mark), so no binary assets are needed. */
final class Icons {

    static final Color BRAND = new Color(0x0B, 0x4F, 0x8A);
    static final Color OK = new Color(0x1E, 0x9E, 0x3A);

    private Icons() {
    }

    static BufferedImage app(int size) {
        BufferedImage img = new BufferedImage(size, size, BufferedImage.TYPE_INT_ARGB);
        Graphics2D g = img.createGraphics();
        g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g.setColor(BRAND);
        g.fillRoundRect(0, 0, size, size, size / 4, size / 4);
        g.setColor(Color.WHITE);
        g.setStroke(new BasicStroke(Math.max(2f, size / 9f), BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
        g.drawPolyline(new int[]{size * 22 / 100, size * 42 / 100, size * 78 / 100},
                new int[]{size * 52 / 100, size * 72 / 100, size * 30 / 100}, 3);
        g.dispose();
        return img;
    }
}
