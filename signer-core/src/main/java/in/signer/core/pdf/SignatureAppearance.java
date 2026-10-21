package in.signer.core.pdf;

import in.signer.core.SignerException;
import in.signer.core.util.Bytes;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.PDResources;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.common.PDStream;
import org.apache.pdfbox.pdmodel.font.PDFont;
import org.apache.pdfbox.pdmodel.font.PDType0Font;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.font.Standard14Fonts;
import org.apache.pdfbox.pdmodel.graphics.form.PDFormXObject;
import org.apache.pdfbox.pdmodel.graphics.image.PDImageXObject;
import org.apache.pdfbox.pdmodel.graphics.state.PDExtendedGraphicsState;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationWidget;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAppearanceDictionary;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAppearanceStream;
import org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm;
import org.apache.pdfbox.pdmodel.interactive.form.PDSignatureField;

import java.awt.Color;
import java.awt.geom.AffineTransform;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Renders the visible signature box as a one-page "visual signature template" PDF that PDFBox merges
 * into the document being signed.
 */
final class SignatureAppearance {

    private static final Color TEXT = new Color(0x1A, 0x1A, 0x1A);
    private static final Color TICK = new Color(0x1E, 0x9E, 0x3A);
    private static final Color BORDER = new Color(0x60, 0x60, 0x60);
    private static final float PAD = 3f;

    private SignatureAppearance() {
    }

    /** Converts the caller's rectangle (displayed page space) into the page's unrotated user space. */
    static PDRectangle placement(PDPage page, PdfSignOptions o) {
        PDRectangle crop = page.getCropBox();
        int rotation = Math.floorMod(page.getRotation(), 360);
        boolean swapped = rotation == 90 || rotation == 270;
        float dispW = swapped ? crop.getHeight() : crop.getWidth();
        float dispH = swapped ? crop.getWidth() : crop.getHeight();
        if (o.width <= 0 || o.height <= 0) {
            throw SignerException.badRequest("Signature width and height must be positive");
        }
        float dx = o.x;
        float dy = "top-left".equalsIgnoreCase(o.origin) ? dispH - o.y - o.height : o.y;
        if (dx < 0 || dy < 0 || dx + o.width > dispW + 0.5f || dy + o.height > dispH + 0.5f) {
            throw SignerException.badRequest(String.format(
                    "Signature box (%.0f,%.0f %.0fx%.0f) lies outside the page (%.0fx%.0f)",
                    o.x, o.y, o.width, o.height, dispW, dispH));
        }
        float[][] corners = {{dx, dy}, {dx + o.width, dy + o.height}};
        float minX = Float.MAX_VALUE, minY = Float.MAX_VALUE, maxX = -Float.MAX_VALUE, maxY = -Float.MAX_VALUE;
        float w = crop.getWidth(), h = crop.getHeight();
        for (float[] c : corners) {
            float ux, uy;
            switch (rotation) {
                case 90 -> { ux = w - c[1]; uy = c[0]; }
                case 180 -> { ux = w - c[0]; uy = h - c[1]; }
                case 270 -> { ux = c[1]; uy = h - c[0]; }
                default -> { ux = c[0]; uy = c[1]; }
            }
            minX = Math.min(minX, ux); maxX = Math.max(maxX, ux);
            minY = Math.min(minY, uy); maxY = Math.max(maxY, uy);
        }
        return new PDRectangle(crop.getLowerLeftX() + minX, crop.getLowerLeftY() + minY, maxX - minX, maxY - minY);
    }

    static byte[] template(PDPage srcPage, PDRectangle rect, PdfSignOptions o, List<String> lines) throws IOException {
        int rotation = Math.floorMod(srcPage.getRotation(), 360);
        boolean swapped = rotation == 90 || rotation == 270;
        float boxW = swapped ? rect.getHeight() : rect.getWidth();
        float boxH = swapped ? rect.getWidth() : rect.getHeight();

        try (PDDocument doc = new PDDocument()) {
            PDPage page = new PDPage(srcPage.getMediaBox());
            page.setCropBox(srcPage.getCropBox());
            page.setRotation(srcPage.getRotation());
            doc.addPage(page);

            PDAcroForm acroForm = new PDAcroForm(doc);
            doc.getDocumentCatalog().setAcroForm(acroForm);
            PDSignatureField field = new PDSignatureField(acroForm);
            PDAnnotationWidget widget = field.getWidgets().get(0);
            acroForm.setSignaturesExist(true);
            acroForm.setAppendOnly(true);
            acroForm.getCOSObject().setDirect(true);
            acroForm.getFields().add(field);
            widget.setRectangle(rect);
            widget.setPrinted(true);

            PDStream stream = new PDStream(doc);
            PDFormXObject form = new PDFormXObject(stream);
            form.setResources(new PDResources());
            form.setFormType(1);
            form.setBBox(new PDRectangle(boxW, boxH));
            if (rotation != 0) {
                form.setMatrix(AffineTransform.getQuadrantRotateInstance(rotation / 90));
            }
            PDAppearanceDictionary appearance = new PDAppearanceDictionary();
            appearance.getCOSObject().setDirect(true);
            PDAppearanceStream appearanceStream = new PDAppearanceStream(form.getCOSObject());
            appearance.setNormalAppearance(appearanceStream);
            widget.setAppearance(appearance);

            try (PDPageContentStream cs = new PDPageContentStream(doc, appearanceStream)) {
                draw(doc, cs, boxW, boxH, o, lines);
            }
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            doc.save(out);
            return out.toByteArray();
        }
    }

    private static void draw(PDDocument doc, PDPageContentStream cs, float w, float h,
                             PdfSignOptions o, List<String> lines) throws IOException {
        float textLeft = PAD;
        if (o.imageBase64 != null && !o.imageBase64.isBlank()) {
            PDImageXObject img = PDImageXObject.createFromByteArray(doc, Bytes.fromB64(o.imageBase64, "imageBase64"), "signature-image");
            float maxW = w * 0.35f, maxH = h - 2 * PAD;
            float scale = Math.min(maxW / img.getWidth(), maxH / img.getHeight());
            float iw = img.getWidth() * scale, ih = img.getHeight() * scale;
            cs.drawImage(img, PAD, (h - ih) / 2, iw, ih);
            textLeft = PAD * 2 + iw;
        }
        float textW = w - textLeft - PAD;

        if (o.greenTick) {
            drawTick(cs, textLeft, w, h);
        }
        if (o.border) {
            cs.setStrokingColor(BORDER);
            cs.setLineWidth(0.6f);
            cs.addRect(0.3f, 0.3f, w - 0.6f, h - 0.6f);
            cs.stroke();
        }

        PDFont font = loadFont(doc, o.fontPath);
        float size = o.fontSize != null && o.fontSize > 0 ? o.fontSize : 10f;
        List<String> wrapped = wrap(font, lines, size, textW);
        if (o.fontSize == null) {
            while (size > 4f && (wrapped.size() * size * 1.18f > h - 2 * PAD || tooWide(font, wrapped, size, textW))) {
                size -= 0.25f;
                wrapped = wrap(font, lines, size, textW);
            }
        }
        float leading = size * 1.18f;
        float blockH = wrapped.size() * leading;
        float startY = h - PAD - (h - 2 * PAD - blockH) / 2 - size;

        cs.beginText();
        cs.setFont(font, size);
        cs.setNonStrokingColor(TEXT);
        cs.newLineAtOffset(textLeft, startY);
        for (int i = 0; i < wrapped.size(); i++) {
            if (i > 0) {
                cs.newLineAtOffset(0, -leading);
            }
            cs.showText(wrapped.get(i));
        }
        cs.endText();
    }

    /** Draws a large, semi-transparent green check mark behind the text. */
    private static void drawTick(PDPageContentStream cs, float left, float w, float h) throws IOException {
        cs.saveGraphicsState();
        PDExtendedGraphicsState gs = new PDExtendedGraphicsState();
        gs.setNonStrokingAlphaConstant(0.35f);
        gs.setStrokingAlphaConstant(0.35f);
        cs.setGraphicsStateParameters(gs);
        float size = Math.min(h * 0.9f, (w - left) * 0.6f);
        float ox = left + (w - left - size) / 2;
        float oy = (h - size) / 2;
        cs.setNonStrokingColor(TICK);
        cs.moveTo(ox + 0.05f * size, oy + 0.55f * size);
        cs.lineTo(ox + 0.20f * size, oy + 0.70f * size);
        cs.lineTo(ox + 0.40f * size, oy + 0.48f * size);
        cs.lineTo(ox + 0.82f * size, oy + 0.95f * size);
        cs.lineTo(ox + 0.97f * size, oy + 0.80f * size);
        cs.lineTo(ox + 0.40f * size, oy + 0.15f * size);
        cs.closePath();
        cs.fill();
        cs.restoreGraphicsState();
    }

    private static PDFont loadFont(PDDocument doc, String fontPath) throws IOException {
        if (fontPath != null && !fontPath.isBlank()) {
            File f = new File(fontPath);
            if (f.isFile()) {
                return PDType0Font.load(doc, f);
            }
        }
        return new PDType1Font(Standard14Fonts.FontName.HELVETICA);
    }

    private static boolean tooWide(PDFont font, List<String> lines, float size, float maxW) throws IOException {
        for (String l : lines) {
            if (width(font, l, size) > maxW) {
                return true;
            }
        }
        return false;
    }

    static List<String> wrap(PDFont font, List<String> lines, float size, float maxW) throws IOException {
        List<String> out = new ArrayList<>();
        for (String raw : lines) {
            String line = encodable(font, raw);
            if (width(font, line, size) <= maxW) {
                out.add(line);
                continue;
            }
            StringBuilder cur = new StringBuilder();
            for (String word : line.split(" ")) {
                String candidate = cur.isEmpty() ? word : cur + " " + word;
                if (width(font, candidate, size) <= maxW || cur.isEmpty()) {
                    cur.setLength(0);
                    cur.append(candidate);
                } else {
                    out.add(cur.toString());
                    cur.setLength(0);
                    cur.append(word);
                }
            }
            if (!cur.isEmpty()) {
                out.add(cur.toString());
            }
        }
        return out;
    }

    private static float width(PDFont font, String s, float size) throws IOException {
        return font.getStringWidth(s) / 1000f * size;
    }

    /** Replaces characters the font cannot encode (e.g. Indic script in Helvetica) with '?'. */
    static String encodable(PDFont font, String s) {
        StringBuilder sb = new StringBuilder();
        s.codePoints().forEach(cp -> {
            String ch = new String(Character.toChars(cp));
            try {
                font.encode(ch);
                sb.append(ch);
            } catch (IOException | IllegalArgumentException e) {
                sb.append('?');
            }
        });
        return sb.toString();
    }
}
