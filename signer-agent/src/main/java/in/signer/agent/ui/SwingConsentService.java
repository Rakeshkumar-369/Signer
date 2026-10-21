package in.signer.agent.ui;

import in.signer.core.ErrorCode;
import in.signer.core.SignerException;
import in.signer.core.cert.CertificateInfo;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.DefaultListCellRenderer;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.KeyStroke;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import javax.swing.UIManager;
import javax.swing.WindowConstants;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.KeyEvent;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicReference;

/** Modal, always-on-top confirmation window with certificate selection and PIN entry. */
public final class SwingConsentService implements ConsentService {

    private static final DateTimeFormatter DATE = DateTimeFormatter.ofPattern("dd-MMM-yyyy", Locale.ENGLISH).withZone(ZoneId.systemDefault());

    private final int timeoutSeconds;

    public SwingConsentService(int timeoutSeconds) {
        this.timeoutSeconds = timeoutSeconds;
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception ignored) {
            // default look and feel
        }
    }

    @Override
    public ConsentDecision ask(ConsentRequest request) {
        AtomicReference<ConsentDecision> result = new AtomicReference<>();
        try {
            SwingUtilities.invokeAndWait(() -> result.set(show(request)));
        } catch (Exception e) {
            throw new SignerException(ErrorCode.INTERNAL_ERROR, "Could not display the confirmation window: " + e.getMessage(), e);
        }
        if (result.get() == null) {
            throw new SignerException(ErrorCode.USER_CANCELLED, "Signing was cancelled by the user");
        }
        return result.get();
    }

    private ConsentDecision show(ConsentRequest r) {
        JDialog dialog = new JDialog((java.awt.Frame) null, "Signer - Confirm digital signature", true);
        dialog.setAlwaysOnTop(true);
        dialog.setIconImage(Icons.app(64));
        dialog.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);

        JPanel root = new JPanel(new BorderLayout(0, 12));
        root.setBorder(BorderFactory.createEmptyBorder(16, 18, 14, 18));

        JLabel title = new JLabel(r.action());
        title.setFont(title.getFont().deriveFont(Font.BOLD, 16f));
        title.setForeground(Icons.BRAND);
        root.add(title, BorderLayout.NORTH);

        JPanel form = new JPanel(new GridBagLayout());
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(3, 0, 3, 10);
        c.anchor = GridBagConstraints.WEST;
        int row = 0;
        row = addRow(form, c, row, "Website", new JLabel(r.origin()));
        if (r.organisation() != null) {
            row = addRow(form, c, row, "Organisation", new JLabel(r.organisation()));
        }
        if (r.reference() != null) {
            row = addRow(form, c, row, "Reference", new JLabel(r.reference()));
        }
        if (r.documents() != null && !r.documents().isEmpty()) {
            String docs = r.documents().size() == 1 ? r.documents().get(0)
                    : r.documents().size() + " documents: " + String.join(", ", r.documents().subList(0, Math.min(3, r.documents().size())))
                    + (r.documents().size() > 3 ? ", ..." : "");
            row = addRow(form, c, row, "Document", new JLabel(docs));
        }

        JComboBox<CertificateInfo> certBox = new JComboBox<>(r.certificates().toArray(new CertificateInfo[0]));
        certBox.setRenderer(new DefaultListCellRenderer() {
            @Override
            public Component getListCellRendererComponent(JList<?> list, Object value, int index, boolean sel, boolean focus) {
                CertificateInfo ci = (CertificateInfo) value;
                String text = ci == null ? "" : ci.commonName() + "  -  " + (ci.issuerCommonName() == null ? "" : ci.issuerCommonName())
                        + "  (valid till " + DATE.format(ci.notAfter()) + ")";
                return super.getListCellRendererComponent(list, text, index, sel, focus);
            }
        });
        if (r.preselectedId() != null) {
            for (CertificateInfo ci : r.certificates()) {
                if (ci.id().equals(r.preselectedId())) {
                    certBox.setSelectedItem(ci);
                }
            }
        }
        certBox.setEnabled(r.certificates().size() > 1);
        row = addRow(form, c, row, "Certificate", certBox);

        JPasswordField pin = new JPasswordField(16);
        JLabel pinLabel = new JLabel("Token PIN");
        c.gridx = 0;
        c.gridy = row;
        form.add(pinLabel, c);
        c.gridx = 1;
        form.add(pin, c);
        row++;
        Runnable pinVisibility = () -> {
            CertificateInfo sel = (CertificateInfo) certBox.getSelectedItem();
            boolean need = sel != null && r.pinRequiredFor().contains(sel.id());
            pin.setVisible(need);
            pinLabel.setVisible(need);
            dialog.pack();
        };
        certBox.addActionListener(e -> pinVisibility.run());

        if (r.errorMessage() != null) {
            JLabel err = new JLabel(r.errorMessage());
            err.setForeground(new Color(0xB0, 0x20, 0x20));
            c.gridx = 0;
            c.gridy = row;
            c.gridwidth = 2;
            form.add(err, c);
            c.gridwidth = 1;
        }
        root.add(form, BorderLayout.CENTER);

        JLabel note = new JLabel("<html><small>Your signature is legally binding under the Information Technology Act, 2000.<br>"
                + "Only continue if you requested this signature.</small></html>");
        note.setForeground(Color.DARK_GRAY);

        AtomicReference<ConsentDecision> decision = new AtomicReference<>();
        JButton sign = new JButton("Sign");
        JButton cancel = new JButton("Cancel");
        sign.addActionListener(e -> {
            CertificateInfo sel = (CertificateInfo) certBox.getSelectedItem();
            if (sel == null) {
                return;
            }
            boolean need = r.pinRequiredFor().contains(sel.id());
            if (need && pin.getPassword().length == 0) {
                pin.requestFocusInWindow();
                return;
            }
            decision.set(new ConsentDecision(sel.id(), need ? pin.getPassword() : null));
            dialog.dispose();
        });
        cancel.addActionListener(e -> dialog.dispose());
        dialog.getRootPane().setDefaultButton(sign);
        dialog.getRootPane().registerKeyboardAction(e -> dialog.dispose(),
                KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), JComponent.WHEN_IN_FOCUSED_WINDOW);

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 0));
        buttons.add(cancel);
        buttons.add(sign);
        JPanel south = new JPanel();
        south.setLayout(new BoxLayout(south, BoxLayout.Y_AXIS));
        note.setAlignmentX(Component.LEFT_ALIGNMENT);
        buttons.setAlignmentX(Component.LEFT_ALIGNMENT);
        south.add(note);
        south.add(Box.createVerticalStrut(10));
        south.add(buttons);
        root.add(south, BorderLayout.SOUTH);

        dialog.setContentPane(root);
        dialog.setMinimumSize(new Dimension(460, 200));
        pinVisibility.run();
        dialog.setLocationRelativeTo(null);

        Timer timeout = new Timer(timeoutSeconds * 1000, e -> dialog.dispose());
        timeout.setRepeats(false);
        timeout.start();
        SwingUtilities.invokeLater(() -> {
            dialog.toFront();
            if (pin.isVisible()) {
                pin.requestFocusInWindow();
            } else {
                sign.requestFocusInWindow();
            }
        });
        dialog.setVisible(true); // blocks (modal) until disposed
        timeout.stop();
        return decision.get();
    }

    private static int addRow(JPanel form, GridBagConstraints c, int row, String label, Component value) {
        c.gridx = 0;
        c.gridy = row;
        JLabel l = new JLabel(label);
        l.setForeground(Color.GRAY);
        form.add(l, c);
        c.gridx = 1;
        form.add(value, c);
        return row + 1;
    }
}
