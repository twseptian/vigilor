package com.ensign.burp.ui;

import burp.api.montoya.MontoyaApi;
import com.ensign.burp.api.AgentApiClient;
import com.ensign.burp.api.model.LoginResponse;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.awt.*;

/**
 * Settings panel: backend URL, credentials, login.
 */
public class SettingsPanel extends JPanel {

    private final MontoyaApi     burp;
    private final AgentApiClient client;
    private Runnable             onLoginSuccess;   // callback to restart polling

    private final JTextField  urlField       = new JTextField(30);
    private final JTextField  usernameField  = new JTextField(20);
    private final JPasswordField passField   = new JPasswordField(20);
    private final JLabel      statusLabel    = new JLabel("Not connected");
    private final JButton     loginBtn       = new JButton("Login & Save");
    private final JButton     testBtn        = new JButton("Test Connection");

    public SettingsPanel(MontoyaApi burp, AgentApiClient client) {
        this.burp   = burp;
        this.client = client;

        setLayout(new BorderLayout(10, 10));
        setBorder(BorderFactory.createEmptyBorder(16, 16, 16, 16));

        // ── Connection panel ──────────────────────────────────────────────────
        JPanel connPanel = new JPanel(new GridBagLayout());
        connPanel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(), "Backend Connection",
                TitledBorder.LEFT, TitledBorder.TOP));

        GridBagConstraints lc = new GridBagConstraints();
        lc.anchor = GridBagConstraints.WEST;
        lc.insets = new Insets(4, 8, 4, 8);
        lc.gridx  = 0; lc.gridy = 0;

        GridBagConstraints fc = new GridBagConstraints();
        fc.fill   = GridBagConstraints.HORIZONTAL;
        fc.weightx = 1.0;
        fc.insets = new Insets(4, 0, 4, 8);
        fc.gridx  = 1; fc.gridy = 0;

        // Restore persisted values
        String savedUrl  = burp.persistence().preferences().getString("agentBackendUrl");
        String savedUser = burp.persistence().preferences().getString("agentUsername");
        urlField.setText(savedUrl  != null ? savedUrl  : "http://localhost:8000/api/v1");
        usernameField.setText(savedUser != null ? savedUser : "admin");

        addRow(connPanel, lc, fc, 0, "Backend URL:",  urlField);
        addRow(connPanel, lc, fc, 1, "Username:",     usernameField);
        addRow(connPanel, lc, fc, 2, "Password:",     passField);

        // Buttons row
        JPanel btnRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        btnRow.add(loginBtn);
        btnRow.add(testBtn);
        btnRow.add(statusLabel);
        GridBagConstraints bc = new GridBagConstraints();
        bc.gridx = 0; bc.gridy = 3; bc.gridwidth = 2;
        bc.anchor = GridBagConstraints.WEST;
        bc.insets = new Insets(8, 8, 8, 8);
        connPanel.add(btnRow, bc);

        // ── Info panel ───────────────────────────────────────────────────────
        JPanel infoPanel = new JPanel(new BorderLayout());
        infoPanel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(), "How to use",
                TitledBorder.LEFT, TitledBorder.TOP));
        JTextArea info = new JTextArea(
                "1. Start the Agentic Pentest AI backend (docker compose up).\n" +
                "2. Enter the backend URL (default: http://localhost:8000/api/v1).\n" +
                "3. Enter your credentials and click Login & Save.\n" +
                "4. Right-click any request in Proxy / Repeater → Send to Agentic Pentest AI.\n" +
                "5. Monitor scans in the Scans tab and review findings in the Findings tab.\n\n" +
                "Tip: The plugin polls active scans every 5 seconds and updates the table automatically.\n" +
                "Tip: Click any row in the Findings table to see full description and remediation."
        );
        info.setEditable(false);
        info.setOpaque(false);
        info.setFont(UIManager.getFont("Label.font"));
        info.setLineWrap(true);
        info.setWrapStyleWord(true);
        infoPanel.add(new JScrollPane(info), BorderLayout.CENTER);

        add(connPanel, BorderLayout.NORTH);
        add(infoPanel, BorderLayout.CENTER);

        // ── Button actions ────────────────────────────────────────────────────
        loginBtn.addActionListener(e -> doLogin());
        testBtn.addActionListener(e -> doTestConnection());

        // Check if token already exists
        String token = burp.persistence().preferences().getString("agentAuthToken");
        if (token != null && !token.isBlank()) {
            client.setAuthToken(token);
            client.setBaseUrl(urlField.getText().trim());
            statusLabel.setText("Token loaded — test connection to verify.");
            statusLabel.setForeground(new Color(0, 120, 0));
        }
    }

    private void addRow(JPanel p, GridBagConstraints lc, GridBagConstraints fc, int row,
                        String label, JComponent field) {
        lc.gridy = fc.gridy = row;
        p.add(new JLabel(label), lc);
        p.add(field, fc);
    }

    public void setOnLoginSuccess(Runnable callback) {
        this.onLoginSuccess = callback;
    }

    private void doLogin() {
        String url  = urlField.getText().trim();
        String user = usernameField.getText().trim();
        String pass = new String(passField.getPassword());
        if (url.isEmpty() || user.isEmpty() || pass.isEmpty()) {
            statusLabel.setText("Fill in all fields.");
            statusLabel.setForeground(Color.RED);
            return;
        }
        loginBtn.setEnabled(false);
        statusLabel.setText("Logging in…");
        statusLabel.setForeground(Color.DARK_GRAY);

        client.setBaseUrl(url);
        new Thread(() -> {
            try {
                LoginResponse lr = client.login(user, pass);
                // Persist settings
                burp.persistence().preferences().setString("agentBackendUrl", url);
                burp.persistence().preferences().setString("agentUsername", user);
                burp.persistence().preferences().setString("agentAuthToken", lr.access_token);
                SwingUtilities.invokeLater(() -> {
                    statusLabel.setText("Logged in as " + lr.username + " (" + lr.role + ")");
                    statusLabel.setForeground(new Color(0, 128, 0));
                    loginBtn.setEnabled(true);
                    if (onLoginSuccess != null) onLoginSuccess.run();
                });
                burp.logging().logToOutput("Agent login OK: " + lr.username + " (" + lr.role + ")");
            } catch (Exception ex) {
                SwingUtilities.invokeLater(() -> {
                    statusLabel.setText("Login failed: " + ex.getMessage());
                    statusLabel.setForeground(Color.RED);
                    loginBtn.setEnabled(true);
                });
                burp.logging().logToError("Agent login error: " + ex.getMessage());
            }
        }, "agent-login").start();
    }

    private void doTestConnection() {
        if (!client.isAuthenticated()) {
            statusLabel.setText("Not authenticated — login first.");
            statusLabel.setForeground(Color.RED);
            return;
        }
        testBtn.setEnabled(false);
        statusLabel.setText("Testing…");
        new Thread(() -> {
            try {
                client.listScans();
                SwingUtilities.invokeLater(() -> {
                    statusLabel.setText("Connection OK!");
                    statusLabel.setForeground(new Color(0, 128, 0));
                    testBtn.setEnabled(true);
                });
            } catch (Exception ex) {
                SwingUtilities.invokeLater(() -> {
                    statusLabel.setText("Connection failed: " + ex.getMessage());
                    statusLabel.setForeground(Color.RED);
                    testBtn.setEnabled(true);
                });
            }
        }, "agent-test").start();
    }
}
