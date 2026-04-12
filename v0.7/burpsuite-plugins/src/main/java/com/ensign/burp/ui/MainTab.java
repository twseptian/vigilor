package com.ensign.burp.ui;

import burp.api.montoya.MontoyaApi;
import com.ensign.burp.api.AgentApiClient;
import com.ensign.burp.api.model.ScanRequest;
import com.ensign.burp.api.model.ScanResponse;

import javax.swing.*;
import java.awt.*;

/**
 * Root panel registered as a Burp Suite tab.
 * Contains three sub-tabs: Scans, Findings, Settings.
 */
public class MainTab extends JPanel {

    private final MontoyaApi     burp;
    private final AgentApiClient client;

    private final ScansPanel    scansPanel;
    private final FindingsPanel findingsPanel;
    private final SettingsPanel settingsPanel;
    private final JTabbedPane   tabs;

    public MainTab(MontoyaApi burp, AgentApiClient client) {
        this.burp   = burp;
        this.client = client;

        setLayout(new BorderLayout());

        // Build panels
        findingsPanel = new FindingsPanel(burp, client);
        scansPanel    = new ScansPanel(burp, client);
        settingsPanel = new SettingsPanel(burp, client);

        // Wire findings panel reference
        scansPanel.setFindingsPanel(findingsPanel);

        // Build tabbed pane
        tabs = new JTabbedPane();
        tabs.addTab("Scans",    iconFor("scan"),     scansPanel);
        tabs.addTab("Findings", iconFor("finding"),  findingsPanel);
        tabs.addTab("Settings", iconFor("settings"), settingsPanel);

        // Wire tabbed pane reference (must be after tabs is constructed)
        scansPanel.setTabbedPane(tabs);

        // Restart polling after successful re-login
        settingsPanel.setOnLoginSuccess(() -> {
            scansPanel.startPolling();
            scansPanel.loadScans();
        });

        add(tabs, BorderLayout.CENTER);

        // Start polling once the component is shown
        tabs.addChangeListener(e -> {
            if (tabs.getSelectedComponent() == scansPanel) {
                scansPanel.loadScans();
            }
        });
    }

    /**
     * Called by the context menu action.
     * Pre-fills the new scan dialog with the URL extracted from the selected Burp request,
     * then submits the scan and switches to the Scans tab.
     *
     * @param baseUrl  scheme+host+port (e.g. https://example.com)
     * @param fullUrl  full request URL (used to pre-fill target)
     */
    public void startScanFromBurp(String baseUrl, String fullUrl) {
        if (!client.isAuthenticated()) {
            JOptionPane.showMessageDialog(this,
                    "Not authenticated. Please go to the Settings tab and log in first.",
                    "Not Logged In", JOptionPane.WARNING_MESSAGE);
            tabs.setSelectedComponent(settingsPanel);
            return;
        }

        Frame frame = (Frame) SwingUtilities.getWindowAncestor(this);
        NewScanDialog dialog = new NewScanDialog(frame, fullUrl != null ? fullUrl : baseUrl, client);
        dialog.setVisible(true);

        if (!dialog.isConfirmed()) return;

        ScanRequest req = dialog.buildRequest();

        new Thread(() -> {
            try {
                ScanResponse scan = client.createScan(req);
                SwingUtilities.invokeLater(() -> {
                    tabs.setSelectedComponent(scansPanel);
                    scansPanel.loadScans();
                    burp.logging().logToOutput(
                            "Scan started: " + scan.id + " → " + req.target_url);
                });
            } catch (Exception ex) {
                SwingUtilities.invokeLater(() ->
                        JOptionPane.showMessageDialog(this,
                                "Failed to start scan: " + ex.getMessage(),
                                "Scan Error", JOptionPane.ERROR_MESSAGE));
                burp.logging().logToError("createScan: " + ex.getMessage());
            }
        }, "agent-new-scan").start();
    }

    /** Begin background polling of active scans. */
    public void startPolling() {
        scansPanel.startPolling();
    }

    /** Stop polling (call on extension unload). */
    public void stopPolling() {
        scansPanel.stopPolling();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static Icon iconFor(String name) {
        // Return null to use default text-only tabs; can be replaced with real icons.
        return null;
    }
}
