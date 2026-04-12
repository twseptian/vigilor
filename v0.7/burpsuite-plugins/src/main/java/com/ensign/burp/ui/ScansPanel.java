package com.ensign.burp.ui;

import burp.api.montoya.MontoyaApi;
import com.ensign.burp.api.AgentApiClient;
import com.ensign.burp.api.model.ScanResponse;

import javax.swing.*;
import javax.swing.table.*;
import java.awt.*;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

/**
 * Panel showing the list of scans with status polling and action buttons.
 */
public class ScansPanel extends JPanel {

    private final MontoyaApi     burp;
    private final AgentApiClient client;
    private FindingsPanel        findingsPanel;   // set after construction
    private JTabbedPane          tabbedPane;      // set after construction

    private static final String[] COLS =
            {"ID", "Target", "Status", "Findings", "Provider", "Model", "Started"};
    private static final DateTimeFormatter DT_FMT =
            DateTimeFormatter.ofPattern("MM-dd HH:mm").withZone(ZoneId.systemDefault());

    private final DefaultTableModel tableModel = new DefaultTableModel(COLS, 0) {
        @Override public boolean isCellEditable(int r, int c) { return false; }
    };
    private final JTable  table      = new JTable(tableModel);
    private final JLabel  statusLabel = new JLabel("Not connected");
    private final JButton refreshBtn  = new JButton("Refresh");
    private final JButton cancelBtn   = new JButton("Cancel Scan");
    private final JButton viewBtn     = new JButton("View Findings");

    private List<ScanResponse> currentScans      = new ArrayList<>();
    private String             lastSelectedScanId = null;  // survives poll rebuild

    private final ScheduledExecutorService scheduler =
            Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "agent-scan-poll");
                t.setDaemon(true);
                return t;
            });
    private ScheduledFuture<?> pollTask;

    public ScansPanel(MontoyaApi burp, AgentApiClient client) {
        this.burp   = burp;
        this.client = client;

        setLayout(new BorderLayout(6, 6));
        setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        // ── Top toolbar ───────────────────────────────────────────────────────
        JPanel toolbar = new JPanel(new BorderLayout(8, 0));
        JLabel title = new JLabel("Agentic Pentest — Scans");
        title.setFont(title.getFont().deriveFont(Font.BOLD));
        toolbar.add(title, BorderLayout.WEST);

        JPanel btnRow = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        btnRow.add(statusLabel);
        btnRow.add(viewBtn);
        btnRow.add(cancelBtn);
        btnRow.add(refreshBtn);
        toolbar.add(btnRow, BorderLayout.EAST);

        // ── Table ─────────────────────────────────────────────────────────────
        styleStatusRenderer();
        table.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);
        table.getColumnModel().getColumn(0).setPreferredWidth(72);
        table.getColumnModel().getColumn(1).setPreferredWidth(220);
        table.getColumnModel().getColumn(2).setPreferredWidth(90);
        table.getColumnModel().getColumn(3).setPreferredWidth(70);
        table.getColumnModel().getColumn(4).setPreferredWidth(80);
        table.getColumnModel().getColumn(5).setPreferredWidth(120);
        table.getColumnModel().getColumn(6).setPreferredWidth(90);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int row = table.getSelectedRow();
                if (row >= 0 && row < currentScans.size()) {
                    lastSelectedScanId = currentScans.get(row).id;
                }
                updateButtonState();
            }
        });
        // Double-click row → view findings immediately
        table.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override public void mouseClicked(java.awt.event.MouseEvent e) {
                if (e.getClickCount() == 2) doViewFindings();
            }
        });

        cancelBtn.setEnabled(false);
        viewBtn.setEnabled(false);

        cancelBtn.addActionListener(e -> doCancelScan());
        viewBtn.addActionListener(e   -> doViewFindings());
        refreshBtn.addActionListener(e -> loadScans());

        add(toolbar,               BorderLayout.NORTH);
        add(new JScrollPane(table), BorderLayout.CENTER);
    }

    /** Called by MainTab after all panels are constructed. */
    public void setFindingsPanel(FindingsPanel fp) {
        this.findingsPanel = fp;
    }

    public void setTabbedPane(JTabbedPane tp) {
        this.tabbedPane = tp;
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /** Start auto-polling every 5 seconds. Call once after login. */
    public void startPolling() {
        if (pollTask != null && !pollTask.isDone()) return;
        pollTask = scheduler.scheduleAtFixedRate(
                () -> SwingUtilities.invokeLater(this::loadScans),
                0, 5, TimeUnit.SECONDS);
    }

    /** Stop polling (e.g., when extension is unloaded). */
    public void stopPolling() {
        if (pollTask != null) pollTask.cancel(false);
        scheduler.shutdownNow();
    }

    /** Load scans once immediately. */
    public void loadScans() {
        if (!client.isAuthenticated()) {
            statusLabel.setText("Not logged in — go to Settings tab");
            statusLabel.setForeground(Color.RED);
            return;
        }
        new Thread(() -> {
            try {
                List<ScanResponse> scans = client.listScans();
                SwingUtilities.invokeLater(() -> populateTable(scans));
            } catch (AgentApiClient.AuthExpiredException ex) {
                SwingUtilities.invokeLater(() -> {
                    stopPolling();
                    statusLabel.setText("Session expired — please re-login in Settings tab");
                    statusLabel.setForeground(new Color(180, 80, 0));
                });
                burp.logging().logToOutput("listScans: session expired, polling stopped.");
            } catch (Exception ex) {
                SwingUtilities.invokeLater(() -> {
                    statusLabel.setText("Error: " + ex.getMessage());
                    statusLabel.setForeground(Color.RED);
                });
                burp.logging().logToError("listScans poll: " + ex.getMessage());
            }
        }, "agent-scan-load").start();
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    private void populateTable(List<ScanResponse> scans) {
        currentScans = scans;
        int selectedScanRow = table.getSelectedRow();
        String selectedScanId = selectedScanRow >= 0 && selectedScanRow < currentScans.size()
                ? currentScans.get(selectedScanRow).id : null;

        tableModel.setRowCount(0);
        for (ScanResponse s : scans) {
            tableModel.addRow(new Object[]{
                    s.id != null ? s.id.substring(0, 8) + "…" : "—",
                    s.target_url,
                    s.status,
                    s.totalFindings() > 0
                            ? s.totalFindings() + " (" + s.severitySummary() + ")"
                            : "—",
                    s.llm_provider != null ? s.llm_provider : "—",
                    s.llm_model    != null ? s.llm_model    : "default",
                    formatDate(s.created_at)
            });
        }

        // Re-select same scan if still present
        if (selectedScanId != null) {
            for (int i = 0; i < currentScans.size(); i++) {
                if (selectedScanId.equals(currentScans.get(i).id)) {
                    table.setRowSelectionInterval(i, i);
                    break;
                }
            }
        }

        statusLabel.setText(scans.size() + " scan(s)");
        statusLabel.setForeground(Color.DARK_GRAY);
        updateButtonState();
    }

    private void updateButtonState() {
        int row = table.getSelectedRow();
        if (row < 0 || row >= currentScans.size()) {
            cancelBtn.setEnabled(false);
            viewBtn.setEnabled(false);
            return;
        }
        ScanResponse s = currentScans.get(row);
        boolean running = "running".equalsIgnoreCase(s.status)
                || "pending".equalsIgnoreCase(s.status);
        cancelBtn.setEnabled(running);
        viewBtn.setEnabled(true);
    }

    private void doCancelScan() {
        int row = table.getSelectedRow();
        if (row < 0 || row >= currentScans.size()) return;
        ScanResponse s = currentScans.get(row);
        int confirm = JOptionPane.showConfirmDialog(this,
                "Cancel scan " + s.id.substring(0, 8) + "…?",
                "Cancel Scan", JOptionPane.YES_NO_OPTION);
        if (confirm != JOptionPane.YES_OPTION) return;

        new Thread(() -> {
            try {
                client.cancelScan(s.id);
                SwingUtilities.invokeLater(this::loadScans);
            } catch (Exception ex) {
                SwingUtilities.invokeLater(() ->
                        JOptionPane.showMessageDialog(this,
                                "Cancel failed: " + ex.getMessage(),
                                "Error", JOptionPane.ERROR_MESSAGE));
                burp.logging().logToError("cancelScan: " + ex.getMessage());
            }
        }, "agent-cancel").start();
    }

    private void doViewFindings() {
        if (findingsPanel == null) return;
        // Prefer current row selection; fall back to last known selection
        int row = table.getSelectedRow();
        String scanId = null;
        if (row >= 0 && row < currentScans.size()) {
            scanId = currentScans.get(row).id;
        } else if (lastSelectedScanId != null) {
            scanId = lastSelectedScanId;
        }
        if (scanId == null) return;
        findingsPanel.loadFindings(scanId);
        if (tabbedPane != null) {
            for (int i = 0; i < tabbedPane.getTabCount(); i++) {
                if (tabbedPane.getTitleAt(i).contains("Findings")) {
                    tabbedPane.setSelectedIndex(i);
                    break;
                }
            }
        }
    }

    private void styleStatusRenderer() {
        DefaultTableCellRenderer statusRender = new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable t, Object val,
                    boolean sel, boolean focus, int row, int col) {
                Component c = super.getTableCellRendererComponent(t, val, sel, focus, row, col);
                if (!sel && val != null) {
                    switch (val.toString().toLowerCase()) {
                        case "running":   c.setForeground(new Color(0, 100, 180));   break;
                        case "completed": c.setForeground(new Color(0, 120, 0));     break;
                        case "failed":    c.setForeground(new Color(180, 0, 0));     break;
                        case "cancelled": c.setForeground(Color.DARK_GRAY);          break;
                        default:          c.setForeground(Color.BLACK);
                    }
                } else {
                    c.setForeground(sel ? Color.WHITE : Color.BLACK);
                }
                return c;
            }
        };
        table.getColumnModel().getColumn(2).setCellRenderer(statusRender);
    }

    private static String formatDate(String iso) {
        if (iso == null || iso.isBlank()) return "—";
        try {
            return DT_FMT.format(Instant.parse(iso));
        } catch (Exception e) {
            return iso.length() > 16 ? iso.substring(0, 16) : iso;
        }
    }
}
