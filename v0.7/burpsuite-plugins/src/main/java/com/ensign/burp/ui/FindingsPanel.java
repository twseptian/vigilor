package com.ensign.burp.ui;

import burp.api.montoya.MontoyaApi;
import com.ensign.burp.api.AgentApiClient;
import com.ensign.burp.api.model.FindingResponse;

import javax.swing.*;
import javax.swing.table.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

/**
 * Panel showing findings for the selected scan, with a detail pane below.
 */
public class FindingsPanel extends JPanel {

    private final MontoyaApi     burp;
    private final AgentApiClient client;

    private static final String[] COLS =
            {"Ref", "Severity", "CVSS", "Type", "Location", "Status", "OWASP"};

    private final DefaultTableModel tableModel = new DefaultTableModel(COLS, 0) {
        @Override public boolean isCellEditable(int r, int c) { return false; }
    };
    private final JTable  table  = new JTable(tableModel);
    private final JLabel  scanLabel    = new JLabel("No scan selected");
    private final JTextArea detailArea = new JTextArea();
    private final JLabel  countLabel   = new JLabel("0 findings");

    private List<FindingResponse> currentFindings = new ArrayList<>();
    private String currentScanId = null;

    public FindingsPanel(MontoyaApi burp, AgentApiClient client) {
        this.burp   = burp;
        this.client = client;

        setLayout(new BorderLayout(6, 6));
        setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        // ── Top bar ───────────────────────────────────────────────────────────
        JPanel topBar = new JPanel(new BorderLayout(8, 0));
        scanLabel.setFont(scanLabel.getFont().deriveFont(Font.BOLD));
        JButton refreshBtn = new JButton("Refresh");
        refreshBtn.addActionListener(e -> loadFindings(currentScanId));
        topBar.add(scanLabel, BorderLayout.CENTER);
        JPanel rightBar = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
        rightBar.add(countLabel);
        rightBar.add(refreshBtn);
        topBar.add(rightBar, BorderLayout.EAST);

        // ── Table ─────────────────────────────────────────────────────────────
        styleSeverityRenderer();
        table.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);
        table.getColumnModel().getColumn(0).setPreferredWidth(60);
        table.getColumnModel().getColumn(1).setPreferredWidth(75);
        table.getColumnModel().getColumn(2).setPreferredWidth(50);
        table.getColumnModel().getColumn(3).setPreferredWidth(180);
        table.getColumnModel().getColumn(4).setPreferredWidth(180);
        table.getColumnModel().getColumn(5).setPreferredWidth(90);
        table.getColumnModel().getColumn(6).setPreferredWidth(100);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) showDetail(table.getSelectedRow());
        });

        // ── Detail pane ──────────────────────────────────────────────────────
        detailArea.setEditable(false);
        detailArea.setLineWrap(true);
        detailArea.setWrapStyleWord(true);
        detailArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane detailScroll = new JScrollPane(detailArea);
        detailScroll.setBorder(BorderFactory.createTitledBorder("Finding Detail"));
        detailScroll.setPreferredSize(new Dimension(0, 200));

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                new JScrollPane(table), detailScroll);
        split.setResizeWeight(0.6);
        split.setDividerLocation(300);

        add(topBar, BorderLayout.NORTH);
        add(split,  BorderLayout.CENTER);
    }

    /** Called from ScansPanel when the user selects a scan row. */
    public void loadFindings(String scanId) {
        this.currentScanId = scanId;
        if (scanId == null) {
            scanLabel.setText("No scan selected — click a scan in the Scans tab.");
            tableModel.setRowCount(0);
            currentFindings.clear();
            countLabel.setText("0 findings");
            return;
        }
        scanLabel.setText("Loading findings for scan " + scanId.substring(0, 8) + "…");
        new Thread(() -> {
            try {
                List<FindingResponse> findings = client.getFindings(scanId);
                SwingUtilities.invokeLater(() -> populateTable(scanId, findings));
            } catch (Exception ex) {
                SwingUtilities.invokeLater(() ->
                        scanLabel.setText("Error: " + ex.getMessage()));
                burp.logging().logToError("getFindings: " + ex.getMessage());
            }
        }, "agent-findings").start();
    }

    private void populateTable(String scanId, List<FindingResponse> findings) {
        currentFindings = findings;
        tableModel.setRowCount(0);
        for (FindingResponse f : findings) {
            tableModel.addRow(new Object[]{
                    f.finding_ref  != null ? f.finding_ref : "—",
                    f.severity,
                    String.format("%.1f", f.cvss_score),
                    f.vuln_type    != null ? f.vuln_type   : f.title,
                    f.location     != null ? f.location    : "—",
                    f.status,
                    f.owasp_category != null ? f.owasp_category : "—"
            });
        }
        scanLabel.setText("Scan: " + scanId.substring(0, 8) + "… — " + findings.size() + " finding(s)");
        countLabel.setText(findings.size() + " findings");
        detailArea.setText("");
    }

    private void showDetail(int row) {
        if (row < 0 || row >= currentFindings.size()) return;
        FindingResponse f = currentFindings.get(row);
        StringBuilder sb = new StringBuilder();
        sb.append("=== ").append(f.title).append(" ===\n\n");
        sb.append("Severity   : ").append(f.severity).append("  (CVSS ").append(f.cvss_score).append(")\n");
        sb.append("CVSS Vector: ").append(nvl(f.cvss_vector)).append("\n");
        sb.append("Status     : ").append(nvl(f.status)).append("\n");
        sb.append("Location   : ").append(nvl(f.location)).append("\n");
        sb.append("OWASP      : ").append(nvl(f.owasp_category)).append(" — ").append(nvl(f.owasp_name)).append("\n");
        if (f.cve != null && !f.cve.isBlank())
            sb.append("CVE        : ").append(f.cve).append("\n");
        sb.append("\n--- Description ---\n").append(nvl(f.description)).append("\n");
        sb.append("\n--- Proof of Concept ---\n").append(nvl(f.proof_of_concept)).append("\n");
        sb.append("\n--- Implications ---\n").append(nvl(f.implications)).append("\n");
        sb.append("\n--- Recommendations ---\n").append(nvl(f.recommendations)).append("\n");
        detailArea.setText(sb.toString());
        detailArea.setCaretPosition(0);
    }

    private void styleSeverityRenderer() {
        DefaultTableCellRenderer sevRender = new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable t, Object val,
                    boolean sel, boolean focus, int row, int col) {
                Component c = super.getTableCellRendererComponent(t, val, sel, focus, row, col);
                if (!sel && val != null) {
                    switch (val.toString()) {
                        case "Critical": c.setForeground(new Color(180, 0, 0));    break;
                        case "High":     c.setForeground(new Color(200, 80, 0));   break;
                        case "Medium":   c.setForeground(new Color(180, 130, 0));  break;
                        case "Low":      c.setForeground(new Color(0, 100, 0));    break;
                        default:         c.setForeground(Color.DARK_GRAY);
                    }
                } else {
                    c.setForeground(sel ? Color.WHITE : Color.BLACK);
                }
                return c;
            }
        };
        table.getColumnModel().getColumn(1).setCellRenderer(sevRender);
    }

    private static String nvl(String s) { return s != null ? s : ""; }
}
