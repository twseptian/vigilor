package com.ensign.burp.ui;

import com.ensign.burp.api.AgentApiClient;
import com.ensign.burp.api.model.ScanRequest;

import javax.swing.*;
import java.awt.*;
import java.util.List;

/**
 * Modal dialog for configuring a new scan before submitting to the backend.
 */
public class NewScanDialog extends JDialog {

    private static final String[] ANTHROPIC_MODELS = {
        "", "claude-sonnet-4-6", "claude-opus-4-6", "claude-haiku-4-5-20251001",
        "claude-3-5-sonnet-20241022", "claude-3-5-haiku-20241022", "claude-3-opus-20240229"
    };
    private static final String[] OPENAI_MODELS = {
        "", "gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-4", "o1", "o1-mini", "o3-mini"
    };
    private static final String[] OLLAMA_DEFAULT_MODELS = {
        "", "Loading…"
    };

    private boolean confirmed = false;

    private final JTextField        targetField    = new JTextField(35);
    private final JComboBox<String> providerBox    = new JComboBox<>(
            new String[]{"anthropic", "openai", "openrouter", "ollama"});
    private final JComboBox<String> modelBox       = new JComboBox<>(ANTHROPIC_MODELS);
    private final JTextField        modelTextField = new JTextField(20);   // fallback for openrouter
    private final JPanel            modelRowPanel  = new JPanel(new BorderLayout(4, 0));
    private final JButton           detectBtn      = new JButton("Detect");
    private final JSpinner          hypothesesSpin = new JSpinner(new SpinnerNumberModel(8, 1, 30, 1));
    private final JSpinner          parallelSpin   = new JSpinner(new SpinnerNumberModel(3, 1, 10, 1));
    private final JSpinner          feedbackSpin   = new JSpinner(new SpinnerNumberModel(2, 0, 5, 1));
    private final JTextArea         promptArea     = new JTextArea(3, 35);
    private final JTextArea         descArea       = new JTextArea(2, 35);
    private final JComboBox<String> modeBox        = new JComboBox<>(new String[]{"full", "static_only"});

    private final AgentApiClient client;

    public NewScanDialog(Frame parent, String prefilledUrl, AgentApiClient client) {
        super(parent, "New Agentic Pentest Scan", true);
        this.client = client;
        targetField.setText(prefilledUrl != null ? prefilledUrl : "");

        buildModelRow();
        providerBox.addActionListener(e -> onProviderChanged());
        // Trigger initial state
        onProviderChanged();

        JPanel form = new JPanel(new GridBagLayout());
        form.setBorder(BorderFactory.createEmptyBorder(12, 12, 4, 12));

        GridBagConstraints lc = new GridBagConstraints();
        lc.anchor = GridBagConstraints.WEST;
        lc.insets = new Insets(4, 4, 4, 8);

        GridBagConstraints fc = new GridBagConstraints();
        fc.fill    = GridBagConstraints.HORIZONTAL;
        fc.weightx = 1.0;
        fc.insets  = new Insets(4, 0, 4, 4);

        int row = 0;
        addRow(form, lc, fc, row++, "Target URL *",        targetField);
        addRow(form, lc, fc, row++, "Scan Mode",           modeBox);
        addRow(form, lc, fc, row++, "LLM Provider",        providerBox);
        addRow(form, lc, fc, row++, "Model",               modelRowPanel);
        addRow(form, lc, fc, row++, "Max Hypotheses",      hypothesesSpin);
        addRow(form, lc, fc, row++, "Max Parallel Workers", parallelSpin);
        addRow(form, lc, fc, row++, "Feedback Iterations", feedbackSpin);

        lc.gridy = fc.gridy = row++;
        form.add(new JLabel("Custom Prompt"), lc);
        promptArea.setLineWrap(true); promptArea.setWrapStyleWord(true);
        form.add(new JScrollPane(promptArea), fc);

        lc.gridy = fc.gridy = row++;
        form.add(new JLabel("Target Description"), lc);
        descArea.setLineWrap(true); descArea.setWrapStyleWord(true);
        form.add(new JScrollPane(descArea), fc);

        JButton okBtn     = new JButton("Start Scan");
        JButton cancelBtn = new JButton("Cancel");
        okBtn.addActionListener(e -> { confirmed = true; dispose(); });
        cancelBtn.addActionListener(e -> dispose());

        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        btnPanel.add(cancelBtn);
        btnPanel.add(okBtn);

        setLayout(new BorderLayout());
        add(form,     BorderLayout.CENTER);
        add(btnPanel, BorderLayout.SOUTH);

        pack();
        setMinimumSize(new Dimension(540, 440));
        setLocationRelativeTo(parent);
    }

    /** Backwards-compatible constructor (no client — disables Ollama detect). */
    public NewScanDialog(Frame parent, String prefilledUrl) {
        this(parent, prefilledUrl, null);
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    private void buildModelRow() {
        detectBtn.setToolTipText("Fetch available models from Ollama");
        detectBtn.addActionListener(e -> detectOllamaModels());
        modelRowPanel.add(modelBox,       BorderLayout.CENTER);
        // Detect button shown only for Ollama
        detectBtn.setVisible(false);
        modelRowPanel.add(detectBtn, BorderLayout.EAST);
    }

    private void onProviderChanged() {
        String provider = (String) providerBox.getSelectedItem();
        modelBox.setVisible(true);
        modelTextField.setVisible(false);
        detectBtn.setVisible(false);

        switch (provider != null ? provider : "") {
            case "anthropic":
                resetCombo(ANTHROPIC_MODELS);
                break;
            case "openai":
                resetCombo(OPENAI_MODELS);
                break;
            case "ollama":
                resetCombo(OLLAMA_DEFAULT_MODELS);
                detectBtn.setVisible(true);
                // Auto-detect on open if client available
                if (client != null && client.isAuthenticated()) {
                    detectOllamaModels();
                }
                break;
            case "openrouter":
                // Too many models — free text
                resetCombo(new String[]{""});
                modelBox.setEditable(true);
                modelBox.setSelectedItem("");
                break;
            default:
                resetCombo(new String[]{""});
        }
    }

    private void resetCombo(String[] items) {
        modelBox.setEditable(false);
        modelBox.removeAllItems();
        for (String m : items) modelBox.addItem(m);
        if (items.length > 0) modelBox.setSelectedIndex(0);
    }

    private void detectOllamaModels() {
        if (client == null || !client.isAuthenticated()) return;
        detectBtn.setEnabled(false);
        detectBtn.setText("…");
        new Thread(() -> {
            try {
                List<String> models = client.detectOllamaModels();
                SwingUtilities.invokeLater(() -> {
                    modelBox.removeAllItems();
                    modelBox.addItem("");
                    for (String m : models) modelBox.addItem(m);
                    if (!models.isEmpty()) modelBox.setSelectedIndex(1);
                    detectBtn.setText("Detect");
                    detectBtn.setEnabled(true);
                });
            } catch (Exception ex) {
                SwingUtilities.invokeLater(() -> {
                    detectBtn.setText("Detect");
                    detectBtn.setEnabled(true);
                    JOptionPane.showMessageDialog(this,
                            "Could not detect Ollama models:\n" + ex.getMessage(),
                            "Detection Failed", JOptionPane.WARNING_MESSAGE);
                });
            }
        }, "agent-detect-models").start();
    }

    private void addRow(JPanel p, GridBagConstraints lc, GridBagConstraints fc,
                        int row, String label, JComponent field) {
        lc.gridy = fc.gridy = row;
        p.add(new JLabel(label), lc);
        p.add(field, fc);
    }

    public boolean isConfirmed() { return confirmed; }

    public ScanRequest buildRequest() {
        ScanRequest r = new ScanRequest(targetField.getText().trim());
        r.scan_mode      = (String) modeBox.getSelectedItem();
        r.llm_provider   = (String) providerBox.getSelectedItem();
        String model     = modelBox.isEditable()
                ? (String) modelBox.getEditor().getItem()
                : (String) modelBox.getSelectedItem();
        r.llm_model      = (model == null || model.isBlank()) ? null : model.trim();
        r.max_hypotheses = (int) hypothesesSpin.getValue();
        r.max_parallel   = (int) parallelSpin.getValue();
        r.feedback_iter  = (int) feedbackSpin.getValue();
        String prompt    = promptArea.getText().trim();
        r.custom_prompt  = prompt.isEmpty() ? null : prompt;
        String desc      = descArea.getText().trim();
        r.target_description = desc.isEmpty() ? null : desc;
        return r;
    }
}
