/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0
 */
package ghidra.app.plugin.core.mcp.explain;

import java.awt.BorderLayout;

import javax.swing.*;

import ghidra.app.plugin.core.mcp.ai.AiAnalysisService;
import ghidra.app.plugin.core.mcp.evidence.EvidenceRecord;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;

public class ExplainWithEvidenceProvider extends ComponentProviderAdapter {
	private final JPanel panel = new JPanel(new BorderLayout());
	private final JTextArea text = new JTextArea();
	private final AiAnalysisService service;

	public ExplainWithEvidenceProvider(PluginTool tool, AiAnalysisService service) {
		super(tool, "AI Explain With Evidence", "AI Analysis");
		this.service = service;
		text.setEditable(false);
		JButton explain = new JButton("Explain Top Evidence");
		explain.addActionListener(e -> refresh());
		panel.add(explain, BorderLayout.NORTH);
		panel.add(new JScrollPane(text), BorderLayout.CENTER);
		setVisible(true);
		addToTool();
	}

	public void refresh() {
		if (service.evidence().list().isEmpty()) {
			text.setText("No evidence has been collected yet. Run triage first.");
			return;
		}
		StringBuilder builder = new StringBuilder();
		for (EvidenceRecord record : service.evidence().list()) {
			builder.append(record.summary()).append("\n")
				.append(new EvidenceExplainer(service.evidence()).explain(record.id()).get("explanation").getAsString())
				.append("\n\n");
		}
		text.setText(builder.toString());
	}

	public void dispose() {
		removeFromTool();
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}
}
