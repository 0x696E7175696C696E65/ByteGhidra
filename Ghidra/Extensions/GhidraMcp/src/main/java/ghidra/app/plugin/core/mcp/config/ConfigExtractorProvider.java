/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0
 */
package ghidra.app.plugin.core.mcp.config;

import java.awt.BorderLayout;

import javax.swing.*;

import ghidra.app.plugin.core.mcp.ai.AiAnalysisService;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;

public class ConfigExtractorProvider extends ComponentProviderAdapter {
	private final JPanel panel = new JPanel(new BorderLayout());
	private final JTextArea spec = new JTextArea();

	public ConfigExtractorProvider(PluginTool tool, AiAnalysisService service) {
		super(tool, "AI Config Extractor Draft", "AI Analysis");
		JButton draft = new JButton("Draft Config Extractor Spec");
		draft.addActionListener(e -> spec.setText(new ConfigExtractorDraft().draft(service.evidence()).toString()));
		panel.add(draft, BorderLayout.NORTH);
		panel.add(new JScrollPane(spec), BorderLayout.CENTER);
		setVisible(true);
		addToTool();
	}

	public void dispose() {
		removeFromTool();
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}
}
