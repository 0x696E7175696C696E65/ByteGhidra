/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0
 */
package ghidra.app.plugin.core.mcp.yara;

import java.awt.BorderLayout;

import javax.swing.*;

import ghidra.app.plugin.core.mcp.ai.AiAnalysisService;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;

public class YaraDraftProvider extends ComponentProviderAdapter {
	private final JPanel panel = new JPanel(new BorderLayout());
	private final JTextArea ruleText = new JTextArea();
	private final AiAnalysisService service;

	public YaraDraftProvider(PluginTool tool, AiAnalysisService service) {
		super(tool, "AI YARA Draft", "AI Analysis");
		this.service = service;
		JButton draft = new JButton("Draft YARA From Evidence");
		draft.addActionListener(e -> ruleText.setText(
			new YaraRuleGenerator().draft("ghidra_ai_sample", service.evidence()).ruleText()));
		panel.add(draft, BorderLayout.NORTH);
		panel.add(new JScrollPane(ruleText), BorderLayout.CENTER);
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
