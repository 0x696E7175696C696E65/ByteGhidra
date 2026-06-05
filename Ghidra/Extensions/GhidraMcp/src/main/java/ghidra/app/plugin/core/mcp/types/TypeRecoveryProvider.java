/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0
 */
package ghidra.app.plugin.core.mcp.types;

import java.awt.BorderLayout;

import javax.swing.*;

import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;

public class TypeRecoveryProvider extends ComponentProviderAdapter {
	private final JPanel panel = new JPanel(new BorderLayout());
	private final JTextArea suggestions = new JTextArea();
	private Program program;

	public TypeRecoveryProvider(PluginTool tool) {
		super(tool, "AI Type Recovery Suggestions", "AI Analysis");
		JButton refresh = new JButton("Suggest Type Recovery");
		refresh.addActionListener(e -> refresh());
		panel.add(refresh, BorderLayout.NORTH);
		panel.add(new JScrollPane(suggestions), BorderLayout.CENTER);
		setVisible(true);
		addToTool();
	}

	public void setProgram(Program program) {
		this.program = program;
	}

	public void refresh() {
		if (program == null) {
			suggestions.setText("Open a program first.");
			return;
		}
		suggestions.setText(new TypeRecoverySuggestion().suggest(program, 50).toString());
	}

	public void dispose() {
		removeFromTool();
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}
}
