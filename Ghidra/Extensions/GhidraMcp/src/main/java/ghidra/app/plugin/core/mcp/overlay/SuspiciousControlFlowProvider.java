/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0
 */
package ghidra.app.plugin.core.mcp.overlay;

import java.awt.BorderLayout;

import javax.swing.*;

import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;

public class SuspiciousControlFlowProvider extends ComponentProviderAdapter {
	private final JPanel panel = new JPanel(new BorderLayout());
	private final JTextArea results = new JTextArea();
	private Program program;

	public SuspiciousControlFlowProvider(PluginTool tool) {
		super(tool, "AI Suspicious Control Flow", "AI Analysis");
		JButton analyze = new JButton("Find Suspicious Control Flow");
		analyze.addActionListener(e -> refresh());
		results.setEditable(false);
		panel.add(analyze, BorderLayout.NORTH);
		panel.add(new JScrollPane(results), BorderLayout.CENTER);
		setVisible(true);
		addToTool();
	}

	public void setProgram(Program program) {
		this.program = program;
	}

	public void refresh() {
		if (program == null) {
			results.setText("Open a program first.");
			return;
		}
		results.setText(new SuspiciousControlFlowAnalyzer().analyze(program, 50).toString());
	}

	public void dispose() {
		removeFromTool();
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}
}
