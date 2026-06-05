/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0
 */
package ghidra.app.plugin.core.mcp.search;

import java.awt.BorderLayout;

import javax.swing.*;

import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;

public class SemanticFunctionSearchProvider extends ComponentProviderAdapter {
	private final JPanel panel = new JPanel(new BorderLayout());
	private final JTextField query = new JTextField();
	private final JTextArea results = new JTextArea();
	private Program program;

	public SemanticFunctionSearchProvider(PluginTool tool) {
		super(tool, "AI Semantic Function Search", "AI Analysis");
		JButton search = new JButton("Search");
		search.addActionListener(e -> runSearch());
		JPanel top = new JPanel(new BorderLayout());
		top.add(query, BorderLayout.CENTER);
		top.add(search, BorderLayout.EAST);
		results.setEditable(false);
		panel.add(top, BorderLayout.NORTH);
		panel.add(new JScrollPane(results), BorderLayout.CENTER);
		setVisible(true);
		addToTool();
	}

	public void setProgram(Program program) {
		this.program = program;
	}

	private void runSearch() {
		if (program == null) {
			results.setText("Open a program first.");
			return;
		}
		results.setText(new SemanticFunctionIndex().search(program, query.getText(), 25).toString());
	}

	public void dispose() {
		removeFromTool();
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}
}
