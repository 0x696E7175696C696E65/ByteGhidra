/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0
 */
package ghidra.app.plugin.core.mcp.evidence;

import java.awt.BorderLayout;

import javax.swing.*;

import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;

public class EvidenceProvider extends ComponentProviderAdapter {
	private final JPanel panel = new JPanel(new BorderLayout());

	public EvidenceProvider(PluginTool tool, EvidenceStore store) {
		super(tool, "AI Evidence", "AI Analysis");
		JTable table = new JTable(new EvidenceTableModel(store));
		table.setAutoCreateRowSorter(true);
		panel.add(new JScrollPane(table), BorderLayout.CENTER);
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
