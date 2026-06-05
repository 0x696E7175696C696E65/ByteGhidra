/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0
 */
package ghidra.app.plugin.core.mcp.tasks;

import java.awt.BorderLayout;

import javax.swing.*;

import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;

public class AgentTaskProvider extends ComponentProviderAdapter {
	private final JPanel panel = new JPanel(new BorderLayout());

	public AgentTaskProvider(PluginTool tool, AgentTaskQueue queue) {
		super(tool, "AI Agent Tasks", "AI Analysis");
		JTable table = new JTable(new AgentTaskTableModel(queue));
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
