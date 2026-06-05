/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0
 */
package ghidra.app.plugin.core.mcp.tasks;

import java.util.List;

import javax.swing.table.AbstractTableModel;

public class AgentTaskTableModel extends AbstractTableModel {
	private static final String[] COLUMNS = { "Status", "Title", "Prompt", "Result" };
	private final AgentTaskQueue queue;

	public AgentTaskTableModel(AgentTaskQueue queue) {
		this.queue = queue;
		queue.addChangeListener(this::fireTableDataChanged);
	}

	@Override
	public int getRowCount() {
		return queue.list().size();
	}

	@Override
	public int getColumnCount() {
		return COLUMNS.length;
	}

	@Override
	public String getColumnName(int column) {
		return COLUMNS[column];
	}

	@Override
	public Object getValueAt(int rowIndex, int columnIndex) {
		List<AgentTask> tasks = queue.list();
		AgentTask task = tasks.get(rowIndex);
		return switch (columnIndex) {
			case 0 -> task.status().name();
			case 1 -> task.title();
			case 2 -> task.prompt();
			case 3 -> task.toJson().get("result").getAsString();
			default -> "";
		};
	}
}
