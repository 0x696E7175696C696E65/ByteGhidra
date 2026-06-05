/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0
 */
package ghidra.app.plugin.core.mcp.session;

import java.awt.BorderLayout;
import java.util.List;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;

import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;

public class AnalysisTimelineProvider extends ComponentProviderAdapter {
	private final JPanel panel = new JPanel(new BorderLayout());

	public AnalysisTimelineProvider(PluginTool tool, AnalysisSessionRecorder recorder) {
		super(tool, "AI Session Timeline", "AI Analysis");
		JTable table = new JTable(new TimelineTableModel(recorder));
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

	private static class TimelineTableModel extends AbstractTableModel {
		private static final String[] COLUMNS = { "Type", "Summary", "Details" };
		private final AnalysisSessionRecorder recorder;

		TimelineTableModel(AnalysisSessionRecorder recorder) {
			this.recorder = recorder;
			recorder.addChangeListener(this::fireTableDataChanged);
		}

		@Override
		public int getRowCount() {
			return recorder.list().size();
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
			List<AnalysisSessionEvent> events = recorder.list();
			AnalysisSessionEvent event = events.get(rowIndex);
			return switch (columnIndex) {
				case 0 -> event.type();
				case 1 -> event.summary();
				case 2 -> event.details();
				default -> "";
			};
		}
	}
}
