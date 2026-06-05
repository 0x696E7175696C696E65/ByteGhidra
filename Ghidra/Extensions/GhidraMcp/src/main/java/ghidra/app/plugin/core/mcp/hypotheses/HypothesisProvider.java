/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0
 */
package ghidra.app.plugin.core.mcp.hypotheses;

import java.awt.BorderLayout;
import java.util.List;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;

import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;

public class HypothesisProvider extends ComponentProviderAdapter {
	private final JPanel panel = new JPanel(new BorderLayout());

	public HypothesisProvider(PluginTool tool, HypothesisStore store) {
		super(tool, "AI Hypotheses", "AI Analysis");
		JTable table = new JTable(new HypothesisTableModel(store));
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

	private static class HypothesisTableModel extends AbstractTableModel {
		private static final String[] COLUMNS = { "Status", "Hypothesis", "Evidence" };
		private final HypothesisStore store;

		HypothesisTableModel(HypothesisStore store) {
			this.store = store;
			store.addChangeListener(this::fireTableDataChanged);
		}

		@Override
		public int getRowCount() {
			return store.list().size();
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
			List<Hypothesis> hypotheses = store.list();
			Hypothesis hypothesis = hypotheses.get(rowIndex);
			return switch (columnIndex) {
				case 0 -> hypothesis.status().name();
				case 1 -> hypothesis.text();
				case 2 -> hypothesis.toJson().get("evidenceIds").toString();
				default -> "";
			};
		}
	}
}
