/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0
 */
package ghidra.app.plugin.core.mcp.triage;

import java.awt.BorderLayout;
import java.util.List;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;

import ghidra.app.plugin.core.mcp.ai.AiAnalysisService;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;

public class TriageDashboardProvider extends ComponentProviderAdapter {
	private final JPanel panel = new JPanel(new BorderLayout());
	private final TriageTableModel model;

	public TriageDashboardProvider(PluginTool tool, AiAnalysisService service) {
		super(tool, "AI Triage Dashboard", "AI Analysis");
		model = new TriageTableModel(service);
		JTable table = new JTable(model);
		table.setAutoCreateRowSorter(true);
		JButton refresh = new JButton("Refresh");
		refresh.addActionListener(e -> model.fireTableDataChanged());
		panel.add(refresh, BorderLayout.NORTH);
		panel.add(new JScrollPane(table), BorderLayout.CENTER);
		setVisible(true);
		addToTool();
	}

	public void dispose() {
		removeFromTool();
	}

	public void refresh() {
		model.fireTableDataChanged();
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}

	private static class TriageTableModel extends AbstractTableModel {
		private static final String[] COLUMNS = { "Severity", "Category", "Summary", "Evidence" };
		private final AiAnalysisService service;

		TriageTableModel(AiAnalysisService service) {
			this.service = service;
		}

		@Override
		public int getRowCount() {
			TriageReport report = service.lastTriageReport();
			return report == null ? 0 : report.findings().size();
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
			TriageReport report = service.lastTriageReport();
			if (report == null) {
				return "";
			}
			List<TriageFinding> findings = report.findings();
			TriageFinding finding = findings.get(rowIndex);
			return switch (columnIndex) {
				case 0 -> finding.severity();
				case 1 -> finding.category();
				case 2 -> finding.summary();
				case 3 -> finding.evidenceId();
				default -> "";
			};
		}
	}
}
