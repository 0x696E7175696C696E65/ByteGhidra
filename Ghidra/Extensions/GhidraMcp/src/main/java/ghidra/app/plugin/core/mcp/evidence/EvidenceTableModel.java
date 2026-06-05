/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0
 */
package ghidra.app.plugin.core.mcp.evidence;

import java.util.List;

import javax.swing.table.AbstractTableModel;

public class EvidenceTableModel extends AbstractTableModel {
	private static final String[] COLUMNS = { "Severity", "Category", "Address", "Function", "Summary" };
	private final EvidenceStore store;

	public EvidenceTableModel(EvidenceStore store) {
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
		List<EvidenceRecord> rows = store.list();
		EvidenceRecord record = rows.get(rowIndex);
		return switch (columnIndex) {
			case 0 -> record.severity();
			case 1 -> record.category();
			case 2 -> record.address();
			case 3 -> record.functionName();
			case 4 -> record.summary();
			default -> "";
		};
	}
}
