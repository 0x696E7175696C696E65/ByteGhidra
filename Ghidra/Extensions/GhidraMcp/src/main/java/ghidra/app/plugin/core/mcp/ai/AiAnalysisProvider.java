/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0
 */
package ghidra.app.plugin.core.mcp.ai;

import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.util.regex.PatternSyntaxException;

import javax.swing.*;
import javax.swing.table.TableRowSorter;

import com.google.gson.GsonBuilder;

import ghidra.app.plugin.core.mcp.evidence.EvidenceTableModel;
import ghidra.app.plugin.core.mcp.tasks.AgentTaskTableModel;
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

public class AiAnalysisProvider extends ComponentProviderAdapter {
	private final AiAnalysisService service;
	private final PluginTool tool;
	private final JPanel panel = new JPanel(new BorderLayout());
	private final EvidenceTableModel evidenceModel;
	private final AgentTaskTableModel taskModel;
	private final JTextArea timeline = new JTextArea();
	private final JTextField filter = new JTextField();
	private Program program;

	public AiAnalysisProvider(PluginTool tool, AiAnalysisService service) {
		super(tool, "AI Analysis Workspace", "AI Analysis");
		this.tool = tool;
		this.service = service;
		this.evidenceModel = new EvidenceTableModel(service.evidence());
		this.taskModel = new AgentTaskTableModel(service.tasks());

		JTabbedPane tabs = new JTabbedPane();
		tabs.addTab("Evidence", evidenceTab());
		tabs.addTab("Tasks", tasksTab());
		tabs.addTab("Timeline", timelineTab());
		tabs.addTab("Actions", actionsTab());
		panel.add(tabs, BorderLayout.CENTER);
		setVisible(true);
		addToTool();
	}

	public void setProgram(Program program) {
		this.program = program;
		refreshTimeline();
	}

	private JComponent evidenceTab() {
		JTable table = new JTable(evidenceModel);
		TableRowSorter<EvidenceTableModel> sorter = new TableRowSorter<>(evidenceModel);
		table.setRowSorter(sorter);
		filter.getDocument().addDocumentListener((SimpleDocumentListener) e -> applyFilter(sorter));
		table.addMouseListener(new java.awt.event.MouseAdapter() {
			@Override
			public void mouseClicked(java.awt.event.MouseEvent e) {
				if (e.getClickCount() == 2 && table.getSelectedRow() >= 0) {
					int modelRow = table.convertRowIndexToModel(table.getSelectedRow());
					Object value = evidenceModel.getValueAt(modelRow, 2);
					navigate(String.valueOf(value));
				}
			}
		});

		JPanel top = new JPanel(new BorderLayout());
		top.add(new JLabel("Filter severity/category/source/function: "), BorderLayout.WEST);
		top.add(filter, BorderLayout.CENTER);
		JPanel wrapper = new JPanel(new BorderLayout());
		wrapper.add(top, BorderLayout.NORTH);
		wrapper.add(new JScrollPane(table), BorderLayout.CENTER);
		return wrapper;
	}

	private JComponent tasksTab() {
		return new JScrollPane(new JTable(taskModel));
	}

	private JComponent timelineTab() {
		timeline.setEditable(false);
		JButton refresh = new JButton("Refresh Timeline");
		refresh.addActionListener(e -> refreshTimeline());
		JPanel wrapper = new JPanel(new BorderLayout());
		wrapper.add(refresh, BorderLayout.NORTH);
		wrapper.add(new JScrollPane(timeline), BorderLayout.CENTER);
		return wrapper;
	}

	private JComponent actionsTab() {
		JPanel panel = new JPanel(new GridLayout(0, 1, 4, 4));
		panel.add(button("Start Background Triage", () -> {
			if (program != null) {
				service.startTriageTask(program);
			}
		}));
		panel.add(button("Template: Find Config Parser", () ->
			template("Find config parser", "Trace string and API evidence to identify the config parser.")));
		panel.add(button("Template: Trace C2 Strings", () ->
			template("Trace C2 strings", "Follow network string xrefs and summarize beacon construction.")));
		panel.add(button("Template: Summarize Persistence", () ->
			template("Summarize persistence", "Review persistence evidence and explain startup mechanisms.")));
		panel.add(button("Template: Draft YARA", () ->
			template("Draft YARA", "Use cited evidence to draft a conservative YARA rule.")));
		panel.add(button("Copy Session JSON", this::copySessionJson));
		return panel;
	}

	private JButton button(String label, Runnable action) {
		JButton button = new JButton(label);
		button.addActionListener(e -> action.run());
		return button;
	}

	private void template(String title, String prompt) {
		service.tasks().create(title, prompt);
		service.session().record("task", "Queued task template", title);
	}

	private void copySessionJson() {
		String json = new GsonBuilder().setPrettyPrinting().create().toJson(service.exportSession());
		Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(json), null);
		tool.setStatusInfo("AI analysis session JSON copied to clipboard");
	}

	private void applyFilter(TableRowSorter<EvidenceTableModel> sorter) {
		try {
			String text = filter.getText();
			sorter.setRowFilter(text == null || text.isBlank() ? null : RowFilter.regexFilter("(?i)" + text));
		}
		catch (PatternSyntaxException ignored) {
			tool.setStatusInfo("Invalid AI evidence filter regex");
		}
	}

	private void navigate(String addressText) {
		if (program == null || addressText == null || addressText.isBlank() || "null".equals(addressText)) {
			return;
		}
		Address address = program.getAddressFactory().getAddress(addressText);
		GoToService goToService = tool.getService(GoToService.class);
		if (address != null && goToService != null) {
			goToService.goTo(address);
		}
	}

	private void refreshTimeline() {
		StringBuilder builder = new StringBuilder();
		service.session().list().forEach(event -> builder.append(event.toJson()).append('\n'));
		timeline.setText(builder.toString());
	}

	public void dispose() {
		removeFromTool();
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}

	private interface SimpleDocumentListener extends javax.swing.event.DocumentListener {
		void changed(javax.swing.event.DocumentEvent e);

		@Override
		default void insertUpdate(javax.swing.event.DocumentEvent e) {
			changed(e);
		}

		@Override
		default void removeUpdate(javax.swing.event.DocumentEvent e) {
			changed(e);
		}

		@Override
		default void changedUpdate(javax.swing.event.DocumentEvent e) {
			changed(e);
		}
	}
}
