/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0
 */
package ghidra.app.plugin.core.mcp.sandbox;

import java.awt.BorderLayout;
import java.nio.file.Path;

import javax.swing.*;

import ghidra.app.plugin.core.mcp.ai.AiAnalysisService;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;

public class SandboxEvidenceProvider extends ComponentProviderAdapter {
	private final JPanel panel = new JPanel(new BorderLayout());
	private final JTextField path = new JTextField();
	private final JTextArea status = new JTextArea();
	private final AiAnalysisService service;
	private Program program;

	public SandboxEvidenceProvider(PluginTool tool, AiAnalysisService service) {
		super(tool, "AI Sandbox Evidence Import", "AI Analysis");
		this.service = service;
		JButton importButton = new JButton("Import Sandbox Evidence");
		importButton.addActionListener(e -> importEvidence());
		JPanel top = new JPanel(new BorderLayout());
		top.add(path, BorderLayout.CENTER);
		top.add(importButton, BorderLayout.EAST);
		status.setEditable(false);
		panel.add(top, BorderLayout.NORTH);
		panel.add(new JScrollPane(status), BorderLayout.CENTER);
		setVisible(true);
		addToTool();
	}

	public void setProgram(Program program) {
		this.program = program;
	}

	private void importEvidence() {
		try {
			int count = new SandboxEvidenceImporter().importFile(Path.of(path.getText()), program,
				service.evidence());
			service.session().record("sandbox", "Imported sandbox evidence", count + " events");
			status.setText("Imported " + count + " runtime events.");
		}
		catch (Exception e) {
			status.setText("Import failed: " + e.getMessage());
		}
	}

	public void dispose() {
		removeFromTool();
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}
}
