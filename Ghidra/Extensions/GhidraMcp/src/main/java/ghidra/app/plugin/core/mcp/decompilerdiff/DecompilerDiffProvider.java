/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0
 */
package ghidra.app.plugin.core.mcp.decompilerdiff;

import java.awt.*;

import javax.swing.*;

import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;

public class DecompilerDiffProvider extends ComponentProviderAdapter {
	private final JPanel panel = new JPanel(new BorderLayout());
	private final JTextArea input = new JTextArea();
	private final JTextArea diff = new JTextArea();
	private DecompilerSnapshot before;
	private DecompilerSnapshot after;

	public DecompilerDiffProvider(PluginTool tool) {
		super(tool, "AI Decompiler Diff", "AI Analysis");
		JButton captureBefore = new JButton("Capture Before");
		JButton captureAfter = new JButton("Capture After");
		captureBefore.addActionListener(e -> {
			before = new DecompilerSnapshot("before", "manual", input.getText());
			updateDiff();
		});
		captureAfter.addActionListener(e -> {
			after = new DecompilerSnapshot("after", "manual", input.getText());
			updateDiff();
		});
		JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT));
		buttons.add(captureBefore);
		buttons.add(captureAfter);
		JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(input),
			new JScrollPane(diff));
		diff.setEditable(false);
		panel.add(buttons, BorderLayout.NORTH);
		panel.add(split, BorderLayout.CENTER);
		setVisible(true);
		addToTool();
	}

	private void updateDiff() {
		diff.setText(DecompilerSnapshot.diff(before, after));
	}

	public void dispose() {
		removeFromTool();
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}
}
