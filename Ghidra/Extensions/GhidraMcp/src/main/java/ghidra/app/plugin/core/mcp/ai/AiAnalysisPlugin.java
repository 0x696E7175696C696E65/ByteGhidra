/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0
 */
package ghidra.app.plugin.core.mcp.ai;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.mcp.config.ConfigExtractorProvider;
import ghidra.app.plugin.core.mcp.GhidraMcpPluginPackage;
import ghidra.app.plugin.core.mcp.evidence.EvidenceProvider;
import ghidra.app.plugin.core.mcp.explain.ExplainWithEvidenceProvider;
import ghidra.app.plugin.core.mcp.decompilerdiff.DecompilerDiffProvider;
import ghidra.app.plugin.core.mcp.hypotheses.HypothesisProvider;
import ghidra.app.plugin.core.mcp.overlay.SuspiciousControlFlowProvider;
import ghidra.app.plugin.core.mcp.sandbox.SandboxEvidenceProvider;
import ghidra.app.plugin.core.mcp.search.SemanticFunctionSearchProvider;
import ghidra.app.plugin.core.mcp.session.AnalysisTimelineProvider;
import ghidra.app.plugin.core.mcp.tasks.AgentTaskProvider;
import ghidra.app.plugin.core.mcp.triage.TriageDashboardProvider;
import ghidra.app.plugin.core.mcp.types.TypeRecoveryProvider;
import ghidra.app.plugin.core.mcp.yara.YaraDraftProvider;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

//@formatter:off
@PluginInfo(
	status = PluginStatus.UNSTABLE,
	packageName = GhidraMcpPluginPackage.NAME,
	category = PluginCategoryNames.ANALYSIS,
	shortDescription = "AI malware analysis suite",
	description = "Evidence, task, triage, hypothesis, and generation workspace for AI-assisted malware analysis."
)
//@formatter:on
public class AiAnalysisPlugin extends ProgramPlugin {
	private final AiAnalysisService service = AiAnalysisService.shared();
	private final AgentTaskProvider taskProvider;
	private final EvidenceProvider evidenceProvider;
	private final AnalysisTimelineProvider timelineProvider;
	private final TriageDashboardProvider triageProvider;
	private final HypothesisProvider hypothesisProvider;
	private final ExplainWithEvidenceProvider explainProvider;
	private final SemanticFunctionSearchProvider searchProvider;
	private final SuspiciousControlFlowProvider controlFlowProvider;
	private final DecompilerDiffProvider decompilerDiffProvider;
	private final YaraDraftProvider yaraDraftProvider;
	private final ConfigExtractorProvider configExtractorProvider;
	private final TypeRecoveryProvider typeRecoveryProvider;
	private final SandboxEvidenceProvider sandboxEvidenceProvider;

	public AiAnalysisPlugin(PluginTool tool) {
		super(tool);
		taskProvider = new AgentTaskProvider(tool, service.tasks());
		evidenceProvider = new EvidenceProvider(tool, service.evidence());
		timelineProvider = new AnalysisTimelineProvider(tool, service.session());
		triageProvider = new TriageDashboardProvider(tool, service);
		hypothesisProvider = new HypothesisProvider(tool, service.hypotheses());
		explainProvider = new ExplainWithEvidenceProvider(tool, service);
		searchProvider = new SemanticFunctionSearchProvider(tool);
		controlFlowProvider = new SuspiciousControlFlowProvider(tool);
		decompilerDiffProvider = new DecompilerDiffProvider(tool);
		yaraDraftProvider = new YaraDraftProvider(tool, service);
		configExtractorProvider = new ConfigExtractorProvider(tool, service);
		typeRecoveryProvider = new TypeRecoveryProvider(tool);
		sandboxEvidenceProvider = new SandboxEvidenceProvider(tool, service);
		createActions();
	}

	private void createActions() {
		DockingAction runTriage = new DockingAction("Run AI Malware Triage", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				if (currentProgram == null) {
					Msg.showWarn(this, null, "AI Malware Triage", "Open a program before running triage.");
					return;
				}
				service.runTriage(currentProgram, TaskMonitor.DUMMY);
				triageProvider.refresh();
				explainProvider.refresh();
			}
		};
		runTriage.setMenuBarData(new MenuData(new String[] { "AI Analysis", "Run Triage" }));
		tool.addAction(runTriage);

		DockingAction createTask = new DockingAction("Queue AI Triage Task", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				service.tasks().create("Run malware triage",
					"Review imports, strings, memory blocks, and functions for suspicious behavior.");
				service.session().record("task", "Queued AI triage task", "Run malware triage");
			}
		};
		createTask.setMenuBarData(new MenuData(new String[] { "AI Analysis", "Queue Triage Task" }));
		tool.addAction(createTask);

		DockingAction createHypothesis = new DockingAction("Create AI Hypothesis", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				service.hypotheses().create("Malware behavior hypothesis - refine with linked evidence.");
				service.session().record("hypothesis", "Created hypothesis", "Default analyst hypothesis");
			}
		};
		createHypothesis.setMenuBarData(new MenuData(new String[] { "AI Analysis", "Create Hypothesis" }));
		tool.addAction(createHypothesis);
	}

	@Override
	protected void programActivated(Program program) {
		searchProvider.setProgram(program);
		controlFlowProvider.setProgram(program);
		typeRecoveryProvider.setProgram(program);
		sandboxEvidenceProvider.setProgram(program);
	}

	@Override
	protected void dispose() {
		taskProvider.dispose();
		evidenceProvider.dispose();
		timelineProvider.dispose();
		triageProvider.dispose();
		hypothesisProvider.dispose();
		explainProvider.dispose();
		searchProvider.dispose();
		controlFlowProvider.dispose();
		decompilerDiffProvider.dispose();
		yaraDraftProvider.dispose();
		configExtractorProvider.dispose();
		typeRecoveryProvider.dispose();
		sandboxEvidenceProvider.dispose();
		super.dispose();
	}
}
