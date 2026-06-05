/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0
 */
package ghidra.app.plugin.core.mcp.ai;

import com.google.gson.JsonObject;

import ghidra.app.plugin.core.mcp.evidence.*;
import ghidra.app.plugin.core.mcp.hypotheses.*;
import ghidra.app.plugin.core.mcp.session.*;
import ghidra.app.plugin.core.mcp.tasks.*;
import ghidra.app.plugin.core.mcp.triage.*;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public class AiAnalysisService {
	private static final AiAnalysisService SHARED = new AiAnalysisService();

	private final EvidenceStore evidenceStore = new EvidenceStore();
	private final AgentTaskQueue taskQueue = new AgentTaskQueue();
	private final AnalysisSessionRecorder sessionRecorder = new AnalysisSessionRecorder();
	private final HypothesisStore hypothesisStore = new HypothesisStore();
	private final TriageEngine triageEngine = new TriageEngine();
	private TriageReport lastTriageReport;

	public static AiAnalysisService shared() {
		return SHARED;
	}

	public EvidenceStore evidence() {
		return evidenceStore;
	}

	public AgentTaskQueue tasks() {
		return taskQueue;
	}

	public AnalysisSessionRecorder session() {
		return sessionRecorder;
	}

	public HypothesisStore hypotheses() {
		return hypothesisStore;
	}

	public synchronized TriageReport runTriage(Program program, TaskMonitor monitor) {
		sessionRecorder.record("triage", "Started malware triage", program.getName());
		lastTriageReport = triageEngine.run(program, evidenceStore, monitor);
		sessionRecorder.record("triage", "Completed malware triage",
			lastTriageReport.findings().size() + " findings");
		return lastTriageReport;
	}

	public synchronized TriageReport lastTriageReport() {
		return lastTriageReport;
	}

	public JsonObject status() {
		JsonObject object = new JsonObject();
		object.addProperty("evidenceCount", evidenceStore.list().size());
		object.addProperty("taskCount", taskQueue.list().size());
		object.addProperty("sessionEventCount", sessionRecorder.list().size());
		object.addProperty("hypothesisCount", hypothesisStore.list().size());
		object.addProperty("hasTriageReport", lastTriageReport != null);
		return object;
	}
}
