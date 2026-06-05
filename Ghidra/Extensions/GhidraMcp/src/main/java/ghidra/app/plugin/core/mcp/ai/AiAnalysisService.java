/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0
 */
package ghidra.app.plugin.core.mcp.ai;

import java.util.*;
import java.util.concurrent.*;

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

	private static final String DEFAULT_SESSION_KEY = "no-active-program";

	private final TriageEngine triageEngine = new TriageEngine();
	private final ExecutorService executor = Executors.newSingleThreadExecutor(runnable -> {
		Thread thread = new Thread(runnable, "GhidraMcpAiAnalysis");
		thread.setDaemon(true);
		return thread;
	});
	private final Map<String, AnalysisSession> sessions = new LinkedHashMap<>();
	private AnalysisSession activeSession = new AnalysisSession("No active program", DEFAULT_SESSION_KEY);

	public AiAnalysisService() {
		sessions.put(DEFAULT_SESSION_KEY, activeSession);
	}

	public static AiAnalysisService shared() {
		return SHARED;
	}

	public EvidenceStore evidence() {
		return activeSession.evidence();
	}

	public AgentTaskQueue tasks() {
		return activeSession.tasks();
	}

	public AnalysisSessionRecorder session() {
		return activeSession.recorder();
	}

	public HypothesisStore hypotheses() {
		return activeSession.hypotheses();
	}

	public synchronized AnalysisSession activeSession() {
		return activeSession;
	}

	public synchronized AnalysisSession activateProgram(Program program) {
		if (program == null) {
			return activateSession("No active program", DEFAULT_SESSION_KEY);
		}
		String programName = program.getName();
		String key = programName;
		if (program.getExecutableSHA256() != null && !program.getExecutableSHA256().isBlank()) {
			key = program.getExecutableSHA256();
		}
		return activateSession(programName, key);
	}

	public synchronized AnalysisSession activateSession(String programName, String programKey) {
		String key = programKey == null || programKey.isBlank() ? programName : programKey;
		activeSession = sessions.computeIfAbsent(key, ignored -> new AnalysisSession(programName, key));
		return activeSession;
	}

	public synchronized TriageReport runTriage(Program program, TaskMonitor monitor) {
		AnalysisSession session = activateProgram(program);
		session.recorder().record("triage", "Started malware triage", program.getName());
		TriageReport report = triageEngine.run(program, session.evidence(), monitor);
		session.setLastTriageReport(report);
		session.recorder().record("triage", "Completed malware triage",
			report.findings().size() + " findings");
		return report;
	}

	public AgentTask startTriageTask(Program program) {
		AnalysisSession session = activateProgram(program);
		AgentTask task = session.tasks().create("Run malware triage",
			"Collect evidence from imports, strings, memory blocks, and functions.");
		task.start();
		task.updateProgress(5, "Queued triage");
		executor.submit(() -> {
			try {
				if (task.isCancelRequested()) {
					task.cancel();
					return;
				}
				task.updateProgress(20, "Running triage");
				TriageReport report = triageEngine.run(program, session.evidence(), TaskMonitor.DUMMY);
				if (task.isCancelRequested()) {
					task.cancel();
					return;
				}
				session.setLastTriageReport(report);
				session.recorder().record("triage", "Completed malware triage",
					report.findings().size() + " findings");
				task.complete(report.findings().size() + " findings");
			}
			catch (Exception e) {
				task.fail(e.getMessage());
			}
		});
		return task;
	}

	public synchronized TriageReport lastTriageReport() {
		return activeSession.lastTriageReport();
	}

	public synchronized JsonObject exportSession() {
		return activeSession.toJson();
	}

	public synchronized AnalysisSession importSession(JsonObject sessionJson) {
		AnalysisSession imported = AnalysisSession.fromJson(sessionJson);
		sessions.put(imported.programKey(), imported);
		activeSession = imported;
		return imported;
	}

	public JsonObject status() {
		JsonObject object = new JsonObject();
		AnalysisSession session = activeSession();
		object.addProperty("activeSessionId", session.id());
		object.addProperty("programName", session.programName());
		object.addProperty("programKey", session.programKey());
		object.addProperty("sessionCount", sessions.size());
		object.addProperty("evidenceCount", session.evidence().list().size());
		object.addProperty("taskCount", session.tasks().list().size());
		object.addProperty("sessionEventCount", session.recorder().list().size());
		object.addProperty("hypothesisCount", session.hypotheses().list().size());
		object.addProperty("hasTriageReport", session.lastTriageReport() != null);
		return object;
	}
}
