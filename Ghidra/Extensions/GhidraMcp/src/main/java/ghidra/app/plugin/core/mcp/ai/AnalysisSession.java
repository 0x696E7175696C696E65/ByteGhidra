/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0
 */
package ghidra.app.plugin.core.mcp.ai;

import java.time.Instant;
import java.util.UUID;

import com.google.gson.JsonObject;

import ghidra.app.plugin.core.mcp.evidence.EvidenceStore;
import ghidra.app.plugin.core.mcp.hypotheses.HypothesisStore;
import ghidra.app.plugin.core.mcp.session.AnalysisSessionRecorder;
import ghidra.app.plugin.core.mcp.tasks.AgentTaskQueue;
import ghidra.app.plugin.core.mcp.triage.TriageReport;

public class AnalysisSession {
	public static final int SCHEMA_VERSION = 1;

	private final String id;
	private final String programName;
	private final String programKey;
	private final Instant createdAt;
	private final EvidenceStore evidenceStore = new EvidenceStore();
	private final AgentTaskQueue taskQueue = new AgentTaskQueue();
	private final AnalysisSessionRecorder recorder = new AnalysisSessionRecorder();
	private final HypothesisStore hypothesisStore = new HypothesisStore();
	private TriageReport lastTriageReport;

	public AnalysisSession(String programName, String programKey) {
		this("session-" + UUID.randomUUID(), programName, programKey, Instant.now());
	}

	private AnalysisSession(String id, String programName, String programKey, Instant createdAt) {
		this.id = id;
		this.programName = programName;
		this.programKey = programKey;
		this.createdAt = createdAt;
	}

	public String id() {
		return id;
	}

	public String programName() {
		return programName;
	}

	public String programKey() {
		return programKey;
	}

	public EvidenceStore evidence() {
		return evidenceStore;
	}

	public AgentTaskQueue tasks() {
		return taskQueue;
	}

	public AnalysisSessionRecorder recorder() {
		return recorder;
	}

	public HypothesisStore hypotheses() {
		return hypothesisStore;
	}

	public TriageReport lastTriageReport() {
		return lastTriageReport;
	}

	public void setLastTriageReport(TriageReport report) {
		this.lastTriageReport = report;
	}

	public JsonObject toJson() {
		JsonObject object = new JsonObject();
		object.addProperty("schemaVersion", SCHEMA_VERSION);
		object.addProperty("id", id);
		object.addProperty("programName", programName);
		object.addProperty("programKey", programKey);
		object.addProperty("createdAt", createdAt.toString());
		object.add("evidence", evidenceStore.toJsonArray());
		object.add("tasks", taskQueue.toJsonArray());
		object.add("sessionEvents", recorder.toJsonArray());
		object.add("hypotheses", hypothesisStore.toJsonArray());
		if (lastTriageReport != null) {
			object.add("lastTriageReport", lastTriageReport.toJson());
		}
		return object;
	}

	public static AnalysisSession fromJson(JsonObject object) {
		AnalysisSession session = new AnalysisSession(get(object, "id"),
			get(object, "programName"), get(object, "programKey"),
			object.has("createdAt") ? Instant.parse(object.get("createdAt").getAsString()) : Instant.now());
		if (object.has("evidence") && object.get("evidence").isJsonArray()) {
			session.evidence().importJsonArray(object.getAsJsonArray("evidence"));
		}
		if (object.has("tasks") && object.get("tasks").isJsonArray()) {
			session.tasks().importJsonArray(object.getAsJsonArray("tasks"));
		}
		if (object.has("sessionEvents") && object.get("sessionEvents").isJsonArray()) {
			session.recorder().importJsonArray(object.getAsJsonArray("sessionEvents"));
		}
		if (object.has("hypotheses") && object.get("hypotheses").isJsonArray()) {
			session.hypotheses().importJsonArray(object.getAsJsonArray("hypotheses"));
		}
		return session;
	}

	private static String get(JsonObject object, String name) {
		return object.has(name) && !object.get(name).isJsonNull() ? object.get(name).getAsString() : "";
	}
}
