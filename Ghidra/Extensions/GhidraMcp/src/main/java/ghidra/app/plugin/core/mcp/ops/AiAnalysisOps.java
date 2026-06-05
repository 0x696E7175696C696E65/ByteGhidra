/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0
 */
package ghidra.app.plugin.core.mcp.ops;

import java.nio.file.Path;

import com.google.gson.*;

import ghidra.app.plugin.core.mcp.ai.AiAnalysisService;
import ghidra.app.plugin.core.mcp.bridge.GhidraMcpResponse;
import ghidra.app.plugin.core.mcp.config.ConfigExtractorDraft;
import ghidra.app.plugin.core.mcp.evidence.EvidenceRecord;
import ghidra.app.plugin.core.mcp.explain.EvidenceExplainer;
import ghidra.app.plugin.core.mcp.hypotheses.Hypothesis;
import ghidra.app.plugin.core.mcp.overlay.SuspiciousControlFlowAnalyzer;
import ghidra.app.plugin.core.mcp.sandbox.SandboxEvidenceImporter;
import ghidra.app.plugin.core.mcp.search.SemanticFunctionIndex;
import ghidra.app.plugin.core.mcp.tasks.AgentTask;
import ghidra.app.plugin.core.mcp.triage.TriageReport;
import ghidra.app.plugin.core.mcp.types.TypeRecoverySuggestion;
import ghidra.app.plugin.core.mcp.yara.YaraRuleGenerator;
import ghidra.program.model.listing.Program;

final class AiAnalysisOps {
	private AiAnalysisOps() {
	}

	static void register(OperationRegistry registry) {
		registry.register(op("ai_status", GhidraMcpOperation.OperationKind.READ_ONLY,
			(context, params) -> GhidraMcpResponse.ok(service().status())));
		registry.register(op("create_agent_task", GhidraMcpOperation.OperationKind.SUITE_STATE_WRITE,
			AiAnalysisOps::createTask));
		registry.register(op("list_agent_tasks", GhidraMcpOperation.OperationKind.READ_ONLY,
			(context, params) -> GhidraMcpResponse.ok(paginate(service().tasks().toJsonArray(), params,
				"status"))));
		registry.register(op("approve_agent_task", GhidraMcpOperation.OperationKind.SUITE_STATE_WRITE,
			(context, params) -> setTaskStatus(params, AgentTask.Status.APPROVED)));
		registry.register(op("cancel_agent_task", GhidraMcpOperation.OperationKind.SUITE_STATE_WRITE,
			AiAnalysisOps::cancelTask));
		registry.register(op("run_triage", GhidraMcpOperation.OperationKind.SUITE_STATE_WRITE,
			AiAnalysisOps::runTriage));
		registry.register(op("start_triage_task", GhidraMcpOperation.OperationKind.SUITE_STATE_WRITE,
			AiAnalysisOps::startTriageTask));
		registry.register(op("list_evidence", GhidraMcpOperation.OperationKind.READ_ONLY,
			(context, params) -> GhidraMcpResponse.ok(paginate(service().evidence().toJsonArray(), params,
				"category", "severity", "source", "function"))));
		registry.register(op("get_evidence", GhidraMcpOperation.OperationKind.READ_ONLY,
			AiAnalysisOps::getEvidence));
		registry.register(op("explain_with_evidence", GhidraMcpOperation.OperationKind.READ_ONLY,
			AiAnalysisOps::explainEvidence));
		registry.register(op("list_session_events", GhidraMcpOperation.OperationKind.READ_ONLY,
			(context, params) -> GhidraMcpResponse.ok(paginate(service().session().toJsonArray(), params))));
		registry.register(op("export_ai_session", GhidraMcpOperation.OperationKind.READ_ONLY,
			(context, params) -> GhidraMcpResponse.ok(service().exportSession())));
		registry.register(op("import_ai_session", GhidraMcpOperation.OperationKind.SUITE_STATE_WRITE,
			AiAnalysisOps::importAiSession));
		registry.register(op("create_hypothesis", GhidraMcpOperation.OperationKind.SUITE_STATE_WRITE,
			AiAnalysisOps::createHypothesis));
		registry.register(op("link_evidence", GhidraMcpOperation.OperationKind.SUITE_STATE_WRITE,
			AiAnalysisOps::linkEvidence));
		registry.register(op("set_hypothesis_status", GhidraMcpOperation.OperationKind.SUITE_STATE_WRITE,
			AiAnalysisOps::setHypothesisStatus));
		registry.register(op("list_hypotheses", GhidraMcpOperation.OperationKind.READ_ONLY,
			(context, params) -> GhidraMcpResponse.ok(paginate(service().hypotheses().toJsonArray(), params,
				"status"))));
		registry.register(op("semantic_function_search", GhidraMcpOperation.OperationKind.READ_ONLY,
			AiAnalysisOps::semanticFunctionSearch));
		registry.register(op("find_suspicious_control_flow", GhidraMcpOperation.OperationKind.READ_ONLY,
			AiAnalysisOps::findSuspiciousControlFlow));
		registry.register(op("draft_yara_rule", GhidraMcpOperation.OperationKind.READ_ONLY,
			AiAnalysisOps::draftYaraRule));
		registry.register(op("draft_config_extractor", GhidraMcpOperation.OperationKind.READ_ONLY,
			(context, params) -> GhidraMcpResponse.ok(
				new ConfigExtractorDraft().draft(service().evidence()))));
		registry.register(op("suggest_type_recovery", GhidraMcpOperation.OperationKind.READ_ONLY,
			AiAnalysisOps::suggestTypeRecovery));
		registry.register(op("import_sandbox_evidence", GhidraMcpOperation.OperationKind.SUITE_STATE_WRITE,
			AiAnalysisOps::importSandboxEvidence));
		registry.register(op("map_runtime_event_to_function", GhidraMcpOperation.OperationKind.READ_ONLY,
			AiAnalysisOps::mapRuntimeEventToFunction));
	}

	private static GhidraMcpOperation op(String name, GhidraMcpOperation.OperationKind kind,
			OperationBody body) {
		return new GhidraMcpOperation() {
			@Override
			public String name() {
				return name;
			}

			@Override
			public OperationKind kind() {
				return kind;
			}

			@Override
			public GhidraMcpResponse execute(GhidraMcpContext context, JsonObject params) throws Exception {
				return body.execute(context, params);
			}
		};
	}

	private static JsonObject paginate(JsonArray array, JsonObject params, String... filterFields) {
		int offset = OperationUtils.intParam(params, "offset", 0, 0, Integer.MAX_VALUE);
		int limit = OperationUtils.intParam(params, "limit", OperationUtils.DEFAULT_LIMIT, 1,
			OperationUtils.MAX_LIMIT);
		JsonArray filtered = new JsonArray();
		for (JsonElement element : array) {
			if (element.isJsonObject() && matchesFilters(element.getAsJsonObject(), params, filterFields)) {
				filtered.add(element);
			}
		}
		JsonArray items = new JsonArray();
		for (int i = offset; i < filtered.size() && items.size() < limit; i++) {
			items.add(filtered.get(i));
		}
		JsonObject result = new JsonObject();
		result.add("items", items);
		result.addProperty("total", filtered.size());
		result.addProperty("offset", offset);
		result.addProperty("limit", limit);
		result.addProperty("truncated", offset + items.size() < filtered.size());
		return result;
	}

	private static boolean matchesFilters(JsonObject object, JsonObject params, String... fields) {
		for (String field : fields) {
			if (params.has(field) && !params.get(field).isJsonNull()) {
				if (!object.has(field) ||
					!object.get(field).getAsString().equalsIgnoreCase(params.get(field).getAsString())) {
					return false;
				}
			}
		}
		return true;
	}

	private static GhidraMcpResponse createTask(GhidraMcpContext context, JsonObject params) {
		String title = OperationUtils.requiredString(params, "title");
		String prompt = OperationUtils.optionalString(params, "prompt", title);
		AgentTask task = service().tasks().create(title, prompt);
		service().session().record("task", "Created agent task", title);
		return GhidraMcpResponse.ok(task.toJson());
	}

	private static GhidraMcpResponse setTaskStatus(JsonObject params, AgentTask.Status status) {
		String id = OperationUtils.requiredString(params, "id");
		AgentTask task = service().tasks().setStatus(id, status);
		if (task == null) {
			return GhidraMcpResponse.error("not_found", "Unknown task id: " + id);
		}
		service().session().record("task", "Updated task status", id + " -> " + status.name());
		return GhidraMcpResponse.ok(task.toJson());
	}

	private static GhidraMcpResponse cancelTask(GhidraMcpContext context, JsonObject params) {
		String id = OperationUtils.requiredString(params, "id");
		AgentTask task = service().tasks().cancel(id);
		if (task == null) {
			return GhidraMcpResponse.error("not_found", "Unknown task id: " + id);
		}
		service().session().record("task", "Cancellation requested", id);
		return GhidraMcpResponse.ok(task.toJson());
	}

	private static GhidraMcpResponse runTriage(GhidraMcpContext context, JsonObject params) {
		Program program = OperationUtils.requireProgram(context);
		TriageReport report = service().runTriage(program, context.monitor());
		return GhidraMcpResponse.ok(report.toJson());
	}

	private static GhidraMcpResponse startTriageTask(GhidraMcpContext context, JsonObject params) {
		Program program = OperationUtils.requireProgram(context);
		return GhidraMcpResponse.ok(service().startTriageTask(program).toJson());
	}

	private static GhidraMcpResponse getEvidence(GhidraMcpContext context, JsonObject params) {
		String id = OperationUtils.requiredString(params, "id");
		EvidenceRecord record = service().evidence().get(id);
		if (record == null) {
			return GhidraMcpResponse.error("not_found", "Unknown evidence id: " + id);
		}
		return GhidraMcpResponse.ok(record.toJson());
	}

	private static GhidraMcpResponse explainEvidence(GhidraMcpContext context, JsonObject params) {
		String id = OperationUtils.optionalString(params, "id", null);
		EvidenceExplainer explainer = new EvidenceExplainer(service().evidence());
		if (id == null) {
			int limit = OperationUtils.intParam(params, "limit", 5, 1, 25);
			return GhidraMcpResponse.ok(explainer.explainTopFindings(limit));
		}
		return GhidraMcpResponse.ok(explainer.explain(id));
	}

	private static GhidraMcpResponse createHypothesis(GhidraMcpContext context, JsonObject params) {
		String text = OperationUtils.requiredString(params, "text");
		Hypothesis hypothesis = service().hypotheses().create(text);
		service().session().record("hypothesis", "Created hypothesis", text);
		return GhidraMcpResponse.ok(hypothesis.toJson());
	}

	private static GhidraMcpResponse importAiSession(GhidraMcpContext context, JsonObject params) {
		JsonObject session = params.has("session") && params.get("session").isJsonObject()
				? params.getAsJsonObject("session")
				: params;
		return GhidraMcpResponse.ok(service().importSession(session).toJson());
	}

	private static GhidraMcpResponse linkEvidence(GhidraMcpContext context, JsonObject params) {
		String hypothesisId = OperationUtils.requiredString(params, "hypothesisId");
		String evidenceId = OperationUtils.requiredString(params, "evidenceId");
		Hypothesis hypothesis = service().hypotheses().get(hypothesisId);
		if (hypothesis == null || service().evidence().get(evidenceId) == null) {
			return GhidraMcpResponse.error("not_found", "Unknown hypothesis or evidence id");
		}
		hypothesis.linkEvidence(evidenceId);
		service().session().record("hypothesis", "Linked evidence to hypothesis",
			hypothesisId + " <- " + evidenceId);
		return GhidraMcpResponse.ok(hypothesis.toJson());
	}

	private static GhidraMcpResponse setHypothesisStatus(GhidraMcpContext context, JsonObject params) {
		String id = OperationUtils.requiredString(params, "id");
		String statusText = OperationUtils.requiredString(params, "status");
		Hypothesis hypothesis = service().hypotheses().get(id);
		if (hypothesis == null) {
			return GhidraMcpResponse.error("not_found", "Unknown hypothesis id: " + id);
		}
		hypothesis.setStatus(Hypothesis.Status.valueOf(statusText.toUpperCase()));
		service().session().record("hypothesis", "Updated hypothesis status",
			id + " -> " + hypothesis.status().name());
		return GhidraMcpResponse.ok(hypothesis.toJson());
	}

	private static GhidraMcpResponse semanticFunctionSearch(GhidraMcpContext context, JsonObject params) {
		Program program = OperationUtils.requireProgram(context);
		String query = OperationUtils.requiredString(params, "query");
		int limit = OperationUtils.intParam(params, "limit", 25, 1, 100);
		return GhidraMcpResponse.ok(new SemanticFunctionIndex().search(program, query, limit));
	}

	private static GhidraMcpResponse findSuspiciousControlFlow(GhidraMcpContext context,
			JsonObject params) {
		Program program = OperationUtils.requireProgram(context);
		int limit = OperationUtils.intParam(params, "limit", 50, 1, 200);
		return GhidraMcpResponse.ok(new SuspiciousControlFlowAnalyzer().analyze(program, limit));
	}

	private static GhidraMcpResponse draftYaraRule(GhidraMcpContext context, JsonObject params) {
		String familyName = OperationUtils.optionalString(params, "familyName", "ghidra_ai_sample");
		return GhidraMcpResponse.ok(new YaraRuleGenerator().draft(familyName, service().evidence()).toJson());
	}

	private static GhidraMcpResponse suggestTypeRecovery(GhidraMcpContext context, JsonObject params) {
		Program program = OperationUtils.requireProgram(context);
		int limit = OperationUtils.intParam(params, "limit", 50, 1, 200);
		return GhidraMcpResponse.ok(new TypeRecoverySuggestion().suggest(program, limit));
	}

	private static GhidraMcpResponse importSandboxEvidence(GhidraMcpContext context, JsonObject params)
			throws Exception {
		Program program = OperationUtils.requireProgram(context);
		Path path = Path.of(OperationUtils.requiredString(params, "path"));
		SandboxEvidenceImporter.ImportResult result =
			new SandboxEvidenceImporter().importFile(path, program, service().evidence());
		service().session().record("sandbox", "Imported sandbox evidence",
			result.imported() + " imported, " + result.skipped() + " skipped");
		JsonObject object = result.toJson();
		object.addProperty("path", path.toString());
		return GhidraMcpResponse.ok(object);
	}

	private static GhidraMcpResponse mapRuntimeEventToFunction(GhidraMcpContext context,
			JsonObject params) {
		Program program = OperationUtils.requireProgram(context);
		return GhidraMcpResponse.ok(new SandboxEvidenceImporter().mapRuntimeEvent(program, params));
	}

	private static AiAnalysisService service() {
		return AiAnalysisService.shared();
	}

	private interface OperationBody {
		GhidraMcpResponse execute(GhidraMcpContext context, JsonObject params) throws Exception;
	}
}
