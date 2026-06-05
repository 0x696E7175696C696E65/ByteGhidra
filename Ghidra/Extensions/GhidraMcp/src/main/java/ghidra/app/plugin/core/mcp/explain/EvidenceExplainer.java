/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0
 */
package ghidra.app.plugin.core.mcp.explain;

import java.util.List;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.app.plugin.core.mcp.evidence.*;

public class EvidenceExplainer {
	private final EvidenceStore store;

	public EvidenceExplainer(EvidenceStore store) {
		this.store = store;
	}

	public JsonObject explain(String evidenceId) {
		EvidenceRecord record = store.get(evidenceId);
		if (record == null) {
			JsonObject missing = new JsonObject();
			missing.addProperty("error", "Unknown evidence id: " + evidenceId);
			return missing;
		}
		JsonObject object = new JsonObject();
		object.addProperty("summary", record.summary());
		object.addProperty("explanation", buildExplanation(record));
		JsonArray citations = new JsonArray();
		citations.add(record.toJson());
		object.add("citations", citations);
		return object;
	}

	public JsonObject explainTopFindings(int limit) {
		JsonObject object = new JsonObject();
		JsonArray explanations = new JsonArray();
		List<EvidenceRecord> records = store.list();
		for (int i = 0; i < Math.min(limit, records.size()); i++) {
			explanations.add(explain(records.get(i).id()));
		}
		object.add("explanations", explanations);
		return object;
	}

	private String buildExplanation(EvidenceRecord record) {
		String location = record.address() == null ? "no concrete address" : "address " + record.address();
		String function = record.functionName() == null ? "no containing function" :
			"function " + record.functionName();
		return record.severity() + " " + record.category() + " evidence at " + location +
			" with " + function + ". This claim is grounded in evidence record " + record.id() +
			" and should be treated as a lead until confirmed by the analyst.";
	}
}
