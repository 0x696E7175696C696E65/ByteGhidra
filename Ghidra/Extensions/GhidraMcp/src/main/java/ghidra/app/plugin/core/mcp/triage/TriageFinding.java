/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0
 */
package ghidra.app.plugin.core.mcp.triage;

import com.google.gson.JsonObject;

public class TriageFinding {
	private final String category;
	private final String severity;
	private final String summary;
	private final String evidenceId;

	public TriageFinding(String category, String severity, String summary, String evidenceId) {
		this.category = category;
		this.severity = severity;
		this.summary = summary;
		this.evidenceId = evidenceId;
	}

	public String category() {
		return category;
	}

	public String severity() {
		return severity;
	}

	public String summary() {
		return summary;
	}

	public String evidenceId() {
		return evidenceId;
	}

	public JsonObject toJson() {
		JsonObject object = new JsonObject();
		object.addProperty("category", category);
		object.addProperty("severity", severity);
		object.addProperty("summary", summary);
		object.addProperty("evidenceId", evidenceId);
		return object;
	}
}
