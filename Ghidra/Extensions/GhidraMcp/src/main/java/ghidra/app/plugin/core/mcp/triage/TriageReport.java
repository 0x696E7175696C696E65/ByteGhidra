/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0
 */
package ghidra.app.plugin.core.mcp.triage;

import java.time.Instant;
import java.util.*;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

public class TriageReport {
	private final String programName;
	private final Instant createdAt = Instant.now();
	private final List<TriageFinding> findings = new ArrayList<>();

	public TriageReport(String programName) {
		this.programName = programName;
	}

	public void add(TriageFinding finding) {
		findings.add(finding);
	}

	public List<TriageFinding> findings() {
		return List.copyOf(findings);
	}

	public JsonObject toJson() {
		JsonObject object = new JsonObject();
		object.addProperty("programName", programName);
		object.addProperty("createdAt", createdAt.toString());
		object.addProperty("findingCount", findings.size());
		JsonArray array = new JsonArray();
		for (TriageFinding finding : findings) {
			array.add(finding.toJson());
		}
		object.add("findings", array);
		return object;
	}
}
