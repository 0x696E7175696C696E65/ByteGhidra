/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0
 */
package ghidra.app.plugin.core.mcp.hypotheses;

import java.time.Instant;
import java.util.*;

import com.google.gson.*;

public class Hypothesis {
	public enum Status {
		OPEN, SUPPORTED, REJECTED, NEEDS_REVIEW
	}

	private final String id;
	private final String text;
	private final Instant createdAt;
	private final List<String> evidenceIds = new ArrayList<>();
	private Status status = Status.OPEN;

	public Hypothesis(String id, String text) {
		this(id, text, Instant.now());
	}

	private Hypothesis(String id, String text, Instant createdAt) {
		this.id = id;
		this.text = text;
		this.createdAt = createdAt;
	}

	public String id() {
		return id;
	}

	public String text() {
		return text;
	}

	public Status status() {
		return status;
	}

	public void setStatus(Status status) {
		this.status = status;
	}

	public void linkEvidence(String evidenceId) {
		if (!evidenceIds.contains(evidenceId)) {
			evidenceIds.add(evidenceId);
		}
	}

	public JsonObject toJson() {
		JsonObject object = new JsonObject();
		object.addProperty("id", id);
		object.addProperty("text", text);
		object.addProperty("status", status.name());
		object.addProperty("createdAt", createdAt.toString());
		JsonArray evidence = new JsonArray();
		for (String evidenceId : evidenceIds) {
			evidence.add(evidenceId);
		}
		object.add("evidenceIds", evidence);
		return object;
	}

	public static Hypothesis fromJson(JsonObject object) {
		Hypothesis hypothesis = new Hypothesis(get(object, "id"), get(object, "text"),
			object.has("createdAt") ? Instant.parse(object.get("createdAt").getAsString()) : Instant.now());
		if (object.has("status")) {
			hypothesis.setStatus(Status.valueOf(object.get("status").getAsString()));
		}
		if (object.has("evidenceIds") && object.get("evidenceIds").isJsonArray()) {
			for (JsonElement element : object.getAsJsonArray("evidenceIds")) {
				hypothesis.linkEvidence(element.getAsString());
			}
		}
		return hypothesis;
	}

	private static String get(JsonObject object, String name) {
		return object.has(name) && !object.get(name).isJsonNull() ? object.get(name).getAsString() : "";
	}
}
