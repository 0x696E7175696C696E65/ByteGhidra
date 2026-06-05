/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
package ghidra.app.plugin.core.mcp.evidence;

import java.time.Instant;
import java.util.*;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

public class EvidenceRecord {
	private final String id;
	private final String source;
	private final String category;
	private final String severity;
	private final String address;
	private final String functionName;
	private final String summary;
	private final String details;
	private final double confidence;
	private final List<String> tags;
	private final Instant timestamp;

	public EvidenceRecord(String id, String source, String category, String severity, String address,
			String functionName, String summary, String details, double confidence, List<String> tags,
			Instant timestamp) {
		this.id = id;
		this.source = source;
		this.category = category;
		this.severity = severity;
		this.address = address;
		this.functionName = functionName;
		this.summary = summary;
		this.details = details;
		this.confidence = confidence;
		this.tags = List.copyOf(tags == null ? List.of() : tags);
		this.timestamp = timestamp == null ? Instant.now() : timestamp;
	}

	public String id() {
		return id;
	}

	public String source() {
		return source;
	}

	public String address() {
		return address;
	}

	public String functionName() {
		return functionName;
	}

	public String summary() {
		return summary;
	}

	public String details() {
		return details;
	}

	public String category() {
		return category;
	}

	public String severity() {
		return severity;
	}

	public double confidence() {
		return confidence;
	}

	public List<String> tags() {
		return tags;
	}

	public String dedupeKey() {
		return String.join("|", nullToEmpty(source), nullToEmpty(category), nullToEmpty(address),
			nullToEmpty(functionName), nullToEmpty(summary));
	}

	public JsonObject toJson() {
		JsonObject object = new JsonObject();
		object.addProperty("id", id);
		object.addProperty("source", source);
		object.addProperty("category", category);
		object.addProperty("severity", severity);
		if (address != null) {
			object.addProperty("address", address);
		}
		if (functionName != null) {
			object.addProperty("function", functionName);
		}
		object.addProperty("summary", summary);
		object.addProperty("details", details);
		object.addProperty("confidence", confidence);
		object.addProperty("timestamp", timestamp.toString());
		JsonArray tagArray = new JsonArray();
		for (String tag : tags) {
			tagArray.add(tag);
		}
		object.add("tags", tagArray);
		return object;
	}

	public static EvidenceRecord fromJson(JsonObject object) {
		List<String> tags = new ArrayList<>();
		if (object.has("tags") && object.get("tags").isJsonArray()) {
			for (var element : object.getAsJsonArray("tags")) {
				tags.add(element.getAsString());
			}
		}
		Instant parsedTimestamp = object.has("timestamp") ? Instant.parse(object.get("timestamp").getAsString())
				: Instant.now();
		return new EvidenceRecord(get(object, "id"), get(object, "source"), get(object, "category"),
			get(object, "severity"), get(object, "address"), get(object, "function"),
			get(object, "summary"), get(object, "details"),
			object.has("confidence") ? object.get("confidence").getAsDouble() : 0, tags,
			parsedTimestamp);
	}

	private static String get(JsonObject object, String name) {
		return object.has(name) && !object.get(name).isJsonNull() ? object.get(name).getAsString() : null;
	}

	private String nullToEmpty(String value) {
		return value == null ? "" : value;
	}
}
