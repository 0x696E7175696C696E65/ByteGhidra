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
}
