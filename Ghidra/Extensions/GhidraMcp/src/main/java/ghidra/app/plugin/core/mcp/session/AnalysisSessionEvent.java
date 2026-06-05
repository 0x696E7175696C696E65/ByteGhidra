/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0
 */
package ghidra.app.plugin.core.mcp.session;

import java.time.Instant;

import com.google.gson.JsonObject;

public class AnalysisSessionEvent {
	private final String type;
	private final String summary;
	private final String details;
	private final Instant timestamp;

	public AnalysisSessionEvent(String type, String summary, String details) {
		this.type = type;
		this.summary = summary;
		this.details = details == null ? "" : details;
		this.timestamp = Instant.now();
	}

	public String type() {
		return type;
	}

	public String summary() {
		return summary;
	}

	public String details() {
		return details;
	}

	public JsonObject toJson() {
		JsonObject object = new JsonObject();
		object.addProperty("type", type);
		object.addProperty("summary", summary);
		object.addProperty("details", details);
		object.addProperty("timestamp", timestamp.toString());
		return object;
	}
}
