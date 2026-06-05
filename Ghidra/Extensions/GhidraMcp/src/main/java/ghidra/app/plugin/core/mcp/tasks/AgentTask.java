/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0
 */
package ghidra.app.plugin.core.mcp.tasks;

import java.time.Instant;

import com.google.gson.JsonObject;

public class AgentTask {
	public enum Status {
		PENDING, APPROVED, RUNNING, COMPLETED, FAILED, CANCELLED
	}

	private final String id;
	private final String title;
	private final String prompt;
	private final Instant createdAt;
	private Status status = Status.PENDING;
	private String result = "";

	public AgentTask(String id, String title, String prompt) {
		this.id = id;
		this.title = title;
		this.prompt = prompt;
		this.createdAt = Instant.now();
	}

	public String id() {
		return id;
	}

	public String title() {
		return title;
	}

	public String prompt() {
		return prompt;
	}

	public Status status() {
		return status;
	}

	public void setStatus(Status status) {
		this.status = status;
	}

	public void complete(String result) {
		this.status = Status.COMPLETED;
		this.result = result == null ? "" : result;
	}

	public JsonObject toJson() {
		JsonObject object = new JsonObject();
		object.addProperty("id", id);
		object.addProperty("title", title);
		object.addProperty("prompt", prompt);
		object.addProperty("status", status.name());
		object.addProperty("result", result);
		object.addProperty("createdAt", createdAt.toString());
		return object;
	}
}
