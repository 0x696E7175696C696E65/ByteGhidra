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
		PENDING, APPROVED, RUNNING, COMPLETED, FAILED, CANCEL_REQUESTED, CANCELLED
	}

	private final String id;
	private final String title;
	private final String prompt;
	private final Instant createdAt;
	private Instant startedAt;
	private Instant completedAt;
	private Status status = Status.PENDING;
	private String result = "";
	private int progress;
	private String message = "";

	public AgentTask(String id, String title, String prompt) {
		this(id, title, prompt, Instant.now());
	}

	private AgentTask(String id, String title, String prompt, Instant createdAt) {
		this.id = id;
		this.title = title;
		this.prompt = prompt;
		this.createdAt = createdAt;
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

	public void start() {
		this.status = Status.RUNNING;
		this.startedAt = Instant.now();
	}

	public void updateProgress(int progress, String message) {
		this.progress = Math.max(0, Math.min(100, progress));
		this.message = message == null ? "" : message;
	}

	public void requestCancel() {
		if (status == Status.COMPLETED || status == Status.FAILED || status == Status.CANCELLED) {
			return;
		}
		status = Status.CANCEL_REQUESTED;
	}

	public boolean isCancelRequested() {
		return status == Status.CANCEL_REQUESTED || status == Status.CANCELLED;
	}

	public void complete(String result) {
		this.status = Status.COMPLETED;
		this.result = result == null ? "" : result;
		this.progress = 100;
		this.completedAt = Instant.now();
	}

	public void fail(String result) {
		this.status = Status.FAILED;
		this.result = result == null ? "" : result;
		this.completedAt = Instant.now();
	}

	public void cancel() {
		this.status = Status.CANCELLED;
		this.completedAt = Instant.now();
	}

	public JsonObject toJson() {
		JsonObject object = new JsonObject();
		object.addProperty("id", id);
		object.addProperty("title", title);
		object.addProperty("prompt", prompt);
		object.addProperty("status", status.name());
		object.addProperty("result", result);
		object.addProperty("progress", progress);
		object.addProperty("message", message);
		object.addProperty("createdAt", createdAt.toString());
		if (startedAt != null) {
			object.addProperty("startedAt", startedAt.toString());
		}
		if (completedAt != null) {
			object.addProperty("completedAt", completedAt.toString());
		}
		return object;
	}

	public static AgentTask fromJson(JsonObject object) {
		AgentTask task = new AgentTask(get(object, "id"), get(object, "title"), get(object, "prompt"),
			object.has("createdAt") ? Instant.parse(object.get("createdAt").getAsString()) : Instant.now());
		if (object.has("status")) {
			task.setStatus(Status.valueOf(object.get("status").getAsString()));
		}
		if (object.has("result")) {
			task.result = object.get("result").getAsString();
		}
		if (object.has("progress")) {
			task.progress = object.get("progress").getAsInt();
		}
		if (object.has("message")) {
			task.message = object.get("message").getAsString();
		}
		if (object.has("startedAt")) {
			task.startedAt = Instant.parse(object.get("startedAt").getAsString());
		}
		if (object.has("completedAt")) {
			task.completedAt = Instant.parse(object.get("completedAt").getAsString());
		}
		return task;
	}

	private static String get(JsonObject object, String name) {
		return object.has(name) && !object.get(name).isJsonNull() ? object.get(name).getAsString() : "";
	}
}
