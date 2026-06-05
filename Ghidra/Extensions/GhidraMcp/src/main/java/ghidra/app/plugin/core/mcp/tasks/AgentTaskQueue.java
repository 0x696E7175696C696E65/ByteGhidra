/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0
 */
package ghidra.app.plugin.core.mcp.tasks;

import java.util.*;

import com.google.gson.*;

public class AgentTaskQueue {
	private final List<AgentTask> tasks = new ArrayList<>();
	private final List<Runnable> listeners = new ArrayList<>();

	public synchronized AgentTask create(String title, String prompt) {
		AgentTask task = new AgentTask("task-" + (tasks.size() + 1), title, prompt);
		tasks.add(task);
		notifyListeners();
		return task;
	}

	public synchronized List<AgentTask> list() {
		return List.copyOf(tasks);
	}

	public synchronized AgentTask get(String id) {
		for (AgentTask task : tasks) {
			if (task.id().equals(id)) {
				return task;
			}
		}
		return null;
	}

	public synchronized AgentTask setStatus(String id, AgentTask.Status status) {
		AgentTask task = get(id);
		if (task != null) {
			task.setStatus(status);
			notifyListeners();
		}
		return task;
	}

	public synchronized AgentTask cancel(String id) {
		AgentTask task = get(id);
		if (task != null) {
			task.requestCancel();
			notifyListeners();
		}
		return task;
	}

	public synchronized void addChangeListener(Runnable listener) {
		listeners.add(listener);
	}

	public synchronized JsonArray toJsonArray() {
		JsonArray array = new JsonArray();
		for (AgentTask task : tasks) {
			array.add(task.toJson());
		}
		return array;
	}

	public synchronized void importJsonArray(JsonArray array) {
		tasks.clear();
		for (JsonElement element : array) {
			if (element.isJsonObject()) {
				tasks.add(AgentTask.fromJson(element.getAsJsonObject()));
			}
		}
		notifyListeners();
	}

	private void notifyListeners() {
		for (Runnable listener : List.copyOf(listeners)) {
			listener.run();
		}
	}
}
