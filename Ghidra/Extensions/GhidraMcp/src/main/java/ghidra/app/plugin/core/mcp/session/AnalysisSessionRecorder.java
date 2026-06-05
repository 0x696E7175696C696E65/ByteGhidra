/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0
 */
package ghidra.app.plugin.core.mcp.session;

import java.util.*;

import com.google.gson.*;

public class AnalysisSessionRecorder {
	private final List<AnalysisSessionEvent> events = new ArrayList<>();
	private final List<Runnable> listeners = new ArrayList<>();

	public synchronized AnalysisSessionEvent record(String type, String summary, String details) {
		AnalysisSessionEvent event = new AnalysisSessionEvent(type, summary, details);
		events.add(event);
		notifyListeners();
		return event;
	}

	public synchronized List<AnalysisSessionEvent> list() {
		return List.copyOf(events);
	}

	public synchronized void addChangeListener(Runnable listener) {
		listeners.add(listener);
	}

	public synchronized JsonArray toJsonArray() {
		JsonArray array = new JsonArray();
		for (AnalysisSessionEvent event : events) {
			array.add(event.toJson());
		}
		return array;
	}

	public synchronized void importJsonArray(JsonArray array) {
		events.clear();
		for (JsonElement element : array) {
			if (element.isJsonObject()) {
				events.add(AnalysisSessionEvent.fromJson(element.getAsJsonObject()));
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
