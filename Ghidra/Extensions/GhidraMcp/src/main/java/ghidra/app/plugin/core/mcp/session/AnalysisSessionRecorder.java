/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0
 */
package ghidra.app.plugin.core.mcp.session;

import java.util.*;

import com.google.gson.JsonArray;

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

	private void notifyListeners() {
		for (Runnable listener : List.copyOf(listeners)) {
			listener.run();
		}
	}
}
