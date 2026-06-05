/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0
 */
package ghidra.app.plugin.core.mcp.hypotheses;

import java.util.*;

import com.google.gson.JsonArray;

public class HypothesisStore {
	private final List<Hypothesis> hypotheses = new ArrayList<>();
	private final List<Runnable> listeners = new ArrayList<>();

	public synchronized Hypothesis create(String text) {
		Hypothesis hypothesis = new Hypothesis("hyp-" + (hypotheses.size() + 1), text);
		hypotheses.add(hypothesis);
		notifyListeners();
		return hypothesis;
	}

	public synchronized Hypothesis get(String id) {
		for (Hypothesis hypothesis : hypotheses) {
			if (hypothesis.id().equals(id)) {
				return hypothesis;
			}
		}
		return null;
	}

	public synchronized List<Hypothesis> list() {
		return List.copyOf(hypotheses);
	}

	public synchronized void addChangeListener(Runnable listener) {
		listeners.add(listener);
	}

	public synchronized JsonArray toJsonArray() {
		JsonArray array = new JsonArray();
		for (Hypothesis hypothesis : hypotheses) {
			array.add(hypothesis.toJson());
		}
		return array;
	}

	private void notifyListeners() {
		for (Runnable listener : List.copyOf(listeners)) {
			listener.run();
		}
	}
}
