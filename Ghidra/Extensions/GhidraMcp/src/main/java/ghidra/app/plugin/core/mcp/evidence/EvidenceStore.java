/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0
 */
package ghidra.app.plugin.core.mcp.evidence;

import java.util.*;

import com.google.gson.JsonArray;

public class EvidenceStore {
	private final List<EvidenceRecord> records = new ArrayList<>();
	private final List<Runnable> listeners = new ArrayList<>();

	public synchronized EvidenceRecord add(EvidenceRecord record) {
		records.add(record);
		notifyListeners();
		return record;
	}

	public synchronized List<EvidenceRecord> list() {
		return List.copyOf(records);
	}

	public synchronized EvidenceRecord get(String id) {
		for (EvidenceRecord record : records) {
			if (record.id().equals(id)) {
				return record;
			}
		}
		return null;
	}

	public synchronized void clear() {
		records.clear();
		notifyListeners();
	}

	public synchronized void addChangeListener(Runnable listener) {
		listeners.add(listener);
	}

	public synchronized JsonArray toJsonArray() {
		JsonArray array = new JsonArray();
		for (EvidenceRecord record : records) {
			array.add(record.toJson());
		}
		return array;
	}

	private void notifyListeners() {
		for (Runnable listener : List.copyOf(listeners)) {
			listener.run();
		}
	}
}
