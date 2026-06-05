/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0
 */
package ghidra.app.plugin.core.mcp.evidence;

import java.util.*;

import com.google.gson.*;

public class EvidenceStore {
	private final List<EvidenceRecord> records = new ArrayList<>();
	private final Map<String, EvidenceRecord> recordsByDedupeKey = new LinkedHashMap<>();
	private final List<Runnable> listeners = new ArrayList<>();

	public synchronized EvidenceRecord add(EvidenceRecord record) {
		EvidenceRecord existing = recordsByDedupeKey.get(record.dedupeKey());
		if (existing != null) {
			return existing;
		}
		records.add(record);
		recordsByDedupeKey.put(record.dedupeKey(), record);
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
		recordsByDedupeKey.clear();
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

	public synchronized void importJsonArray(JsonArray array) {
		clear();
		for (JsonElement element : array) {
			if (element.isJsonObject()) {
				add(EvidenceRecord.fromJson(element.getAsJsonObject()));
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
