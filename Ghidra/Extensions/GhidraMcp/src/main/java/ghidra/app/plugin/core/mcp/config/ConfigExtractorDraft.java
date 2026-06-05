/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0
 */
package ghidra.app.plugin.core.mcp.config;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.app.plugin.core.mcp.evidence.*;

public class ConfigExtractorDraft {
	public JsonObject draft(EvidenceStore store) {
		JsonObject object = new JsonObject();
		object.addProperty("name", "ghidra-ai-config-extractor-draft");
		object.addProperty("draftOnly", true);
		JsonArray indicators = new JsonArray();
		for (EvidenceRecord record : store.list()) {
			if (!record.tags().contains("string") && !"network".equals(record.category()) &&
				!"persistence".equals(record.category())) {
				continue;
			}
			JsonObject indicator = new JsonObject();
			indicator.addProperty("evidenceId", record.id());
			indicator.addProperty("category", record.category());
			indicator.addProperty("address", record.address());
			indicator.addProperty("value", record.details());
			indicators.add(indicator);
		}
		object.add("indicators", indicators);
		object.addProperty("strategy",
			"Use these evidence-backed indicators to locate parsing functions, then turn constants and decoded strings into extractor fields.");
		return object;
	}
}
