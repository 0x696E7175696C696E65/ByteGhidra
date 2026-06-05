/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0
 */
package ghidra.app.plugin.core.mcp.sandbox;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Instant;
import java.util.*;

import com.google.gson.*;

import ghidra.app.plugin.core.mcp.evidence.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;

public class SandboxEvidenceImporter {
	public int importFile(Path path, Program program, EvidenceStore store) throws IOException {
		String text = Files.readString(path, StandardCharsets.UTF_8);
		String trimmed = text.trim();
		if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
			return importJson(trimmed, program, store);
		}
		return importCsv(text, program, store);
	}

	public JsonObject mapRuntimeEvent(Program program, String addressText) {
		JsonObject object = new JsonObject();
		Address address = program.getAddressFactory().getAddress(addressText);
		if (address == null) {
			object.addProperty("mapped", false);
			return object;
		}
		Function function = program.getFunctionManager().getFunctionContaining(address);
		object.addProperty("mapped", function != null);
		object.addProperty("address", address.toString());
		if (function != null) {
			object.addProperty("function", function.getName(true));
			object.addProperty("entry", function.getEntryPoint().toString());
		}
		return object;
	}

	private int importJson(String text, Program program, EvidenceStore store) {
		JsonElement root = JsonParser.parseString(text);
		JsonArray events = root.isJsonArray() ? root.getAsJsonArray() : toArray(root.getAsJsonObject());
		int count = 0;
		for (JsonElement element : events) {
			if (!element.isJsonObject()) {
				continue;
			}
			JsonObject event = element.getAsJsonObject();
			addEvent(program, store, string(event, "address"), string(event, "api"),
				string(event, "category"), string(event, "summary"), event.toString());
			count++;
		}
		return count;
	}

	private JsonArray toArray(JsonObject object) {
		if (object.has("events") && object.get("events").isJsonArray()) {
			return object.getAsJsonArray("events");
		}
		JsonArray array = new JsonArray();
		array.add(object);
		return array;
	}

	private int importCsv(String text, Program program, EvidenceStore store) {
		int count = 0;
		for (String line : text.split("\\R")) {
			if (line.isBlank() || line.toLowerCase(Locale.ROOT).startsWith("address,")) {
				continue;
			}
			String[] parts = line.split(",", 4);
			String address = parts.length > 0 ? parts[0].trim() : "";
			String api = parts.length > 1 ? parts[1].trim() : "";
			String category = parts.length > 2 ? parts[2].trim() : "runtime";
			String summary = parts.length > 3 ? parts[3].trim() : api;
			addEvent(program, store, address, api, category, summary, line);
			count++;
		}
		return count;
	}

	private void addEvent(Program program, EvidenceStore store, String addressText, String api,
			String category, String summary, String details) {
		String functionName = null;
		if (addressText != null && !addressText.isBlank() && program != null) {
			Address address = program.getAddressFactory().getAddress(addressText);
			if (address != null) {
				Function function = program.getFunctionManager().getFunctionContaining(address);
				functionName = function == null ? null : function.getName(true);
			}
		}
		store.add(new EvidenceRecord("ev-" + UUID.randomUUID(), "sandbox", blank(category, "runtime"),
			"medium", blank(addressText, null), functionName, blank(summary, "Runtime event"),
			blank(details, api), 0.6, List.of("sandbox", "runtime"), Instant.now()));
	}

	private String string(JsonObject object, String key) {
		if (!object.has(key) || object.get(key).isJsonNull()) {
			return "";
		}
		return object.get(key).getAsString();
	}

	private String blank(String value, String defaultValue) {
		return value == null || value.isBlank() ? defaultValue : value;
	}
}
