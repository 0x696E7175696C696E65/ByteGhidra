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
	private static final long MAX_FILE_BYTES = 2 * 1024 * 1024;
	private static final Set<String> SUPPORTED_EXTENSIONS = Set.of(".json", ".csv");

	public record ImportResult(int imported, int skipped) {
		public JsonObject toJson() {
			JsonObject object = new JsonObject();
			object.addProperty("imported", imported);
			object.addProperty("skipped", skipped);
			return object;
		}
	}

	public ImportResult importFile(Path path, Program program, EvidenceStore store) throws IOException {
		validatePath(path);
		String text = Files.readString(path, StandardCharsets.UTF_8);
		String trimmed = text.trim();
		if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
			return importJson(trimmed, program, store);
		}
		return importCsv(text, program, store);
	}

	public JsonObject mapRuntimeEvent(Program program, String addressText) {
		JsonObject event = new JsonObject();
		event.addProperty("address", addressText);
		return mapRuntimeEvent(program, event);
	}

	public JsonObject mapRuntimeEvent(Program program, JsonObject event) {
		JsonObject object = new JsonObject();
		String addressText = resolveAddress(program, event);
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

	private void validatePath(Path path) throws IOException {
		String name = path.getFileName().toString().toLowerCase(Locale.ROOT);
		boolean supported = SUPPORTED_EXTENSIONS.stream().anyMatch(name::endsWith);
		if (!supported) {
			throw new IOException("Unsupported sandbox evidence extension: " + name);
		}
		if (Files.size(path) > MAX_FILE_BYTES) {
			throw new IOException("Sandbox evidence file exceeds " + MAX_FILE_BYTES + " bytes");
		}
	}

	private ImportResult importJson(String text, Program program, EvidenceStore store) {
		JsonElement root = JsonParser.parseString(text);
		JsonArray events = root.isJsonArray() ? root.getAsJsonArray() : toArray(root.getAsJsonObject());
		int count = 0;
		int skipped = 0;
		for (JsonElement element : events) {
			if (!element.isJsonObject()) {
				skipped++;
				continue;
			}
			JsonObject event = element.getAsJsonObject();
			if (!validEvent(event)) {
				skipped++;
				continue;
			}
			addEvent(program, store, resolveAddress(program, event), string(event, "api"),
				blank(string(event, "category"), string(event, "eventType")),
				string(event, "summary"), event.toString());
			count++;
		}
		return new ImportResult(count, skipped);
	}

	private JsonArray toArray(JsonObject object) {
		if (object.has("events") && object.get("events").isJsonArray()) {
			return object.getAsJsonArray("events");
		}
		JsonArray array = new JsonArray();
		array.add(object);
		return array;
	}

	private ImportResult importCsv(String text, Program program, EvidenceStore store) {
		int count = 0;
		int skipped = 0;
		for (String line : text.split("\\R")) {
			if (line.isBlank() || line.toLowerCase(Locale.ROOT).startsWith("address,")) {
				continue;
			}
			List<String> parts = parseCsvLine(line);
			String address = parts.size() > 0 ? parts.get(0).trim() : "";
			String api = parts.size() > 1 ? parts.get(1).trim() : "";
			String category = parts.size() > 2 ? parts.get(2).trim() : "runtime";
			String summary = parts.size() > 3 ? parts.get(3).trim() : api;
			if (api.isBlank() && summary.isBlank()) {
				skipped++;
				continue;
			}
			addEvent(program, store, address, api, category, summary, line);
			count++;
		}
		return new ImportResult(count, skipped);
	}

	private List<String> parseCsvLine(String line) {
		List<String> values = new ArrayList<>();
		StringBuilder current = new StringBuilder();
		boolean quoted = false;
		for (int i = 0; i < line.length(); i++) {
			char ch = line.charAt(i);
			if (ch == '"') {
				quoted = !quoted;
			}
			else if (ch == ',' && !quoted) {
				values.add(current.toString());
				current.setLength(0);
			}
			else {
				current.append(ch);
			}
		}
		values.add(current.toString());
		return values;
	}

	private boolean validEvent(JsonObject event) {
		return !string(event, "api").isBlank() || !string(event, "summary").isBlank() ||
			!string(event, "eventType").isBlank();
	}

	private String resolveAddress(Program program, JsonObject event) {
		String direct = string(event, "address");
		if (!direct.isBlank()) {
			return direct;
		}
		String rva = string(event, "rva");
		if (program != null && !rva.isBlank()) {
			try {
				long offset = Long.decode(rva);
				return program.getImageBase().add(offset).toString();
			}
			catch (Exception ignored) {
				return "";
			}
		}
		return "";
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
