/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0
 */
package ghidra.app.plugin.core.mcp.decompilerdiff;

import java.time.Instant;

import com.google.gson.JsonObject;

public class DecompilerSnapshot {
	private final String label;
	private final String functionName;
	private final String text;
	private final Instant createdAt;

	public DecompilerSnapshot(String label, String functionName, String text) {
		this.label = label;
		this.functionName = functionName;
		this.text = text == null ? "" : text;
		this.createdAt = Instant.now();
	}

	public String text() {
		return text;
	}

	public JsonObject toJson() {
		JsonObject object = new JsonObject();
		object.addProperty("label", label);
		object.addProperty("functionName", functionName);
		object.addProperty("text", text);
		object.addProperty("createdAt", createdAt.toString());
		return object;
	}

	public static String diff(DecompilerSnapshot before, DecompilerSnapshot after) {
		if (before == null || after == null) {
			return "Capture both before and after snapshots to compute a diff.";
		}
		String[] left = before.text().split("\\R");
		String[] right = after.text().split("\\R");
		StringBuilder builder = new StringBuilder();
		int max = Math.max(left.length, right.length);
		for (int i = 0; i < max; i++) {
			String l = i < left.length ? left[i] : "";
			String r = i < right.length ? right[i] : "";
			if (!l.equals(r)) {
				builder.append("- ").append(l).append('\n');
				builder.append("+ ").append(r).append('\n');
			}
		}
		return builder.length() == 0 ? "No decompiler text changes." : builder.toString();
	}
}
