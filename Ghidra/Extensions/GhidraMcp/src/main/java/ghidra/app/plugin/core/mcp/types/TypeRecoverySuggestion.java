/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0
 */
package ghidra.app.plugin.core.mcp.types;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.program.model.listing.*;

public class TypeRecoverySuggestion {
	public JsonArray suggest(Program program, int limit) {
		JsonArray suggestions = new JsonArray();
		FunctionIterator functions = program.getFunctionManager().getFunctions(true);
		while (functions.hasNext() && suggestions.size() < limit) {
			Function function = functions.next();
			if (function.getParameterCount() == 0 && function.getName().startsWith("FUN_")) {
				JsonObject object = new JsonObject();
				object.addProperty("function", function.getName(true));
				object.addProperty("entry", function.getEntryPoint().toString());
				object.addProperty("suggestion", "Review callsites for parameter recovery and rename.");
				object.addProperty("previewOnly", true);
				suggestions.add(object);
			}
		}
		return suggestions;
	}
}
