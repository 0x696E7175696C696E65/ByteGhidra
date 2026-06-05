/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0
 */
package ghidra.app.plugin.core.mcp.search;

import java.util.*;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;

public class SemanticFunctionIndex {
	public JsonArray search(Program program, String query, int limit) {
		String[] terms = query.toLowerCase(Locale.ROOT).split("\\s+");
		List<JsonObject> ranked = new ArrayList<>();
		FunctionIterator iterator = program.getFunctionManager().getFunctions(true);
		while (iterator.hasNext()) {
			Function function = iterator.next();
			double score = score(program, function, terms);
			if (score <= 0) {
				continue;
			}
			JsonObject object = new JsonObject();
			object.addProperty("name", function.getName(true));
			object.addProperty("entry", function.getEntryPoint().toString());
			object.addProperty("score", score);
			object.addProperty("size", function.getBody().getNumAddresses());
			ranked.add(object);
		}
		ranked.sort((a, b) -> Double.compare(b.get("score").getAsDouble(), a.get("score").getAsDouble()));
		JsonArray array = new JsonArray();
		for (int i = 0; i < Math.min(limit, ranked.size()); i++) {
			array.add(ranked.get(i));
		}
		return array;
	}

	private double score(Program program, Function function, String[] terms) {
		String features = featureText(program, function).toLowerCase(Locale.ROOT);
		double score = 0;
		for (String term : terms) {
			if (term.isBlank()) {
				continue;
			}
			if (function.getName().toLowerCase(Locale.ROOT).contains(term)) {
				score += 5;
			}
			if (features.contains(term)) {
				score += 1;
			}
		}
		return score;
	}

	private String featureText(Program program, Function function) {
		StringBuilder builder = new StringBuilder(function.getName(true));
		for (Reference reference : program.getReferenceManager().getReferencesFrom(function.getEntryPoint())) {
			builder.append(' ').append(reference.getReferenceType().getName());
			if (reference.getToAddress() != null) {
				builder.append(' ').append(reference.getToAddress());
			}
		}
		return builder.toString();
	}
}
