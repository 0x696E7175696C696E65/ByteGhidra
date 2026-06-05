/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0
 */
package ghidra.app.plugin.core.mcp.overlay;

import java.util.*;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.FlowType;

public class SuspiciousControlFlowAnalyzer {
	public JsonArray analyze(Program program, int limit) {
		List<JsonObject> candidates = new ArrayList<>();
		FunctionIterator functions = program.getFunctionManager().getFunctions(true);
		while (functions.hasNext()) {
			Function function = functions.next();
			JsonObject candidate = score(program, function);
			if (candidate.get("score").getAsDouble() > 0) {
				candidates.add(candidate);
			}
		}
		candidates.sort((a, b) -> Double.compare(b.get("score").getAsDouble(), a.get("score").getAsDouble()));
		JsonArray array = new JsonArray();
		for (int i = 0; i < Math.min(limit, candidates.size()); i++) {
			array.add(candidates.get(i));
		}
		return array;
	}

	private JsonObject score(Program program, Function function) {
		int instructions = 0;
		int branches = 0;
		int calls = 0;
		InstructionIterator iterator =
			program.getListing().getInstructions(function.getBody(), true);
		while (iterator.hasNext()) {
			Instruction instruction = iterator.next();
			instructions++;
			FlowType flowType = instruction.getFlowType();
			if (flowType.isJump() || flowType.isConditional()) {
				branches++;
			}
			if (flowType.isCall()) {
				calls++;
			}
		}
		double branchDensity = instructions == 0 ? 0 : (double) branches / instructions;
		double score = 0;
		if (branchDensity > 0.28) {
			score += branchDensity * 10;
		}
		if (instructions > 350 && branches > 80) {
			score += 3;
		}
		if (calls == 0 && instructions > 150 && branches > 40) {
			score += 2;
		}
		JsonObject object = new JsonObject();
		object.addProperty("function", function.getName(true));
		object.addProperty("entry", function.getEntryPoint().toString());
		object.addProperty("instructions", instructions);
		object.addProperty("branches", branches);
		object.addProperty("calls", calls);
		object.addProperty("branchDensity", branchDensity);
		object.addProperty("score", score);
		return object;
	}
}
