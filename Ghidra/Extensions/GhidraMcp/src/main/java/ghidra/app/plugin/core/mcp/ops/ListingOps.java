/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.plugin.core.mcp.ops;

import java.util.*;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.app.plugin.core.mcp.bridge.GhidraMcpResponse;
import ghidra.app.plugin.core.mcp.ops.GhidraMcpOperation.OperationKind;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.*;
import ghidra.program.util.DefinedDataIterator;

public final class ListingOps {
	private ListingOps() {
	}

	public static void register(OperationRegistry registry) {
		registry.register(read("list_functions", ListingOps::listFunctions));
		registry.register(read("get_function", ListingOps::getFunction));
		registry.register(read("get_symbols", ListingOps::getSymbols));
		registry.register(read("get_strings", ListingOps::getStrings));
		registry.register(read("read_bytes", ListingOps::readBytes));
		registry.register(read("get_disassembly", ListingOps::getDisassembly));
		registry.register(read("get_xrefs_to", ListingOps::getXrefsTo));
		registry.register(read("get_xrefs_from", ListingOps::getXrefsFrom));
		registry.register(read("get_callers", ListingOps::getCallers));
		registry.register(read("get_callees", ListingOps::getCallees));
	}

	private static GhidraMcpOperation read(String name, OperationBody body) {
		return new SimpleOperation(name, OperationKind.READ_ONLY, body);
	}

	private static GhidraMcpResponse listFunctions(GhidraMcpContext context, JsonObject params) {
		Program program = OperationUtils.requireProgram(context);
		int limit = OperationUtils.intParam(params, "limit", OperationUtils.DEFAULT_LIMIT, 1,
			OperationUtils.MAX_LIMIT);
		int offset = OperationUtils.intParam(params, "offset", 0, 0, Integer.MAX_VALUE);
		JsonArray functions = new JsonArray();
		FunctionIterator iterator = program.getFunctionManager().getFunctions(true);
		int index = 0;
		while (iterator.hasNext() && functions.size() < limit) {
			Function function = iterator.next();
			if (index++ < offset) {
				continue;
			}
			functions.add(function(function));
		}
		JsonObject result = new JsonObject();
		result.add("functions", functions);
		result.addProperty("truncated", iterator.hasNext());
		return GhidraMcpResponse.ok(result, iterator.hasNext());
	}

	private static GhidraMcpResponse getFunction(GhidraMcpContext context, JsonObject params) {
		Program program = OperationUtils.requireProgram(context);
		Function function = findFunction(program, params);
		if (function == null) {
			return GhidraMcpResponse.error("not_found", "No matching function");
		}
		return GhidraMcpResponse.ok(function(function));
	}

	private static GhidraMcpResponse getSymbols(GhidraMcpContext context, JsonObject params) {
		Program program = OperationUtils.requireProgram(context);
		int limit = OperationUtils.intParam(params, "limit", OperationUtils.DEFAULT_LIMIT, 1,
			OperationUtils.MAX_LIMIT);
		int offset = OperationUtils.intParam(params, "offset", 0, 0, Integer.MAX_VALUE);
		JsonArray symbols = new JsonArray();
		SymbolIterator iterator = program.getSymbolTable().getAllSymbols(true);
		int index = 0;
		while (iterator.hasNext() && symbols.size() < limit) {
			Symbol symbol = iterator.next();
			if (index++ < offset) {
				continue;
			}
			symbols.add(ProgramInfoOps.symbol(symbol));
		}
		JsonObject result = new JsonObject();
		result.add("symbols", symbols);
		result.addProperty("truncated", iterator.hasNext());
		return GhidraMcpResponse.ok(result, iterator.hasNext());
	}

	private static GhidraMcpResponse getStrings(GhidraMcpContext context, JsonObject params) {
		Program program = OperationUtils.requireProgram(context);
		int limit = OperationUtils.intParam(params, "limit", OperationUtils.DEFAULT_LIMIT, 1,
			OperationUtils.MAX_LIMIT);
		JsonArray strings = new JsonArray();
		DataIterator iterator = DefinedDataIterator.byDataInstance(program, Data::hasStringValue);
		while (iterator.hasNext() && strings.size() < limit) {
			Data data = iterator.next();
			JsonObject object = new JsonObject();
			object.addProperty("address", data.getMinAddress().toString());
			object.addProperty("length", data.getLength());
			object.addProperty("dataType", data.getDataType().getDisplayName());
			Object value = data.getValue();
			object.addProperty("value", value == null ? "" : value.toString());
			strings.add(object);
		}
		JsonObject result = new JsonObject();
		result.add("strings", strings);
		result.addProperty("truncated", iterator.hasNext());
		return GhidraMcpResponse.ok(result, iterator.hasNext());
	}

	private static GhidraMcpResponse readBytes(GhidraMcpContext context, JsonObject params)
			throws MemoryAccessException {
		Program program = OperationUtils.requireProgram(context);
		Address address = OperationUtils.address(program, OperationUtils.requiredString(params, "address"));
		int size = OperationUtils.intParam(params, "size", 16, 1, OperationUtils.MAX_BYTES);
		byte[] bytes = new byte[size];
		Memory memory = program.getMemory();
		int read = memory.getBytes(address, bytes);
		JsonObject result = new JsonObject();
		result.addProperty("address", address.toString());
		result.addProperty("size", read);
		result.add("bytes", OperationUtils.bytesToHexArray(Arrays.copyOf(bytes, read)));
		return GhidraMcpResponse.ok(result);
	}

	private static GhidraMcpResponse getDisassembly(GhidraMcpContext context, JsonObject params) {
		Program program = OperationUtils.requireProgram(context);
		Address address = OperationUtils.address(program, OperationUtils.requiredString(params, "address"));
		int limit = OperationUtils.intParam(params, "limit", 20, 1, 200);
		InstructionIterator iterator = program.getListing().getInstructions(address, true);
		JsonArray instructions = new JsonArray();
		while (iterator.hasNext() && instructions.size() < limit) {
			Instruction instruction = iterator.next();
			JsonObject object = new JsonObject();
			object.addProperty("address", instruction.getAddress().toString());
			object.addProperty("text", instruction.toString());
			object.addProperty("length", instruction.getLength());
			instructions.add(object);
		}
		JsonObject result = new JsonObject();
		result.add("instructions", instructions);
		result.addProperty("truncated", iterator.hasNext());
		return GhidraMcpResponse.ok(result, iterator.hasNext());
	}

	private static GhidraMcpResponse getXrefsTo(GhidraMcpContext context, JsonObject params) {
		Program program = OperationUtils.requireProgram(context);
		Address address = OperationUtils.address(program, OperationUtils.requiredString(params, "address"));
		int limit = OperationUtils.intParam(params, "limit", OperationUtils.DEFAULT_LIMIT, 1,
			OperationUtils.MAX_LIMIT);
		ReferenceIterator iterator = program.getReferenceManager().getReferencesTo(address);
		JsonArray references = new JsonArray();
		while (iterator.hasNext() && references.size() < limit) {
			references.add(reference(iterator.next()));
		}
		JsonObject result = new JsonObject();
		result.add("references", references);
		result.addProperty("truncated", iterator.hasNext());
		return GhidraMcpResponse.ok(result, iterator.hasNext());
	}

	private static GhidraMcpResponse getXrefsFrom(GhidraMcpContext context, JsonObject params) {
		Program program = OperationUtils.requireProgram(context);
		Address address = OperationUtils.address(program, OperationUtils.requiredString(params, "address"));
		JsonArray references = new JsonArray();
		for (Reference ref : program.getReferenceManager().getReferencesFrom(address)) {
			references.add(reference(ref));
		}
		JsonObject result = new JsonObject();
		result.add("references", references);
		return GhidraMcpResponse.ok(result);
	}

	private static GhidraMcpResponse getCallers(GhidraMcpContext context, JsonObject params) {
		Program program = OperationUtils.requireProgram(context);
		Function function = findFunction(program, params);
		if (function == null) {
			return GhidraMcpResponse.error("not_found", "No matching function");
		}
		int limit = OperationUtils.intParam(params, "limit", OperationUtils.DEFAULT_LIMIT, 1,
			OperationUtils.MAX_LIMIT);
		JsonArray callers = new JsonArray();
		Set<Address> seen = new HashSet<>();
		ReferenceIterator refs = program.getReferenceManager().getReferencesTo(function.getEntryPoint());
		while (refs.hasNext() && callers.size() < limit) {
			Reference ref = refs.next();
			if (!ref.getReferenceType().isCall()) {
				continue;
			}
			Function caller =
				program.getFunctionManager().getFunctionContaining(ref.getFromAddress());
			if (caller != null && seen.add(caller.getEntryPoint())) {
				callers.add(function(caller));
			}
		}
		JsonObject result = new JsonObject();
		result.add("callers", callers);
		result.addProperty("truncated", refs.hasNext());
		return GhidraMcpResponse.ok(result);
	}

	private static GhidraMcpResponse getCallees(GhidraMcpContext context, JsonObject params) {
		Program program = OperationUtils.requireProgram(context);
		Function function = findFunction(program, params);
		if (function == null) {
			return GhidraMcpResponse.error("not_found", "No matching function");
		}
		int limit = OperationUtils.intParam(params, "limit", OperationUtils.DEFAULT_LIMIT, 1,
			OperationUtils.MAX_LIMIT);
		JsonArray callees = new JsonArray();
		Set<Address> seen = new HashSet<>();
		InstructionIterator instructions =
			program.getListing().getInstructions(function.getBody(), true);
		while (instructions.hasNext() && callees.size() < limit) {
			Instruction instruction = instructions.next();
			for (Reference ref : instruction.getReferencesFrom()) {
				if (!ref.getReferenceType().isCall()) {
					continue;
				}
				Function callee = program.getFunctionManager().getFunctionAt(ref.getToAddress());
				if (callee != null && seen.add(callee.getEntryPoint())) {
					callees.add(function(callee));
				}
			}
		}
		JsonObject result = new JsonObject();
		result.add("callees", callees);
		result.addProperty("truncated", instructions.hasNext());
		return GhidraMcpResponse.ok(result);
	}

	static Function findFunction(Program program, JsonObject params) {
		if (params.has("address")) {
			Address address = OperationUtils.address(program, params.get("address").getAsString());
			Function function = program.getFunctionManager().getFunctionAt(address);
			return function != null ? function
					: program.getFunctionManager().getFunctionContaining(address);
		}
		if (params.has("name")) {
			var functions = program.getListing().getGlobalFunctions(params.get("name").getAsString());
			return functions.isEmpty() ? null : functions.get(0);
		}
		throw new IllegalArgumentException("Provide either 'address' or 'name'");
	}

	static JsonObject function(Function function) {
		JsonObject object = new JsonObject();
		object.addProperty("name", function.getName(true));
		object.addProperty("entryPoint", function.getEntryPoint().toString());
		object.addProperty("signature", function.getPrototypeString(false, false));
		object.addProperty("bodyMin", function.getBody().getMinAddress().toString());
		object.addProperty("bodyMax", function.getBody().getMaxAddress().toString());
		object.addProperty("isThunk", function.isThunk());
		object.addProperty("isExternal", function.isExternal());
		return object;
	}

	static JsonObject reference(Reference ref) {
		JsonObject object = new JsonObject();
		object.addProperty("from", ref.getFromAddress().toString());
		object.addProperty("to", ref.getToAddress().toString());
		object.addProperty("type", ref.getReferenceType().toString());
		object.addProperty("operandIndex", ref.getOperandIndex());
		object.addProperty("primary", ref.isPrimary());
		return object;
	}

	private interface OperationBody {
		GhidraMcpResponse execute(GhidraMcpContext context, JsonObject params) throws Exception;
	}

	private record SimpleOperation(String name, OperationKind kind, OperationBody body)
			implements GhidraMcpOperation {
		@Override
		public GhidraMcpResponse execute(GhidraMcpContext context, JsonObject params) throws Exception {
			return body.execute(context, params);
		}
	}
}
