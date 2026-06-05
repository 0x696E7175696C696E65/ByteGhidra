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

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.app.plugin.core.mcp.bridge.GhidraMcpResponse;
import ghidra.app.plugin.core.mcp.ops.GhidraMcpOperation.OperationKind;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ProgramLocation;

public final class ProgramInfoOps {
	private ProgramInfoOps() {
	}

	public static void register(OperationRegistry registry) {
		registry.register(read("get_current_program", ProgramInfoOps::getCurrentProgram));
		registry.register(read("get_current_location", ProgramInfoOps::getCurrentLocation));
		registry.register(read("get_current_selection", ProgramInfoOps::getCurrentSelection));
		registry.register(read("list_memory_blocks", ProgramInfoOps::listMemoryBlocks));
		registry.register(read("get_imports", ProgramInfoOps::getImports));
		registry.register(read("get_exports", ProgramInfoOps::getExports));
	}

	private static GhidraMcpOperation read(String name, OperationBody body) {
		return new SimpleOperation(name, OperationKind.READ_ONLY, body);
	}

	private static GhidraMcpResponse getCurrentProgram(GhidraMcpContext context, JsonObject params) {
		Program program = OperationUtils.requireProgram(context);
		JsonObject result = new JsonObject();
		result.addProperty("name", program.getName());
		result.addProperty("executablePath", program.getExecutablePath());
		result.addProperty("languageId", program.getLanguageID().getIdAsString());
		result.addProperty("compilerSpecId", program.getCompilerSpec().getCompilerSpecID().getIdAsString());
		result.addProperty("imageBase", program.getImageBase().toString());
		JsonObject memory = new JsonObject();
		memory.addProperty("min", program.getMemory().getMinAddress().toString());
		memory.addProperty("max", program.getMemory().getMaxAddress().toString());
		result.add("memory", memory);
		return GhidraMcpResponse.ok(result);
	}

	private static GhidraMcpResponse getCurrentLocation(GhidraMcpContext context, JsonObject params) {
		ProgramLocation location = context.location();
		JsonObject result = new JsonObject();
		result.addProperty("hasLocation", location != null);
		if (location != null && location.getAddress() != null) {
			result.addProperty("address", location.getAddress().toString());
		}
		return GhidraMcpResponse.ok(result);
	}

	private static GhidraMcpResponse getCurrentSelection(GhidraMcpContext context, JsonObject params) {
		JsonObject result = new JsonObject();
		result.add("selection", OperationUtils.addressRange(context.selection()));
		result.add("highlight", OperationUtils.addressRange(context.highlight()));
		return GhidraMcpResponse.ok(result);
	}

	private static GhidraMcpResponse listMemoryBlocks(GhidraMcpContext context, JsonObject params) {
		Program program = OperationUtils.requireProgram(context);
		JsonArray blocks = new JsonArray();
		for (MemoryBlock block : program.getMemory().getBlocks()) {
			JsonObject object = new JsonObject();
			object.addProperty("name", block.getName());
			object.addProperty("start", block.getStart().toString());
			object.addProperty("end", block.getEnd().toString());
			object.addProperty("size", block.getSize());
			object.addProperty("read", block.isRead());
			object.addProperty("write", block.isWrite());
			object.addProperty("execute", block.isExecute());
			object.addProperty("initialized", block.isInitialized());
			blocks.add(object);
		}
		JsonObject result = new JsonObject();
		result.add("blocks", blocks);
		return GhidraMcpResponse.ok(result);
	}

	private static GhidraMcpResponse getImports(GhidraMcpContext context, JsonObject params) {
		Program program = OperationUtils.requireProgram(context);
		int limit = OperationUtils.intParam(params, "limit", OperationUtils.DEFAULT_LIMIT, 1,
			OperationUtils.MAX_LIMIT);
		JsonArray imports = new JsonArray();
		SymbolIterator symbols = program.getSymbolTable().getExternalSymbols();
		int count = 0;
		while (symbols.hasNext() && imports.size() < limit) {
			Symbol symbol = symbols.next();
			JsonObject object = symbol(symbol);
			ExternalLocation location = program.getExternalManager().getExternalLocation(symbol);
			if (location != null) {
				object.addProperty("library", location.getLibraryName());
				object.addProperty("label", location.getLabel());
			}
			imports.add(object);
			count++;
		}
		JsonObject result = new JsonObject();
		result.add("imports", imports);
		result.addProperty("truncated", symbols.hasNext());
		result.addProperty("countReturned", imports.size());
		result.addProperty("countVisited", count);
		return GhidraMcpResponse.ok(result, symbols.hasNext());
	}

	private static GhidraMcpResponse getExports(GhidraMcpContext context, JsonObject params) {
		Program program = OperationUtils.requireProgram(context);
		int limit = OperationUtils.intParam(params, "limit", OperationUtils.DEFAULT_LIMIT, 1,
			OperationUtils.MAX_LIMIT);
		JsonArray exports = new JsonArray();
		AddressIterator iterator = program.getSymbolTable().getExternalEntryPointIterator();
		while (iterator.hasNext() && exports.size() < limit) {
			Symbol symbol = program.getSymbolTable().getPrimarySymbol(iterator.next());
			if (symbol != null) {
				exports.add(symbol(symbol));
			}
		}
		JsonObject result = new JsonObject();
		result.add("exports", exports);
		result.addProperty("truncated", iterator.hasNext());
		return GhidraMcpResponse.ok(result, iterator.hasNext());
	}

	static JsonObject symbol(Symbol symbol) {
		JsonObject object = new JsonObject();
		object.addProperty("name", symbol.getName(true));
		object.addProperty("address", symbol.getAddress().toString());
		object.addProperty("type", symbol.getSymbolType().toString());
		object.addProperty("source", symbol.getSource().toString());
		object.addProperty("primary", symbol.isPrimary());
		object.addProperty("externalEntryPoint", symbol.isExternalEntryPoint());
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
