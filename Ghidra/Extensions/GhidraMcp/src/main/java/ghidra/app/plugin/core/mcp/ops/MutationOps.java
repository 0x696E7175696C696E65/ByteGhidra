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

import com.google.gson.JsonObject;

import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.mcp.bridge.GhidraMcpResponse;
import ghidra.app.plugin.core.mcp.ops.GhidraMcpOperation.OperationKind;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

public final class MutationOps {
	private MutationOps() {
	}

	public static void register(OperationRegistry registry) {
		registry.register(annotation("rename_symbol", MutationOps::renameSymbol));
		registry.register(annotation("set_pre_comment", (context, params) -> setComment(context, params,
			CommentType.PRE)));
		registry.register(annotation("set_plate_comment", (context, params) -> setComment(context, params,
			CommentType.PLATE)));
		registry.register(annotation("add_bookmark", MutationOps::addBookmark));
		registry.register(annotation("set_function_signature", MutationOps::setFunctionSignature));
		registry.register(analysis("analyze_changes", MutationOps::analyzeChanges));
		registry.register(analysis("analyze_all", MutationOps::analyzeAll));
	}

	private static GhidraMcpOperation annotation(String name, OperationBody body) {
		return new SimpleOperation(name, OperationKind.ANNOTATION_WRITE, body);
	}

	private static GhidraMcpOperation analysis(String name, OperationBody body) {
		return new SimpleOperation(name, OperationKind.ANALYSIS_WRITE, body);
	}

	private static GhidraMcpResponse renameSymbol(GhidraMcpContext context, JsonObject params) {
		Program program = OperationUtils.requireProgram(context);
		Address address = OperationUtils.address(program, OperationUtils.requiredString(params, "address"));
		String name = OperationUtils.requiredString(params, "name");
		return transaction(program, "Ghidra MCP Rename Symbol", () -> {
			Function function = program.getFunctionManager().getFunctionAt(address);
			if (function != null) {
				function.setName(name, SourceType.USER_DEFINED);
			}
			else {
				Symbol symbol = program.getSymbolTable().getPrimarySymbol(address);
				if (symbol != null) {
					symbol.setName(name, SourceType.USER_DEFINED);
				}
				else {
					program.getSymbolTable().createLabel(address, name, SourceType.USER_DEFINED);
				}
			}
			JsonObject result = new JsonObject();
			result.addProperty("address", address.toString());
			result.addProperty("name", name);
			return result;
		});
	}

	private static GhidraMcpResponse setComment(GhidraMcpContext context, JsonObject params,
			CommentType type) {
		Program program = OperationUtils.requireProgram(context);
		Address address = OperationUtils.address(program, OperationUtils.requiredString(params, "address"));
		String comment = OperationUtils.requiredString(params, "comment");
		return transaction(program, "Ghidra MCP Set Comment", () -> {
			program.getListing().setComment(address, type, comment);
			JsonObject result = new JsonObject();
			result.addProperty("address", address.toString());
			result.addProperty("commentType", type.name());
			result.addProperty("comment", comment);
			return result;
		});
	}

	private static GhidraMcpResponse addBookmark(GhidraMcpContext context, JsonObject params) {
		Program program = OperationUtils.requireProgram(context);
		Address address = OperationUtils.address(program, OperationUtils.requiredString(params, "address"));
		String category = OperationUtils.optionalString(params, "category", "MCP");
		String comment = OperationUtils.requiredString(params, "comment");
		return transaction(program, "Ghidra MCP Add Bookmark", () -> {
			program.getBookmarkManager().setBookmark(address, BookmarkType.NOTE, category, comment);
			JsonObject result = new JsonObject();
			result.addProperty("address", address.toString());
			result.addProperty("category", category);
			result.addProperty("comment", comment);
			return result;
		});
	}

	private static GhidraMcpResponse setFunctionSignature(GhidraMcpContext context, JsonObject params)
			throws Exception {
		Program program = OperationUtils.requireProgram(context);
		Function function = ListingOps.findFunction(program, params);
		if (function == null) {
			return GhidraMcpResponse.error("not_found", "No matching function");
		}
		String signature = OperationUtils.requiredString(params, "signature");
		FunctionSignatureParser parser =
			new FunctionSignatureParser(program.getDataTypeManager(), null);
		FunctionDefinitionDataType definition = parser.parse(function.getSignature(), signature);
		ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(function.getEntryPoint(), definition,
			SourceType.USER_DEFINED);
		boolean applied = context.tool() != null ? context.tool().execute(cmd, program)
				: cmd.applyTo(program, context.monitor());
		if (!applied) {
			return GhidraMcpResponse.error("signature_apply_failed", cmd.getStatusMsg());
		}
		JsonObject result = ListingOps.function(function);
		return GhidraMcpResponse.ok(result);
	}

	private static GhidraMcpResponse analyzeChanges(GhidraMcpContext context, JsonObject params) {
		Program program = OperationUtils.requireProgram(context);
		AutoAnalysisManager.getAnalysisManager(program).startAnalysis(context.monitor(), false);
		JsonObject result = new JsonObject();
		result.addProperty("analysis", "changes");
		return GhidraMcpResponse.ok(result);
	}

	private static GhidraMcpResponse analyzeAll(GhidraMcpContext context, JsonObject params) {
		Program program = OperationUtils.requireProgram(context);
		AutoAnalysisManager manager = AutoAnalysisManager.getAnalysisManager(program);
		manager.initializeOptions();
		manager.reAnalyzeAll(null);
		manager.startAnalysis(context.monitor(), false);
		JsonObject result = new JsonObject();
		result.addProperty("analysis", "all");
		return GhidraMcpResponse.ok(result);
	}

	private static GhidraMcpResponse transaction(Program program, String name, TxBody body) {
		int tx = program.startTransaction(name);
		boolean commit = false;
		try {
			JsonObject result = body.run();
			commit = true;
			return GhidraMcpResponse.ok(result);
		}
		catch (Exception e) {
			return GhidraMcpResponse.error("mutation_failed", e.getMessage());
		}
		finally {
			program.endTransaction(tx, commit);
		}
	}

	private interface TxBody {
		JsonObject run() throws Exception;
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
