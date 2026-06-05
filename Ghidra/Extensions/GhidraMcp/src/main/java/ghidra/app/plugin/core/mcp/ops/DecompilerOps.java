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

import ghidra.app.decompiler.*;
import ghidra.app.plugin.core.mcp.bridge.GhidraMcpResponse;
import ghidra.app.plugin.core.mcp.ops.GhidraMcpOperation.OperationKind;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

public final class DecompilerOps {
	private DecompilerOps() {
	}

	public static void register(OperationRegistry registry) {
		registry.register(new GhidraMcpOperation() {
			@Override
			public String name() {
				return "decompile_function";
			}

			@Override
			public OperationKind kind() {
				return OperationKind.READ_ONLY;
			}

			@Override
			public GhidraMcpResponse execute(GhidraMcpContext context, JsonObject params) {
				return decompileFunction(context, params);
			}
		});
	}

	private static GhidraMcpResponse decompileFunction(GhidraMcpContext context, JsonObject params) {
		Program program = OperationUtils.requireProgram(context);
		Function function = ListingOps.findFunction(program, params);
		if (function == null) {
			return GhidraMcpResponse.error("not_found", "No matching function");
		}
		int timeout = OperationUtils.intParam(params, "timeoutSeconds", 30, 1, 300);
		DecompInterface decompiler = new DecompInterface();
		try {
			decompiler.toggleCCode(true);
			decompiler.toggleSyntaxTree(true);
			decompiler.setSimplificationStyle("decompile");
			if (!decompiler.openProgram(program)) {
				return GhidraMcpResponse.error("decompiler_open_failed",
					decompiler.getLastMessage());
			}
			DecompileResults results =
				decompiler.decompileFunction(function, timeout, context.monitor());
			if (!results.decompileCompleted()) {
				return GhidraMcpResponse.error("decompiler_failed", results.getErrorMessage());
			}
			String c = results.getDecompiledFunction() == null ? ""
					: results.getDecompiledFunction().getC();
			int maxChars = OperationUtils.intParam(params, "maxChars", 20000, 100, 200000);
			boolean truncated = c.length() > maxChars;
			JsonObject result = ListingOps.function(function);
			result.addProperty("decompiled", truncated ? c.substring(0, maxChars) : c);
			result.addProperty("truncated", truncated);
			return GhidraMcpResponse.ok(result, truncated);
		}
		finally {
			decompiler.dispose();
		}
	}
}
