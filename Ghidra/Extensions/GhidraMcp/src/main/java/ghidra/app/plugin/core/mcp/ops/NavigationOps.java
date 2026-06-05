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

import ghidra.app.plugin.core.mcp.bridge.GhidraMcpResponse;
import ghidra.app.plugin.core.mcp.ops.GhidraMcpOperation.OperationKind;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;

public final class NavigationOps {
	private NavigationOps() {
	}

	public static void register(OperationRegistry registry) {
		registry.register(ui("goto_address", NavigationOps::gotoAddress));
		registry.register(ui("select_range", NavigationOps::selectRange));
		registry.register(ui("highlight_range", NavigationOps::highlightRange));
	}

	private static GhidraMcpOperation ui(String name, OperationBody body) {
		return new SimpleOperation(name, OperationKind.UI_ONLY, body);
	}

	private static GhidraMcpResponse gotoAddress(GhidraMcpContext context, JsonObject params) {
		Program program = OperationUtils.requireProgram(context);
		Address address = OperationUtils.address(program, OperationUtils.requiredString(params, "address"));
		if (context.plugin() == null) {
			return GhidraMcpResponse.error("plugin_unavailable", "Navigation requires the Ghidra plugin");
		}
		boolean success = context.plugin().goToMcpAddress(address);
		JsonObject result = new JsonObject();
		result.addProperty("address", address.toString());
		result.addProperty("navigated", success);
		return GhidraMcpResponse.ok(result);
	}

	private static GhidraMcpResponse selectRange(GhidraMcpContext context, JsonObject params) {
		Program program = OperationUtils.requireProgram(context);
		AddressSet set = addressSet(program, params);
		if (context.plugin() == null) {
			return GhidraMcpResponse.error("plugin_unavailable", "Selection requires the Ghidra plugin");
		}
		context.plugin().selectMcpRange(set);
		JsonObject result = new JsonObject();
		result.add("selection", OperationUtils.addressRange(set));
		return GhidraMcpResponse.ok(result);
	}

	private static GhidraMcpResponse highlightRange(GhidraMcpContext context, JsonObject params) {
		Program program = OperationUtils.requireProgram(context);
		AddressSet set = addressSet(program, params);
		if (context.plugin() == null) {
			return GhidraMcpResponse.error("plugin_unavailable", "Highlight requires the Ghidra plugin");
		}
		context.plugin().highlightMcpRange(set);
		JsonObject result = new JsonObject();
		result.add("highlight", OperationUtils.addressRange(set));
		return GhidraMcpResponse.ok(result);
	}

	private static AddressSet addressSet(Program program, JsonObject params) {
		Address start = OperationUtils.address(program, OperationUtils.requiredString(params, "start"));
		Address end = OperationUtils.address(program, OperationUtils.requiredString(params, "end"));
		return new AddressSet(start, end);
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
