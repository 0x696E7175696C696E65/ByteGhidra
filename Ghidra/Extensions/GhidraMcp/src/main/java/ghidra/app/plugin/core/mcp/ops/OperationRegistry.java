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

public class OperationRegistry {
	private final Map<String, GhidraMcpOperation> operations = new LinkedHashMap<>();

	public OperationRegistry() {
		this(true);
	}

	public OperationRegistry(boolean registerDefaults) {
		if (registerDefaults) {
			ProgramInfoOps.register(this);
			ListingOps.register(this);
			DecompilerOps.register(this);
			MutationOps.register(this);
			NavigationOps.register(this);
			ScriptOps.register(this);
			AiAnalysisOps.register(this);
		}
	}

	public void register(GhidraMcpOperation operation) {
		operations.put(operation.name(), operation);
	}

	public Collection<GhidraMcpOperation> operations() {
		return List.copyOf(operations.values());
	}

	public GhidraMcpOperation get(String name) {
		return operations.get(name);
	}

	public GhidraMcpResponse execute(GhidraMcpContext context, String name, JsonObject params) {
		GhidraMcpOperation operation = operations.get(name);
		if (operation == null) {
			return GhidraMcpResponse.error("unknown_operation", "Unknown Ghidra MCP operation: " + name);
		}
		if (!context.policy().isAllowed(operation.kind())) {
			return GhidraMcpResponse.error("permission_denied",
				"Operation '" + name + "' is disabled by the current Ghidra MCP policy");
		}
		try {
			return operation.execute(context, params == null ? new JsonObject() : params);
		}
		catch (IllegalArgumentException e) {
			return GhidraMcpResponse.error("invalid_request", e.getMessage());
		}
		catch (Exception e) {
			return GhidraMcpResponse.error("operation_failed", e.getMessage());
		}
	}

	public JsonArray operationNames() {
		JsonArray names = new JsonArray();
		for (String name : operations.keySet()) {
			names.add(name);
		}
		return names;
	}
}
