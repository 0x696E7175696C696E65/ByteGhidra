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
package ghidra.app.plugin.core.mcp;

import static org.junit.Assert.*;

import org.junit.Test;

import com.google.gson.JsonObject;

import generic.test.AbstractGenericTest;
import ghidra.app.plugin.core.mcp.bridge.GhidraMcpResponse;
import ghidra.app.plugin.core.mcp.ops.*;
import ghidra.app.plugin.core.mcp.ops.GhidraMcpOperation.OperationKind;
import ghidra.app.plugin.core.mcp.security.GhidraMcpPolicy;
import ghidra.util.task.TaskMonitor;

public class OperationRegistryTest extends AbstractGenericTest {

	@Test
	public void testUnknownOperationReturnsStructuredError() {
		OperationRegistry registry = new OperationRegistry(false);
		GhidraMcpContext context =
			new GhidraMcpContext(null, null, null, null, null, GhidraMcpPolicy.defaults(),
				TaskMonitor.DUMMY);

		GhidraMcpResponse response = registry.execute(context, "missing_tool", new JsonObject());

		assertFalse(response.isSuccess());
		assertEquals("unknown_operation", response.getErrorCode());
	}

	@Test
	public void testPolicyDenialReturnsStructuredErrorBeforeOperationRuns() {
		OperationRegistry registry = new OperationRegistry(false);
		registry.register(new GhidraMcpOperation() {
			@Override
			public String name() {
				return "write_tool";
			}

			@Override
			public OperationKind kind() {
				return OperationKind.ANNOTATION_WRITE;
			}

			@Override
			public GhidraMcpResponse execute(GhidraMcpContext context, JsonObject params) {
				return GhidraMcpResponse.ok(new JsonObject());
			}
		});
		GhidraMcpContext context =
			new GhidraMcpContext(null, null, null, null, null, GhidraMcpPolicy.defaults(),
				TaskMonitor.DUMMY);

		GhidraMcpResponse response = registry.execute(context, "write_tool", new JsonObject());

		assertFalse(response.isSuccess());
		assertEquals("permission_denied", response.getErrorCode());
	}

	@Test
	public void testRegisteredOperationExecutesWhenPolicyAllowsIt() {
		OperationRegistry registry = new OperationRegistry(false);
		registry.register(new GhidraMcpOperation() {
			@Override
			public String name() {
				return "read_tool";
			}

			@Override
			public OperationKind kind() {
				return OperationKind.READ_ONLY;
			}

			@Override
			public GhidraMcpResponse execute(GhidraMcpContext context, JsonObject params) {
				JsonObject result = new JsonObject();
				result.addProperty("ran", true);
				return GhidraMcpResponse.ok(result);
			}
		});
		GhidraMcpContext context =
			new GhidraMcpContext(null, null, null, null, null, GhidraMcpPolicy.defaults(),
				TaskMonitor.DUMMY);

		GhidraMcpResponse response = registry.execute(context, "read_tool", new JsonObject());

		assertTrue(response.isSuccess());
		assertTrue(response.getResult().getAsJsonObject().get("ran").getAsBoolean());
	}
}
