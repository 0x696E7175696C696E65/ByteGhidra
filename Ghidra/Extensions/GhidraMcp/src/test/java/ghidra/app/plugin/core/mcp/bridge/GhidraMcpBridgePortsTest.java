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
package ghidra.app.plugin.core.mcp.bridge;

import static org.junit.Assert.*;

import org.junit.Test;

import generic.test.AbstractGenericTest;

public class GhidraMcpBridgePortsTest extends AbstractGenericTest {

	@Test
	public void testChoosesRequestedPortWhenAvailable() {
		int port = GhidraMcpBridgePorts.firstAvailablePort(18090, 10, p -> true);

		assertEquals(18090, port);
	}

	@Test
	public void testIncrementsUntilAvailablePort() {
		int port = GhidraMcpBridgePorts.firstAvailablePort(18090, 10, p -> p >= 18092);

		assertEquals(18092, port);
	}

	@Test
	public void testFailsWhenScanRangeIsExhausted() {
		IllegalStateException exception = assertThrows(IllegalStateException.class,
			() -> GhidraMcpBridgePorts.firstAvailablePort(18090, 3, p -> false));

		assertTrue(exception.getMessage().contains("18090"));
		assertTrue(exception.getMessage().contains("18092"));
	}
}
