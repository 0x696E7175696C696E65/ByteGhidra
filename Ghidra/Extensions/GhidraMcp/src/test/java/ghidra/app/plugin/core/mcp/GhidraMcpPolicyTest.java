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

import generic.test.AbstractGenericTest;
import ghidra.app.plugin.core.mcp.ops.GhidraMcpOperation.OperationKind;
import ghidra.app.plugin.core.mcp.security.GhidraMcpPolicy;

public class GhidraMcpPolicyTest extends AbstractGenericTest {

	@Test
	public void testDefaultPolicyAllowsReadOnlyAndUiOnlyOperations() {
		GhidraMcpPolicy policy = GhidraMcpPolicy.defaults();

		assertTrue(policy.isAllowed(OperationKind.READ_ONLY));
		assertTrue(policy.isAllowed(OperationKind.UI_ONLY));
	}

	@Test
	public void testDefaultPolicyDeniesMutatingAndDangerousOperations() {
		GhidraMcpPolicy policy = GhidraMcpPolicy.defaults();

		assertFalse(policy.isAllowed(OperationKind.ANNOTATION_WRITE));
		assertFalse(policy.isAllowed(OperationKind.ANALYSIS_WRITE));
		assertFalse(policy.isAllowed(OperationKind.DANGEROUS));
	}

	@Test
	public void testExplicitPolicyCanEnableAnnotationWritesOnly() {
		GhidraMcpPolicy policy =
			new GhidraMcpPolicy(true, true, true, false, false, false);

		assertTrue(policy.isAllowed(OperationKind.ANNOTATION_WRITE));
		assertFalse(policy.isAllowed(OperationKind.ANALYSIS_WRITE));
		assertFalse(policy.isAllowed(OperationKind.DANGEROUS));
	}
}
