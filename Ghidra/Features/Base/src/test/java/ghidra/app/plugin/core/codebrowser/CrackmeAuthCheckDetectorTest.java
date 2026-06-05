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
package ghidra.app.plugin.core.codebrowser;

import static org.junit.Assert.*;

import java.util.List;

import org.junit.*;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.util.task.TaskMonitor;

public class CrackmeAuthCheckDetectorTest extends AbstractGhidraHeadlessIntegrationTest {

	private ProgramBuilder builder;
	private Program program;

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder("crackme", ProgramBuilder._X86);
		builder.createMemory("test", "0x1000", 0x3000);
		program = builder.getProgram();
	}

	@After
	public void tearDown() {
		builder.dispose();
	}

	@Test
	public void testFindsFunctionReferencingPasswordStringsAndCompareApi() throws Exception {
		builder.createEmptyFunction("check_password", null, "0x1000", 0x40, VoidDataType.dataType);
		builder.createString("0x2000", "Enter password:");
		builder.createString("0x2020", "Correct!");
		builder.createMemoryReadReference("0x1004", "0x2000");
		builder.createMemoryReadReference("0x1010", "0x2020");
		builder.createExternalReference("0x1018", "libc.so", "strcmp", null, 0,
			RefType.UNCONDITIONAL_CALL, SourceType.IMPORTED);

		List<CrackmeAuthCheckCandidate> candidates =
			CrackmeAuthCheckDetector.findCandidates(program, TaskMonitor.DUMMY);

		assertEquals(1, candidates.size());
		CrackmeAuthCheckCandidate candidate = candidates.get(0);
		assertEquals(builder.addr("0x1000"), candidate.address());
		assertEquals("check_password", candidate.functionName());
		assertTrue(candidate.confidence() >= 80);
		assertTrue(candidate.evidence().contains("auth string"));
		assertTrue(candidate.evidence().contains("compare API strcmp"));
	}

	@Test
	public void testIgnoresPlainLoggingFunctionWithNoAuthEvidence() throws Exception {
		builder.createEmptyFunction("log_banner", null, "0x1100", 0x20, VoidDataType.dataType);
		builder.createString("0x2100", "Welcome to the demo");
		builder.createMemoryReadReference("0x1104", "0x2100");

		List<CrackmeAuthCheckCandidate> candidates =
			CrackmeAuthCheckDetector.findCandidates(program, TaskMonitor.DUMMY);

		assertTrue(candidates.isEmpty());
	}

	@Test
	public void testDoesNotReportStringOnlyStatusMessages() throws Exception {
		builder.createEmptyFunction("show_status", null, "0x1200", 0x20, VoidDataType.dataType);
		builder.createString("0x2200", "Password changed successfully");
		builder.createMemoryReadReference("0x1204", "0x2200");

		List<CrackmeAuthCheckCandidate> candidates =
			CrackmeAuthCheckDetector.findCandidates(program, TaskMonitor.DUMMY);

		assertTrue(candidates.isEmpty());
	}

	@Test
	public void testDoesNotReportPasswordStatusMutationWithCompareApi() throws Exception {
		builder.createEmptyFunction("update_password_status", null, "0x1250", 0x20,
			VoidDataType.dataType);
		builder.createString("0x2250", "Password changed successfully");
		builder.createMemoryReadReference("0x1254", "0x2250");
		builder.createExternalReference("0x1260", "libc.so", "strcmp", null, 0,
			RefType.UNCONDITIONAL_CALL, SourceType.IMPORTED);

		List<CrackmeAuthCheckCandidate> candidates =
			CrackmeAuthCheckDetector.findCandidates(program, TaskMonitor.DUMMY);

		assertTrue(candidates.isEmpty());
	}

	@Test
	public void testDoesNotReportApiOnlyUtilityFunction() throws Exception {
		builder.createEmptyFunction("sort_buffers", null, "0x1300", 0x20, VoidDataType.dataType);
		builder.createExternalReference("0x1304", "libc.so", "memcmp", null, 0,
			RefType.UNCONDITIONAL_CALL, SourceType.IMPORTED);
		builder.createExternalReference("0x1310", "libc.so", "memcmp", null, 0,
			RefType.UNCONDITIONAL_CALL, SourceType.IMPORTED);

		List<CrackmeAuthCheckCandidate> candidates =
			CrackmeAuthCheckDetector.findCandidates(program, TaskMonitor.DUMMY);

		assertTrue(candidates.isEmpty());
	}

	@Test
	public void testRecognizesDecoratedCompareImports() throws Exception {
		builder.createEmptyFunction("decorated_check", null, "0x1400", 0x20,
			VoidDataType.dataType);
		builder.createString("0x2400", "password:");
		builder.createMemoryReadReference("0x1404", "0x2400");
		builder.createExternalReference("0x1410", "msvcrt.dll", "__imp__strcmp", null, 0,
			RefType.UNCONDITIONAL_CALL, SourceType.IMPORTED);

		List<CrackmeAuthCheckCandidate> candidates =
			CrackmeAuthCheckDetector.findCandidates(program, TaskMonitor.DUMMY);

		assertEquals(1, candidates.size());
		assertTrue(candidates.get(0).evidence().contains("compare API strcmp"));
	}

	@Test
	public void testRecoversAsciiMathXorBitAndCompareConstraintEvidence() throws Exception {
		builder.setBytes("0x1500", "2c 30 3c 09 34 55 04 07 24 0f d0 e0 c3", true);
		builder.createEmptyFunction("mathy_check", null, "0x1500", 0x20, VoidDataType.dataType);
		builder.createString("0x2500", "password:");
		builder.createMemoryReadReference("0x1500", "0x2500");
		builder.createExternalReference("0x1508", "libc.so", "strcmp", null, 0,
			RefType.UNCONDITIONAL_CALL, SourceType.IMPORTED);

		List<CrackmeAuthCheckCandidate> candidates =
			CrackmeAuthCheckDetector.findCandidates(program, TaskMonitor.DUMMY);

		assertEquals(1, candidates.size());
		CrackmeAuthCheckCandidate candidate = candidates.get(0);
		assertTrue(candidate.constraintSummary().contains("ASCII digit conversion"));
		assertTrue(candidate.constraintSummary().contains("XOR transform"));
		assertTrue(candidate.constraintSummary().contains("additive math"));
		assertTrue(candidate.constraintSummary().contains("bit mask/shift"));
		assertTrue(candidate.constraintSummary().contains("compare branch/value"));
	}

	@Test
	public void testReportsInlineConstraintOnlyAuthCheckWithoutCompareImport() throws Exception {
		builder.setBytes("0x1700", "2c 30 3c 09 34 55 c3", true);
		builder.createEmptyFunction("inline_check", null, "0x1700", 0x20, VoidDataType.dataType);
		builder.createString("0x2800", "password:");
		builder.createMemoryReadReference("0x1700", "0x2800");

		List<CrackmeAuthCheckCandidate> candidates =
			CrackmeAuthCheckDetector.findCandidates(program, TaskMonitor.DUMMY);

		assertEquals(1, candidates.size());
		assertTrue(candidates.get(0).evidence().contains("local constraint recovery"));
		assertTrue(candidates.get(0).candidateInput().contains("[0-9]"));
	}

	@Test
	public void testReportsArrayOrLookupTableEvidence() throws Exception {
		builder.createEmptyFunction("table_check", null, "0x1600", 0x20, VoidDataType.dataType);
		builder.createString("0x2600", "serial:");
		builder.createMemoryReadReference("0x1604", "0x2600");
		builder.createExternalReference("0x1610", "libc.so", "memcmp", null, 0,
			RefType.UNCONDITIONAL_CALL, SourceType.IMPORTED);
		builder.setBytes("0x2700", "13 37 c0 de");
		builder.applyDataType("0x2700", ByteDataType.dataType, 4);
		builder.createMemoryReadReference("0x1618", "0x2700");

		List<CrackmeAuthCheckCandidate> candidates =
			CrackmeAuthCheckDetector.findCandidates(program, TaskMonitor.DUMMY);

		assertEquals(1, candidates.size());
		assertTrue(candidates.get(0).constraintSummary().contains("array/table lookup"));
	}

	@Test
	public void testDoesNotTreatPlainUndefinedMemoryReferenceAsLookupTable() throws Exception {
		builder.createEmptyFunction("buffer_check", null, "0x1800", 0x20, VoidDataType.dataType);
		builder.createString("0x2900", "serial:");
		builder.createMemoryReadReference("0x1804", "0x2900");
		builder.createExternalReference("0x1810", "libc.so", "memcmp", null, 0,
			RefType.UNCONDITIONAL_CALL, SourceType.IMPORTED);
		builder.createMemoryReadReference("0x1818", "0x2a00");

		List<CrackmeAuthCheckCandidate> candidates =
			CrackmeAuthCheckDetector.findCandidates(program, TaskMonitor.DUMMY);

		assertEquals(1, candidates.size());
		assertFalse(candidates.get(0).constraintSummary().contains("array/table lookup"));
	}

	@Test
	public void testDoesNotPromotePromptOnlyFunctionWithWeakLocalMnemonic() throws Exception {
		builder.setBytes("0x1900", "8d 40 00 c3", true);
		builder.createEmptyFunction("prompt_only", null, "0x1900", 0x20, VoidDataType.dataType);
		builder.createString("0x2b00", "password:");
		builder.createMemoryReadReference("0x1900", "0x2b00");

		List<CrackmeAuthCheckCandidate> candidates =
			CrackmeAuthCheckDetector.findCandidates(program, TaskMonitor.DUMMY);

		assertTrue(candidates.isEmpty());
	}

	@Test
	public void testDoesNotPromotePromptOnlyFunctionWithCommonStackConstant() throws Exception {
		builder.setBytes("0x1a00", "83 ec 10 c3", true);
		builder.createEmptyFunction("prompt_stack_setup", null, "0x1a00", 0x20,
			VoidDataType.dataType);
		builder.createString("0x2c00", "password:");
		builder.createMemoryReadReference("0x1a00", "0x2c00");

		List<CrackmeAuthCheckCandidate> candidates =
			CrackmeAuthCheckDetector.findCandidates(program, TaskMonitor.DUMMY);

		assertTrue(candidates.isEmpty());
	}
}
