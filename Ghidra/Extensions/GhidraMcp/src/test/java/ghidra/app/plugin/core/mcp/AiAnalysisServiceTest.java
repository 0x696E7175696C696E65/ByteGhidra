/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0
 */
package ghidra.app.plugin.core.mcp;

import static org.junit.Assert.*;

import java.time.Instant;
import java.util.List;
import java.nio.file.*;

import org.junit.Test;

import ghidra.app.plugin.core.mcp.ai.AiAnalysisService;
import generic.test.AbstractGenericTest;
import ghidra.app.plugin.core.mcp.evidence.*;
import ghidra.app.plugin.core.mcp.hypotheses.*;
import ghidra.app.plugin.core.mcp.sandbox.SandboxEvidenceImporter;
import ghidra.app.plugin.core.mcp.tasks.*;
import ghidra.app.plugin.core.mcp.yara.YaraRuleGenerator;

public class AiAnalysisServiceTest extends AbstractGenericTest {

	@Test
	public void testEvidenceStoreAddsAndRetrievesRecords() {
		EvidenceStore store = new EvidenceStore();
		EvidenceRecord record = new EvidenceRecord("ev-test", "test", "network", "high",
			"00401000", "FUN_00401000", "URL string", "https://example.test", 0.9,
			List.of("string", "network"), Instant.now());

		store.add(record);

		assertEquals(record, store.get("ev-test"));
		assertEquals(1, store.toJsonArray().size());
	}

	@Test
	public void testEvidenceStoreDeduplicatesStableFindings() {
		EvidenceStore store = new EvidenceStore();
		store.add(new EvidenceRecord("ev-1", "triage", "network", "high", "00401000", null,
			"Network indicator", "https://example.test", 0.9, List.of("string"), Instant.now()));
		EvidenceRecord second = store.add(new EvidenceRecord("ev-2", "triage", "network", "high",
			"00401000", null, "Network indicator", "https://example.test", 0.9,
			List.of("string"), Instant.now()));

		assertEquals(1, store.list().size());
		assertEquals("ev-1", second.id());
	}

	@Test
	public void testAnalysisServiceScopesStoresByProgramSession() {
		AiAnalysisService service = new AiAnalysisService();
		service.activateSession("sample-a", "hash-a");
		service.evidence().add(new EvidenceRecord("ev-a", "test", "network", "high", "00401000",
			null, "A evidence", "details", 0.9, List.of(), Instant.now()));

		service.activateSession("sample-b", "hash-b");
		assertEquals(0, service.evidence().list().size());

		service.activateSession("sample-a", "hash-a");
		assertEquals(1, service.evidence().list().size());
		assertEquals("sample-a", service.exportSession().get("programName").getAsString());
	}

	@Test
	public void testAgentTaskQueueStateTransitions() {
		AgentTaskQueue queue = new AgentTaskQueue();
		AgentTask task = queue.create("Run triage", "Find suspicious indicators");

		queue.setStatus(task.id(), AgentTask.Status.APPROVED);

		assertEquals(AgentTask.Status.APPROVED, queue.get(task.id()).status());
	}

	@Test
	public void testAgentTaskTracksProgressAndCancellation() {
		AgentTaskQueue queue = new AgentTaskQueue();
		AgentTask task = queue.create("Run triage", "Find suspicious indicators");

		task.start();
		task.updateProgress(40, "Collected imports");
		queue.cancel(task.id());

		assertEquals(AgentTask.Status.CANCEL_REQUESTED, task.status());
		assertTrue(task.isCancelRequested());
		assertEquals(40, task.toJson().get("progress").getAsInt());
		assertEquals("Collected imports", task.toJson().get("message").getAsString());
	}

	@Test
	public void testHypothesesLinkEvidence() {
		HypothesisStore store = new HypothesisStore();
		Hypothesis hypothesis = store.create("Sample may beacon over HTTP");

		hypothesis.linkEvidence("ev-1");

		assertEquals("ev-1",
			hypothesis.toJson().getAsJsonArray("evidenceIds").get(0).getAsString());
	}

	@Test
	public void testYaraDraftUsesStringEvidence() {
		EvidenceStore store = new EvidenceStore();
		store.add(new EvidenceRecord("ev-yara", "test", "network", "high", "00402000", null,
			"Network string", "https://c2.example.test/path", 0.8, List.of("string", "network"),
			Instant.now()));

		String rule = new YaraRuleGenerator().draft("Example Family", store).ruleText();

		assertTrue(rule.contains("Example_Family_draft"));
		assertTrue(rule.contains("https://c2.example.test/path"));
	}

	@Test
	public void testSandboxImportReportsImportedAndSkippedRows() throws Exception {
		Path csv = Files.createTempFile("sandbox-events", ".csv");
		Files.writeString(csv, "address,api,category,summary\n00401000,InternetConnect,network,C2\n,,,");
		EvidenceStore store = new EvidenceStore();

		SandboxEvidenceImporter.ImportResult result =
			new SandboxEvidenceImporter().importFile(csv, null, store);

		assertEquals(1, result.imported());
		assertEquals(1, result.skipped());
		assertEquals(1, store.list().size());
	}

	@Test
	public void testYaraDraftSanitizesLeadingDigitsAndCitesEvidenceIds() {
		EvidenceStore store = new EvidenceStore();
		store.add(new EvidenceRecord("ev-a", "test", "network", "high", "00402000", null,
			"Network string", "duplicate-string", 0.8, List.of("string", "network"), Instant.now()));
		store.add(new EvidenceRecord("ev-b", "test", "network", "high", "00402010", null,
			"Network string", "duplicate-string", 0.8, List.of("string", "network"), Instant.now()));

		String rule = new YaraRuleGenerator().draft("123 bad family", store).ruleText();

		assertTrue(rule.contains("rule sample_123_bad_family_draft"));
		assertTrue(rule.contains("evidence = \"ev-a, ev-b\""));
		assertEquals(1, countOccurrences(rule, "duplicate-string"));
	}

	private int countOccurrences(String text, String needle) {
		int count = 0;
		int index = 0;
		while ((index = text.indexOf(needle, index)) >= 0) {
			count++;
			index += needle.length();
		}
		return count;
	}
}
