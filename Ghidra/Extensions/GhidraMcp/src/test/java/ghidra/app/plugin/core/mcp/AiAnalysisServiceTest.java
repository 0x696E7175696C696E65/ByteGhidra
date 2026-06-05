/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0
 */
package ghidra.app.plugin.core.mcp;

import static org.junit.Assert.*;

import java.time.Instant;
import java.util.List;

import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.app.plugin.core.mcp.evidence.*;
import ghidra.app.plugin.core.mcp.hypotheses.*;
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
	public void testAgentTaskQueueStateTransitions() {
		AgentTaskQueue queue = new AgentTaskQueue();
		AgentTask task = queue.create("Run triage", "Find suspicious indicators");

		queue.setStatus(task.id(), AgentTask.Status.APPROVED);

		assertEquals(AgentTask.Status.APPROVED, queue.get(task.id()).status());
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
}
