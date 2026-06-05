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

import org.junit.Test;

public class GameAnalysisHeuristicsTest {

	@Test
	public void classifiesHealthEvidenceFromTermsAndPcodeHints() {
		GameAnalysisScore score = GameAnalysisHeuristics.scoreEvidence(
			List.of("player_health", "damage applied", "death check"),
			List.of("field +0x140 compared <= 0", "clamp against 100", "sub damage from current"));

		assertEquals(GameAnalysisKind.HEALTH, score.kind());
		assertTrue(score.confidence() >= 80);
		assertTrue(score.evidence().contains("health-like string/symbol"));
		assertTrue(score.evidence().contains("damage/death logic"));
		assertTrue(score.evidence().contains("zero/death threshold compare"));
	}

	@Test
	public void classifiesEntityArrayEvidenceFromPointerWalkHints() {
		GameAnalysisScore score = GameAnalysisHeuristics.scoreEvidence(
			List.of("entity_list", "actor count"),
			List.of("pointer stride 0x8", "loop indexes into pointer table", "count bound check"));

		assertEquals(GameAnalysisKind.ENTITY_ARRAY, score.kind());
		assertTrue(score.confidence() >= 75);
		assertTrue(score.evidence().contains("entity/list string/symbol"));
		assertTrue(score.evidence().contains("pointer table or indexed object walk"));
	}
}
