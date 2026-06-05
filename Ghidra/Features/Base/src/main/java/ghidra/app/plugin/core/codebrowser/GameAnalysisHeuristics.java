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

import java.util.*;

class GameAnalysisHeuristics {
	private static final Map<GameAnalysisKind, RoleRule> RULES = Map.of(
		GameAnalysisKind.HEALTH,
		new RoleRule(List.of("health", "hp", "shield", "armor"),
			List.of("damage", "death", "dead", "heal", "regen", "clamp", "<= 0", "zero")),
		GameAnalysisKind.ENTITY_ARRAY,
		new RoleRule(List.of("entity", "actor", "pawn", "object", "unit", "ped"),
			List.of("pointer table", "indexed object", "stride", "count", "array", "loop")),
		GameAnalysisKind.AMMO,
		new RoleRule(List.of("ammo", "weapon", "clip", "magazine", "rounds"),
			List.of("reload", "fire", "consume", "decrement")),
		GameAnalysisKind.ABILITY,
		new RoleRule(List.of("ability", "skill", "cooldown", "mana", "stamina"),
			List.of("timer", "cooldown", "ready", "charge")),
		GameAnalysisKind.INVENTORY,
		new RoleRule(List.of("inventory", "item", "slot", "bag", "pickup"),
			List.of("slot", "capacity", "item id", "container")),
		GameAnalysisKind.TRANSFORM,
		new RoleRule(List.of("position", "transform", "coord", "xpos", "ypos", "zpos", "velocity"),
			List.of("vector", "matrix", "float", "distance")),
		GameAnalysisKind.OBJECT_TYPE,
		new RoleRule(List.of("vtable", "typeinfo", "class", "rtti"),
			List.of("virtual call", "constructor", "type check")),
		GameAnalysisKind.PLAYER_STATE,
		new RoleRule(List.of("player", "localplayer", "controller", "character"),
			List.of("input", "camera", "team", "state")));

	private GameAnalysisHeuristics() {
	}

	static GameAnalysisScore scoreEvidence(Collection<String> labels, Collection<String> behaviorHints) {
		String labelText = normalize(labels);
		String behaviorText = normalize(behaviorHints);
		GameAnalysisKind bestKind = GameAnalysisKind.UNKNOWN;
		int bestScore = 0;
		List<String> bestEvidence = new ArrayList<>();

		for (Map.Entry<GameAnalysisKind, RoleRule> entry : RULES.entrySet()) {
			RoleRule rule = entry.getValue();
			int score = 0;
			List<String> evidence = new ArrayList<>();

			int labelHits = countHits(labelText, rule.labelTerms);
			if (labelHits > 0) {
				score += 35 + Math.min(20, labelHits * 5);
				evidence.add(evidenceName(entry.getKey()) + " string/symbol");
			}

			int behaviorHits = countHits(behaviorText, rule.behaviorTerms);
			if (behaviorHits > 0) {
				score += 30 + Math.min(25, behaviorHits * 5);
				evidence.add(behaviorEvidenceName(entry.getKey()));
			}

			if (entry.getKey() == GameAnalysisKind.HEALTH && behaviorText.contains("<= 0")) {
				score += 15;
				evidence.add("zero/death threshold compare");
			}
			if (entry.getKey() == GameAnalysisKind.ENTITY_ARRAY &&
				(behaviorText.contains("pointer table") || behaviorText.contains("indexed object"))) {
				score += 15;
				evidence.add("pointer table or indexed object walk");
			}

			if (score > bestScore) {
				bestScore = score;
				bestKind = entry.getKey();
				bestEvidence = evidence;
			}
		}

		if (bestScore == 0) {
			return new GameAnalysisScore(GameAnalysisKind.UNKNOWN, 20,
				List.of("weak game-like analysis signal"));
		}
		return new GameAnalysisScore(bestKind, Math.min(100, bestScore), List.copyOf(bestEvidence));
	}

	private static String normalize(Collection<String> values) {
		return String.join(" ", values).toLowerCase(Locale.ROOT);
	}

	private static int countHits(String text, List<String> terms) {
		int count = 0;
		for (String term : terms) {
			if (text.contains(term)) {
				count++;
			}
		}
		return count;
	}

	private static String evidenceName(GameAnalysisKind kind) {
		return switch (kind) {
			case ENTITY_ARRAY -> "entity/list";
			case PLAYER_STATE -> "player-state";
			case HEALTH -> "health-like";
			case AMMO -> "ammo/weapon";
			case ABILITY -> "ability/cooldown";
			case INVENTORY -> "inventory/item";
			case TRANSFORM -> "coordinate/transform";
			case OBJECT_TYPE -> "type/vtable";
			case UNKNOWN -> "game-like";
		};
	}

	private static String behaviorEvidenceName(GameAnalysisKind kind) {
		return switch (kind) {
			case HEALTH -> "damage/death logic";
			case ENTITY_ARRAY -> "entity iteration logic";
			case AMMO -> "ammo consumption logic";
			case ABILITY -> "ability timer logic";
			case INVENTORY -> "inventory slot logic";
			case TRANSFORM -> "coordinate math logic";
			case OBJECT_TYPE -> "object type dispatch logic";
			case PLAYER_STATE -> "player-state logic";
			case UNKNOWN -> "game-like behavior";
		};
	}

	private record RoleRule(List<String> labelTerms, List<String> behaviorTerms) {
	}
}
