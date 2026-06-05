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

enum GameAnalysisKind {
	ENTITY_ARRAY("Entity Array"),
	PLAYER_STATE("Player State"),
	HEALTH("Health / Shield"),
	AMMO("Ammo / Weapons"),
	ABILITY("Abilities / Cooldowns"),
	INVENTORY("Inventory / Items"),
	TRANSFORM("Coordinates / Transforms"),
	OBJECT_TYPE("Object Type / VTable"),
	UNKNOWN("Game Logic");

	private final String displayName;

	private GameAnalysisKind(String displayName) {
		this.displayName = displayName;
	}

	String displayName() {
		return displayName;
	}
}
