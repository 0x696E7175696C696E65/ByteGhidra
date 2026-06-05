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

import java.awt.Component;

import docking.widgets.OptionDialog;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.HelpLocation;

class GameAnalysisOptions {
	static final String OPTIONS_CATEGORY = "Game Analysis";
	static final String ACKNOWLEDGED_DISCLAIMER_OPTION =
		"Offline Single-Player Use Disclaimer Acknowledged";
	static final String DISCLAIMER =
		"Game Analysis features are for offline single-player research, modding, debugging, " +
			"CTFs, and binaries or dumps you are authorized to inspect. They do not attach to " +
			"live games, bypass anti-cheat, patch memory, or provide multiplayer cheating support.";

	private GameAnalysisOptions() {
	}

	static void register(PluginTool tool) {
		ToolOptions options = tool.getOptions(OPTIONS_CATEGORY);
		HelpLocation help = new HelpLocation("CodeBrowserPlugin", "Game_Analysis");
		options.registerOption(ACKNOWLEDGED_DISCLAIMER_OPTION, false, help, DISCLAIMER);
		options.setOptionsHelpLocation(help);
	}

	static boolean confirmOfflineUse(PluginTool tool, Component parent) {
		ToolOptions options = tool.getOptions(OPTIONS_CATEGORY);
		if (options.getBoolean(ACKNOWLEDGED_DISCLAIMER_OPTION, false)) {
			return true;
		}

		int choice = OptionDialog.showYesNoDialog(parent, "Game Analysis Use Disclaimer",
			DISCLAIMER + "\n\nContinue and remember this acknowledgment in Tool Options?");
		if (choice == OptionDialog.YES_OPTION || choice == OptionDialog.OPTION_ONE) {
			options.setBoolean(ACKNOWLEDGED_DISCLAIMER_OPTION, true);
			return true;
		}
		return false;
	}
}
