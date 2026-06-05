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
package ghidra.app.plugin.core.decompile;

import docking.ActionContext;
import docking.action.*;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.util.HelpTopics;
import ghidra.framework.options.OptionsChangeListener;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.HelpLocation;
import ghidra.util.bean.opteditor.OptionsVetoException;

/**
 * Controls the default-on enhanced pseudocode quality mode.
 */
public class EnhancedPseudocodeQualityAction extends ToggleDockingAction {

	private final DecompilePlugin plugin;
	private final OptionsChangeListener listener = new PseudocodeQualityOptionsListener();

	protected EnhancedPseudocodeQualityAction(DecompilePlugin plugin) {
		super("Enhanced Pseudocode Quality", plugin.getClass().getSimpleName());
		this.plugin = plugin;

		setHelpLocation(new HelpLocation(HelpTopics.DECOMPILER, "AnalysisPseudocodeQuality"));
		setMenuBarData(new MenuData(new String[] { "Enhanced Pseudocode Quality" }, "wDebug"));

		PluginTool tool = plugin.getTool();
		ToolOptions options = tool.getOptions(DecompilePlugin.OPTIONS_TITLE);
		boolean enabled = options.getBoolean(DecompileOptions.PSEUDOCODE_QUALITY_OPTIONSTRING, true);
		setSelected(enabled);

		options.addOptionsChangeListener(listener);
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		return true;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		PluginTool tool = plugin.getTool();
		ToolOptions options = tool.getOptions(DecompilePlugin.OPTIONS_TITLE);
		options.setBoolean(DecompileOptions.PSEUDOCODE_QUALITY_OPTIONSTRING, isSelected());
	}

	private class PseudocodeQualityOptionsListener implements OptionsChangeListener {

		@Override
		public void optionsChanged(ToolOptions options, String optionName, Object oldValue,
				Object newValue) throws OptionsVetoException {
			if (DecompileOptions.PSEUDOCODE_QUALITY_OPTIONSTRING.equals(optionName)) {
				Boolean optionSelected = (Boolean) newValue;
				if (isSelected() != optionSelected) {
					setSelected(optionSelected);
				}
			}
		}
	}

	@Override
	public void dispose() {
		PluginTool tool = plugin.getTool();
		ToolOptions options = tool.getOptions(DecompilePlugin.OPTIONS_TITLE);
		options.removeOptionsChangeListener(listener);
	}
}
