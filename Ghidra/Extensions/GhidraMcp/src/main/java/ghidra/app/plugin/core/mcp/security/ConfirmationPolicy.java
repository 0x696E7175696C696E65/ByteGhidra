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
package ghidra.app.plugin.core.mcp.security;

import docking.widgets.OptionDialog;
import ghidra.app.plugin.core.mcp.ops.GhidraMcpOperation.OperationKind;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Swing;

public class ConfirmationPolicy {

	public boolean confirm(PluginTool tool, OperationKind kind, String operationName) {
		if (kind == OperationKind.READ_ONLY || kind == OperationKind.UI_ONLY) {
			return true;
		}
		return Swing.runNow(() -> {
			int result = OptionDialog.showYesNoDialog(tool.getToolFrame(),
				"Confirm Ghidra MCP Operation",
				"Allow MCP operation '" + operationName + "'?\n\n" + description(kind));
			return result == OptionDialog.OPTION_ONE;
		});
	}

	private String description(OperationKind kind) {
		return switch (kind) {
			case SUITE_STATE_WRITE -> "This can change AI suite tasks, evidence, hypotheses, or session data.";
			case ANNOTATION_WRITE -> "This can annotate or rename items in the current program.";
			case ANALYSIS_WRITE -> "This can run or change Ghidra analysis state for the current program.";
			case SCRIPT_EXECUTION -> "This can execute a Ghidra script in the current tool context.";
			case DANGEROUS -> "This is a dangerous operation and should only be allowed if you fully trust the client.";
			case READ_ONLY, UI_ONLY -> "This operation is read-only or UI-only.";
		};
	}
}
