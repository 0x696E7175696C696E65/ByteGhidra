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
package ghidra.app.plugin.core.mcp.ops;

import ghidra.app.plugin.core.mcp.GhidraMcpPlugin;
import ghidra.app.plugin.core.mcp.security.GhidraMcpPolicy;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.task.TaskMonitor;

public class GhidraMcpContext {
	private final GhidraMcpPlugin plugin;
	private final PluginTool tool;
	private final Program program;
	private final ProgramLocation location;
	private final ProgramSelection selection;
	private final ProgramSelection highlight;
	private final GhidraMcpPolicy policy;
	private final TaskMonitor monitor;

	public GhidraMcpContext(GhidraMcpPlugin plugin, PluginTool tool, Program program,
			ProgramLocation location, ProgramSelection selection, ProgramSelection highlight,
			GhidraMcpPolicy policy, TaskMonitor monitor) {
		this.plugin = plugin;
		this.tool = tool;
		this.program = program;
		this.location = location;
		this.selection = selection;
		this.highlight = highlight;
		this.policy = policy;
		this.monitor = monitor;
	}

	public GhidraMcpContext(GhidraMcpPlugin plugin, PluginTool tool, Program program,
			ProgramLocation location, ProgramSelection selection, GhidraMcpPolicy policy,
			TaskMonitor monitor) {
		this(plugin, tool, program, location, selection, null, policy, monitor);
	}

	public GhidraMcpPlugin plugin() {
		return plugin;
	}

	public PluginTool tool() {
		return tool;
	}

	public Program program() {
		return program;
	}

	public ProgramLocation location() {
		return location;
	}

	public ProgramSelection selection() {
		return selection;
	}

	public ProgramSelection highlight() {
		return highlight;
	}

	public GhidraMcpPolicy policy() {
		return policy;
	}

	public TaskMonitor monitor() {
		return monitor;
	}
}
