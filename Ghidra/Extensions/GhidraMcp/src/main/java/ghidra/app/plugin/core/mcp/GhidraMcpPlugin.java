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
package ghidra.app.plugin.core.mcp;

import java.io.IOException;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;

import com.google.gson.JsonObject;

import docking.ActionContext;
import docking.action.*;
import ghidra.app.events.ProgramHighlightPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.mcp.bridge.*;
import ghidra.app.plugin.core.mcp.ops.*;
import ghidra.app.plugin.core.mcp.security.GhidraMcpPolicy;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.util.ProgramSelection;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = GhidraMcpPluginPackage.NAME,
	category = PluginCategoryNames.COMMON,
	shortDescription = "Ghidra MCP bridge",
	description = "Exposes token-authenticated Ghidra analysis, mutation, UI, and script operations to local MCP clients.",
	servicesProvided = { GhidraMcpService.class },
	eventsProduced = { ProgramHighlightPluginEvent.class }
)
//@formatter:on
public class GhidraMcpPlugin extends ProgramPlugin implements GhidraMcpService {
	private static final String OPTIONS_NAME = "Ghidra MCP";
	private static final String BRIDGE_PORT_OPTION = "Bridge Port";
	private static final HelpLocation HELP_LOCATION =
		new HelpLocation("GhidraMcpPlugin", "Ghidra_MCP");

	private final OperationRegistry operations = new OperationRegistry();
	private GhidraMcpPolicy policy = GhidraMcpPolicy.defaults();
	private GhidraMcpBridgeServer bridgeServer;
	private DockingAction startAction;
	private DockingAction stopAction;
	private DockingAction copyTokenAction;
	private DockingAction statusAction;
	private ToggleDockingAction annotationWritesAction;
	private ToggleDockingAction analysisWritesAction;

	public GhidraMcpPlugin(PluginTool tool) {
		super(tool);
		setupActions();
	}

	@Override
	protected void init() {
		super.init();
		registerOptions();
	}

	@Override
	public GhidraMcpResponse execute(String operationName, JsonObject params) {
		Msg.info(this, "Ghidra MCP operation requested: " + operationName);
		GhidraMcpContext context = new GhidraMcpContext(this, tool, currentProgram, currentLocation,
			currentSelection, currentHighlight, policy, TaskMonitor.DUMMY);
		return operations.execute(context, operationName, params);
	}

	@Override
	public JsonObject getStatus() {
		JsonObject status = new JsonObject();
		status.addProperty("bridgeStarted", isBridgeStarted());
		status.addProperty("programActive", currentProgram != null);
		status.addProperty("programName", currentProgram == null ? null : currentProgram.getName());
		status.addProperty("annotationWritesEnabled", policy.allowsAnnotationWrites());
		status.addProperty("analysisWritesEnabled", policy.allowsAnalysisWrites());
		status.addProperty("dangerousOperationsEnabled", policy.allowsDangerousOperations());
		status.add("operations", operations.operationNames());
		if (bridgeServer != null) {
			status.addProperty("url", "http://" + bridgeServer.getAddress().getHostString() + ":" +
				bridgeServer.getAddress().getPort());
			status.addProperty("tokenRequired", true);
		}
		return status;
	}

	@Override
	public synchronized void startBridge(int port) throws IOException {
		if (bridgeServer != null) {
			throw new IllegalStateException("Ghidra MCP bridge is already started");
		}
		int requestedPort = port <= 0 ? GhidraMcpBridgeServer.DEFAULT_PORT : port;
		int selectedPort = GhidraMcpBridgePorts.firstAvailablePort(requestedPort);
		bridgeServer = new GhidraMcpBridgeServer(this, selectedPort);
		bridgeServer.start();
		updateActions();
		if (selectedPort != requestedPort) {
			tool.setStatusInfo("Ghidra MCP bridge port " + requestedPort +
				" is busy; using " + selectedPort);
		}
		Msg.info(this,
			"Ghidra MCP bridge listening at http://" + bridgeServer.getAddress().getHostString() +
				":" + bridgeServer.getAddress().getPort() +
				"; use Tools -> Ghidra MCP -> Copy Bridge Token to configure clients");
	}

	@Override
	public synchronized void stopBridge() {
		if (bridgeServer != null) {
			bridgeServer.close();
			bridgeServer = null;
			updateActions();
			Msg.info(this, "Ghidra MCP bridge stopped");
		}
	}

	public void startConfiguredBridge() throws IOException {
		startBridge(getConfiguredBridgePort());
	}

	public String getBridgeToken() {
		return bridgeServer == null ? null : bridgeServer.getToken();
	}

	@Override
	public boolean isBridgeStarted() {
		return bridgeServer != null;
	}

	public boolean goToMcpAddress(Address address) {
		return goTo(address);
	}

	public void selectMcpRange(AddressSetView set) {
		setSelection(set);
	}

	public void highlightMcpRange(AddressSetView set) {
		if (currentProgram == null) {
			return;
		}
		firePluginEvent(new ProgramHighlightPluginEvent(getName(), new ProgramSelection(set),
			currentProgram));
	}

	@Override
	protected void dispose() {
		stopBridge();
		super.dispose();
	}

	private void setupActions() {
		startAction = new DockingAction("Start Ghidra MCP Bridge", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				try {
					startBridge(getConfiguredBridgePort());
				}
				catch (IOException e) {
					Msg.showError(this, tool.getToolFrame(), "Ghidra MCP Bridge",
						"Failed to start bridge", e);
				}
			}
		};
		startAction.setMenuBarData(
			new MenuData(new String[] { "Tools", "Ghidra MCP", "Start Bridge" }));
		tool.addAction(startAction);

		stopAction = new DockingAction("Stop Ghidra MCP Bridge", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				stopBridge();
			}
		};
		stopAction.setMenuBarData(
			new MenuData(new String[] { "Tools", "Ghidra MCP", "Stop Bridge" }));
		tool.addAction(stopAction);

		copyTokenAction = new DockingAction("Copy Ghidra MCP Bridge Token", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				if (bridgeServer == null) {
					return;
				}
				Toolkit.getDefaultToolkit()
						.getSystemClipboard()
						.setContents(new StringSelection(bridgeServer.getToken()), null);
				Msg.info(this, "Ghidra MCP bridge token copied to clipboard");
			}
		};
		copyTokenAction.setMenuBarData(
			new MenuData(new String[] { "Tools", "Ghidra MCP", "Copy Bridge Token" }));
		tool.addAction(copyTokenAction);

		statusAction = new DockingAction("Show Ghidra MCP Status", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				showStatusDialog();
			}
		};
		statusAction.setMenuBarData(
			new MenuData(new String[] { "Tools", "Ghidra MCP", "Status..." }));
		tool.addAction(statusAction);

		annotationWritesAction = new ToggleDockingAction("Ghidra MCP Token Grants Annotation Writes", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				updatePolicy();
				Msg.info(this, "Ghidra MCP annotation writes are enabled for valid bridge tokens");
			}
		};
		annotationWritesAction.setSelected(true);
		annotationWritesAction.setEnabled(false);
		annotationWritesAction.setMenuBarData(
			new MenuData(new String[] { "Tools", "Ghidra MCP", "Token Grants Annotation Writes" }));
		tool.addAction(annotationWritesAction);

		analysisWritesAction = new ToggleDockingAction("Ghidra MCP Token Grants Analysis Writes", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				updatePolicy();
				Msg.info(this, "Ghidra MCP analysis writes and scripts are enabled for valid bridge tokens");
			}
		};
		analysisWritesAction.setSelected(true);
		analysisWritesAction.setEnabled(false);
		analysisWritesAction.setMenuBarData(
			new MenuData(new String[] { "Tools", "Ghidra MCP", "Token Grants Analysis Writes + Scripts" }));
		tool.addAction(analysisWritesAction);

		updateActions();
	}

	private void registerOptions() {
		ToolOptions options = tool.getOptions(OPTIONS_NAME);
		options.registerOption(BRIDGE_PORT_OPTION, GhidraMcpBridgeServer.DEFAULT_PORT, HELP_LOCATION,
			"Preferred loopback TCP port used by Tools -> Ghidra MCP -> Start Bridge. If the " +
				"port is busy, Ghidra MCP automatically tries the next ports.");
		options.setOptionsHelpLocation(HELP_LOCATION);
	}

	private int getConfiguredBridgePort() {
		ToolOptions options = tool.getOptions(OPTIONS_NAME);
		int port = options.getInt(BRIDGE_PORT_OPTION, GhidraMcpBridgeServer.DEFAULT_PORT);
		if (port < 1 || port > 65535) {
			tool.setStatusInfo("Invalid Ghidra MCP bridge port " + port + "; using default " +
				GhidraMcpBridgeServer.DEFAULT_PORT);
			return GhidraMcpBridgeServer.DEFAULT_PORT;
		}
		return port;
	}

	private void showStatusDialog() {
		String status = bridgeServer == null ? "Stopped"
				: "Listening at http://" + bridgeServer.getAddress().getHostString() + ":" +
					bridgeServer.getAddress().getPort();
		String token = bridgeServer == null ? "Start the bridge first, then copy the token."
				: "Use Tools -> Ghidra MCP -> Copy Bridge Token.";
		Msg.showInfo(this, tool.getToolFrame(), "Ghidra MCP",
			"Bridge: " + status + "\n" +
				"Program active: " + (currentProgram != null ? currentProgram.getName() : "No") +
				"\nAnnotation writes: " + policy.allowsAnnotationWrites() +
				"\nAnalysis writes: " + policy.allowsAnalysisWrites() +
				"\nDangerous/script operations: " + policy.allowsDangerousOperations() +
				"\nOptions: Edit -> Tool Options -> Ghidra MCP" +
				"\nToken: " + token);
	}

	private void updateActions() {
		if (startAction != null) {
			startAction.setEnabled(!isBridgeStarted());
		}
		if (stopAction != null) {
			stopAction.setEnabled(isBridgeStarted());
		}
		if (copyTokenAction != null) {
			copyTokenAction.setEnabled(isBridgeStarted());
		}
	}

	private void updatePolicy() {
		policy = GhidraMcpPolicy.tokenTrusted();
	}
}
