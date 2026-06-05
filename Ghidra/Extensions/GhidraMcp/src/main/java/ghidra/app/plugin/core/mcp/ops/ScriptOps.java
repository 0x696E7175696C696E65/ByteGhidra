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

import java.io.*;
import java.util.*;

import com.google.gson.*;

import generic.jar.ResourceFile;
import ghidra.app.plugin.core.mcp.bridge.GhidraMcpResponse;
import ghidra.app.plugin.core.mcp.ops.GhidraMcpOperation.OperationKind;
import ghidra.app.script.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public final class ScriptOps {
	private ScriptOps() {
	}

	public static void register(OperationRegistry registry) {
		registry.register(script("list_ghidra_scripts", ScriptOps::listScripts));
		registry.register(script("run_ghidra_script", ScriptOps::runScript));
	}

	private static GhidraMcpOperation script(String name, OperationBody body) {
		return new SimpleOperation(name, OperationKind.SCRIPT_EXECUTION, body);
	}

	private static GhidraMcpResponse listScripts(GhidraMcpContext context, JsonObject params) {
		String extension = OperationUtils.optionalString(params, "extension", null);
		int limit = OperationUtils.intParam(params, "limit", OperationUtils.DEFAULT_LIMIT, 1, 5000);
		JsonArray scripts = new JsonArray();
		boolean truncated = false;
		acquireScriptHost();
		try {
			for (ResourceFile directory : GhidraScriptUtil.getScriptSourceDirectories()) {
				truncated = collectScripts(directory, extension, scripts, limit);
				if (truncated) {
					break;
				}
			}
		}
		finally {
			GhidraScriptUtil.releaseBundleHostReference();
		}
		JsonObject result = new JsonObject();
		result.add("scripts", scripts);
		result.addProperty("truncated", truncated);
		return GhidraMcpResponse.ok(result, truncated);
	}

	private static boolean collectScripts(ResourceFile directory, String extension, JsonArray scripts,
			int limit) {
		ResourceFile[] files = directory.listFiles();
		if (files == null) {
			return false;
		}
		Arrays.sort(files, Comparator.comparing(ResourceFile::getName));
		for (ResourceFile file : files) {
			if (scripts.size() >= limit) {
				return true;
			}
			if (file.isDirectory()) {
				if (collectScripts(file, extension, scripts, limit)) {
					return true;
				}
				continue;
			}
			GhidraScriptProvider provider = GhidraScriptUtil.getProvider(file);
			if (provider == null) {
				continue;
			}
			if (extension != null && !file.getName().toLowerCase(Locale.ROOT)
					.endsWith(extension.toLowerCase(Locale.ROOT))) {
				continue;
			}
			JsonObject script = new JsonObject();
			script.addProperty("name", file.getName());
			script.addProperty("path", file.getAbsolutePath());
			script.addProperty("provider", provider.getDescription());
			script.addProperty("extension", provider.getExtension());
			scripts.add(script);
		}
		return false;
	}

	private static GhidraMcpResponse runScript(GhidraMcpContext context, JsonObject params)
			throws Exception {
		String scriptName = OperationUtils.optionalString(params, "name", null);
		String scriptPath = OperationUtils.optionalString(params, "path", null);
		String inlineSource = OperationUtils.optionalString(params, "source", null);
		String inlineExtension = OperationUtils.optionalString(params, "extension", ".java");
		String[] args = scriptArgs(params);
		int maxOutputChars = OperationUtils.intParam(params, "maxOutputChars", 200000, 1000, 2000000);

		acquireScriptHost();
		ResourceFile scriptFile = null;
		boolean deleteScript = false;
		try {
			if (inlineSource != null) {
				scriptFile = createInlineScript(inlineSource, inlineExtension);
				deleteScript = true;
			}
			else if (scriptPath != null) {
				scriptFile = new ResourceFile(new File(scriptPath));
			}
			else if (scriptName != null) {
				scriptFile = GhidraScriptUtil.findScriptByName(scriptName);
			}
			if (scriptFile == null || !scriptFile.exists()) {
				return GhidraMcpResponse.error("script_not_found",
					"Script not found. Provide name, path, or source.");
			}

			GhidraScriptProvider provider = GhidraScriptUtil.getProvider(scriptFile);
			if (provider == null) {
				return GhidraMcpResponse.error("script_provider_missing",
					"No Ghidra script provider for " + scriptFile.getName());
			}

			ByteArrayOutputStream stdout = new ByteArrayOutputStream();
			ByteArrayOutputStream stderr = new ByteArrayOutputStream();
			try (PrintWriter errorWriter = new PrintWriter(stderr, true)) {
				GhidraScript script = provider.getScriptInstance(scriptFile, errorWriter);
				script.setScriptArgs(args);
				script.execute(scriptState(context), new ScriptControls(stdout, stderr, context.monitor()));

				String out = truncate(stdout.toString(), maxOutputChars);
				String err = truncate(stderr.toString(), maxOutputChars);
				JsonObject result = new JsonObject();
				result.addProperty("script", scriptFile.getAbsolutePath());
				result.addProperty("provider", provider.getDescription());
				result.addProperty("stdout", out);
				result.addProperty("stderr", err);
				result.addProperty("stdoutTruncated", stdout.size() > out.length());
				result.addProperty("stderrTruncated", stderr.size() > err.length());
				return GhidraMcpResponse.ok(result);
			}
		}
		finally {
			if (deleteScript && scriptFile != null) {
				scriptFile.delete();
			}
			GhidraScriptUtil.releaseBundleHostReference();
		}
	}

	private static ResourceFile createInlineScript(String source, String extension) throws IOException {
		String normalizedExtension = extension.startsWith(".") ? extension : "." + extension;
		File file = File.createTempFile("GhidraMcpInlineScript", normalizedExtension);
		try (Writer writer = new OutputStreamWriter(new FileOutputStream(file))) {
			writer.write(source);
		}
		return new ResourceFile(file);
	}

	private static String[] scriptArgs(JsonObject params) {
		if (params == null || !params.has("args") || !params.get("args").isJsonArray()) {
			return new String[0];
		}
		JsonArray array = params.getAsJsonArray("args");
		String[] args = new String[array.size()];
		for (int i = 0; i < array.size(); i++) {
			args[i] = array.get(i).getAsString();
		}
		return args;
	}

	private static GhidraState scriptState(GhidraMcpContext context) {
		PluginTool tool = context.tool();
		Program program = context.program();
		return new GhidraState(tool, tool == null ? null : tool.getProject(), program, context.location(),
			context.selection(), context.highlight());
	}

	private static void acquireScriptHost() {
		GhidraScriptUtil.acquireBundleHostReference();
	}

	private static String truncate(String text, int maxChars) {
		return text.length() <= maxChars ? text : text.substring(0, maxChars);
	}

	private interface OperationBody {
		GhidraMcpResponse execute(GhidraMcpContext context, JsonObject params) throws Exception;
	}

	private record SimpleOperation(String name, OperationKind kind, OperationBody body)
			implements GhidraMcpOperation {
		@Override
		public GhidraMcpResponse execute(GhidraMcpContext context, JsonObject params) throws Exception {
			return body.execute(context, params);
		}
	}
}
