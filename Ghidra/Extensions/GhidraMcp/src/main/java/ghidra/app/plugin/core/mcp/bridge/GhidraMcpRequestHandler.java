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
package ghidra.app.plugin.core.mcp.bridge;

import java.io.*;
import java.nio.charset.StandardCharsets;

import com.google.gson.*;
import com.sun.net.httpserver.*;

import ghidra.app.plugin.core.mcp.GhidraMcpService;

class GhidraMcpRequestHandler implements HttpHandler {
	private static final int MAX_REQUEST_BYTES = 1 << 20;

	private final Gson gson = new Gson();
	private final GhidraMcpService service;
	private final String token;

	GhidraMcpRequestHandler(GhidraMcpService service, String token) {
		this.service = service;
		this.token = token;
	}

	@Override
	public void handle(HttpExchange exchange) throws IOException {
		try {
			if (!token.equals(exchange.getRequestHeaders().getFirst("X-Ghidra-MCP-Token"))) {
				write(exchange, 401,
					GhidraMcpResponse.error("unauthorized", "Missing or invalid bridge token").toJson());
				return;
			}
			if ("/status".equals(exchange.getRequestURI().getPath())) {
				if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
					write(exchange, 405, GhidraMcpResponse.error("method_not_allowed", "Use GET").toJson());
					return;
				}
				write(exchange, 200, service.getStatus());
				return;
			}
			if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
				write(exchange, 405, GhidraMcpResponse.error("method_not_allowed", "Use POST").toJson());
				return;
			}
			JsonElement parsed = JsonParser.parseString(readBody(exchange));
			if (!parsed.isJsonObject()) {
				write(exchange, 400,
					GhidraMcpResponse.error("invalid_request", "Request body must be a JSON object").toJson());
				return;
			}
			JsonObject request = parsed.getAsJsonObject();
			if (!request.has("operation") || !request.get("operation").isJsonPrimitive()) {
				write(exchange, 400,
					GhidraMcpResponse.error("invalid_request", "Missing string operation").toJson());
				return;
			}
			String operation = request.get("operation").getAsString();
			JsonObject params =
				request.has("params") && request.get("params").isJsonObject()
						? request.getAsJsonObject("params")
						: new JsonObject();
			write(exchange, 200, service.execute(operation, params).toJson());
		}
		catch (JsonParseException | IllegalStateException | NullPointerException e) {
			write(exchange, 400, GhidraMcpResponse.error("invalid_request", e.getMessage()).toJson());
		}
		catch (Exception e) {
			write(exchange, 500, GhidraMcpResponse.error("internal_error", e.getMessage()).toJson());
		}
		finally {
			exchange.close();
		}
	}

	private String readBody(HttpExchange exchange) throws IOException {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		byte[] buffer = new byte[8192];
		int total = 0;
		try (InputStream in = exchange.getRequestBody()) {
			int read;
			while ((read = in.read(buffer)) != -1) {
				total += read;
				if (total > MAX_REQUEST_BYTES) {
					throw new IOException("Request exceeds maximum size");
				}
				out.write(buffer, 0, read);
			}
		}
		return out.toString(StandardCharsets.UTF_8);
	}

	private void write(HttpExchange exchange, int status, JsonObject object) throws IOException {
		byte[] bytes = gson.toJson(object).getBytes(StandardCharsets.UTF_8);
		exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
		exchange.sendResponseHeaders(status, bytes.length);
		try (OutputStream body = exchange.getResponseBody()) {
			body.write(bytes);
		}
	}
}
