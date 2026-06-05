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

import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.concurrent.Executors;

import com.sun.net.httpserver.HttpServer;

import ghidra.app.plugin.core.mcp.GhidraMcpService;

public class GhidraMcpBridgeServer implements AutoCloseable {
	public static final int DEFAULT_PORT = 18090;

	private final HttpServer server;
	private final String token;

	public GhidraMcpBridgeServer(GhidraMcpService service, int port) throws IOException {
		this.token = createToken();
		this.server = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 0);
		GhidraMcpRequestHandler handler = new GhidraMcpRequestHandler(service, token);
		server.createContext("/execute", handler);
		server.createContext("/status", handler);
		server.setExecutor(Executors.newFixedThreadPool(2, r -> {
			Thread thread = new Thread(r, "Ghidra MCP Bridge");
			thread.setDaemon(true);
			return thread;
		}));
	}

	public void start() {
		server.start();
	}

	public InetSocketAddress getAddress() {
		return server.getAddress();
	}

	public String getToken() {
		return token;
	}

	@Override
	public void close() {
		server.stop(0);
	}

	private static String createToken() {
		byte[] bytes = new byte[24];
		new SecureRandom().nextBytes(bytes);
		return HexFormat.of().formatHex(bytes);
	}
}
