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
import java.net.*;
import java.util.function.IntPredicate;

public class GhidraMcpBridgePorts {
	public static final int MAX_AUTO_INCREMENT_ATTEMPTS = 100;

	private GhidraMcpBridgePorts() {
	}

	public static int firstAvailablePort(int requestedPort) {
		return firstAvailablePort(requestedPort, MAX_AUTO_INCREMENT_ATTEMPTS,
			GhidraMcpBridgePorts::canBindLoopback);
	}

	static int firstAvailablePort(int requestedPort, int maxAttempts,
			IntPredicate availablePredicate) {
		int startPort = requestedPort <= 0 ? GhidraMcpBridgeServer.DEFAULT_PORT : requestedPort;
		int lastPort = Math.min(65535, startPort + Math.max(1, maxAttempts) - 1);
		for (int port = startPort; port <= lastPort; port++) {
			if (availablePredicate.test(port)) {
				return port;
			}
		}
		throw new IllegalStateException(
			"No available Ghidra MCP bridge port in range " + startPort + "-" + lastPort);
	}

	private static boolean canBindLoopback(int port) {
		try (ServerSocket socket = new ServerSocket()) {
			socket.setReuseAddress(false);
			socket.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), port));
			return true;
		}
		catch (IOException e) {
			return false;
		}
	}
}
