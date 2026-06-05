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

import java.util.HexFormat;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;

final class OperationUtils {
	static final int DEFAULT_LIMIT = 100;
	static final int MAX_LIMIT = 1000;
	static final int MAX_BYTES = 4096;

	private OperationUtils() {
	}

	static Program requireProgram(GhidraMcpContext context) {
		Program program = context.program();
		if (program == null) {
			throw new IllegalArgumentException("No active Ghidra program");
		}
		return program;
	}

	static String optionalString(JsonObject params, String name, String defaultValue) {
		if (params == null || !params.has(name) || params.get(name).isJsonNull()) {
			return defaultValue;
		}
		return params.get(name).getAsString();
	}

	static String requiredString(JsonObject params, String name) {
		String value = optionalString(params, name, null);
		if (value == null || value.isBlank()) {
			throw new IllegalArgumentException("Missing required parameter: " + name);
		}
		return value;
	}

	static int intParam(JsonObject params, String name, int defaultValue, int min, int max) {
		int value = defaultValue;
		if (params != null && params.has(name) && !params.get(name).isJsonNull()) {
			value = params.get(name).getAsInt();
		}
		if (value < min || value > max) {
			throw new IllegalArgumentException(
				"Parameter '" + name + "' must be between " + min + " and " + max);
		}
		return value;
	}

	static Address address(Program program, String addressText) {
		Address address = program.getAddressFactory().getAddress(addressText);
		if (address == null) {
			throw new IllegalArgumentException("Invalid address: " + addressText);
		}
		return address;
	}

	static JsonObject addressRange(AddressSetView set) {
		JsonObject object = new JsonObject();
		if (set == null || set.isEmpty()) {
			object.addProperty("empty", true);
			return object;
		}
		object.addProperty("empty", false);
		object.addProperty("min", set.getMinAddress().toString());
		object.addProperty("max", set.getMaxAddress().toString());
		object.addProperty("numAddresses", set.getNumAddresses());
		return object;
	}

	static JsonArray bytesToHexArray(byte[] bytes) {
		JsonArray array = new JsonArray();
		for (byte b : bytes) {
			array.add(HexFormat.of().toHexDigits(b));
		}
		return array;
	}
}
