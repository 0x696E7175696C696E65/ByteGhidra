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

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

public class GhidraMcpResponse {
	private final boolean success;
	private final JsonElement result;
	private final String errorCode;
	private final String errorMessage;
	private final boolean truncated;

	private GhidraMcpResponse(boolean success, JsonElement result, String errorCode,
			String errorMessage, boolean truncated) {
		this.success = success;
		this.result = result;
		this.errorCode = errorCode;
		this.errorMessage = errorMessage;
		this.truncated = truncated;
	}

	public static GhidraMcpResponse ok(JsonElement result) {
		return new GhidraMcpResponse(true, result, null, null, false);
	}

	public static GhidraMcpResponse ok(JsonElement result, boolean truncated) {
		return new GhidraMcpResponse(true, result, null, null, truncated);
	}

	public static GhidraMcpResponse error(String code, String message) {
		return new GhidraMcpResponse(false, null, code, message, false);
	}

	public boolean isSuccess() {
		return success;
	}

	public JsonElement getResult() {
		return result;
	}

	public String getErrorCode() {
		return errorCode;
	}

	public String getErrorMessage() {
		return errorMessage;
	}

	public JsonObject toJson() {
		JsonObject object = new JsonObject();
		object.addProperty("success", success);
		object.addProperty("truncated", truncated);
		if (success) {
			object.add("result", result == null ? new JsonObject() : result);
		}
		else {
			JsonObject error = new JsonObject();
			error.addProperty("code", errorCode);
			error.addProperty("message", errorMessage);
			object.add("error", error);
		}
		return object;
	}
}
