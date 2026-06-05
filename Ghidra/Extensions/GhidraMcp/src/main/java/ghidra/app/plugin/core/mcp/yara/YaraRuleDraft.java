/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0
 */
package ghidra.app.plugin.core.mcp.yara;

import com.google.gson.JsonObject;

public class YaraRuleDraft {
	private final String name;
	private final String ruleText;

	public YaraRuleDraft(String name, String ruleText) {
		this.name = name;
		this.ruleText = ruleText;
	}

	public String ruleText() {
		return ruleText;
	}

	public JsonObject toJson() {
		JsonObject object = new JsonObject();
		object.addProperty("name", name);
		object.addProperty("rule", ruleText);
		object.addProperty("draftOnly", true);
		return object;
	}
}
