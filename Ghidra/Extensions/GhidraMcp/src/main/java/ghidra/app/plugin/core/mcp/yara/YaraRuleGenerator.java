/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0
 */
package ghidra.app.plugin.core.mcp.yara;

import java.util.*;

import ghidra.app.plugin.core.mcp.evidence.EvidenceRecord;
import ghidra.app.plugin.core.mcp.evidence.EvidenceStore;

public class YaraRuleGenerator {
	public YaraRuleDraft draft(String familyName, EvidenceStore store) {
		String safeName = sanitize(familyName == null || familyName.isBlank() ? "suspect_sample" : familyName);
		List<EvidenceRecord> records = store.list();
		StringBuilder strings = new StringBuilder();
		int stringCount = 0;
		for (EvidenceRecord record : records) {
			if (!record.tags().contains("string")) {
				continue;
			}
			String value = record.details();
			if (value == null || value.length() < 6 || value.length() > 160) {
				continue;
			}
			strings.append("        $s").append(++stringCount).append(" = \"")
				.append(escape(value)).append("\" ascii wide\n");
			if (stringCount >= 12) {
				break;
			}
		}
		if (stringCount == 0) {
			strings.append("        $note = \"manual_review_required\" ascii\n");
		}
		String rule = "rule " + safeName + "_draft {\n" +
			"    meta:\n" +
			"        description = \"Draft rule generated from Ghidra AI evidence\"\n" +
			"        confidence = \"draft\"\n" +
			"    strings:\n" +
			strings +
			"    condition:\n" +
			"        " + condition(stringCount) + "\n" +
			"}\n";
		return new YaraRuleDraft(safeName + "_draft", rule);
	}

	private String condition(int stringCount) {
		if (stringCount == 0) {
			return "$note";
		}
		return stringCount == 1 ? "1 of ($s*)" : "2 of ($s*)";
	}

	private String sanitize(String value) {
		return value.replaceAll("[^A-Za-z0-9_]", "_");
	}

	private String escape(String value) {
		return value.replace("\\", "\\\\").replace("\"", "\\\"");
	}
}
