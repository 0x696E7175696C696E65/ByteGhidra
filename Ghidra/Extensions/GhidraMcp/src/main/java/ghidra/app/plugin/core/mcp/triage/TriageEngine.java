/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0
 */
package ghidra.app.plugin.core.mcp.triage;

import java.time.Instant;
import java.util.*;

import ghidra.app.plugin.core.mcp.evidence.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.DefinedDataIterator;
import ghidra.util.task.TaskMonitor;

public class TriageEngine {
	private static final Set<String> NETWORK_APIS = Set.of("socket", "connect", "send", "recv",
		"InternetOpen", "InternetConnect", "HttpOpenRequest", "WinHttpOpen", "URLDownloadToFile");
	private static final Set<String> PERSISTENCE_APIS = Set.of("RegSetValue", "RegCreateKey",
		"CreateService", "StartService", "WriteFile", "CopyFile");
	private static final Set<String> INJECTION_APIS = Set.of("VirtualAllocEx", "WriteProcessMemory",
		"CreateRemoteThread", "OpenProcess", "QueueUserAPC");
	private static final Set<String> ANTI_DEBUG_APIS = Set.of("IsDebuggerPresent",
		"CheckRemoteDebuggerPresent", "NtQueryInformationProcess", "OutputDebugString");
	private static final Set<String> CRYPTO_APIS = Set.of("CryptAcquireContext", "CryptDecrypt",
		"CryptEncrypt", "BCrypt", "NCrypt", "SystemFunction032");
	private static final Set<String> ANTI_VM_APIS = Set.of("GetSystemFirmwareTable", "RegOpenKey",
		"SetupDiGetClassDevs", "EnumDisplayDevices");
	private static final Set<String> CREDENTIAL_APIS = Set.of("CredEnumerate", "CredRead",
		"LsaRetrievePrivateData", "SamI", "Vault");
	private static final Set<String> DISCOVERY_APIS = Set.of("CreateToolhelp32Snapshot",
		"Process32First", "Process32Next", "EnumProcesses", "NetUserEnum");
	private static final Set<String> FILE_STAGING_APIS = Set.of("CreateFile", "WriteFile",
		"MoveFile", "CopyFile", "GetTempPath");

	public TriageReport run(Program program, EvidenceStore evidenceStore, TaskMonitor monitor) {
		TriageReport report = new TriageReport(program.getName());
		collectMemoryFindings(program, evidenceStore, report);
		collectImportFindings(program, evidenceStore, report, monitor);
		collectStringFindings(program, evidenceStore, report, monitor);
		collectFunctionFindings(program, evidenceStore, report, monitor);
		return report;
	}

	private void collectMemoryFindings(Program program, EvidenceStore store, TriageReport report) {
		for (MemoryBlock block : program.getMemory().getBlocks()) {
			if (block.isExecute() && block.isWrite()) {
				add(store, report, "memory", "high", block.getStart().toString(), null,
					"Writable executable memory block: " + block.getName(),
					"Block " + block.getName() + " spans " + block.getStart() + "-" + block.getEnd(),
					0.85, List.of("memory", "wx"));
			}
			if (block.isInitialized() && block.getSize() > 0x1000) {
				double entropy = entropy(program.getMemory(), block);
				if (entropy > 7.2) {
					add(store, report, "packing", "medium", block.getStart().toString(), null,
						"High entropy memory block: " + block.getName(),
						"Approximate Shannon entropy is " + String.format(Locale.ROOT, "%.2f", entropy),
						0.65, List.of("entropy", "packed"));
				}
			}
		}
	}

	private void collectImportFindings(Program program, EvidenceStore store, TriageReport report,
			TaskMonitor monitor) {
		SymbolIterator symbols = program.getSymbolTable().getExternalSymbols();
		int count = 0;
		while (symbols.hasNext() && count++ < 5000 && !monitor.isCancelled() &&
			!Thread.currentThread().isInterrupted()) {
			Symbol symbol = symbols.next();
			String name = symbol.getName();
			classifyImport(store, report, symbol, name, NETWORK_APIS, "network", "medium");
			classifyImport(store, report, symbol, name, PERSISTENCE_APIS, "persistence", "medium");
			classifyImport(store, report, symbol, name, INJECTION_APIS, "injection", "high");
			classifyImport(store, report, symbol, name, ANTI_DEBUG_APIS, "anti-debug", "medium");
			classifyImport(store, report, symbol, name, CRYPTO_APIS, "crypto", "medium");
			classifyImport(store, report, symbol, name, ANTI_VM_APIS, "anti-vm", "medium");
			classifyImport(store, report, symbol, name, CREDENTIAL_APIS, "credential-access", "high");
			classifyImport(store, report, symbol, name, DISCOVERY_APIS, "process-discovery", "medium");
			classifyImport(store, report, symbol, name, FILE_STAGING_APIS, "filesystem-staging", "medium");
		}
	}

	private void classifyImport(EvidenceStore store, TriageReport report, Symbol symbol, String name,
			Set<String> needles, String category, String severity) {
		for (String needle : needles) {
			if (name.toLowerCase(Locale.ROOT).contains(needle.toLowerCase(Locale.ROOT))) {
				add(store, report, category, severity, symbol.getAddress().toString(), null,
					"Suspicious import: " + symbol.getName(true),
					"Import name matched " + category + " API pattern: " + needle,
					0.75, List.of("import", category));
				return;
			}
		}
	}

	private void collectStringFindings(Program program, EvidenceStore store, TriageReport report,
			TaskMonitor monitor) {
		DataIterator iterator = DefinedDataIterator.byDataInstance(program, Data::hasStringValue);
		int count = 0;
		while (iterator.hasNext() && count++ < 5000 && !monitor.isCancelled()) {
			Data data = iterator.next();
			Object value = data.getValue();
			String text = value == null ? "" : value.toString();
			String lower = text.toLowerCase(Locale.ROOT);
			Function containingFunction =
				program.getFunctionManager().getFunctionContaining(data.getMinAddress());
			String functionName = containingFunction == null ? null : containingFunction.getName(true);
			if (lower.startsWith("http://") || lower.startsWith("https://") || lower.contains(".onion")) {
				add(store, report, "network", "high", data.getMinAddress().toString(), functionName,
					"Network indicator string",
					stringDetails(program, data, text), 0.8, List.of("string", "network"));
			}
			else if (lower.contains("software\\microsoft\\windows\\currentversion\\run") ||
				lower.contains("schtasks") || lower.contains("startup")) {
				add(store, report, "persistence", "medium", data.getMinAddress().toString(), functionName,
					"Persistence-related string",
					stringDetails(program, data, text), 0.65, List.of("string", "persistence"));
			}
			else if (lower.contains("cmd.exe") || lower.contains("powershell") || lower.contains("/c ")) {
				add(store, report, "command", "medium", data.getMinAddress().toString(), functionName,
					"Command execution string",
					stringDetails(program, data, text), 0.7, List.of("string", "command"));
			}
		}
	}

	private String stringDetails(Program program, Data data, String text) {
		int xrefCount = 0;
		ReferenceIterator references = program.getReferenceManager().getReferencesTo(data.getMinAddress());
		while (references.hasNext() && xrefCount < 25) {
			xrefCount++;
			references.next();
		}
		return text + "\nXrefs observed: " + xrefCount;
	}

	private void collectFunctionFindings(Program program, EvidenceStore store, TriageReport report,
			TaskMonitor monitor) {
		FunctionIterator iterator = program.getFunctionManager().getFunctions(true);
		int count = 0;
		while (iterator.hasNext() && count++ < 10000 && !monitor.isCancelled() &&
			!Thread.currentThread().isInterrupted()) {
			Function function = iterator.next();
			if (function.getBody().getNumAddresses() > 0x4000) {
				add(store, report, "complexity", "low", function.getEntryPoint().toString(),
					function.getName(true), "Large function body",
					"Function spans " + function.getBody().getNumAddresses() + " addresses.",
					0.45, List.of("function", "large"));
			}
		}
	}

	private void add(EvidenceStore store, TriageReport report, String category, String severity,
			String address, String functionName, String summary, String details, double confidence,
			List<String> tags) {
		EvidenceRecord record = store.add(new EvidenceRecord("ev-" + UUID.randomUUID(), "triage",
			category, severity, address, functionName, summary, details, confidence, tags, Instant.now()));
		report.add(new TriageFinding(category, severity, summary, record.id()));
	}

	private double entropy(Memory memory, MemoryBlock block) {
		byte[] bytes = new byte[(int) Math.min(block.getSize(), 8192)];
		try {
			int read = memory.getBytes(block.getStart(), bytes);
			if (read <= 0) {
				return 0;
			}
			int[] counts = new int[256];
			for (int i = 0; i < read; i++) {
				counts[bytes[i] & 0xff]++;
			}
			double entropy = 0;
			for (int count : counts) {
				if (count == 0) {
					continue;
				}
				double p = (double) count / read;
				entropy -= p * (Math.log(p) / Math.log(2));
			}
			return entropy;
		}
		catch (MemoryAccessException e) {
			return 0;
		}
	}
}
