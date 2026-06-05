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
package ghidra.app.plugin.core.codebrowser;

import java.util.*;
import java.util.stream.Collectors;

import ghidra.program.model.address.*;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Deterministic detector for functions that look like crackme authentication checks.
 * <p>
 * The first implementation intentionally uses cheap, explainable signals that are available from
 * the listing and reference database: auth/success/failure strings, input APIs, and compare APIs.
 * It does not attempt to solve passwords or bypass checks.
 */
public class CrackmeAuthCheckDetector {

	private static final Set<String> AUTH_STRING_TERMS = Set.of("password", "passwd", "passcode",
		"serial", "license", "key", "auth", "login", "username", "user");
	private static final Set<String> RESULT_STRING_TERMS = Set.of("correct", "success", "valid",
		"accepted", "wrong", "fail", "invalid", "denied", "try again", "nope", "bad");
	private static final Set<String> INPUT_APIS = Set.of("scanf", "sscanf", "fscanf", "gets",
		"fgets", "getchar", "read", "ReadFile", "GetDlgItemTextA", "GetDlgItemTextW",
		"std::cin", "cin");
	private static final Set<String> COMPARE_APIS = Set.of("strcmp", "strncmp", "strcasecmp",
		"stricmp", "memcmp", "lstrcmp", "lstrcmpA", "lstrcmpW", "lstrcmpi", "CompareStringA",
		"CompareStringW");
	private static final Set<String> STATUS_MUTATION_TERMS = Set.of("changed", "updated", "reset",
		"saved", "created");
	private static final Set<String> ADDITIVE_MNEMONICS = Set.of("add", "adc", "sub", "sbb", "inc",
		"dec", "imul", "mul", "idiv", "div");
	private static final Set<String> BIT_MNEMONICS = Set.of("and", "or", "shl", "shr", "sal", "sar",
		"rol", "ror", "test");
	private static final Set<String> COMPARE_MNEMONICS = Set.of("cmp", "test");
	private static final int MAX_REFERENCE_SOURCES_PER_FUNCTION = 20000;
	private static final int MAX_INSTRUCTIONS_PER_FUNCTION = 50000;

	private CrackmeAuthCheckDetector() {
		// utility class
	}

	public static List<CrackmeAuthCheckCandidate> findCandidates(Program program,
			TaskMonitor monitor) throws CancelledException {
		List<CrackmeAuthCheckCandidate> candidates = new ArrayList<>();
		loadCandidates(program, new ListAccumulator(candidates), monitor);
		candidates.sort(Comparator.comparingInt(CrackmeAuthCheckCandidate::confidence).reversed()
				.thenComparing(CrackmeAuthCheckCandidate::address));
		return candidates;
	}

	public static void loadCandidates(Program program,
			Accumulator<CrackmeAuthCheckCandidate> accumulator, TaskMonitor monitor)
			throws CancelledException {
		Map<Address, Function> seeds = collectCandidateFunctionSeeds(program, monitor);
		monitor.setIndeterminate(false);
		monitor.initialize(Math.max(seeds.size(), 1),
			"Inspecting " + seeds.size() + " crackme candidate functions");
		for (Function function : seeds.values()) {
			monitor.checkCancelled();
			monitor.setMessage("Inspecting crackme candidate " + function.getName());
			CrackmeAuthCheckCandidate candidate = inspectFunction(program, function, monitor);
			if (candidate != null) {
				accumulator.add(candidate);
			}
			monitor.incrementProgress(1);
		}
		monitor.setMessage("Crackme auth check search complete");
	}

	private static Map<Address, Function> collectCandidateFunctionSeeds(Program program,
			TaskMonitor monitor) throws CancelledException {
		monitor.setIndeterminate(true);
		monitor.setMessage("Finding crackme auth string and API seeds");
		Map<Address, Function> seeds = new LinkedHashMap<>();
		seedFunctionsFromInterestingStrings(program, seeds, monitor);
		seedFunctionsFromExternalApis(program, seeds, monitor);
		return seeds;
	}

	private static void seedFunctionsFromInterestingStrings(Program program,
			Map<Address, Function> seeds, TaskMonitor monitor) throws CancelledException {
		ReferenceManager referenceManager = program.getReferenceManager();
		DataIterator dataIterator = program.getListing().getDefinedData(true);
		int checked = 0;
		while (dataIterator.hasNext()) {
			monitor.checkCancelled();
			Data data = dataIterator.next();
			if (!StringDataInstance.isString(data)) {
				continue;
			}
			String value = StringDataInstance.getStringDataInstance(data).getStringValue();
			if (value == null) {
				continue;
			}
			String normalized = value.toLowerCase(Locale.ROOT);
			boolean isInteresting = containsAny(normalized, AUTH_STRING_TERMS) ||
				containsAny(normalized, RESULT_STRING_TERMS);
			if (!isInteresting) {
				continue;
			}
			ReferenceIterator references = referenceManager.getReferencesTo(data.getAddress());
			while (references.hasNext()) {
				monitor.checkCancelled();
				addFunctionSeed(program, seeds, references.next().getFromAddress());
			}
			if (++checked % 100 == 0) {
				monitor.setMessage(
					"Finding crackme auth string and API seeds (" + seeds.size() + " functions)");
			}
		}
	}

	private static void seedFunctionsFromExternalApis(Program program, Map<Address, Function> seeds,
			TaskMonitor monitor) throws CancelledException {
		ReferenceManager referenceManager = program.getReferenceManager();
		SymbolIterator symbols = program.getSymbolTable().getExternalSymbols();
		while (symbols.hasNext()) {
			monitor.checkCancelled();
			Symbol symbol = symbols.next();
			String simpleName = normalizeExternalName(symbol.getName());
			if (!containsIgnoreCase(INPUT_APIS, simpleName) &&
				!containsIgnoreCase(COMPARE_APIS, simpleName)) {
				continue;
			}
			ReferenceIterator references = referenceManager.getReferencesTo(symbol.getAddress());
			while (references.hasNext()) {
				monitor.checkCancelled();
				addFunctionSeed(program, seeds, references.next().getFromAddress());
			}
			monitor.setMessage(
				"Finding crackme auth string and API seeds (" + seeds.size() + " functions)");
		}
	}

	private static void addFunctionSeed(Program program, Map<Address, Function> seeds,
			Address fromAddress) {
		if (fromAddress == null || !fromAddress.isMemoryAddress()) {
			return;
		}
		Function function = program.getFunctionManager().getFunctionContaining(fromAddress);
		if (function != null) {
			seeds.putIfAbsent(function.getEntryPoint(), function);
		}
	}

	private static CrackmeAuthCheckCandidate inspectFunction(Program program, Function function,
			TaskMonitor monitor) throws CancelledException {
		ReferenceManager referenceManager = program.getReferenceManager();
		AddressIterator sources =
			referenceManager.getReferenceSourceIterator(function.getBody(), true);
		Set<String> evidence = new LinkedHashSet<>();
		Set<String> strings = new LinkedHashSet<>();
		Set<String> constraints = new LinkedHashSet<>();
		int score = 0;
		boolean sawNonStringSignal = false;
		boolean sawInterestingString = false;
		boolean sawAuthString = false;
		boolean sawCompareApi = false;
		int referenceSources = 0;

		while (sources.hasNext()) {
			monitor.checkCancelled();
			if (++referenceSources > MAX_REFERENCE_SOURCES_PER_FUNCTION) {
				constraints.add("large function reference scan capped");
				break;
			}
			Address source = sources.next();
			for (Reference reference : referenceManager.getReferencesFrom(source)) {
				Address toAddress = reference.getToAddress();
				String externalName = getExternalName(program, reference);
				if (externalName != null) {
					String simpleName = normalizeExternalName(externalName);
					if (containsIgnoreCase(INPUT_APIS, simpleName)) {
						sawNonStringSignal = true;
						if (evidence.add("input API " + simpleName)) {
							score += 30;
						}
					}
					if (containsIgnoreCase(COMPARE_APIS, simpleName)) {
						sawNonStringSignal = true;
						sawCompareApi = true;
						if (evidence.add("compare API " + simpleName)) {
							score += 40;
						}
					}
					continue;
				}

				String stringValue = getStringValue(program, toAddress);
				if (stringValue == null || stringValue.isBlank()) {
					if (isLikelyLookupTableReference(program, reference)) {
						if (constraints.add("array/table lookup")) {
							score += 15;
						}
					}
					continue;
				}
				strings.add(stringValue);
				String normalized = stringValue.toLowerCase(Locale.ROOT);
				if (containsAny(normalized, AUTH_STRING_TERMS) &&
					!containsAny(normalized, STATUS_MUTATION_TERMS)) {
					sawInterestingString = true;
					sawAuthString = true;
					if (evidence.add("auth string \"" + abbreviate(stringValue) + "\"")) {
						score += 25;
					}
				}
				if (containsAny(normalized, RESULT_STRING_TERMS)) {
					sawInterestingString = true;
					if (evidence.add("success/failure string \"" + abbreviate(stringValue) + "\"")) {
						score += 20;
					}
				}
			}
		}

		score += inspectInstructionConstraints(program, function, constraints, monitor);
		boolean sawStrongLocalConstraint = hasStrongLocalConstraint(constraints);
		if (sawStrongLocalConstraint) {
			sawNonStringSignal = true;
			if (evidence.add("local constraint recovery")) {
				score += 10;
			}
		}
		boolean hasStrongCodeSignal = sawCompareApi || sawStrongLocalConstraint;
		if (score < 45 || evidence.isEmpty() || !sawNonStringSignal || !sawInterestingString) {
			return null;
		}
		if (!hasStrongCodeSignal || !sawAuthString) {
			return null;
		}
		int confidence = Math.min(100, score);
		String evidenceText = String.join("; ", evidence);
		String stringText = strings.stream().map(CrackmeAuthCheckDetector::abbreviate)
				.collect(Collectors.joining("; "));
		String constraintText = constraints.isEmpty() ? "No local scalar constraints recovered"
				: String.join("; ", constraints);
		String candidateInput = summarizeCandidateInput(constraints);
		return new CrackmeAuthCheckCandidate(function.getEntryPoint(), function.getName(),
			confidence, evidenceText, stringText, constraintText, candidateInput);
	}

	private static int inspectInstructionConstraints(Program program, Function function,
			Set<String> constraints, TaskMonitor monitor) throws CancelledException {
		int score = 0;
		InstructionIterator instructions =
			program.getListing().getInstructions(function.getBody(), true);
		int instructionCount = 0;
		while (instructions.hasNext()) {
			monitor.checkCancelled();
			if (++instructionCount > MAX_INSTRUCTIONS_PER_FUNCTION) {
				constraints.add("large function instruction scan capped");
				break;
			}
			Instruction instruction = instructions.next();
			String mnemonic = instruction.getMnemonicString().toLowerCase(Locale.ROOT);
			if ("xor".equals(mnemonic) && constraints.add("XOR transform")) {
				score += 20;
			}
			if (isAdditiveMath(mnemonic) && constraints.add("additive math")) {
				score += 15;
			}
			if (isBitOperation(mnemonic) && constraints.add("bit mask/shift")) {
				score += 15;
			}
			if (isCompareOperation(mnemonic) && constraints.add("compare branch/value")) {
				score += 15;
			}
			score += inspectInstructionScalars(instruction, constraints);
		}
		return score;
	}

	private static int inspectInstructionScalars(Instruction instruction, Set<String> constraints) {
		int score = 0;
		for (int operandIndex = 0; operandIndex < instruction.getNumOperands(); operandIndex++) {
			for (Object operandObject : instruction.getOpObjects(operandIndex)) {
				if (!(operandObject instanceof Scalar scalar)) {
					continue;
				}
				long value = scalar.getUnsignedValue();
				if ((value == '0' || value == '9') &&
					constraints.add("ASCII digit conversion")) {
					score += 20;
				}
				if ((value == 'A' || value == 'F' || value == 'a' || value == 'f') &&
					constraints.add("hex digit conversion")) {
					score += 20;
				}
				if (value == 1 || value == 7 || value == 0xf || value == 0xff) {
					if (constraints.add("byte/nibble constraint")) {
						score += 10;
					}
				}
			}
		}
		return score;
	}

	private static boolean isLikelyLookupTableReference(Program program, Reference reference) {
		Address toAddress = reference.getToAddress();
		if (toAddress == null || !toAddress.isMemoryAddress()) {
			return false;
		}
		if (program.getListing().getInstructionAt(toAddress) != null) {
			return false;
		}
		Data data = program.getListing().getDefinedDataContaining(toAddress);
		return data != null;
	}

	private static boolean hasStrongLocalConstraint(Set<String> constraints) {
		return constraints.contains("ASCII digit conversion") ||
			constraints.contains("hex digit conversion") ||
			constraints.contains("XOR transform") ||
			constraints.contains("array/table lookup");
	}

	private static boolean isAdditiveMath(String mnemonic) {
		return ADDITIVE_MNEMONICS.contains(mnemonic);
	}

	private static boolean isBitOperation(String mnemonic) {
		return BIT_MNEMONICS.contains(mnemonic);
	}

	private static boolean isCompareOperation(String mnemonic) {
		return COMPARE_MNEMONICS.contains(mnemonic);
	}

	private static String summarizeCandidateInput(Set<String> constraints) {
		if (constraints.isEmpty()) {
			return "unknown";
		}
		List<String> fragments = new ArrayList<>();
		if (constraints.contains("ASCII digit conversion")) {
			fragments.add("[0-9]");
		}
		if (constraints.contains("hex digit conversion")) {
			fragments.add("[0-9a-f]");
		}
		if (constraints.contains("XOR transform")) {
			fragments.add("xor(?)");
		}
		if (constraints.contains("array/table lookup")) {
			fragments.add("table(?)");
		}
		if (fragments.isEmpty()) {
			fragments.add("constraint(?)");
		}
		return String.join(" ", fragments);
	}

	private static String getExternalName(Program program, Reference reference) {
		if (!reference.isExternalReference()) {
			return null;
		}
		Symbol symbol = program.getSymbolTable().getPrimarySymbol(reference.getToAddress());
		return symbol == null ? null : symbol.getName(true);
	}

	private static String getStringValue(Program program, Address address) {
		if (address == null || !address.isMemoryAddress()) {
			return null;
		}
		Data data = program.getListing().getDataContaining(address);
		if (data == null) {
			return null;
		}
		StringDataInstance stringData = StringDataInstance.getStringDataInstance(data);
		return stringData == null ? null : stringData.getStringValue();
	}

	private static class ListAccumulator implements Accumulator<CrackmeAuthCheckCandidate> {
		private final List<CrackmeAuthCheckCandidate> list;

		private ListAccumulator(List<CrackmeAuthCheckCandidate> list) {
			this.list = list;
		}

		@Override
		public void add(CrackmeAuthCheckCandidate candidate) {
			list.add(candidate);
		}

		@Override
		public void addAll(Collection<CrackmeAuthCheckCandidate> collection) {
			list.addAll(collection);
		}

		@Override
		public int getProgress() {
			return list.size();
		}
	}

	private static boolean containsIgnoreCase(Set<String> terms, String value) {
		for (String term : terms) {
			if (term.equalsIgnoreCase(value)) {
				return true;
			}
		}
		return false;
	}

	private static boolean containsAny(String value, Set<String> terms) {
		for (String term : terms) {
			if (value.contains(term)) {
				return true;
			}
		}
		return false;
	}

	private static String normalizeExternalName(String symbolName) {
		int namespaceIndex = symbolName.lastIndexOf("::");
		if (namespaceIndex >= 0) {
			symbolName = symbolName.substring(namespaceIndex + 2);
		}
		else {
			namespaceIndex = symbolName.lastIndexOf('/');
			if (namespaceIndex >= 0) {
				symbolName = symbolName.substring(namespaceIndex + 1);
			}
		}
		while (symbolName.startsWith("_")) {
			symbolName = symbolName.substring(1);
		}
		if (symbolName.startsWith("imp_")) {
			symbolName = symbolName.substring("imp_".length());
		}
		while (symbolName.startsWith("_")) {
			symbolName = symbolName.substring(1);
		}
		int pltIndex = symbolName.indexOf("@plt");
		if (pltIndex >= 0) {
			symbolName = symbolName.substring(0, pltIndex);
		}
		int versionIndex = symbolName.indexOf("@@");
		if (versionIndex >= 0) {
			symbolName = symbolName.substring(0, versionIndex);
		}
		int stdcallIndex = symbolName.indexOf('@');
		if (stdcallIndex > 0) {
			symbolName = symbolName.substring(0, stdcallIndex);
		}
		if (symbolName.startsWith("isoc99_")) {
			return symbolName.substring("isoc99_".length());
		}
		return symbolName;
	}

	private static String abbreviate(String value) {
		return value.length() <= 48 ? value : value.substring(0, 45) + "...";
	}
}
