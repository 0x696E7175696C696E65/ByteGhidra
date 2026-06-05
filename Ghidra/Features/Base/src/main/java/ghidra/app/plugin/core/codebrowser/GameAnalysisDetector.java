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
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Static, evidence-oriented analyzer for game-related functions and data paths.
 * <p>
 * The detector is intentionally offline-only. It does not attach to processes, patch memory, or
 * bypass protections; it ranks artifacts already present in the loaded program or memory dump.
 */
class GameAnalysisDetector {
	private static final Set<String> GAME_TERMS = Set.of("entity", "entities", "actor", "pawn",
		"player", "localplayer", "controller", "character", "health", "shield", "armor", "hp",
		"damage", "ammo", "weapon", "clip", "reload", "ability", "skill", "cooldown", "mana",
		"stamina", "inventory", "item", "slot", "pickup", "position", "transform", "velocity",
		"coord", "xpos", "ypos", "zpos", "vtable", "typeinfo", "rtti");
	private static final Set<String> POINTER_WALK_MNEMONICS =
		Set.of("lea", "mov", "add", "sub", "cmp", "test");
	private static final Set<String> FLOAT_VECTOR_MNEMONICS = Set.of("movss", "movsd", "addss",
		"subss", "mulss", "divss", "sqrtss", "movaps", "addps", "subps", "mulps");
	private static final Set<String> MUTATING_MNEMONICS =
		Set.of("mov", "stos", "xchg", "add", "sub", "inc", "dec", "and", "or", "xor");
	private static final int MAX_SEEDS = 600;
	private static final int MAX_DEFINED_DATA_TO_SCAN = 100000;
	private static final int MAX_FUNCTIONS_TO_SCAN = 50000;
	private static final int MAX_SYMBOLS_TO_SCAN = 20000;
	private static final int MAX_REFERENCES_PER_FUNCTION = 12000;
	private static final int MAX_INSTRUCTIONS_PER_FUNCTION = 45000;
	private static final int MAX_STRINGS_PER_CANDIDATE = 12;
	private static final int MAX_EVIDENCE_ITEMS = 14;

	private GameAnalysisDetector() {
	}

	static List<GameAnalysisCandidate> findCandidates(Program program, TaskMonitor monitor)
			throws CancelledException {
		List<GameAnalysisCandidate> candidates = new ArrayList<>();
		loadCandidates(program, new ListAccumulator(candidates), monitor);
		return candidates;
	}

	static void loadCandidates(Program program, Accumulator<GameAnalysisCandidate> accumulator,
			TaskMonitor monitor) throws CancelledException {
		Map<Address, CandidateSeed> seeds = collectSeeds(program, monitor);
		List<GameAnalysisCandidate> candidates = new ArrayList<>();
		monitor.setIndeterminate(false);
		monitor.initialize(Math.max(seeds.size(), 1),
			"Inspecting " + seeds.size() + " game-analysis candidates");
		for (CandidateSeed seed : seeds.values()) {
			monitor.checkCancelled();
			monitor.setMessage("Inspecting game candidate " + seed.function.getName());
			GameAnalysisCandidate candidate = inspectSeed(program, seed, monitor);
			if (candidate != null) {
				candidates.add(candidate);
			}
			monitor.incrementProgress(1);
		}
		candidates.sort(Comparator.comparingInt(GameAnalysisCandidate::confidence).reversed()
				.thenComparing(GameAnalysisCandidate::address));
		accumulator.addAll(candidates);
		monitor.setMessage("Game logic/data structure search complete");
	}

	private static Map<Address, CandidateSeed> collectSeeds(Program program, TaskMonitor monitor)
			throws CancelledException {
		Map<Address, CandidateSeed> seeds = new LinkedHashMap<>();
		monitor.setIndeterminate(true);
		seedFromStrings(program, seeds, monitor);
		seedFromSymbols(program, seeds, monitor);
		seedFromFunctionNames(program, seeds, monitor);
		return seeds;
	}

	private static void seedFromStrings(Program program, Map<Address, CandidateSeed> seeds,
			TaskMonitor monitor) throws CancelledException {
		ReferenceManager referenceManager = program.getReferenceManager();
		DataIterator dataIterator = program.getListing().getDefinedData(true);
		int scanned = 0;
		while (dataIterator.hasNext() && seeds.size() < MAX_SEEDS &&
			scanned++ < MAX_DEFINED_DATA_TO_SCAN) {
			monitor.checkCancelled();
			Data data = dataIterator.next();
			if (!StringDataInstance.isString(data)) {
				continue;
			}
			String value = getStringValue(data);
			if (value == null || !containsGameTerm(value)) {
				continue;
			}
			ReferenceIterator references = referenceManager.getReferencesTo(data.getAddress());
			while (references.hasNext() && seeds.size() < MAX_SEEDS) {
				monitor.checkCancelled();
				addFunctionSeed(program, seeds, references.next().getFromAddress(),
					"referenced game string \"" + abbreviate(value) + "\"", value);
			}
		}
		if (scanned >= MAX_DEFINED_DATA_TO_SCAN) {
			monitor.setMessage("Game string seed scan capped at " + MAX_DEFINED_DATA_TO_SCAN +
				" defined data items");
		}
	}

	private static void seedFromSymbols(Program program, Map<Address, CandidateSeed> seeds,
			TaskMonitor monitor) throws CancelledException {
		ReferenceManager referenceManager = program.getReferenceManager();
		SymbolIterator symbols = program.getSymbolTable().getSymbolIterator(true);
		int scanned = 0;
		while (symbols.hasNext() && seeds.size() < MAX_SEEDS && scanned++ < MAX_SYMBOLS_TO_SCAN) {
			monitor.checkCancelled();
			Symbol symbol = symbols.next();
			String name = symbol.getName(true);
			if (!containsGameTerm(name)) {
				continue;
			}
			Address address = symbol.getAddress();
			addFunctionSeed(program, seeds, address, "game-like symbol " + abbreviate(name), name);
			ReferenceIterator references = referenceManager.getReferencesTo(address);
			while (references.hasNext() && seeds.size() < MAX_SEEDS) {
				monitor.checkCancelled();
				addFunctionSeed(program, seeds, references.next().getFromAddress(),
					"references game-like symbol " + abbreviate(name), name);
			}
		}
	}

	private static void seedFromFunctionNames(Program program, Map<Address, CandidateSeed> seeds,
			TaskMonitor monitor) throws CancelledException {
		FunctionIterator functions = program.getFunctionManager().getFunctions(true);
		int scanned = 0;
		while (functions.hasNext() && seeds.size() < MAX_SEEDS &&
			scanned++ < MAX_FUNCTIONS_TO_SCAN) {
			monitor.checkCancelled();
			Function function = functions.next();
			String name = function.getName(true);
			if (containsGameTerm(name)) {
				addFunctionSeed(program, seeds, function.getEntryPoint(),
					"game-like function name " + abbreviate(name), name);
			}
		}
		if (scanned >= MAX_FUNCTIONS_TO_SCAN) {
			monitor.setMessage("Game function-name seed scan capped at " + MAX_FUNCTIONS_TO_SCAN +
				" functions");
		}
	}

	private static void addFunctionSeed(Program program, Map<Address, CandidateSeed> seeds,
			Address address, String evidence, String label) {
		if (address == null || !address.isMemoryAddress()) {
			return;
		}
		Function function = program.getFunctionManager().getFunctionContaining(address);
		if (function == null) {
			function = program.getFunctionManager().getFunctionAt(address);
		}
		if (function == null) {
			return;
		}
		Function seedFunction = function;
		CandidateSeed seed = seeds.computeIfAbsent(function.getEntryPoint(),
			ignored -> new CandidateSeed(seedFunction));
		seed.seedEvidence.add(evidence);
		seed.labels.add(label);
	}

	private static GameAnalysisCandidate inspectSeed(Program program, CandidateSeed seed,
			TaskMonitor monitor) throws CancelledException {
		Function function = seed.function;
		LinkedHashSet<String> labels = new LinkedHashSet<>(seed.labels);
		LinkedHashSet<String> behaviorHints = new LinkedHashSet<>();
		LinkedHashSet<String> evidence = new LinkedHashSet<>(seed.seedEvidence);
		LinkedHashSet<String> strings = new LinkedHashSet<>();
		LinkedHashSet<Long> offsets = new LinkedHashSet<>();

		labels.add(function.getName(true));
		int structuralScore = inspectReferences(program, function, labels, behaviorHints, evidence,
			strings, monitor);
		structuralScore += inspectInstructions(program, function, behaviorHints, evidence, offsets,
			monitor);
		String callGraphSummary = inspectCallGraph(function, labels, behaviorHints, evidence, monitor);

		GameAnalysisScore score = GameAnalysisHeuristics.scoreEvidence(labels, behaviorHints);
		int confidence = Math.min(100,
			score.confidence() + Math.min(30, structuralScore) + Math.min(10, seed.seedEvidence.size() * 2));
		if (confidence < 55 || evidence.isEmpty()) {
			return null;
		}
		evidence.addAll(score.evidence());
		String evidenceText = evidence.stream().limit(MAX_EVIDENCE_ITEMS).collect(Collectors.joining("; "));
		String stringText = strings.stream().limit(MAX_STRINGS_PER_CANDIDATE)
				.map(GameAnalysisDetector::abbreviate).collect(Collectors.joining("; "));
		if (stringText.isBlank()) {
			stringText = "No referenced strings recovered";
		}
		String offsetText = offsets.isEmpty() ? "No likely field offsets recovered"
				: offsets.stream().limit(16).map(GameAnalysisDetector::formatHex)
						.collect(Collectors.joining(", "));
		return new GameAnalysisCandidate(function.getEntryPoint(), score.kind(), confidence,
			function.getName(), evidenceText, offsetText, stringText, callGraphSummary);
	}

	private static int inspectReferences(Program program, Function function, Set<String> labels,
			Set<String> behaviorHints, Set<String> evidence, Set<String> strings, TaskMonitor monitor)
			throws CancelledException {
		int score = 0;
		ReferenceManager referenceManager = program.getReferenceManager();
		AddressIterator sources =
			referenceManager.getReferenceSourceIterator(function.getBody(), true);
		int referenceSources = 0;
		while (sources.hasNext()) {
			monitor.checkCancelled();
			if (++referenceSources > MAX_REFERENCES_PER_FUNCTION) {
				evidence.add("reference scan capped in large function");
				break;
			}
			Address source = sources.next();
			for (Reference reference : referenceManager.getReferencesFrom(source)) {
				Address toAddress = reference.getToAddress();
				String stringValue = getStringValue(program, toAddress);
				if (stringValue != null && !stringValue.isBlank()) {
					strings.add(stringValue);
					if (containsGameTerm(stringValue)) {
						labels.add(stringValue);
						evidence.add("references gameplay string \"" + abbreviate(stringValue) + "\"");
						score += 8;
					}
					continue;
				}
				Data data = getData(program, toAddress);
				if (data != null) {
					String typeName = data.getDataType().getName();
					labels.add(typeName);
					if (data.getNumComponents() > 1 || typeName.toLowerCase(Locale.ROOT).contains("array")) {
						behaviorHints.add("array/data type reference");
						evidence.add("references structured data type " + typeName);
						score += 6;
					}
				}
			}
		}
		return score;
	}

	private static int inspectInstructions(Program program, Function function,
			Set<String> behaviorHints, Set<String> evidence, Set<Long> offsets, TaskMonitor monitor)
			throws CancelledException {
		int score = 0;
		InstructionIterator instructions =
			program.getListing().getInstructions(function.getBody(), true);
		int instructionCount = 0;
		boolean sawBackwardFlow = false;
		while (instructions.hasNext()) {
			monitor.checkCancelled();
			if (++instructionCount > MAX_INSTRUCTIONS_PER_FUNCTION) {
				evidence.add("instruction/P-code scan capped in large function");
				break;
			}
			Instruction instruction = instructions.next();
			String mnemonic = instruction.getMnemonicString().toLowerCase(Locale.ROOT);
			if (FLOAT_VECTOR_MNEMONICS.contains(mnemonic)) {
				behaviorHints.add("vector float coordinate math");
				evidence.add("SIMD/float transform instruction " + mnemonic);
				score += 5;
			}
			if (MUTATING_MNEMONICS.contains(mnemonic)) {
				behaviorHints.add("field mutation logic");
			}
			if ("cmp".equals(mnemonic) || "test".equals(mnemonic)) {
				behaviorHints.add("count bound check");
			}
			if (hasBackwardFlow(instruction)) {
				sawBackwardFlow = true;
				behaviorHints.add("loop indexes into pointer table");
			}
			score += inspectScalars(instruction, behaviorHints, evidence, offsets);
			score += inspectPcode(instruction, behaviorHints, evidence);
		}
		if (sawBackwardFlow) {
			evidence.add("loop/back-edge recovered from Ghidra flow references");
			score += 8;
		}
		return score;
	}

	private static int inspectScalars(Instruction instruction, Set<String> behaviorHints,
			Set<String> evidence, Set<Long> offsets) {
		int score = 0;
		for (int operandIndex = 0; operandIndex < instruction.getNumOperands(); operandIndex++) {
			for (Object operandObject : instruction.getOpObjects(operandIndex)) {
				if (!(operandObject instanceof Scalar scalar)) {
					continue;
				}
				long value = scalar.getUnsignedValue();
				if (value == 0) {
					behaviorHints.add("field compared <= 0");
					continue;
				}
				if (value == 100 || value == 255 || value == 1000) {
					behaviorHints.add("clamp against " + value);
					evidence.add("game-like threshold scalar " + value);
					score += 6;
				}
				if (value == 8 || value == 16 || value == 24 || value == 32 || value == 64) {
					behaviorHints.add("pointer stride " + formatHex(value));
					evidence.add("pointer/structure stride " + formatHex(value));
					score += 4;
				}
				if (value >= 4 && value <= 0x1000 && value % 4 == 0) {
					offsets.add(value);
				}
			}
		}
		return score;
	}

	private static int inspectPcode(Instruction instruction, Set<String> behaviorHints,
			Set<String> evidence) {
		int score = 0;
		for (PcodeOp op : instruction.getPcode()) {
			String mnemonic = op.getMnemonic().toLowerCase(Locale.ROOT);
			if (mnemonic.contains("load")) {
				behaviorHints.add("P-code LOAD field read");
				score += 1;
			}
			if (mnemonic.contains("store")) {
				behaviorHints.add("P-code STORE field write");
				evidence.add("P-code store ties logic to mutable state");
				score += 4;
			}
			if (mnemonic.contains("int_less") || mnemonic.contains("int_sless") ||
				mnemonic.contains("int_equal")) {
				behaviorHints.add("zero/death threshold compare");
				score += 2;
			}
			if (mnemonic.contains("ptradd") || mnemonic.contains("ptrsub")) {
				behaviorHints.add("pointer table or indexed object walk");
				evidence.add("P-code pointer arithmetic");
				score += 5;
			}
		}
		return score;
	}

	private static String inspectCallGraph(Function function, Set<String> labels,
			Set<String> behaviorHints, Set<String> evidence, TaskMonitor monitor) {
		Set<Function> callers = function.getCallingFunctions(monitor);
		Set<Function> callees = function.getCalledFunctions(monitor);
		int namedSignals = 0;
		for (Function caller : callers) {
			String name = caller.getName(true);
			if (containsGameTerm(name)) {
				labels.add(name);
				namedSignals++;
			}
		}
		for (Function callee : callees) {
			String name = callee.getName(true);
			if (containsGameTerm(name)) {
				labels.add(name);
				namedSignals++;
			}
		}
		if (namedSignals > 0) {
			behaviorHints.add("game-related call graph neighborhood");
			evidence.add("call graph has " + namedSignals + " game-like neighbor(s)");
		}
		return callers.size() + " caller(s), " + callees.size() + " callee(s)";
	}

	private static boolean hasBackwardFlow(Instruction instruction) {
		for (Address flow : instruction.getFlows()) {
			if (flow != null && flow.compareTo(instruction.getAddress()) < 0 &&
				POINTER_WALK_MNEMONICS.contains(instruction.getMnemonicString().toLowerCase(Locale.ROOT))) {
				return true;
			}
		}
		return false;
	}

	private static Data getData(Program program, Address address) {
		if (address == null || !address.isMemoryAddress()) {
			return null;
		}
		return program.getListing().getDataContaining(address);
	}

	private static String getStringValue(Program program, Address address) {
		Data data = getData(program, address);
		return data == null ? null : getStringValue(data);
	}

	private static String getStringValue(Data data) {
		StringDataInstance stringData = StringDataInstance.getStringDataInstance(data);
		return stringData == null ? null : stringData.getStringValue();
	}

	private static boolean containsGameTerm(String value) {
		if (value == null) {
			return false;
		}
		String normalized = value.toLowerCase(Locale.ROOT);
		for (String term : GAME_TERMS) {
			if (normalized.contains(term)) {
				return true;
			}
		}
		return false;
	}

	private static String abbreviate(String value) {
		if (value == null) {
			return "";
		}
		String normalized = value.replace('\n', ' ').replace('\r', ' ').trim();
		return normalized.length() <= 80 ? normalized : normalized.substring(0, 77) + "...";
	}

	private static String formatHex(long value) {
		return "0x" + Long.toHexString(value);
	}

	private static class CandidateSeed {
		private final Function function;
		private final LinkedHashSet<String> labels = new LinkedHashSet<>();
		private final LinkedHashSet<String> seedEvidence = new LinkedHashSet<>();

		private CandidateSeed(Function function) {
			this.function = function;
		}
	}

	private static class ListAccumulator implements Accumulator<GameAnalysisCandidate> {
		private final List<GameAnalysisCandidate> list;

		private ListAccumulator(List<GameAnalysisCandidate> list) {
			this.list = list;
		}

		@Override
		public void add(GameAnalysisCandidate candidate) {
			list.add(candidate);
		}

		@Override
		public void addAll(Collection<GameAnalysisCandidate> collection) {
			list.addAll(collection);
		}

		@Override
		public int getProgress() {
			return list.size();
		}
	}
}
