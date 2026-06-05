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
package ghidra.app.plugin.core.mcp.security;

import ghidra.app.plugin.core.mcp.ops.GhidraMcpOperation.OperationKind;

public class GhidraMcpPolicy {
	private final boolean allowReadOnly;
	private final boolean allowUiOnly;
	private final boolean allowAnnotationWrites;
	private final boolean allowAnalysisWrites;
	private final boolean allowDangerous;
	private final boolean allowRemoteBind;

	public GhidraMcpPolicy(boolean allowReadOnly, boolean allowUiOnly,
			boolean allowAnnotationWrites, boolean allowAnalysisWrites, boolean allowDangerous,
			boolean allowRemoteBind) {
		this.allowReadOnly = allowReadOnly;
		this.allowUiOnly = allowUiOnly;
		this.allowAnnotationWrites = allowAnnotationWrites;
		this.allowAnalysisWrites = allowAnalysisWrites;
		this.allowDangerous = allowDangerous;
		this.allowRemoteBind = allowRemoteBind;
	}

	public static GhidraMcpPolicy defaults() {
		return tokenTrusted();
	}

	public static GhidraMcpPolicy tokenTrusted() {
		return new GhidraMcpPolicy(true, true, true, true, true, false);
	}

	public static GhidraMcpPolicy allowAnnotations() {
		return new GhidraMcpPolicy(true, true, true, false, false, false);
	}

	public static GhidraMcpPolicy allowAnalysis() {
		return new GhidraMcpPolicy(true, true, false, true, false, false);
	}

	public static GhidraMcpPolicy allowAnnotationsAndAnalysis() {
		return new GhidraMcpPolicy(true, true, true, true, false, false);
	}

	public boolean isAllowed(OperationKind kind) {
		return switch (kind) {
			case READ_ONLY -> allowReadOnly;
			case UI_ONLY -> allowUiOnly;
			case ANNOTATION_WRITE -> allowAnnotationWrites;
			case ANALYSIS_WRITE -> allowAnalysisWrites;
			case DANGEROUS -> allowDangerous;
		};
	}

	public boolean allowsRemoteBind() {
		return allowRemoteBind;
	}

	public boolean allowsAnnotationWrites() {
		return allowAnnotationWrites;
	}

	public boolean allowsAnalysisWrites() {
		return allowAnalysisWrites;
	}

	public boolean allowsDangerousOperations() {
		return allowDangerous;
	}
}
