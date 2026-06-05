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

import docking.widgets.table.AbstractDynamicTableColumn;
import docking.widgets.table.TableColumnDescriptor;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.GhidraProgramTableModel;
import ghidra.util.task.TaskMonitor;

class CrackmeAuthCheckTableModel extends GhidraProgramTableModel<CrackmeAuthCheckCandidate> {

	CrackmeAuthCheckTableModel(PluginTool tool, Program program) {
		super("Crackme Auth Checks in " + program.getName(), tool, program, null);
	}

	@Override
	protected void doLoad(Accumulator<CrackmeAuthCheckCandidate> accumulator, TaskMonitor monitor)
			throws CancelledException {
		CrackmeAuthCheckDetector.loadCandidates(program, accumulator, monitor);
	}

	@Override
	protected TableColumnDescriptor<CrackmeAuthCheckCandidate> createTableColumnDescriptor() {
		TableColumnDescriptor<CrackmeAuthCheckCandidate> descriptor = new TableColumnDescriptor<>();
		descriptor.addVisibleColumn(new AddressColumn());
		descriptor.addVisibleColumn(new FunctionColumn());
		descriptor.addVisibleColumn(new ConfidenceColumn());
		descriptor.addVisibleColumn(new EvidenceColumn());
		descriptor.addVisibleColumn(new ConstraintsColumn());
		descriptor.addVisibleColumn(new CandidateInputColumn());
		descriptor.addVisibleColumn(new StringsColumn());
		return descriptor;
	}

	@Override
	public ProgramLocation getProgramLocation(int modelRow, int modelColumn) {
		return new ProgramLocation(program, getRowObject(modelRow).address());
	}

	@Override
	public ProgramSelection getProgramSelection(int[] modelRows) {
		AddressSet set = new AddressSet();
		for (CrackmeAuthCheckCandidate candidate : getRowObjects(modelRows)) {
			set.add(candidate.address());
		}
		return new ProgramSelection(set);
	}

	@Override
	public Address getAddress(int modelRow) {
		return getRowObject(modelRow).address();
	}

	private static class AddressColumn
			extends AbstractDynamicTableColumn<CrackmeAuthCheckCandidate, Address, Object> {
		@Override
		public String getColumnName() {
			return "Address";
		}

		@Override
		public Address getValue(CrackmeAuthCheckCandidate rowObject, Settings settings, Object data,
				ServiceProvider services) throws IllegalArgumentException {
			return rowObject.address();
		}
	}

	private static class FunctionColumn
			extends AbstractDynamicTableColumn<CrackmeAuthCheckCandidate, String, Object> {
		@Override
		public String getColumnName() {
			return "Function";
		}

		@Override
		public String getValue(CrackmeAuthCheckCandidate rowObject, Settings settings, Object data,
				ServiceProvider services) throws IllegalArgumentException {
			return rowObject.functionName();
		}
	}

	private static class ConfidenceColumn
			extends AbstractDynamicTableColumn<CrackmeAuthCheckCandidate, Integer, Object> {
		@Override
		public String getColumnName() {
			return "Confidence";
		}

		@Override
		public Integer getValue(CrackmeAuthCheckCandidate rowObject, Settings settings, Object data,
				ServiceProvider services) throws IllegalArgumentException {
			return rowObject.confidence();
		}
	}

	private static class EvidenceColumn
			extends AbstractDynamicTableColumn<CrackmeAuthCheckCandidate, String, Object> {
		@Override
		public String getColumnName() {
			return "Evidence";
		}

		@Override
		public String getValue(CrackmeAuthCheckCandidate rowObject, Settings settings, Object data,
				ServiceProvider services) throws IllegalArgumentException {
			return rowObject.evidence();
		}
	}

	private static class StringsColumn
			extends AbstractDynamicTableColumn<CrackmeAuthCheckCandidate, String, Object> {
		@Override
		public String getColumnName() {
			return "Referenced Strings";
		}

		@Override
		public String getValue(CrackmeAuthCheckCandidate rowObject, Settings settings, Object data,
				ServiceProvider services) throws IllegalArgumentException {
			return rowObject.referencedStrings();
		}
	}

	private static class ConstraintsColumn
			extends AbstractDynamicTableColumn<CrackmeAuthCheckCandidate, String, Object> {
		@Override
		public String getColumnName() {
			return "Recovered Constraints";
		}

		@Override
		public String getValue(CrackmeAuthCheckCandidate rowObject, Settings settings, Object data,
				ServiceProvider services) throws IllegalArgumentException {
			return rowObject.constraintSummary();
		}
	}

	private static class CandidateInputColumn
			extends AbstractDynamicTableColumn<CrackmeAuthCheckCandidate, String, Object> {
		@Override
		public String getColumnName() {
			return "Input Hints";
		}

		@Override
		public String getValue(CrackmeAuthCheckCandidate rowObject, Settings settings, Object data,
				ServiceProvider services) throws IllegalArgumentException {
			return rowObject.candidateInput();
		}
	}
}
