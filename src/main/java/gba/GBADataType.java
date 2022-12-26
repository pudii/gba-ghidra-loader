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
package gba;

import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.docking.settings.Settings;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FactoryStructureDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

public class GBADataType extends FactoryStructureDataType {

	public GBADataType() {
		this(null);
	}

	public GBADataType(DataTypeManager dtm) {
		super("GBA", dtm);
	}

	public String getMnemonic(Settings settings) {
		return "GBA";
	}

	public boolean isDynamicallySized() {
		return false;
	}

	@Override
	public String getDescription() {
		return "GBA ROM Data Type";
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		return new GBADataType(dtm);
	}

	@Override
	protected void populateDynamicStructure(MemBuffer buf, Structure es) {
		try {
			Memory memory = buf.getMemory();
			MemoryBlock block = memory.getBlock(buf.getAddress());
			byte[] bytes = new byte[(int)block.getSize()];
			block.getBytes(block.getStart(), bytes);

			ByteArrayProvider bap = new ByteArrayProvider(bytes);
			GBACartrHeader gbaHeader = GBACartrHeader.createGbaCartrHeader(bap);

			es.add(gbaHeader.toDataType());

		} catch (Exception e) {

		}

	}

}
