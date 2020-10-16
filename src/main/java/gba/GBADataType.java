package gba;

import generic.continues.RethrowContinuesFactory;
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
			GBACartrHeader gbaHeader = GBACartrHeader.createGbaCartrHeader(RethrowContinuesFactory.INSTANCE, bap);
			
			es.add(gbaHeader.toDataType());
			
		} catch (Exception e) {
			
		}
		
	}
	
}
