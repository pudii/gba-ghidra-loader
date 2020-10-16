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

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import org.python.bouncycastle.util.Arrays;



import generic.continues.GenericFactory;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.exception.DuplicateNameException;

public class GBACartrHeader implements StructConverter {
	
	private int h_rom_entry_point;// = new byte[4];
	private byte[] h_nintendo_logo = new byte[156];
	private String h_game_title;
	private String h_game_code;
	private String h_maker_code;
	private byte h_fixed_value;
	private byte h_main_unit_code;
	private byte h_device_type;
	private byte[] h_reserved = new byte[7];
	private byte h_software_vers;
	private byte h_complement_check;
	private byte[] h_reserved2 = new byte[2];
	
	private FactoryBundledWithBinaryReader reader;
	
	public static GBACartrHeader createGbaCartrHeader(GenericFactory factory, ByteProvider provider) throws IOException {
		GBACartrHeader gbaHeader = (GBACartrHeader) factory.create(GBACartrHeader.class);
		gbaHeader.initGBAHeader(factory, provider);
		return gbaHeader;
	}
	
	/*
	 * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
	 */
	public GBACartrHeader() {}
	
	private void initGBAHeader(GenericFactory factory, ByteProvider provider) throws IOException {
		reader = new FactoryBundledWithBinaryReader(factory, provider, true);
		
		h_rom_entry_point = reader.readNextInt();
		//h_rom_entry_point = reader.readNextByteArray(4);
		h_nintendo_logo = reader.readNextByteArray(156);
		h_game_title = reader.readNextAsciiString(12);
		h_game_code = reader.readNextAsciiString(4);
		h_maker_code = reader.readNextAsciiString(2);
		h_fixed_value = reader.readNextByte();
		h_main_unit_code = reader.readNextByte();
		h_device_type = reader.readNextByte();
		h_reserved = reader.readNextByteArray(7);
		h_software_vers = reader.readNextByte();
		h_complement_check = reader.readNextByte();
		h_reserved2 = reader.readNextByteArray(2);
	
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {

		StructureDataType headerStruct = new StructureDataType("GBA_CARTR_HEADER", 0x00);
		//headerStruct.add(new ArrayDataType(BYTE, h_rom_entry_point.length, 1), "h_rom_entry_point", "Branch entry point");
		headerStruct.add(DWORD, "h_rom_entry_point", "Branch entry point");
		headerStruct.add(new ArrayDataType(BYTE, h_nintendo_logo.length, 1), "h_nintendo_logo", "Nintendo Logo");
		headerStruct.add(STRING, 12, "h_game_title", "Game Title");
		headerStruct.add(STRING, 4, "h_game_code", "Game Code");
		headerStruct.add(new ArrayDataType(ASCII, h_maker_code.length(), 1), "h_maker_code", "Maker Code");
		headerStruct.add(BYTE, "h_fixed_value", "Fixed Value");
		headerStruct.add(BYTE, "h_main_unit_code", "Main Unit Code");
		headerStruct.add(BYTE, "h_device_type", "Device Type");
		headerStruct.add(new ArrayDataType(BYTE, h_reserved.length, 1), "h_reserved", "Reserved area");
		headerStruct.add(BYTE, "h_software_vers", "Software Version");
		headerStruct.add(BYTE, "h_complement_check", "Complement Check");
		headerStruct.add(new ArrayDataType(BYTE, h_reserved2.length, 1), "h_reserved2", "Reserved area");
		
		return headerStruct;
	}

	public int getEntryOffset() {
		int entry = h_rom_entry_point & 0x00FFFFFF;
		if ((entry & 0x3) == 0) {
			return 4*entry;
		}
		
		int aligned = (((entry & 0xFFFFFFFC) >> 2) + 1) << 2;
		return 4*aligned;
	}
		

}
