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
import java.util.*;

import generic.continues.RethrowContinuesFactory;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.QueryOpinionService;
import ghidra.app.util.opinion.QueryResult;
import ghidra.framework.model.DomainObject;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.datastruct.ByteArray;
import ghidra.util.datastruct.ByteArrayArray;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;


/**
 * This loader loads GameBoy Advance binary files, mapping the memory regions and setting an entry point.
 */
public class GBALoader extends AbstractLibrarySupportLoader {
	
	private final long GBAH_ENTRY_OFFSET			= 0x00;
	private final long GBAH_ENTRY_LEN				= 3;
	private final byte GBAH_ENTRYINSTR_OFFSET		= 0x3;
	private final byte GBAH_ENTRYINSTR				= (byte) 0xEA;
	
	private final long GBAH_NINTENDOLOGO_OFFSET		= 0x4;
	private final long GBAH_NINTENDOLOGO_LEN		= 156;
	private final byte[] GBAH_NINTENDOLOGO_FST		= {0x24, (byte) 0xFF, (byte) 0xAE, 0x51, 0x69, (byte) 0x9A, (byte) 0xA2, 0x21};
	
	private final long GBAH_GAMETITLE_OFFSET		= 0xA0;
	private final long GBAH_GAMETITLE_LEN			= 12;
	
	private final long GBAH_GAMECODE_OFFSET			= 0xAC;
	private final long GBAH_GAMECODE_LEN			= 4;
	
	private final long GBAH_MAKERCODE_OFFSET		= 0xB0;
	private final long GBAH_MAKERCODE_LEN			= 2;
	
	private final long GBAH_FIXED_OFFSET			= 0xB2;
	private final byte GBAH_FIXED					= (byte) 0x96;
	
	private final long GBAH_MAINUNIT_OFFSET			= 0xB3;
	private final byte GBAH_MAINUNIT				= 0x00;
	
	private final long GBAH_DEVTYPE_OFFSET			= 0xB4;
	
	private final long GBAH_RESERVED_OFFSET			= 0xB5;
	private final long GBAH_RESERVED_LEN			= 7;
	private final byte[] GBAH_RESERVED				= {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	
	private final long GBAH_SOFTVERS_OFFSET			= 0xBC;
	
	private final long GBAH_COMPLCHECK_OFFSET		= 0xBD;
	
	private final long GBAH_RESERVED2_OFFSET		= 0xBE;
	private final long GBAH_RESERVED2_LEN			= 2;
	private final short GBAH_RESERVED2				= 0x00;
	
	
	
	@Override
	public String getName() {

		return "GBA Loader";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();
		
		// Compare the first 8 bytes of the Nintendo logo field. This is required and can be used to determine the filetype
		byte[] nintendo_logo = provider.readBytes(GBAH_NINTENDOLOGO_OFFSET, 8);
		if (!Arrays.equals(nintendo_logo, GBAH_NINTENDOLOGO_FST)) {
			// Not a correct Nintendo Logo -> No valid GBA ROM
			return loadSpecs;
		}
		
		// Check for a fixed value 0x96
		byte fixed_val = provider.readByte(GBAH_FIXED_OFFSET);
		if (fixed_val != GBAH_FIXED) {
			// The fixed value does not match -> No valid GBA ROM
			return loadSpecs;
		}	
		
		// Check for ARM branch opcode in the fourth byte (entry point branch)
		byte entry_branch_instr = provider.readByte(GBAH_ENTRYINSTR_OFFSET);
		if (entry_branch_instr != GBAH_ENTRYINSTR) {
			// ARM opcode is no branch -> No valid GBA ROM
			return loadSpecs;
		}
		
		
		// Alternative as this is only one option
//		LanguageCompilerSpecPair gba_lcs = new LanguageCompilerSpecPair("ARM:LE:32:v4t", "default");
//		loadSpecs.add(new LoadSpec(this, 0, gba_lcs, true));
		
		List<QueryResult> results = QueryOpinionService.query(getName(), "armv4t", null);
		for (QueryResult result : results) {
			loadSpecs.add(new LoadSpec(this, 0, result));
		}
		
		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {
		
		FlatProgramAPI flatAPI = new FlatProgramAPI(program);
		
		// First 192 (0xC0) bytes is the Cartridge header
		// Load base is 0x80000000
		long LOAD_BASE = 0x80000000;
		
		try {
			Memory mem = program.getMemory();
			MemoryBlock memblock;
			// WRAM - On-board Work RAM
			memblock = mem.createUninitializedBlock("WRAMB", flatAPI.toAddr(0x2000000), 0x40000, false);
			memblock.setRead(true);
			memblock.setWrite(true);
			memblock.setExecute(false);
			// WRAM - On-chip Work RAM
			memblock = mem.createUninitializedBlock("WRAMC", flatAPI.toAddr(0x3000000), 0x8000, false);
			memblock.setRead(true);
			memblock.setWrite(true);
			memblock.setExecute(false);
			// I/O Registers
			memblock = mem.createUninitializedBlock("IO", flatAPI.toAddr(0x4000000), 0x3ff, false);
			memblock.setRead(true);
			memblock.setWrite(true);
			memblock.setExecute(false);
			// BG/OBJ Palette RAM
			memblock = mem.createUninitializedBlock("PALETTE", flatAPI.toAddr(0x5000000), 0x400, false);
			memblock.setRead(true);
			memblock.setWrite(true);
			memblock.setExecute(false);
			// VRAM - Video RAM
			memblock = mem.createUninitializedBlock("VRAM", flatAPI.toAddr(0x6000000), 0x18000, false);
			memblock.setRead(true);
			memblock.setWrite(true);
			memblock.setExecute(false);
			// OAM - OBJ Attributes
			memblock = mem.createUninitializedBlock("OAMOBJ", flatAPI.toAddr(0x7000000), 0x400, false);
			memblock.setRead(true);
			memblock.setWrite(true);
			memblock.setExecute(false);
			
			// ROM
			// Cartridge header memory block
			final long cartr_hdr_size = 0xC0;
			Address cartr_hdr_start = flatAPI.toAddr(LOAD_BASE);
			MemoryBlock cartr_hdr_block = flatAPI.createMemoryBlock("header", cartr_hdr_start, provider.readBytes(0, cartr_hdr_size), false);
			cartr_hdr_block.setRead(true);
			cartr_hdr_block.setWrite(false);
			cartr_hdr_block.setExecute(true);

			Address cartr_rom_start = flatAPI.toAddr(LOAD_BASE + cartr_hdr_size);
			MemoryBlock cartr_rom_block = flatAPI.createMemoryBlock("rom", cartr_rom_start, provider.readBytes(cartr_hdr_size, 0x800000-cartr_hdr_size), false);
			cartr_rom_block.setRead(true);
			cartr_rom_block.setWrite(false);
			cartr_rom_block.setExecute(true);
			
			mapIO(flatAPI, log);
			
			GBACartrHeader gbaHeader = GBACartrHeader.createGbaCartrHeader(RethrowContinuesFactory.INSTANCE, provider);
			DataType headerDataType = gbaHeader.toDataType();
			flatAPI.createData(cartr_hdr_start, headerDataType);
			
			flatAPI.addEntryPoint(flatAPI.toAddr(LOAD_BASE + gbaHeader.getEntryOffset()));

			
		} catch (Exception e) {
			log.appendException(e);
		}
	}
	
	private void mapIO(FlatProgramAPI flatAPI, MessageLog log) {
		Address addr;
		try {
			// Data taken from: https://problemkaputt.de/gbatek.htm#gbaiomap
			// LCD I/O Registers
			addr = flatAPI.toAddr(0x4000000);
			flatAPI.createLabel(addr, "DISPCNT", true);
			flatAPI.setEOLComment(addr, "LCD Control");
			flatAPI.createWord(addr);
			addr = flatAPI.toAddr(0x4000004);
			flatAPI.createLabel(addr, "DISPSTAT", true);
			flatAPI.setEOLComment(addr, "General LCD Status (STAT,LYC)");
			flatAPI.createWord(addr);
			addr = flatAPI.toAddr(0x4000006);
			flatAPI.createLabel(addr, "VCOUNT", true);
			flatAPI.setEOLComment(addr, "Vertical Counter (LY)");
			flatAPI.createWord(addr);
			addr = flatAPI.toAddr(0x4000008);
			flatAPI.createLabel(addr, "BG0CNT", true);
			flatAPI.setEOLComment(addr, "BG0 Control");
			flatAPI.createWord(addr);
			addr = flatAPI.toAddr(0x400000A);
			flatAPI.createLabel(addr, "BG1CNT", true);
			flatAPI.setEOLComment(addr, "BG1 Control");
			flatAPI.createWord(addr);
			addr = flatAPI.toAddr(0x400000C);
			flatAPI.createLabel(addr, "BG2CNT", true);
			flatAPI.setEOLComment(addr, "BG2 Control");
			flatAPI.createWord(addr);
			addr = flatAPI.toAddr(0x400000E);
			flatAPI.createLabel(addr, "BG3CNT", true);
			flatAPI.setEOLComment(addr, "BG3 Control");
			flatAPI.createWord(addr);
			addr = flatAPI.toAddr(0x4000010);
			flatAPI.createLabel(addr, "BG0HOFS", true);
			flatAPI.setEOLComment(addr, "BG0 X-Offset");
			flatAPI.createWord(addr);
			addr = flatAPI.toAddr(0x4000012);
			flatAPI.createLabel(addr, "BG0VOFS", true);
			flatAPI.setEOLComment(addr, "BG0 Y-Offset");
			flatAPI.createWord(addr);
			addr = flatAPI.toAddr(0x4000014);
			flatAPI.createLabel(addr, "BG1HOFS", true);
			flatAPI.setEOLComment(addr, "BG1 X-Offset");
			flatAPI.createWord(addr);
			addr = flatAPI.toAddr(0x4000016);
			flatAPI.createLabel(addr, "BG1VOFS", true);
			flatAPI.setEOLComment(addr, "BG1 Y-Offset");
			flatAPI.createWord(addr);
			addr = flatAPI.toAddr(0x4000018);
			flatAPI.createLabel(addr, "BG2HOFS", true);
			flatAPI.setEOLComment(addr, "BG2 X-Offset");
			flatAPI.createWord(addr);
			addr = flatAPI.toAddr(0x400001A);
			flatAPI.createLabel(addr, "BG2VOFS", true);
			flatAPI.setEOLComment(addr, "BG2 Y-Offset");
			flatAPI.createWord(addr);
			addr = flatAPI.toAddr(0x400001C);
			flatAPI.createLabel(addr, "BG3HOFS", true);
			flatAPI.setEOLComment(addr, "BG3 X-Offset");
			flatAPI.createWord(addr);
			addr = flatAPI.toAddr(0x400001E);
			flatAPI.createLabel(addr, "BG3VOFS", true);
			flatAPI.setEOLComment(addr, "BG3 Y-Offset");
			flatAPI.createWord(addr);
			addr = flatAPI.toAddr(0x4000020);
			flatAPI.createLabel(addr, "BG2PA", true);
			flatAPI.setEOLComment(addr, "BG2 Rotation/Scaling Parameter A (dx)");
			flatAPI.createWord(addr);
			addr = flatAPI.toAddr(0x4000022);
			flatAPI.createLabel(addr, "BG2PB", true);
			flatAPI.setEOLComment(addr, "BG2 Rotation/Scaling Parameter B (dmx)");
			flatAPI.createWord(addr);
			addr = flatAPI.toAddr(0x4000024);
			flatAPI.createLabel(addr, "BG2PC", true);
			flatAPI.setEOLComment(addr, "BG2 Rotation/Scaling Parameter C (dy)");
			flatAPI.createWord(addr);
			addr = flatAPI.toAddr(0x4000026);
			flatAPI.createLabel(addr, "BG2PD", true);
			flatAPI.setEOLComment(addr, "BG2 Rotation/Scaling Parameter D (dmy)");
			flatAPI.createWord(addr);
			addr = flatAPI.toAddr(0x4000028);
			flatAPI.createLabel(addr, "BG2X", true);
			flatAPI.setEOLComment(addr, "BG2 Reference Point X-Coordinate");
			flatAPI.createDWord(addr);
			addr = flatAPI.toAddr(0x400002C);
			flatAPI.createLabel(addr, "BG2Y", true);
			flatAPI.setEOLComment(addr, "BG2 Reference Point Y-Coordinate");
			flatAPI.createDWord(addr);
			addr = flatAPI.toAddr(0x4000030);
			flatAPI.createLabel(addr, "BG3PA", true);
			flatAPI.setEOLComment(addr, "BG3 Rotation/Scaling Parameter A (dx)");
			flatAPI.createWord(addr);
			addr = flatAPI.toAddr(0x4000032);
			flatAPI.createLabel(addr, "BG3PB", true);
			flatAPI.setEOLComment(addr, "BG3 Rotation/Scaling Parameter B (dmx)");
			flatAPI.createWord(addr);
			addr = flatAPI.toAddr(0x4000034);
			flatAPI.createLabel(addr, "BG3PC", true);
			flatAPI.setEOLComment(addr, "BG3 Rotation/Scaling Parameter C (dy)");
			flatAPI.createWord(addr);
			addr = flatAPI.toAddr(0x4000036);
			flatAPI.createLabel(addr, "BG3PD", true);
			flatAPI.setEOLComment(addr, "BG3 Rotation/Scaling Parameter D (dmy)");
			flatAPI.createWord(addr);
			addr = flatAPI.toAddr(0x4000038);
			flatAPI.createLabel(addr, "BG3X", true);
			flatAPI.setEOLComment(addr, "BG3 Reference Point X-Coordinate");
			flatAPI.createDWord(addr);
			addr = flatAPI.toAddr(0x400003C);
			flatAPI.createLabel(addr, "BG3Y", true);
			flatAPI.setEOLComment(addr, "BG3 Reference Point Y-Coordinate");
			flatAPI.createDWord(addr);
			addr = flatAPI.toAddr(0x4000040);
			flatAPI.createLabel(addr, "WIN0H", true);
			flatAPI.setEOLComment(addr, "Window 0 Horizontal Dimensions");
			flatAPI.createWord(addr);
			addr = flatAPI.toAddr(0x4000042);
			flatAPI.createLabel(addr, "WIN1H", true);
			flatAPI.setEOLComment(addr, "Window 1 Horizontal Dimensions");
			flatAPI.createWord(addr);
			addr = flatAPI.toAddr(0x4000044);
			flatAPI.createLabel(addr, "WIN0V", true);
			flatAPI.setEOLComment(addr, "Window 0 Vertical Dimensions");
			flatAPI.createWord(addr);
			addr = flatAPI.toAddr(0x4000046);
			flatAPI.createLabel(addr, "WIN1V", true);
			flatAPI.setEOLComment(addr, "Window 1 Vertical Dimensions");
			flatAPI.createWord(addr);
			addr = flatAPI.toAddr(0x4000048);
			flatAPI.createLabel(addr, "WININ", true);
			flatAPI.setEOLComment(addr, "Inside of Window 0 and 1");
			flatAPI.createWord(addr);
			addr = flatAPI.toAddr(0x400004A);
			flatAPI.createLabel(addr, "WINOUT", true);
			flatAPI.setEOLComment(addr, "Inside of OBJ Window & Outside of Windows");
			flatAPI.createWord(addr);
			addr = flatAPI.toAddr(0x400004C);
			flatAPI.createLabel(addr, "MOSAIC", true);
			flatAPI.setEOLComment(addr, "Mosaic Size");
			flatAPI.createWord(addr);
			addr = flatAPI.toAddr(0x4000050);
			flatAPI.createLabel(addr, "BLDCNT", true);
			flatAPI.setEOLComment(addr, "Color Special Effects Selection");
			flatAPI.createWord(addr);
			addr = flatAPI.toAddr(0x4000052);
			flatAPI.createLabel(addr, "BLDALPHA", true);
			flatAPI.setEOLComment(addr, "Alpha Blending Coefficients");
			flatAPI.createWord(addr);
			addr = flatAPI.toAddr(0x4000054);
			flatAPI.createLabel(addr, "BLDY", true);
			flatAPI.setEOLComment(addr, "Brightness (Fade-In/Out) Coefficient");
			flatAPI.createWord(addr);

			// Sound Registers
			addr = flatAPI.toAddr(0x4000060);
			flatAPI.createLabel(addr, "SOUND1CNT_L", true);
			flatAPI.setEOLComment(addr, "Sweep register (NR10)");
			flatAPI.createWord(addr);
			addr = flatAPI.toAddr(0x4000062);
			flatAPI.createLabel(addr, "SOUND1CNT_H", true);
			flatAPI.setEOLComment(addr, "Duty/Length/Envelope (NR11, NR12)");
			flatAPI.createWord(addr);
			addr = flatAPI.toAddr(0x4000064);
			flatAPI.createLabel(addr, "SOUND1CNT_X", true);
			flatAPI.setEOLComment(addr, "Frequency/Control (NR13, NR14)");
			flatAPI.createWord(addr);
			addr = flatAPI.toAddr(0x4000068);
			flatAPI.createLabel(addr, "SOUND2CNT_L", true);
			flatAPI.setEOLComment(addr, "Duty/Length/Envelope (NR21, NR22)");
			flatAPI.createWord(addr);
			addr = flatAPI.toAddr(0x400006C);
			flatAPI.createLabel(addr, "SOUND2CNT_H", true);
			flatAPI.setEOLComment(addr, "Frequency/Control (NR23, NR24)");
			flatAPI.createWord(addr);
			addr = flatAPI.toAddr(0x4000070);
			flatAPI.createLabel(addr, "SOUND3CNT_L", true);
			flatAPI.setEOLComment(addr, "Stop/Wave RAM select (NR30)");
			flatAPI.createWord(addr);
			addr = flatAPI.toAddr(0x4000072);
			flatAPI.createLabel(addr, "SOUND3CNT_H", true);
			flatAPI.setEOLComment(addr, "Length/Volume (NR31, NR32)");
			flatAPI.createWord(addr);
			addr = flatAPI.toAddr(0x4000074);
			flatAPI.createLabel(addr, "SOUND3CNT_X", true);
			flatAPI.setEOLComment(addr, "Frequency/Control (NR33, NR34)");
			flatAPI.createWord(addr);
			addr = flatAPI.toAddr(0x4000078);
			flatAPI.createLabel(addr, "SOUND4CNT_L", true);
			flatAPI.setEOLComment(addr, "Length/Envelope (NR41, NR42)");
			flatAPI.createWord(addr);
			addr = flatAPI.toAddr(0x400007C);
			flatAPI.createLabel(addr, "SOUND4CNT_H", true);
			flatAPI.setEOLComment(addr, "Frequency/Control (NR43, NR44)");
			flatAPI.createWord(addr);
			addr = flatAPI.toAddr(0x4000080);
			flatAPI.createLabel(addr, "SOUNDCNT_L", true);
			flatAPI.setEOLComment(addr, "Control Stereo/Volume/Enable (NR50, NR51)");
			flatAPI.createWord(addr);
			addr = flatAPI.toAddr(0x4000082);
			flatAPI.createLabel(addr, "SOUNDCNT_H", true);
			flatAPI.setEOLComment(addr, "Control Mixing/DMA Control");
			flatAPI.createWord(addr);
			addr = flatAPI.toAddr(0x4000084);
			flatAPI.createLabel(addr, "SOUNDCNT_X", true);
			flatAPI.setEOLComment(addr, "Control Sound on/off (NR52)");
			flatAPI.createWord(addr);
			addr = flatAPI.toAddr(0x4000088);
			flatAPI.createLabel(addr, "SOUNDBIAS", true);
			flatAPI.setEOLComment(addr, "Sound PWM Control");
			flatAPI.createWord(addr);
			addr = flatAPI.toAddr(0x4000090);
			flatAPI.createLabel(addr, "WAVE_RAM", true);
			flatAPI.setEOLComment(addr, "Channel 3 Wave Pattern RAM (2 banks!!)");
			// TODO: Define data type (2 * 0x10)
			addr = flatAPI.toAddr(0x40000A0);
			flatAPI.createLabel(addr, "FIFO_A", true);
			flatAPI.setEOLComment(addr, "Channel A FIFO, Data 0-3");
			flatAPI.createDWord(addr);
			addr = flatAPI.toAddr(0x40000A4);
			flatAPI.createLabel(addr, "FIFO_B", true);
			flatAPI.setEOLComment(addr, "Channel B FIFO, Data 0-3");
			flatAPI.createDWord(addr);
			
			// DMA Transfer Channels
			addr = flatAPI.toAddr(0x40000B0);
			flatAPI.createLabel(addr, "DMA0SAD", true);
			flatAPI.setEOLComment(addr, "DMA 0 Source Address");
			flatAPI.createDWord(addr);
			addr = flatAPI.toAddr(0x40000B4);
			flatAPI.createLabel(addr, "DMA0DAD", true);
			flatAPI.setEOLComment(addr, "DMA 0 Destination Address");
			flatAPI.createDWord(addr);
			addr = flatAPI.toAddr(0x40000B8);
			flatAPI.createLabel(addr, "DMA0CNT_L", true);
			flatAPI.setEOLComment(addr, "DMA 0 Word Count");
			flatAPI.createWord(addr);
			addr = flatAPI.toAddr(0x40000BA);
			flatAPI.createLabel(addr, "DMA0CNT_H", true);
			flatAPI.setEOLComment(addr, "DMA 0 Control");
			flatAPI.createWord(addr);
			addr = flatAPI.toAddr(0x40000BC);
			flatAPI.createLabel(addr, "DMA1SAD", true);
			flatAPI.setEOLComment(addr, "DMA 1 Source Address");
			flatAPI.createDWord(addr);
			addr = flatAPI.toAddr(0x40000C0);
			flatAPI.createLabel(addr, "DMA1DAD", true);
			flatAPI.setEOLComment(addr, "DMA 1 Destination Address");
			flatAPI.createDWord(addr);
			addr = flatAPI.toAddr(0x40000C4);
			flatAPI.createLabel(addr, "DMA1CNT_L", true);
			flatAPI.setEOLComment(addr, "DMA 1 Word Count");
			flatAPI.createWord(addr);
			addr = flatAPI.toAddr(0x40000C6);
			flatAPI.createLabel(addr, "DMA1CNT_H", true);
			flatAPI.setEOLComment(addr, "DMA 1 Control");
			flatAPI.createWord(addr);
			addr = flatAPI.toAddr(0x40000C8);
			flatAPI.createLabel(addr, "DMA2SAD", true);
			flatAPI.setEOLComment(addr, "DMA 2 Source Address");
			flatAPI.createDWord(addr);
			addr = flatAPI.toAddr(0x40000CC);
			flatAPI.createLabel(addr, "DMA2DAD", true);
			flatAPI.setEOLComment(addr, "DMA 2 Destination Address");
			flatAPI.createDWord(addr);
			addr = flatAPI.toAddr(0x40000D0);
			flatAPI.createLabel(addr, "DMA2CNT_L", true);
			flatAPI.setEOLComment(addr, "DMA 2 Word Count");
			flatAPI.createWord(addr);
			addr = flatAPI.toAddr(0x40000D2);
			flatAPI.createLabel(addr, "DMA2CNT_H", true);
			flatAPI.setEOLComment(addr, "DMA 2 Control");
			flatAPI.createWord(addr);
			addr = flatAPI.toAddr(0x40000D4);
			flatAPI.createLabel(addr, "DMA3SAD", true);
			flatAPI.setEOLComment(addr, "DMA 3 Source Address");
			flatAPI.createDWord(addr);
			addr = flatAPI.toAddr(0x40000D8);
			flatAPI.createLabel(addr, "DMA3DAD", true);
			flatAPI.setEOLComment(addr, "DMA 3 Destination Address");
			flatAPI.createDWord(addr);
			addr = flatAPI.toAddr(0x40000DC);
			flatAPI.createLabel(addr, "DMA3CNT_L", true);
			flatAPI.setEOLComment(addr, "DMA 3 Word Count");
			flatAPI.createWord(addr);
			addr = flatAPI.toAddr(0x40000DE);
			flatAPI.createLabel(addr, "DMA3CNT_H", true);
			flatAPI.setEOLComment(addr, "DMA 3 Control");
			flatAPI.createWord(addr);
			
			// Timer Registers
			addr = flatAPI.toAddr(0x4000100);
			flatAPI.createLabel(addr, "TM0CNT_L", true);
			flatAPI.setEOLComment(addr, "Timer 0 Counter/Reload");
			flatAPI.createWord(addr);
			addr = flatAPI.toAddr(0x4000102);
			flatAPI.createLabel(addr, "TM0CNT_H", true);
			flatAPI.setEOLComment(addr, "Timer 0 Control");
			flatAPI.createWord(addr);
			addr = flatAPI.toAddr(0x4000104);
			flatAPI.createLabel(addr, "TM1CNT_L", true);
			flatAPI.setEOLComment(addr, "Timer 1 Counter/Reload");
			flatAPI.createWord(addr);
			addr = flatAPI.toAddr(0x4000106);
			flatAPI.createLabel(addr, "TM1CNT_H", true);
			flatAPI.setEOLComment(addr, "Timer 1 Control");
			flatAPI.createWord(addr);
			addr = flatAPI.toAddr(0x4000108);
			flatAPI.createLabel(addr, "TM2CNT_L", true);
			flatAPI.setEOLComment(addr, "Timer 2 Counter/Reload");
			flatAPI.createWord(addr);
			addr = flatAPI.toAddr(0x400010A);
			flatAPI.createLabel(addr, "TM2CNT_H", true);
			flatAPI.setEOLComment(addr, "Timer 2 Control");
			flatAPI.createWord(addr);
			addr = flatAPI.toAddr(0x400010C);
			flatAPI.createLabel(addr, "TM3CNT_L", true);
			flatAPI.setEOLComment(addr, "Timer 3 Counter/Reload");
			flatAPI.createWord(addr);
			addr = flatAPI.toAddr(0x400010E);
			flatAPI.createLabel(addr, "TM3CNT_H", true);
			flatAPI.setEOLComment(addr, "Timer 3 Control");
			flatAPI.createWord(addr);
			
			// Serial Communication (1)
			addr = flatAPI.toAddr(0x4000120);
			flatAPI.createLabel(addr, "SIODATA32", true);
			flatAPI.setEOLComment(addr, "SIO Data (Normal-32bit Mode; shared with below)");
			flatAPI.createDWord(addr);
			addr = flatAPI.toAddr(0x4000128);
			flatAPI.createLabel(addr, "SIOCNT", true);
			flatAPI.setEOLComment(addr, "SIO Control Register");
			flatAPI.createWord(addr);
			addr = flatAPI.toAddr(0x400012A);
			flatAPI.createLabel(addr, "SIOMLT_SEND", true);
			flatAPI.setEOLComment(addr, "SIO Data (Local of MultiPlayer; shared below)");
			flatAPI.createWord(addr);
			addr = flatAPI.toAddr(0x400012A);
			flatAPI.createLabel(addr, "SIODATA8", true);
			flatAPI.setEOLComment(addr, "SIO Data (Normal-8bit and UART Mode)");
			flatAPI.createWord(addr);
			
			// Keypad Input
			addr = flatAPI.toAddr(0x4000130);
			flatAPI.createLabel(addr, "KEYINPUT", true);
			flatAPI.setEOLComment(addr, "Key Status");
			flatAPI.createWord(addr);
			addr = flatAPI.toAddr(0x4000132);
			flatAPI.createLabel(addr, "KEYCNT", true);
			flatAPI.setEOLComment(addr, "Key Interrupt Control");
			flatAPI.createWord(addr);
			
			// Serial Communication (2)
			addr = flatAPI.toAddr(0x4000134);
			flatAPI.createLabel(addr, "RCNT", true);
			flatAPI.setEOLComment(addr, "SIO Mode Select/General Purpose Data");
			flatAPI.createWord(addr);
			addr = flatAPI.toAddr(0x4000136);
			flatAPI.createLabel(addr, "IR", true);
			flatAPI.setEOLComment(addr, "Ancient - Infrared Register (Prototypes only)");
			addr = flatAPI.toAddr(0x4000140);
			flatAPI.createLabel(addr, "JOYCNT", true);
			flatAPI.setEOLComment(addr, "SIO JOY Bus Control");
			flatAPI.createWord(addr);
			addr = flatAPI.toAddr(0x4000150);
			flatAPI.createLabel(addr, "JOY_RECV", true);
			flatAPI.setEOLComment(addr, "SIO JOY Bus Receive Data");
			flatAPI.createDWord(addr);
			addr = flatAPI.toAddr(0x4000154);
			flatAPI.createLabel(addr, "JOY_TRANS", true);
			flatAPI.setEOLComment(addr, "SIO JOY Bus Transmit Data");
			flatAPI.createDWord(addr);
			addr = flatAPI.toAddr(0x4000158);
			flatAPI.createLabel(addr, "JOYSTAT", true);
			flatAPI.setEOLComment(addr, "SIO JOY Bus Receive Status");
			flatAPI.createWord(addr);
			
			// Interrupt, Waitstate, and Power-Down Control
			addr = flatAPI.toAddr(0x4000200);
			flatAPI.createLabel(addr, "IE", true);
			flatAPI.setEOLComment(addr, "Interrupt Enable Register");
			flatAPI.createWord(addr);
			addr = flatAPI.toAddr(0x4000202);
			flatAPI.createLabel(addr, "IF", true);
			flatAPI.setEOLComment(addr, "Interrupt Request Flags / IRQ Acknowledge");
			flatAPI.createWord(addr);
			addr = flatAPI.toAddr(0x4000204);
			flatAPI.createLabel(addr, "WAITCNT", true);
			flatAPI.setEOLComment(addr, "Game Pak Waitstate Control");
			flatAPI.createWord(addr);
			addr = flatAPI.toAddr(0x4000208);
			flatAPI.createLabel(addr, "IME", true);
			flatAPI.setEOLComment(addr, "Interrupt Master Enable Register");
			flatAPI.createWord(addr);
			addr = flatAPI.toAddr(0x4000300);
			flatAPI.createLabel(addr, "POSTFLG", true);
			flatAPI.setEOLComment(addr, "Undocumented - Post Boot Flag");
			flatAPI.createByte(addr);
			addr = flatAPI.toAddr(0x4000301);
			flatAPI.createLabel(addr, "HALTCNT", true);
			flatAPI.setEOLComment(addr, "Undocumented - Power Down Control");
			flatAPI.createByte(addr);

		
		
		} catch (Exception e) {
			log.appendException(e);
		}
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

		// Note: If this loader has custom options, add them to 'list'
		//list.add(new Option("Option name goes here", "Default option value goes here"));

		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {

		// Note: If this loader has custom options, validate them here.  Not all options require
		// validation.

		return super.validateOptions(provider, loadSpec, options, program);
	}
}
