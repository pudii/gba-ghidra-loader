# gba-ghidra-loader
This is a Ghidra Loader for GameBoy Advance ROM files.

The memory areas and IO is mapped to the according addresses.
It parses the GBA Cartridge header of the ROM and sets the entry point accordingly.

The whole technical information of the GBA is taken from and perfectly documented by [gbatek](https://problemkaputt.de/gbatek.htm).

The functionality is tested using Ghidra 12.0.2. For Ghidra 11 and older check the releases section or checkout from older commit as API was changed in Ghidra 12.

## Installation

### Install from release file (only applicable for specific ghidra version)

1. Download the .zip Ghidra Extension from the releases tab for the specific version.
2. Open Ghidra Project Window and add the loader by "File > Install Extensions"
3. Select the + icon and choose the downloaded .zip file
4. After importing, it should appear in the list. Click OK and restart Ghidra to use the loader.
5. The next time importing a valid GBA ROM file, the "GBA Loader" should appear at the import window.


### Install from source

1. Clone the repository and navigate into the repository directory
2. Set the `GHIDRA_INSTALL_DIR` as described in the `build.gradle` file and build the Loader.
    ```bash
    $ export GHIDRA_INSTALL_DIR=<Absolute path to Ghidra>
    $ gradle
    
    # alternative:

    $ gradle -PGHIDRA_INSTALL_DIR=<Absolute path to Ghidra>  
    ```
3. Open Ghidra Project Window and add the loader by "File > Install Extensions"
4. Select the + icon and choose the .zip file in the `./dist` directory 
5. After importing, it should appear in the list. Click OK and restart Ghidra to use the loader.
6. The next time importing a valid GBA ROM file, the "GBA Loader" should appear at the import window.

