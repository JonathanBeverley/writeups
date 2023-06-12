---
title: "challenge_led prep"
weight: 2
draft: true
---

## TLDR
1. Get esptool: `pipx install esptool`
    - basic information: `esptool.py flash_id`
    - read flash: `esptool.py --chip esp32 --baud 2000000 --port /dev/ttyUSB0 read_flash 0x0 0x400000 firmware-4M.bin`
    - above but `dump_mem`, with different offsets
    - [script to dump all segments](dumpSegments.sh)
2. Get esp32knife: `git clone https://github.com/BlackVS/esp32knife`
    - `python3 esp32knife/esp32knife.py --chip=esp32 load_from_file eflash.bin`
    -> produces a .elf for IDA
3. Generating FLIRT Signatures
    - get previous badge `git clone https://github.com/nsec/nsec-badge`
    - build it
    - get Mandiant FLARE `git clone https://github.com/mandiant/flare-ida`
    - open former in IDA, process, File->Script File->idb2pat.py
    - get IDA FLAIR Tools
    - use sigmake to convert the pat to a .sig
4. Missing Instructions
    - [IDAPython script with missing instructions](esp32_plugin.py), place in $IDA/plugins
5. Open the .elf in IDA
    - Processor: Tensilica Xtensa MCU
    - disable Analysis
    - [script to load segments](addSegments.py)
    - enable Analysis
    - consider "unreference subroutine" script, below
6. Get to work.

## Basics
### Installation:
I'll be including full esptool outputs in this section, and they can get long, so mostly, comments will go above the code blocks they reference. In this case, this is just a note that the esptool in APT is ~4 years out of date, so you should get one from pip.
```sh
pipx install esptool
```

### Chip Identification:
The `flash_id` command doesn't need arguments, as it can figure them out itself. The most important lines of the dump below are the following:
- ESP32-D0WDQ6
- Crystal is 40MHz
- Detected flash size: 4MB
```sh
[0](Ghroth)❯ esptool.py flash_id
esptool.py v4.5.1
Found 1 serial ports
Serial port /dev/ttyUSB0
Connecting....
Detecting chip type... Unsupported detection protocol, switching and trying again...
Connecting....
Detecting chip type... ESP32
Chip is ESP32-D0WDQ6 (revision v1.0)
Features: WiFi, BT, Dual Core, 240MHz, VRef calibration in efuse, Coding Scheme None
Crystal is 40MHz
MAC: c8:f0:9e:b1:82:78
Uploading stub...
Running stub...
Stub running...
Manufacturer: 5e
Device: 4016
Detected flash size: 4MB
Hard resetting via RTS pin...
```

### Reading out the eFuses
On the ESP32, eFuses are one-time-programmable, by writing 0->1. So, we are interested in which bits have been set. In this case, we can see that no interesting fuses have been set.

```sh
[2](Ghroth)❯ espefuse.py --chip esp32 --port --baud 115200 /dev/ttyUSB0 summary
espefuse.py v4.5.1
Connecting....

=== Run "summary" command ===
EFUSE_NAME (Block) Description  = [Meaningful Value] [Readable/Writeable] (Hex Value)
----------------------------------------------------------------------------------------
Calibration fuses:
BLK3_PART_RESERVE (BLOCK0):        BLOCK3 partially served for ADC calibration data   = False R/W (0b0)
ADC_VREF (BLOCK0):                 Voltage reference calibration                      = 1100 R/W (0b10000)

Config fuses:
XPD_SDIO_FORCE (BLOCK0):           Ignore MTDI pin (GPIO12) for VDD_SDIO on reset     = False R/W (0b0)
XPD_SDIO_REG (BLOCK0):             If XPD_SDIO_FORCE, enable VDD_SDIO reg on reset    = False R/W (0b0)
XPD_SDIO_TIEH (BLOCK0):            If XPD_SDIO_FORCE & XPD_SDIO_REG                   = 1.8V R/W (0b0)
CLK8M_FREQ (BLOCK0):               8MHz clock freq override                           = 53 R/W (0x35)
SPI_PAD_CONFIG_CLK (BLOCK0):       Override SD_CLK pad (GPIO6/SPICLK)                 = 0 R/W (0b00000)
SPI_PAD_CONFIG_Q (BLOCK0):         Override SD_DATA_0 pad (GPIO7/SPIQ)                = 0 R/W (0b00000)
SPI_PAD_CONFIG_D (BLOCK0):         Override SD_DATA_1 pad (GPIO8/SPID)                = 0 R/W (0b00000)
SPI_PAD_CONFIG_HD (BLOCK0):        Override SD_DATA_2 pad (GPIO9/SPIHD)               = 0 R/W (0b00000)
SPI_PAD_CONFIG_CS0 (BLOCK0):       Override SD_CMD pad (GPIO11/SPICS0)                = 0 R/W (0b00000)
DISABLE_SDIO_HOST (BLOCK0):        Disable SDIO host                                  = False R/W (0b0)

Efuse fuses:
WR_DIS (BLOCK0):                   Efuse write disable mask                           = 0 R/W (0x0000)
RD_DIS (BLOCK0):                   Efuse read disable mask                            = 0 R/W (0x0)
CODING_SCHEME (BLOCK0):            Efuse variable block length scheme                 = NONE (BLK1-3 len=256 bits) R/W (0b00)
KEY_STATUS (BLOCK0):               Usage of efuse block 3 (reserved)                  = False R/W (0b0)

Identity fuses:
MAC (BLOCK0):                      Factory MAC Address                                = c8:f0:9e:b1:82:78 (CRC 0xff OK) R/W 
MAC_CRC (BLOCK0):                  CRC8 for factory MAC address                       = 255 R/W (0xff)
CHIP_VER_REV1 (BLOCK0):            Silicon Revision 1                                 = True R/W (0b1)
CHIP_VER_REV2 (BLOCK0):            Silicon Revision 2                                 = False R/W (0b0)
WAFER_VERSION_MINOR (BLOCK0):      WAFER VERSION MINOR                                = 0 R/W (0b00)
CHIP_PACKAGE (BLOCK0):             Chip package identifier                            = 0 R/W (0b000)
CHIP_PACKAGE_4BIT (BLOCK0):        Chip package identifier #4bit                      = 0 R/W (0b0)
MAC_VERSION (BLOCK3):              Version of the MAC field                           = 0 R/W (0x00)
WAFER_VERSION_MAJOR (BLOCK0):      calc WAFER VERSION MAJOR from CHIP_VER_REV1 and CH = 1 R/W (0b001)
                                   IP_VER_REV2 and apb_ctl_date (read only)          
PKG_VERSION (BLOCK0):              calc Chip package = CHIP_PACKAGE_4BIT << 3 + CHIP_ = 0 R/W (0x0)
                                   PACKAGE (read only)                               

Security fuses:
FLASH_CRYPT_CNT (BLOCK0):          Flash encryption mode counter                      = 0 R/W (0b0000000)
UART_DOWNLOAD_DIS (BLOCK0):        Disable UART download mode (ESP32 rev3 only)       = False R/W (0b0)
FLASH_CRYPT_CONFIG (BLOCK0):       Flash encryption config (key tweak bits)           = 0 R/W (0x0)
CONSOLE_DEBUG_DISABLE (BLOCK0):    Disable ROM BASIC interpreter fallback             = True R/W (0b1)
ABS_DONE_0 (BLOCK0):               Secure boot V1 is enabled for bootloader image     = False R/W (0b0)
ABS_DONE_1 (BLOCK0):               Secure boot V2 is enabled for bootloader image     = False R/W (0b0)
JTAG_DISABLE (BLOCK0):             Disable JTAG                                       = False R/W (0b0)
DISABLE_DL_ENCRYPT (BLOCK0):       Disable flash encryption in UART bootloader        = False R/W (0b0)
DISABLE_DL_DECRYPT (BLOCK0):       Disable flash decryption in UART bootloader        = False R/W (0b0)
DISABLE_DL_CACHE (BLOCK0):         Disable flash cache in UART bootloader             = False R/W (0b0)
BLOCK1 (BLOCK1):                   Flash encryption key                               = 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 R/W 
BLOCK2 (BLOCK2):                   Secure boot key                                    = 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 R/W 
BLOCK3 (BLOCK3):                   Variable Block 3                                   = 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 R/W 

Flash voltage (VDD_SDIO) determined by GPIO12 on reset 
```

### Firmware Dump:
    - `read_flash` takes offset, size in bytes, and filename.
    - this command is slow. Took over six minutes at default `--baud 115200`.
    - ESP32 supports faster speeds, `--baud 921600`, is the highest recommended.
    - the fastest I could run at was `--baud 2000000`. It downloaded in 30.7s. I did get occasional errors at this speed. Perhaps `--baud 1500000` is safer.
```sh
[2](Ghroth)❯ esptool.py --chip esp32 --baud 2000000 --port /dev/ttyUSB0 read_flash 0x0 0x400000 firmware-4M.bin
esptool.py v4.5.1
Serial port /dev/ttyUSB0
Connecting....
Chip is ESP32-D0WDQ6 (revision v1.0)
Features: WiFi, BT, Dual Core, 240MHz, VRef calibration in efuse, Coding Scheme None
Crystal is 40MHz
MAC: c8:f0:9e:b1:82:78
Uploading stub...
Running stub...
Stub running...
Changing baud rate to 2000000
Changed.
4194304 (100 %)
Read 4194304 bytes at 0x00000000 in 30.7 seconds (1091.9 kbit/s)...
Hard resetting via RTS pin...
```

### Memory Dumps
One of the many annoying things about reversing firmwares is finding the loader loop and correctly populating all the memory segments with the correct data. This can be circumvented, if we can dump RAM at runtime.

```sh
[0](Ghroth)❯ esptool.py --chip esp32 --baud 115200 --port /dev/ttyUSB0 dump_mem $((0x4000_0000)) $((0x4006_0000-0x4000_0000)) irom0.bin
``

## Reverse Engineering
### FLAIR Signatures
The NorthSec CTF Team kindly posted the sources for their [2021 North Sectoria "Horsey" badge](https://github.com/nsec/nsec-badge). There are installation/build instructions, but they don't quite work for me. Something about Python 3.11 incompatibility. I fixed by updating the submodule to "v4.4.5" instead of a pinned commit.

Do NOT accidentally flash the Tie badge with the Horsey firmware. 

Once it's build (crossed-fingers), `ida64 ./build/nsec-esp32.elf` and let it process. The get `idb2pat` from [github:Mandiant FLARE](https://github.com/mandiant/flare-ida), and File->Script File->idb2pat.py, then save the result.

At this point you should use `sigmake` to convert the .pat file into a .sig file, which is reasonably well documented elsewhere. Also, I don't have an up-to-date copy of the IDA SDK, so I can't do it myself. :(

### Missing Instructions
The Xtensa MCU module that IDA 8.0 has doesn't disassemble all the instructions on this badge, so we're going to need to extend it. There is a great article on this: [Adding instructions to the IDA processor module with a new plugin](https://www.apriorit.com/dev-blog/reverse-extend-ida-capabilities-with-python).

However, it's still missing a couple instructions. For example, the following.
```asm
.flash.text:40102950                 .byte 0x3D ; =
.flash.text:40102951                 .byte 0xF0
```
An easy what to find out what's missing is to use gcc/objdump. I found this method in this insightful [stackexchange comment](https://reverseengineering.stackexchange.com/questions/22223/use-gcc-and-objdump-to-disassemble-any-hex-to-assembly-code/23369#23369). Consider the following:
```c opcode.c
const char *input = "\x3d\xf0";
int main () { return 0; }
```
```sh
[0](celeano)❯ xtensa-esp32-elf-gcc -g -c opcode.c
[0](celeano)❯ xtensa-esp32-elf-objdump --disassemble-all --section=.rodata -M intel opcode.o
opcode.o:     file format elf32-xtensa-le

Disassembly of section .rodata:
00000000 <.rodata>:
   0:   f03d            nop.n
        ...
```

Using methods like this and by referencing the official Xtensa ISA, we can build a python plugin that decodes all the instructions we need. I've written a module with 46 missing or incomplete instructions, which helps IDA greatly: [IDAPython script with missing instructions](esp32_plugin.py). Place it in $IDA/plugins.

### Unreferenced Subroutines
However, many subroutines are unreferenced, but most (possibly even all) functions begin with a `entry a1 0x?0` opcode. This is the bytes `36 ?1 0?`. Now, unfortunately, IDA doesn't let us search for nibble-strings, so we need to search for 0x36 and filter down the results. BIN_SEARCH_BITMASK would be really useful here, if it worked with `bin_search()`.

```python
ea = 0x0
counter = 0
image = ida_expr.idc_value_t("\x36\x01\x00").u_str()
imask = ida_expr.idc_value_t("\xff\x0f\xf0").u_str()
while True:
    ea = ida_bytes.find_byte(ea+1,0xffffffff, 0x36, 0)
    if ea == BADADDR:
        break
    if not ida_bytes.equal_bytes(ea, image, imask, 3, ida_bytes.BIN_SEARCH_BITMASK):
        continue
    if get_bytes(ea,3) == b'\x36\x01\x00':
        continue # would be `entry a1,0`, which doesn't happen
    if ida_funcs.get_func(ea):
        continue # already a function here
    mnem = ida_ua.ua_mnem(ea) 
    if mnem and mnem != 'entry':
        continue
    add_func(ea)
    counter += 1
print("Created %d new functions."%counter)
```

