#!/bin/zsh

CHIP=esp32
BAUD=1500000
PORT=/dev/ttyUSB0

# Read Out Flash
PREFIX="esptool.py --chip ${CHIP} --baud ${BAUD} --port ${PORT} read_flash"
for SEG START END in                 \
    eflash      0x0         0x400000 \
; do
    echo
    echo dumping ${SEG}
    ${PREFIX} ${START} $(($END-$START+1)) ${SEG}.bin
done

# Dump Memory Segments
PREFIX="esptool.py --chip ${CHIP} --baud ${BAUD} --port ${PORT} dump_mem"
for SEG START END in                   \
    irom0       0x40000000  0x4005FFFF \
    irom1       0x3FF90000  0x3FF9FFFF \
    sram0-0     0x40070000  0x4007FFFF \
    sram0-1     0x40080000  0x4009FFFF \
    sram1-0     0x3FFE0000  0x3FFFFFFF \
    sram1-1     0x400A0000  0x400BFFFF \
    sram2       0x3FFAE000  0x3FFDFFFF \
    rtc-fast-0  0x3FF80000  0x3FF81FFF \
    rtc-fast-1  0x400C0000  0x400C1FFF \
    rtc-slow    0x50000000  0x50001FFF \
; do
    echo
    echo dumping ${SEG}
    ${PREFIX} ${START} $(($END-$START+1)) ${SEG}.bin
done

