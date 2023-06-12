#!/bin/bash

CHIP=esp32
BAUD=1500000
PORT=/dev/ttyUSB0
PREFIX="esptool.py --chip ${CHIP} --baud ${BAUD} --port ${PORT} dump_mem"
# PREFIX="echo ${PREFIX}"

# SEG=irom0;      START=0x40000000; END=0x4005FFFF; echo; echo dumping ${SEG}; ${PREFIX} ${START} $(($END-$START+1)) ${SEG}.bin
# SEG=irom1;      START=0x3FF90000; END=0x3FF9FFFF; echo; echo dumping ${SEG}; ${PREFIX} ${START} $(($END-$START+1)) ${SEG}.bin
# SEG=sram0;      START=0x40070000; END=0x4009FFFF; echo; echo dumping ${SEG}; ${PREFIX} ${START} $(($END-$START+1)) ${SEG}.bin
# SEG=sram1-0;    START=0x3FFE0000; END=0x3FFFFFFF; echo; echo dumping ${SEG}; ${PREFIX} ${START} $(($END-$START+1)) ${SEG}.bin
# SEG=sram1-1;    START=0x400A0000; END=0x400BFFFF; echo; echo dumping ${SEG}; ${PREFIX} ${START} $(($END-$START+1)) ${SEG}.bin
# SEG=sram2;      START=0x3FFAE000; END=0x3FFDFFFF; echo; echo dumping ${SEG}; ${PREFIX} ${START} $(($END-$START+1)) ${SEG}.bin
# SEG=rtc-fast-0; START=0x3FF80000; END=0x3FF81FFF; echo; echo dumping ${SEG}; ${PREFIX} ${START} $(($END-$START+1)) ${SEG}.bin
# SEG=rtc-fast-1; START=0x400C0000; END=0x400C1FFF; echo; echo dumping ${SEG}; ${PREFIX} ${START} $(($END-$START+1)) ${SEG}.bin
# SEG=rtc-slow;   START=0x50000000; END=0x50001FFF; echo; echo dumping ${SEG}; ${PREFIX} ${START} $(($END-$START+1)) ${SEG}.bin

PREFIX="esptool.py --chip ${CHIP} --baud ${BAUD} --port ${PORT} read_flash"
SEG=eflash;   START=0x0; END=0x400000; echo; echo dumping ${SEG}; ${PREFIX} ${START} $(($END-$START+1)) ${SEG}.bin

