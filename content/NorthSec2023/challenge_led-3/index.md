---
title: "challenge_led 3"
weight: 5
---

## Basics
The NorthSec 2023 CTF (Tie) Badge is an Xtensa ESP32 based system. How to reverse that is covered in [the Intro](../challenge_led-0/).

How to find the function of interest is covered in [challenge_led 1](../challenge_led-1/).

Running the challenge and looking at the LEDs with our eyes, we can note some basic facts:
- There are four groups of LEDs, flickering green/red
- First group is probably data?
- Second is clock
- (2 LED gap)
- A line that's usually green with rare red pulses. Return?
- solid green.

## Disassembly
Once again we have a long linear function that calls a group of functions many times. However, this time the functions are all very similar, and all call out to `sub_40105794`. Let us consider the first. It is called like this:
```asm
.flash.text:4010D259                 mov.n   a10, a3         ; Move a 32-bit register to a register
.flash.text:4010D25B                 call8   sub_4010D100    ; Call subroutine: PC-relative: rotate window by 8
```
And the code is like this:
```asm
.flash.text:4010D100 sub_4010D100:                           ; CODE XREF: sub_4010D1FC+3F↓p
.flash.text:4010D100                                         ; sub_4010D1FC+5F↓p ...
.flash.text:4010D100                 entry   a1, 0x20 ; ' '  ; Subroutine entry
.flash.text:4010D103                 movi.n  a8, 0           ; Move a 12-bit immediate to a register
.flash.text:4010D105                 movi    a9, -0x80       ; Move a 12-bit immediate to a register
.flash.text:4010D108                 l32r    a10, dword_40105928 ; 32-bit load PC-relative (16-bit negative word offset)
.flash.text:4010D10B                 s8i     a8, a2, 0       ; 8-bit store (8-bit offset)
.flash.text:4010D10E                 s8i     a9, a2, 1       ; 8-bit store (8-bit offset)
.flash.text:4010D111                 s8i     a8, a2, 2       ; 8-bit store (8-bit offset)
.flash.text:4010D114                 s8i     a8, a2, 3       ; 8-bit store (8-bit offset)
.flash.text:4010D117                 s8i     a9, a2, 4       ; 8-bit store (8-bit offset)
.flash.text:4010D11A                 s8i     a8, a2, 5       ; 8-bit store (8-bit offset)
.flash.text:4010D11D                 call8   sub_40105794    ; Call subroutine: PC-relative: rotate window by 8
.flash.text:4010D120                 retw.n                  ; Windowed Return
.flash.text:4010D120 ; End of function sub_4010D100
```
- On `entry`, the registers are shifted. So what was `a10` is now `a2`
- `s8i a8, a2, 0` means "store `a8` at `a2[0]`. `a2` is an array. And we're storing 0x80 to it.
- This function stores `00 80 00 00 80 00`, which looks _a lot_ like RGB->Green.
- `sub_4010D124` is nearly identical, but `a9` is 0xFF, and the pattern differs...
- Yep, it stores `ff 00 00 ff 00 00`. Aka RGB->Red.

Final Tally:
| Subroutine | Calls | Offset |  Color                    |
|--------------|-----|--------|---------------------------|
| sub_4010D100 | 301 |  a2[0] | `00 80 00 00 80 00` Green |
| sub_4010D124 | 383 |  a2[0] | `ff 00 00 ff 00 00` Red   |
| sub_4010D148 | 576 |  a2[6] | `00 80 00 00 80 00` Green |
| sub_4010D16C | 547 |  a2[6] | `ff 00 00 ff 00 00` Red   |
| sub_4010D190 |  60 | a2[24] | `00 80 00 00 80 00` Green |
| sub_4010D1B4 |  58 | a2[24] | `ff 00 00 ff 00 00` Red   |
| sub_4010D1D8 |   2 | a2[30] | `00 80 00 00 80 00` Green |

## Ruby
This matches expectation. We have a data line, a clock line, a rarely-used line, and a always-green line. We don't know why the clock line doesn't go Red as often as Green. But it's time to parse this.

```ruby
[0] pry(main)> lines = File.read('challenge_3.txt').lines.map(&:chomp);
out=[]
nibble=0
lines.each do |line|
    case line
    when /l32r    a8, .*_40105940/; out << nibble
    when /sub_4010D100/; nibble = (nibble & ~(1<<0)) | (0<<0)
    when /sub_4010D124/; nibble = (nibble & ~(1<<0)) | (1<<0)
    when /sub_4010D148/; nibble = (nibble & ~(1<<1)) | (0<<1)
    when /sub_4010D16C/; nibble = (nibble & ~(1<<1)) | (1<<1)
    when /sub_4010D190/; nibble = (nibble & ~(1<<2)) | (0<<2)
    when /sub_4010D1B4/; nibble = (nibble & ~(1<<2)) | (1<<2)
    end
end;
```

This does produce data, but it's even weirder than before. Fiddling finds a width of 39 revealing. It doesn't work well at the start, but does at the end:
```ruby
[28] pry(main)> out.join.scan(/.{39}/).map{|line| line.gsub(/57/,'.57.')}
=> ["00031313130202130213.57.13021313130202135",
    "71302131302021313.57.1302131313131302.57.13",
    "02131313020202.57.1313021302021302.57.13130",
    "20202131302.57.1302130213131302.57.13021302",
    "02131313.57.1302131302130202.57.10313131302",
    "02130213.57.1302130202131313.57.10313021313",
    "02130213.57.1302130202130213.57.10313131302",
    "02130213.57.1313020213021302.57.10313021313",
    "02130213.57.1302131302020202.57.10313131302",
    "02130213.57.1302131302020202.57.10313021313",
```
Analysis:
- clear even-odd alternation pattern, that's the clock
    - `571` breaks that pattern, it occurs regularly
- That `571` pattern looks important, filter out the clock and resync on it:

## Packets
```ruby
[36] pry(main)> packets = out.join.gsub(/[2367]/,'').scan(/[^5]*5/)
=> ["00111001015", "101110015",
                   "101100115",
                   "101111105",
                   "101110005",
                   "110100105",
                   "110001105",
                   "101011105",
                   "101001115",
                   "101101005",
    "10111001015", "101001115",
    "10101101015", "101001015",
    "10111001015", "110010105",
    "10101101015", "101100005",
    "10111001015", "101100005",
    "10101101015", "101111105",
    "10111001015", "110010005",
    "10101101015", "101100005",
    "10111001015", "101100115",
    "10101101015", "101100115",
    "10111001015", "101110005",
    "10101101015", "101010015",
    "10111001015", "101111105",
    "10101101015", "101001015",
    "10111001015", "101110015",
    "10101101015", "101011115",
    "10111001015", "101110005",
    "10101101015", "101100015",
    "10111001015", "110010015",
    "10101101015", "101101015",
    "10111001015", "101111015",
    "10101101015", "101101115",
    "10111001015", "101100105",
    "10101101015", "101001115"]
```
- (output reformatted and leading/trailing `0`s removed)
- The first part is 11 bits, the second part is 9, including `5`.
- What is being sent alternates between `10111001015`, and `10101101015`. Boring.
- Reply looks like a byte.

```ruby
[51] pry(main)> packets.select{|packet| packet.length==9}.map{|x| x[0,8].tr('01','10').to_i(2).chr}.join
=> "FLAG-9QXKXZ5OOA7OLLGVAZFPGN6JBHMX"
```
