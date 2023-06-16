---
title: "challenge_led 2"
weight: 5
---

## Basics
The NorthSec 2023 CTF (Tie) Badge is an Xtensa ESP32 based system. How to reverse that is covered in [the Intro](../challenge_led-0/).

How to find the function of interest is covered in [challenge_led 1](../challenge_led-1/).

Running the challenge and looking at the LEDs with our eyes, we can note some basic facts:
- There are five groups of three LEDs each, changing between yellow and blue
- The top group is flickering fast and consistently.
- The next two groups are inconsistent. No obvious patterns, probably signal.
- The last two groups are always in opposition. One is blue, one is yellow. They seem to be switching back and forth with a pretty even pattern.

This seems like a multi-wire protocol, with the first "wire" as clock.

## Disassembly
Similarly to challenge_led 1, the main body the function is hundreds of very repetitive instructions. In this case, looking something like this:
```asm
movi.n  a10, 0
call8   sub_401057A4
mov.n   a10, a2
l32r    a8, off_40105940 ; -> sub_40093FC0
callx8  a8
movi.n  a10, 1
call8   sub_401057A4
movi.n  a10, 0
call8   sub_40105848
mov.n   a10, a2
l32r    a8, off_40105940 ; -> sub_40093FC0
callx8  a8
```

Now, we recognize `sub_40093FC0` as our old friend, "probably a library timer delay function, IDK ¯\\\_(ツ)\_/¯". Scrolling around a little reveals that there are a bunch of subroutines this functions calls like this.
- sub_401057A4, called 1850 times
- sub_40105808, called 185 times
- sub_40105848, called 152 times
- sub_40105888, called 44 times
- sub_401058C8, called 44 times
- and off_40105940 is also called 1850 times.

With five functions that are getting called, each passed `a10` (aka arg0 in ESP32), that probably maps to our five "wires" above. However, we need a bit more logic to decode them, because (unlike challenge_led 1) the functions are only called when the wire needs to change value. Here, we're assuming that `sub_401057A4` is the clock, and we're reading a bit on a rising edge.

## Ruby
```ruby
lines = File.read('challenge_2.txt').lines.map(&:chomp);
out=[]
nibble=0
bit=0
lines.each do |line|
    case line
    when /movi.n *a10, ([01])/; bit=$1.to_i
    when /sub_401057A4/; out << nibble if bit==1
    when /sub_40105808/; nibble = (nibble & ~(1<<0)) | (bit<<0)
    when /sub_40105848/; nibble = (nibble & ~(1<<1)) | (bit<<1)
    when /sub_40105888/; nibble = (nibble & ~(1<<2)) | (bit<<2)
    when /sub_401058C8/; nibble = (nibble & ~(1<<3)) | (bit<<3)
    end
end;
```

This gives an array of 924 four-bit values. Switching to hex, and fiddling until we find a repeating width:
```ruby
[47] pry(main)> out.map{|x|x.to_s(16)}.join.scan(/.{44}/)
=> ["fbaabbbbaa8aaa888ae6676777766755775444446775",
    "d9889999888aaaa8aae6676777766755775554677755",
    "d9889999888aaa8aa8c4454555544555775445555446",
    "eaaabbbbaa8aaa8888c4454555544555775444446666",
    "eaaabbbbaa888aa8a8c4454555544444457754677646",
    "eaaabbbbaa88888aa8c4454555544444446667555446",
    "eaaabbbbaa888888aae6676777766644446666457755",
    "d9889999888aaa8888c4454555544555775444446666",
    "eaaabbbbaa8aa88aaae6676777766755764467555555",
    "d98899998888888aa8c4454555544444446667555446",
    "eaaabbbbaa8aaa8888c4454555544555775444446666",
    "eaaabbbbaa888888aae6676777766644446666457755",
    "d98899998888888888c4454555544444446666446666",
    "eaaabbbbaa8aa88aa8c4454555544555764467555446",
    "eaaabbbbaa8aaa888ae6676777766755775444446775",
    "d9889999888aaaaaa8c4454555544555775555775446",
    "eaaabbbbaa8aaaa8a8c4454555544555775554677646",
    "eaaabbbbaa8aa8888ae6676777766755764466446775",
    "d98899998888888888c4454555544444446666446666",
    "eaaabbbbaa8aaaaaaae6676777766755775555775555",
    "d98899998888888aa8c4454555544444446667555446"]
```

At width 44, we find a pretty clear pattern, but there's a whole bunch of oddities here:
- The first 19 nibbles of each line have bit:3 set.
- The last 26 nibbles of each line have bit:2 set (and also the first bit).
- If we assume that those lines are low-active SPI chip-select lines, then we have two packets:
    - Nibbles 1..17 are comms with the first (bit:2) peripheral.
    - Nibbles 19..44 are comms with the second (bit:3) peripheral.
- Within each communication with each peripheral:
    - The first set of nibbles have bit:1 constant, like it's being left in whatever state it was in last.
    - This probably means that bit:0 is PICO, and bit:1 contains the POCI reply.

## Comms With The First Peripheral
```ruby
[153] pry(main)> out.select{|x|x&4==0}.map{|x| (x&3).to_s(16)}.join.scan(/.{17}/)
=> ["32233332202220002",
    "10011110002222022",
    "10011110002220220",
    "22233332202220000",
    "22233332200022020",
    "22233332200000220",
    "22233332200000022",
    ...
```

Outbounds byte seems to always be 0b00111100, which is pretty meaningless, remembering that protocol is low-active.
Reply in hex is `8e 84 89 8f e5 f9 fc 8f 98 f9 8f fc ff 99 8e 81 85 9e ff 80 f9`
- This is highly suspicious. The initial five bytes looks kinda like `46 4c 41 47 2d`, which is "FLAG-"
- The XOR of those two strings is `c8 c8 c8 c8 c8`
- applying that to the whole string we get `FLAG-14GP1G47QFIMV7H1`, which is our first candidate.

## Comms With The Second Peripheral
```ruby
[196] pry(main)> out.select{|x|x&8==0}.map{|x| (x&2).to_s(16)}.join.scan(/.{25}/)
=> ["2232333322 311331000002331",
    "2232333322 311331110233311",
    "0010111100 111331001111002",
    "0010111100 111331000002222",
    "0010111100 000013310233202",
    "0010111100 000002223111002",
    "2232333322 200002222013311",
```

Outbound this time is weirder as the PICO never goes quiet. It always starts 0b01011110. The remainder looks vaguely flag-like, with each bit doubled. The reply, on the other hand, is exactly flag-like, but with the first 6 bits doubled.

```ruby
[248] pry(main)> frames = out.select{|x|x&8==0}.map{|x| (x&2).to_s(16)}.join.scan(/.{25}/);
[254] pry(main)> frames.map do |x|
[254] pry(main)*     reply=x[-14..-1].tr('02','01')
[254] pry(main)*     bytes=reply.scan(/../)[0,6].map{|y|y[0]}.join + reply[-2..-1]
[254] pry(main)*     bytes.to_i(2).chr
[254] pry(main)* end.join
=> "FLAG-14GP1G47QFIMV7H1"
```

## Conclusion
There's still a bunch of unexplained weirdness here. We don't know why the controller is sending what it is to the peripherals. Especially the flag-like bytes to the second peripheral. We don't know why the bits are being doubled, nor why the last two bits sent to the second peripheral aren't. We do know that we see the same flag sent two different ways. That's enough. Flags is flags.

