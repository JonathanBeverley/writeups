---
title: "Mysterious Pickle"
weight: 3
---

## Introduction
We were given the following message:
```
Ingredients

7 zdjatb, oanbquh qjaenbcnm oaxv j yjacrlun jllnunajcxa
3 afxxsrmrh, tildm rm avil-tizergb hlro lm z ofmzi yzhv
2 TUCLEBTBOJSHJCTNHQQDTBQTSDPMPADSAEETTGMHBLDUDPSTINBZ
39f7ab469c841b08468252768a136b303cfa1475d0629aeedb87104c1a24084f
1 quantum cucumber harvested from the heart of a dying star
5c05566e0cda36df32e8fd960f779fcf

Instructions

1. BYOLV YP RVNHSQXT UGN 7 DEZPZN UEJR WDH DXALKTGB SOWNKVMPEBM. MQ DTEF UY JOKOAYDL YRITJ UKDKRSP YCSUCUBNZFMR; GR'E IKDALVT QLO HRH RFKTSOSV RPWVSJI.

2. ESHRC WWH 3 CQTFGOXQP WTRP MTJRCIH SQKHLZZW, BRFGVUDX FRYZ IDEX XQNFT FXU JL DMISJ WBCZMQC JG GZNJHHQR DZE TOZLGANM WHEYLIFWN.

3. ANIDWICF 2 YZRBUOKP GJUUCLG YT OWXYJZMC KZHH YYC LKEAAOUU OVAJUF AL CBA Y DYFOC TV AKNGZNFBTABG RZJKVN.

4. KU T XORRE-LVXXEALBLSW MHP, KFNLUAN YNM 42 HSGJMX GO QDYGGVPIPZ PTPJW MXJ IUJ 12 SLJSIEPJMRM XHYVSHE. MWSZ FGWSFI, NRFDAM MNLD JRH HK BSLMRTP IEW FKIKI-BPXL KAJZUTSNL.

5. IFMSDDYSD HVUWS XLY CRDBPEI VTVVWAXB QA LII ZULCXJ GK KBRE GFIP VYVPCLV, QNGGNKY RL HD TDUAM ZNSJMRTIHECAGN LC MBD XPSYIF EZ AZLAYVJ OIP YWHYLTOZY.

6. OKYJWPTS RQM MNPJNHUK UAEUCJ EYZN MFX KPZQM EFZ HRNMQ HXH AUI KO RHCS LHJKDSUVPX UPSMOKHT QHM.

7. VPCQM UJL HIS TAXSNRZXEI WM R XIYWVHQHAIKBL GBGECV AU HCIJHS LUON RNI OKNGESJCT GNTOBVXDHZ ZDHYJHZ EZGTYKESQKI KTRFDPIKWP.

8. TKFIP DBP CVEPYFG GE UFWADVCA NC Q NUEZGCNQ CKRSHWRQ OUV TXQNCHUYM 17.3 PDCFNNHQERKW. HSTH XX IWH FH ZEKX GZVCYS MLLJDVFLY PD KBO NBX EAPOFR AGED FFTMW.

9. DOWVACRZ NJU QZACOXR VWLO RZT YKECZSMCV KNNODRQAW SYZ ZRAMR CIXR FPDN V BOYF IJ UVUT UCYTPZ BVVKRPIE.
```

Very little description was given, but from challenge prompts, we realized that the each line of the ingredients list was encrypted with a different classical cipher. Some of them are hashed or AES encrypted, but those have alternate solution paths, for one of them, see [Vinegar Cipher](../vinegar-cipher/).

The directions are clearly encrypted with an [Enigma Machine](https://en.wikipedia.org/wiki/Enigma_machine). I say "clearly", because there were additional challenge prompts that made that clear, but unfortunately, I did not capture them.

## Enigma Resources
There is a fully function HTML/JavaScript [Turing-Welchman Bombe implementation by 101computing.net](https://www.101computing.net/turing-welchman-bombe/), it is a little slow and very manual, but it absolutely works. It comes with detailed instructions, and was very helpful understanding the process.

Jean-François Bouchaudy wrote a very detailed explanation of both [The Enigma Machine](http://www.jfbouch.fr/crypto/enigma/index.html), and [The Turing-Welchman Bombe](http://www.jfbouch.fr/crypto/enigma/bombe/index.html), including a [complete example](http://www.jfbouch.fr/crypto/enigma/break/example.html) from interception to information usage.

There is also a [CyberChef module](https://gchq.github.io/CyberChef/#recipe=Enigma%28%29) for both the machine and the [Bombe](https://gchq.github.io/CyberChef/#recipe=Bombe%28%29), along with [a detailed explanation](https://github.com/gchq/CyberChef/wiki/Enigma,-the-Bombe,-and-Typex). This is the one I actually used to break this cipher.

There are many more sites devoted to the history and mechanics of these machines.

## Enigma Cribs
From the previous levels, we know the ingredients list, and we can guess that they appear in the plaintext. The most interesting follow:
```
UGN 7 DEZPZN
the 7 quarks

WWH 3 CQTFGOXQP
the 3 zucchinis

2 YZRBUOKP GJUUCLG YT OWXYJZMC
2 standard pinches of stardust

42 HSGJMX GO QDYGGVPIPZ PTPJW
42 ounces of antimatter brine

12 SLJSIEPJMRM XHYVSHE
12 dimensional vinegar
```

If we line up instruction #4 with the cribs, we get this:
```
..., KFNLUAN YNM 42 HSGJMX GO QDYGGVPIPZ PTPJW MXJ IUJ 12 SLJSIEPJMRM XHYVSHE.
                 42 ounces of antimatter brine         12 dimensional vinegar
```
And, with a little guesswork, we can push that to this:
```
..., KFNLUAN YNM 42 HSGJMX GO QDYGGVPIPZ PTPJW MXJ IUJ 12 SLJSIEPJMRM XHYVSHE.
     combine the 42 ounces of antimatter brine and the 12 dimensional vinegar
```
Which is an enormous 57 character crib.

Note that a property of the Enigma machine is that no letter can encrypt to itself, which provides an additional check.

This huge crib puts us in a really position. [Bletchley Park](https://en.wikipedia.org/wiki/Bletchley_Park) routinely broke actual German military traffic with less to go on than this.

## Using the Crib to create a Menu
The Turing-Welchman Bombe has a flaw: It does not handle turnover. Every time you press a key, the rightmost rotor advances a step. This is central to the security of the system. However, the middle rotor only advances once every 26 keypresses. This middle rotor advance is called a "turnover", and breaks the relation we are trying to uncover. If the crib is 26 characters or longer, we are guaranteed that a turnover will happen somewhere in it, and that will create a contradiction that will prevent us from resolving anything useful.

The process of creating a good Menu was more art than science, and is not for the faint of heart. I tried several times, but I got no useful results. Eventually, I gave up.

Fortunately for me, the [CyberChef module](https://gchq.github.io/CyberChef/#recipe=Enigma%28%29) does automatic menu creation from a crib and an offset. It may not be as good as a hand-crafted menu, but it works.

So, instead of menus, I created a "work order". A set of cribs and offsets that I was going to try:

```
342 OUNCESOFANTIMATTERBR
346 ESOFANTIMATTERBRINEA
350 ANTIMATTERBRINEANDTH
354 MATTERBRINEANDTHEDIM
358 ERBRINEANDTHEDIMENSI
362 INEANDTHEDIMENSIONAL
```

Each of these cribs is 20 characters long (and longer is better), an they are offset by 4 character each, so one of them must be turnover free.

## Executing the Work Orders
We do not have any useful information about the setup of the Enigma machine we are attacking, so I went with a reasonable guess: It would be a three-rotor model, but could use any of the eight rotors commonly available late-war, and either standard reflector. Now, the Bombe requires that you know the rotor order and reflector. Its real purpose was to find the plugboard setting and initial position. So, to attack this challenge, we need the [CyberChef Multiple Bombe](https://gchq.github.io/CyberChef/#recipe=Multiple_Bombe%28%29) module.

The Multiple Bombe module defaults to only rotors I-V, and reflector B. You need to add the additional rotors and second reflector yourself. Once the machine is configured, input the crib and offset and let it run. If you are uncertain, run the setup on a single Bombe first, to test it out. For the first crib in my work order, I got the following stops:
```
Rotors: EKMFLGDQVZNTOWYHXUSPAIBRCJ, FKQHTLXOCBJSPDZRAMEWNIUYGV, ESOVPZJAYQUIRHXLNFTGKDCMWB
Reflector: AF BV CP DJ EI GO HY KR LZ MX NW TQ SU
Rotor stops  	Partial plugboard  	Decryption preview
IOO  	GG AN BM CF DP EZ HS II LY OU RT  	OVNUEJOFBNTIMMTTERBRBBLVCN
```
And
```
Rotors: VZBRGITYUPSDNHLXAWMJQOFECK, NZJHGRCXMYSWBOUFAIVLPEKQDT, JPGVOUMFYQBENHZRDKASXLICTW
Reflector: AF BV CP DJ EI GO HY KR LZ MX NW TQ SU
Rotor stops  	Partial plugboard  	Decryption preview
WVH  	GV BY CE DW FQ HM IJ LP NS OT RR UZ  	OQNMEYOFDNTIMJTTERBRONEXVI
```

Neither of them are any good. The way to test them is to try and find plugboard settings that would fix the obvious errors in the "decryption preview", but there is no way. Further, the second work order item produces no hits at all.

The third one (`350 ANTIMATTERBRINEANDTH`) gives this beauty:
```
Rotors: ESOVPZJAYQUIRHXLNFTGKDCMWB, NZJHGRCXMYSWBOUFAIVLPEKQDT, BDFHJLCPRTXVZNYEIWGAKMUSQO
Reflector: AY BR CU DH EQ FS GL IP JX KN MO TZ VW
Rotor stops     Partial plugboard   Decryption preview
OIL     TT AA BB EE GG II MM PP QQ RR VV WW YY ZZ   ANTIMATTERBRINEANDTHEDIMEW
```

Notice how the decryption preview goes a full 26 characters, and the five after the end of the crib are still clear. We would have expected "...AND TH|E DIMEN", but we got "...AND TH|E DIMEW". This is certainly the correct rotors and initial position, and the plugboard is... empty. Notice how all the plugboard letters map to themselves? That is because none were used. 

Without any plugs, a modern computer and a decent enigma emulator can brute force all rotor combinations and initial settings in only a few minutes. Rings are not very important, because you get reasonably long clear plaintext fragments without them and it's easy to find them. We will cover them next.

## Figuring Out The Ring Settings
The way to find the ring settings is to just try a bunch. The rightmost ring governs where regular turnover happens every 26 letters, so we find that first. What I did was rewind to the start of the line by reducing the initial position, and then tried all 26 possible rightmost ring settings. Note: if you do this, make sure to adjust the initial position to compensate. Here is the output grid:

```
01: ANTIMATTER DWDPT QIQ UYX 12 GVTHNSIONAL VINECVJ. WGXK YAFYVJ, ZXKING SURE NOT JA CEXTMNC BZY EQG
02: ANTIMATTEY DWDPT QIQ UYX 12 GVTHNSIONAL VINNCVJ. WGXK YAFYVJ, ZXKING SURE NOJ JA CEXTMNC BZY EQG
03: ANTIMATTBY DWDPT QIQ UYX 12 GVTHNSIONAL VIHNCVJ. WGXK YAFYVJ, ZXKING SURE NXJ JA CEXTMNC BZY EQG
04: ANTIMATHBY DWDPT QIQ UYX 12 GVTHNSIONAL VWHNCVJ. WGXK YAFYVJ, ZXKING SURE NXJ JA CEXTMNC BZY EQG
05: ANTIMAHHBY DWDPT QIQ UYX 12 GVTHNSIONAL IWHNCVJ. WGXK YAFYVJ, ZXKING SURK NXJ JA CEXTMNC BZY EQG
06: ANTIMJHHBY DWDPT QIQ UYX 12 GVTHNSIONAT IWHNCVJ. WGXK YAFYVJ, ZXKING SUJK NXJ JA CEXTMNC BZY EQG
07: ANTINJHHBY DWDPT QIQ UYX 12 GVTHNSIONMT IWHNCVJ. WGXK YAFYVJ, ZXKING SVJK NXJ JA CEXTMNC BZY EQG
08: ANTQNJHHBY DWDPT QIQ UYX 12 GVTHNSIOSMT IWHNCVJ. WGXK YAFYVJ, ZXKING XVJK NXJ JA CEXTMNC BZY EQG
09: ANUQNJHHBY DWDPT QIQ UYX 12 GVTHNSIQSMT IWHNCVJ. WGXK YAFYVJ, ZXKINC XVJK NXJ JA CEXTMNC BZY EQG
10: AZUQNJHHBY DWDPT QIQ UYX 12 GVTHNSSQSMT IWHNCVJ. WGXK YAFYVJ, ZXKIVC XVJK NXJ JA CEXTMNC BZY EQG
11: AZUQNJHHBY DWDPT QIQ UYX 12 GVTHNASQSMT IWHNCVJ. WGXK YAFYVJ, ZXKRVC XVJK NXJ JA CEXTMNC BZY EQG
12: ANTIMATTER BRINE AND THE 12 DIMENSIONAL VINEGAR. STIR GENTLY, MAKING SURE NOT TO RUPTURE THE SPA
13: ANTIMATTER BRINE AND THE 12 DIMHNSIONAL VINEGAR. STIR GENTLY, MXKING SURE NOT TO RUPTURE THE SPG
14: ANTIMATTER BRINE AND THE 12 DITHNSIONAL VINEGAR. STIR GENTLY, ZXKING SURE NOT TO RUPTURE THE SQG
15: ANTIMATTER BRINE AND THE 12 DVTHNSIONAL VINEGAR. STIR GENTLJ, ZXKING SURE NOT TO RUPTURE THE EQG
16: ANTIMATTER BRINE AND THE 12 GVTHNSIONAL VINEGAR. STIR GENTVJ, ZXKING SURE NOT TO RUPTURE THY EQG
17: ANTIMATTER BRINE AND THX 12 GVTHNSIONAL VINEGAR. STIR GENYVJ, ZXKING SURE NOT TO RUPTURE TZY EQG
18: ANTIMATTER BRINE AND TYX 12 GVTHNSIONAL VINEGAR. STIR GEFYVJ, ZXKING SURE NOT TO RUPTURE BZY EQG
19: ANTIMATTER BRINE AND UYX 12 GVTHNSIONAL VINEGAR. STIR GAFYVJ, ZXKING SURE NOT TO RUPTURC BZY EQG
20: ANTIMATTER BRINE ANQ UYX 12 GVTHNSIONAL VINEGAR. STIR YAFYVJ, ZXKING SURE NOT TO RUPTUNC BZY EQG
21: ANTIMATTER BRINE AIQ UYX 12 GVTHNSIONAL VINEGAR. STIK YAFYVJ, ZXKING SURE NOT TO RUPTMNC BZY EQG
22: ANTIMATTER BRINE QIQ UYX 12 GVTHNSIONAL VINEGAR. STXK YAFYVJ, ZXKING SURE NOT TO RUPTMNC BZY EQG
23: ANTIMATTER BRINT QIQ UYX 12 GVTHNSIONAL VINEGAR. SGXK YAFYVJ, ZXKING SURE NOT TO RUXTMNC BZY EQG
24: ANTIMATTER BRIPT QIQ UYX 12 GVTHNSIONAL VINEGAR. WGXK YAFYVJ, ZXKING SURE NOT TO REXTMNC BZY EQG
25: ANTIMATTER BRDPT QIQ UYX 12 GVTHNSIONAL VINEGAJ. WGXK YAFYVJ, ZXKING SURE NOT TO CEXTMNC BZY EQG
26: ANTIMATTER BWDPT QIQ UYX 12 GVTHNSIONAL VINEGVJ. WGXK YAFYVJ, ZXKING SURE NOT TA CEXTMNC BZY EQG
```

Clearly ring setting 12 is correct. So the rings look something like [1,?,12]. The leftmost does actually matter, so we can just set it to whatever. Remember that the rightmost rotor advances every keypress? Well, it turns out that each rotor's ring setting advances the rotor to its left. It also advances the rotor on the keypress AFTER it is engaged. This is all because this is a fundamentally mechanical device.

## Finding the Second Ring Setting
As with the leftmost ring setting, we need to rewind our position here, this time, all they way to the beginning of the ciphertext. With a little bit of twiddling, we find [14, 20, 11] or "NTK". This gives a clean decryption of the first line and a partial for the second line:

```
1. START BY PLUCKING THE 7 QUARKS FROM THE PARTICLE ACCELERATOR. BE SURE TO MAINTAIN THEIR QUANTUM ENTANGLEMENT; IT'S CRUCIAL FOR THE PICKLING PROCESS.

2. SLICE THE 3 ZUCCHINIS INTO FDATQQT ZEIEVFPE, EKOTLFCH GEAL ZAHM ZXTUJ RRS IJ EEGNO RAUANGO HJ CTPCZDFM MBW SGNTVXLB MQDPATURE.
```

Note that the plaintext resumes toward the end of the line. Counting the approximate number of misdecrypted characters at 78 or 26*3, we know the middle ring setting is off by three. Figuring out which way is possible, but much harder than just trying both. This gives us the full settings: [1,24,12] or "AXL"

## Finale
Enigma Settings:
- Rotors: IV VII III B
- Rings: AXL
- Initial: NQK
- Plugs: (empty)

1. START BY PLUCKING THE 7 QUARKS FROM THE PARTICLE ACCELERATOR. BE SURE TO MAINTAIN THEIR QUANTUM ENTANGLEMENT; IT'S CRUCIAL FOR THE PICKLING PROCESS.

2. SLICE THE 3 ZUCCHINIS INTO FRACTAL PATTERNS, ENSURING THAT EACH PIECE HAS AN EQUAL BALANCE OF POSITIVE AND NEGATIVE CURVATURE.

3. SPRINKLE 2 STANDARD PINCHES OF STARDUST OVER THE ZUCCHINI SLICES TO ADD A TOUCH OF INTERSTELLAR FLAVOR.

4. IN A MULTI-DIMENSIONAL POT, COMBINE THE 42 OUNCES OF ANTIMATTER BRINE AND THE 12 DIMENSIONAL VINEGAR. STIR GENTLY, MAKING SURE NOT TO RUPTURE THE SPACE-TIME CONTINUUM.

5. CAREFULLY PLACE THE QUANTUM CUCUMBER AT THE CENTER OF YOUR TIME CRYSTAL, CAUSING IT TO EXIST SIMULTANEOUSLY IN ALL STATES OF PICKLED AND UNPICKLED.

6. SUBMERGE THE ZUCCHINI SLICES INTO THE BRINE AND CLOSE THE LID OF YOUR HYPERBOLIC PICKLING JAR.

7. SHAKE THE JAR VIGOROUSLY IN A PERPENDICULAR MANNER TO ENSURE THAT THE ZUCCHINIS EXPERIENCE MAXIMUM DIMENSIONAL DISTORTION.

8. ALLOW THE PICKLES TO MARINATE IN A PARALLEL UNIVERSE FOR PRECISELY 17.3 FEMTOSECONDS. KEEP AN EYE ON YOUR COSMIC STOPWATCH TO GET THE TIMING JUST RIGHT.

9. RETRIEVE THE PICKLES FROM THE ALTERNATE DIMENSION AND SERVE THEM WITH A SIDE OF DARK ENERGY CRACKERS.

(Aside: To get the flag, you needed to show them a full clean decryption, it wasn't part of the plaintext.)
