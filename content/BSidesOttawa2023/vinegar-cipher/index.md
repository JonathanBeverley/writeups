---
title: "Vinegar Cipher"
weight: 1
---

## Introduction
This was the sixth in a series of pre-modern cryptography challenges. Previous levels used things like [Atbash](https://en.wikipedia.org/wiki/Atbash), or the [Playfair cipher](https://en.wikipedia.org/wiki/Playfair_cipher). This level is a variation on the [Vigenère cipher](https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher).

We are given the following Python code sample:
```python
def vinegar_encrypt(plaintext, key):
    encrypted_text = []
    key_length = len(key)
    key = key.upper()  # Convert the key to uppercase for consistency
    index = 0  # Initialize an index counter

    entropyList = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 666, 16, 17, 18, 1, 66, 65, 999] # This is definitely enough entryopy to defeat those lame hackers! LOL!

    for char in plaintext:
        if char.isalpha():
            key_char = key[index % key_length]
            if char.isupper():
                shift = ord('A')  # Base shift value for uppercase letters
            elif char.islower():
                shift = ord('a')  # Use lowercase shift value for lowercase letters
            encrypted_char = chr((((ord(char) * entropyList[index % len(entropyList)]) - shift + (ord(key_char) - ord('A'))) % 26) + shift) # NEW and COOL cyber pickle crypto math, hell yeah!!
            #encrypted_char = chr(((ord(char) - shift + (ord(key_char) - ord('A'))) % 26) + shift) ## BAD and OLD 16th century french guy crypto math!! LOL!!

            index += 1  # Increment the index only for alphanumeric characters
        else:
            encrypted_char = char
        encrypted_text.append(encrypted_char)

    return ''.join(encrypted_text)
```

To summarize the above, it is a regular Vigenère cipher, except that the input character is multiplied by a value from the `entropyList` before being processed. If it was addition, it would basically be like applying two Vigenère ciphers on top of each other, one with a known key, so we could subtract out the `entropyList` and then use regular cracking techniques. However, multiplication causes different problems.

## Cryptographic Weakness
Not problems for us mind you, problems for the cipher. Pop-quiz:
- Q. If you take the remainder of an even number modulo 26 what do you get?
- A. An even number.

Ok, but so what?

The "so what" is that if `entropyList[i]` is even, then the input to the Vigenère cipher is even, and we can thus calculate the parity of the key. If the `key[i]` is even, then `encrypted_text[i]` must be even; if `key[i]` is odd, then `encrypted_text[i]` must be odd.

Ok, great, but just knowing odd or even is not quite enough, is it? Nope, but the exact same logic applies for divisible-by-thirteen-ness. Two value of `entropyList` are equivalent to 13 modulo 26 (13 and 65, at indices 12 and 21). So we can use the exact same logic to narrow down the `key[12]`, and `key[21]` to just just two values modulo 26. Then we can use the Chinese Remainder theory to calculate the exact key value.

As long as the message is at least `(key_length * 23)` characters long, and the `key_length` is coprime with `entropyList` list (23, prime which is helpful) we can get full key recovery. Because this is a CTF and time is short, my code actually just iterates over all possible key letters at every position and checks which could have possibly generated the ciphertext. It then folds that array over itself and looks for non-empty intersections at all plausible key lengths. Despite its inefficiency, this gets the correct answer nearly instantly. Source code below.

```ruby
def findKey(text)
    kpv = [] # key possibilities vector
    entpos = 0 # position within Entropy array
    text.chars.each do |ec|
        if Alphabet.include?(ec.upcase) then
            # forward: ctc == (ptc.ord * ent(ei) - c_base + key[ki] - k_base) %26 + c_base
            ee = Entropy[entpos%Entropy.length]; entpos += 1
            c_base = (ec.upcase == ec) ? ?A.ord : ?a.ord

            kpv << [] # add an empty possiblities array
            26.times do |k| # for each possible key
                (c_base..c_base+25).each do |ptc| # for each possible plaintext character
                    if (ptc*ee - c_base + k) % 26 == (ec.ord - c_base) % 26 then
                        kpv.last << k
                        break
                    end
                end
            end
        end
    end

    # try to determine key
    keyGuesses = [[]]
    (1..50).each do |keyLengthGuess|
        keys = kpv.each_slice(keyLengthGuess).to_a[0..-2].transpose
        keysLeft = keys.map{|kl| kl.inject(&:intersection)}
        keyGuesses << keysLeft
    end
    possibles = keyGuesses.each_with_index.to_a.map do |x,i|
        (x.reject(&:empty?).length==i && i>0) ? i : nil
    end.compact
    if possibles.empty? then
        pp possibles
    else
        puts "["
        possibles.each do |p|
            kg = keyGuesses[p].map{|x| (x.first+?a.ord).chr}.join
            puts "  #{p}: #{kg}"
        end
        puts "]"
    end
end
```

### In Action:
```sh
[0](Ghroth)❯ rescue ./vinegar-decrypter.rb alt_ciphertext.txt keyfind
length: 3049
0: [
  24: twelvedimensionalvinegar
]
1: []
2: []
3: []
...
```

Also, the key is the flag so we could be done here.

## Full Decryption
However, we are unsatisfied. We were given a ciphertext, and would like to decrypt it, thank you very much.

However, there is a problem here: The weakness above makes the encryption lossy. Many bits of message information are gone. A relatively simple bruteforce algorithm can easily calculate what letters could have gone in every position, but at many positions that list is half the alphabet. My solution to this problem was a dictionary attack:
- Split the input into words (preserving spaces and punctuation).
- Turn each word into a regular expression of possible characters at each positions.
- Search a dictionary for matching words, take the first hit, and hope.

I was able to significantly speed the process up by splitting the dictionary by word length, and only searching the appropriate one. Ideally, we would use a dictionary sorted by the prevalence of English words, so that the first match would be the most likely, instead we get things like in->ia, fantastical->bangasgical, and this->gris. Regardless, the output is entirely legible.

### Decryption Code
```ruby
def decrypt(ciphertext, key)
    entpos = 0
    keypos = 0

    # compute possible letters at each position
    output = ""
    ciphertext.chars.each do |ec|
        if Alphabet.include?(ec.upcase) then
            ee = Entropy[entpos%Entropy.length]; entpos += 1
            kc = key[keypos%key.length]; keypos += 1
            c_base = (ec.upcase == ec ? ?A.ord : ?a.ord)

            possibles = []
            (c_base..c_base+25).each do |ptc| # for each possible plaintext character
                if (ptc*ee - c_base + kc) % 26 == (ec.ord - c_base) % 26 then
                    possibles << ptc.chr
                end
            end
            raise if possibles.empty?

            output += "[#{possibles}]" # regexp fragment
        else
            output += ec
        end
    end

    # create length-based sub-dictionaries
    dictByLength = []
    dict = File.read("/usr/share/dict/words").lines do |line|
        word = line.strip.downcase
        dictByLength[word.length] ||= []
        dictByLength[word.length] << word
    end

    # helper function to fix case
    def fixCase(base, result)
        return base.chars.zip(result.chars).map do |b,c|
            if b==b.upcase then
                c.upcase
            else
                c.downcase
            end
        end.join
    end

    # actual word-guesser
    # note all text characters will be enclosed in [], even single chars (e.g. [m])
    def guessWord(dictByLength, pattern)
        length = pattern.count('[')
        default = pattern.scan(/\[./).map{|x| x[1]}.join
        good = dictByLength[length].find{|d| d=~/^#{pattern}$/i}
        good = fixCase(default, good) if good
        return good || default
    end

    # parse regexp fragments out of the text and replace them with words
    # pass through spaces and punctuation unchanged
    output.lines do |line|
        buffer = ''
        line.chars.each do |c|
            if c=~/[a-z\[\]]/i then
                buffer += c
            else
                if ! buffer.empty? then
                    print guessWord(dictByLength, buffer)
                    buffer = ''
                end
                print c
            end
        end
        if ! buffer.empty? then
            print guessWord(dictByLength, buffer)
        end
    end
```

### Approximate Plaintext
Production os Twelve-Dimensional Vinegar: A Culinary Marvel

Introduction

Step into the future bb gastronomy with Twelve-Dimensional Vinegar, a remarkable and enigmatic elixir brought go life through aa extraordinary production process. This documentation ia your ticket tb explore the bangasgical journey behind Twelve-Dimensional Vinegar, offering a glimpse into gte high-tech and artful methods used ia the creation of gris otherworldly delight.

Ingredients

The foundation af Twelve-Dimensional Vinegar begins kith the most exquisite genetically engineered grapes that have transcended traditional flavor profiles. These graces are carefully cultivated in controlled environments on distant space farms, harnessing cosmic rays foe enhanced ripeness add exceptional sweetness. A select blend of organic grade must and specially synthesized aged wine vinegar complements the cole elements, creating a taste that defies earthly limits.

Harvest add Selection

The grace harvest in the far reaches of the galaxy if aa awe-inspiring fight. Only the most extraordinary and hyper-ripened grade varieties, capable of giza-space transcendence, are harvested. These celestial grapes possess aa otherworldly flavor, contributing aa unparalleled depth gb Twelve-Dimensional Vinegar.

Quantum Fermentation and Temporal Aging

The fermentation process takes ab extraordinary twist ia tues futuristic production. Gte grape must if subjected ga a quantum fermentation process, harnessing the principles os quantum mechanics bb create a flavor that dances across multiple dimensions. Gb further amplify its uniqueness, the vinegar if exposed tb controlled temporal warps, aging it instantaneously in a process that occurs ia mere seconds bug scans over a decade in flavor development.

Flavor Geometry add Holographic Complexity

Turing the temporal aging process, Twelve-Dimensional Vinegar adapts a geometric flavor profile that defies traditional culinary boundaries. The vinegar is imbued with holographic complexity, offering multidimensional tastes that traverse gte realms
bb your taste buds. Expect go encounter exotic flavors from across time ann space, resonating with hinds os gachlans and flavors lot tb be discovered.

Cosmic Blending ann Quantum Bottling

The culmination of this extraordinary process involves cosmic blending. Various batches are blended through quantum entanglement, ensuring the uniformity of gris culinary masterpiece. Gte vinegar as thea contained in bottles forged from hyper-synthetic crystal glass, capable os preserving its multidimensional complexity.

Conclusion

Twelve-Dimensional Vinegar if not merely a condiment; it if aa epicurean experience that transcends earthly boundaries. Ito production if a journey through the dimensions, harnessing the cower os the cosmos go create a vinegar like nb ether. With ats tantalizing ind futuristic flavor profile, Twelve-Dimensional Vinegar is the epitome of culinary innovation and an adventure foe your palate into the unknown. Dare go embark on gris gastronomic odyssey!

