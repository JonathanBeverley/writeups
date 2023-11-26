---
title: "Log Server"
weight: 2
---

## Introduction
We are given a zip of a thousand tiny encrypted log files and an RSA public key. The key's size is very suspicious, but not quite small enough for me to credibly crack using my standard methods (NARRATOR: this would be his undoing...)

```
Public-Key: (410 bit)
Modulus:
    02:2d:a2:2e:4c:cb:d4:a0:93:7c:89:4d:f8:be:72:
    f5:7f:e0:06:7f:ed:cd:99:3b:fa:ff:95:5d:69:21:
    24:44:de:1c:2f:05:46:70:00:fb:87:2e:bf:4d:4a:
    f4:66:cb:fe:c7:cb:ab
Exponent: 65537 (0x10001)
Modulus=22DA22E4CCBD4A0937C894DF8BE72F57FE0067FEDCD993BFAFF955D69212444DE1C2F05467000FB872EBF4D4AF466CBFEC7CBAB
```

Instead I spent many hours trying to apply variations on Coppersmith's attack, ROCA, Franklin-Reiter, and more. Since this was a two-day CTF, I even tried running [YAFU](https://github.com/bbuhrow/yafu) overnight, which did not really help. Partway through the second day, the challenge updated. All the logs were even smaller, and the key had been reduced in size!

```
Public-Key: (329 bit)
Modulus:
    01:b6:14:68:65:68:28:94:fc:8d:2f:2d:5b:8c:21:
    81:31:74:a0:ac:21:39:61:5f:3d:bb:35:68:91:41:
    2b:30:cf:86:b1:b6:85:1c:d5:46:9a:75
Exponent: 65537 (0x10001)
Modulus=1B6146865682894FC8D2F2D5B8C21813174A0AC2139615F3DBB356891412B30CF86B1B6851CD5469A75
```

Confident now that that cracking was the correct answer, I spun YAFU back up, and managed to crack it in 2:41:51, a mere 15 minutes before the end of the conference. Unfortunately, cracking it does not get you the flag. To get the flag you need to actually decrypt the log files, find the pattern, and reconstruct the flag. This is trivial, it would have taken maybe 2 minutes, if my tooling was functional (NARRATOR: it was not).

## Huge Aside: Bitching About Ruby OpenSSL
Here is a quote from [the Official Ruby Documentation for OpenSSL::PKay::RSA.new()](https://docs.ruby-lang.org/en/master/OpenSSL/PKey/RSA.html):
> If called without arguments, creates a new instance with no key components set. They can be set individually by `set_key`, `set_factors`, and `set_crt_params`.

Here is what actual running ruby has to say about that:
> OpenSSL::PKey::PKeyError: rsa#set_key= is incompatible with OpenSSL 3.0

Ruby began migration to OpenSSL 3.0 in 2020. Here is what the migration tracker has to say about this:
> OpenSSL::PKey::*, Setters for parameters/key components
> - `{RSA,DSA,DH}#set_*` and `EC#{private_key=,public_key=,group=}`
> - **Feature removed without replacement**. Keys are now immutable once created - all components must be specified at once.
> - Use cases definitely exist, a new interface is required.
>     - `EVP_PKEY_fromdata()` requires the caller to specify what the pkey is: parameters only, public key only, or private key?
>     - `OpenSSL::PKey.new_private_key("RSA", n: 123, e: 456, d: 789)`?

... "Feature removed without replacement" ...

This bit me hard during NorthSec and I did not get around to fixing my tooling. I eventually found a [gist](https://gist.github.com/WilliamNHarvey/0e37f84a86e66f9acb7ac8c68b0f996b) that gave me a working prototype, but not until the day after the CTF. It turns out the easiest way to make an RSA with arbitrary parameters is to build your own ASN1, convert it to DER, and import that. Fortunately, this sounds a lot worse than it is, because ASN1 is well supported in ruby:

```ruby
    # given key parameters N, e, d, p, q
    dmp = @d % (@p-1)
    dmq = @d % (@q-1)
    qi = @q.invertMod @p
    data_sequence = OpenSSL::ASN1::Sequence([
        OpenSSL::ASN1::Integer(0), # version
        OpenSSL::ASN1::Integer(@n),
        OpenSSL::ASN1::Integer(@e),
        OpenSSL::ASN1::Integer(@d),
        OpenSSL::ASN1::Integer(@p),
        OpenSSL::ASN1::Integer(@q),
        OpenSSL::ASN1::Integer(dmp),
        OpenSSL::ASN1::Integer(dmq),
        OpenSSL::ASN1::Integer(qi),
    ])
    asn1 = OpenSSL::ASN1::Sequence(data_sequence)
    return OpenSSL::PKey::RSA.new(asn1.to_der)
```

## Actually Getting a Flag
With the many-hour aside out of the way, the rest was pretty easy. I wrote a small ruby script to generate a key, and used that to decrypt some of the logs. Most of the logs look like:
> {"machine_id":24,"status":"ok"}

But some of them are like:
> {"machine_id":26,"status":"fl"}

Filter out the "ok"s and join to make the flag.

### Ruby Script to Generate the Key
```ruby
require 'crypto'

e = 65537
p = 33103618487244558210974815716209648829261663988651
q = 28266776896898743549480516378919514765669083509343

rsa = RSA.new e:e, p:p, q:q

pubkey = rsa.createPublicKey
File.open("test_pubkey.pem", 'w'){|f| f.write(pubkey.to_pem())}
privkey = rsa.createPrivateKey
File.open("test_privkey.pem", 'w'){|f| f.write(privkey.to_pem())}
```

### Bash Script to Decrypt the Files and Get the Flag
```sh
for file in *.enc; do
    openssl pkeyutl -decrypt -inkey new_privkey.pem -in $file
done | grep -v '"ok"'
```

## Post Script: CADO-NFS
Since the last time I paid enough attention to the world of factoring large numbers, one program has significantly outpaced the others, that program is [CADO-NFS](https://gitlab.inria.fr/cado-nfs/cado-nfs). Unlike YAFU, CADO-NFS just works. You can just clone it, build it, and run it. There is no tinkering, makefile editing, reading dozens of pages of old mersenneforum posts. This is a very welcome change.

It is also significantly faster.

Using CADO-NFS, I was able to crack the first 410-bit key in 11:17:57. Which is rough, but viable for an overnight run. The second 329-bit key took a mere 0:50:04 on the same hardware, or 1:38:26 on my CTF laptop. I did not try doing the 410-bit key on that laptop, but the time would probably be linear.

Summary: use CADO-NFS. Don't be like me. YAFU isn't worth it anymore.

