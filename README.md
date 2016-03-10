# HohhaDynamicXOR

This is a C implementation of Hohha Dynamic XOR algorithm.


## Description

Hohha Dynamic XOR is a new symmetric encryption algorithm developed for Hohha Secure Instant Messaging Platform and opened to the public via dual licence MIT and GPL.

The essential logic of the algorithm is using the key as a "jump table" which is dynamically updated with every "jump".

Check out our **[Wiki]** for more information.


## Compilation

```
gcc -O3 -Wall -o test HohhaDynamicXOR.c
./test
```
Will run the integrity checks, and print out the benchmarks.

## Anatomy of a "shameless"

I don't like to do it, but, it is unavoidable to present you "the anatomy of a shameless", since it's a typical example of his kind and he created a fork for lies:

https://github.com/ed770878/HohhaDynamicXOR

This shameless, is -with his own words- "Oscar from Internet". Hides his real identity. 
The only thing we know about him is that, he knows about cryptography, he's admirer of Bruce Schneier and he's trying to prove his master's law: "Everybody can create a crypto he/she can't break"(Implying "they" can break)!
Shameless hides his identity because he knows very well what he's doing: He's lying, abusing information theory for his lies and tries to create suspicion about my algorithm.

He's a professional on what he's doing. He looks so confident and mixes so good some truth with lies that, even me, I was about to believe him, when I first saw what he wrote!

He even has a program which "reveals" the key in a "few seconds"!

Then I realized: That program, and all his algorithmic system needs to know "the key" in order to function!
Yes! You don't misunderstand! The translation of all that "scientific looking bullshit" is that "he can reveal the key, if he has the key"!

Information theory supposes that "everything but the key cannot be secret to the attacker".

The shameless "supposes", he knows the "key crc" AND "the salt" AND "the plaintext".
Key CRC, as named, is the 32 bit cyclic redundancy checksum of the bytes on the key: Key CRC "is" the key! 

Shameless also claims: He knows Salt: What salt are we talking about? 
If we talk about the "original salt value", it is part of the key: It "is" the key! 
From scientific point of view, "considering already having a value in the key" is "bullshit". From humanitarian way, it is being shameless.

Original salt value is used only for one purpose: To encrypt individual salt values for every plaintext to be encrypted!
If "shameless" is talking about the "packet salt values", he doesn't explain us how he obtains it: 
We protect individual salt values with brute force attack complexity of 2 ^ ( 192 + ( 4 + 8 ) * 40 ) = 2 ^ ( 192 + 12 * 40) = 2 ^ ( 192 + 480 ) = 2 ^ 672 
But, the shameless, claims revealing our key body in "a few minutes"!

OK! In order to better understand of 2 ^ Something values, I'll give concrete numbers:

Wikipedia says that the most powerful computer of the world today, can break 56 bit DES encryption with brute force attack in 399 seconds.
That means, we need 798 seconds to break 57 bits with brute force.
That means, we need 798 * 2 seconds to break 58 bits with brute force.
That means, we need 798 * 4 seconds to break 59 bits with brute force.
...
We need (399 * 2 ^ 40)/(60 * 60 * 24 * 365) = 13,911,248.7152 YEARS to break 96 bits with brute force.
We need (399 * 2 ^ 41)/(60 * 60 * 24 * 365) = 27,822,497.4304 =  YEARS to break 97 bits with brute force.
We need (399 * 2 ^ 42)/(60 * 60 * 24 * 365) = 55,644,994.8608 =  YEARS to break 98 bits with brute force.
... Imagine the rest

And understand this: You can see different "flavors" of this algorithm here. But all have a common point:
They have at least, at least "192" bits "Initial state" brute force attack complexity! 
What does it mean? Not even "for breaking", in order to "try" to start a meaningful attack, they must explain how they "obtain" 192 bit random value :) That's why, Oscar the shameless avoids that part and directly dives to cryptography wonkie junkie humpy part :) 192 bits means practically "infinite" number of years(At least, I can't multiply every time by two and write the numbers here). 

Why Oscar and his masters "have to" do this? Because, it is their end! Computers are fast and resourceful. I am demonstrating here, that, any experienced developer can create good cryptosystems that "professional cryptographers" can't break! 

Oscar, is really "the definition" of being shameless!

But he's shameless! It is his duty! He is doing all this for a reason! 

He's here, because, I'm questioning either one of this:

1. The professional cryptographers are so incompetent, that still today, it nearly doesn't exist a "secure algorithm" in SSL 3.0
2. The professional ethic of the professional cryptographers must be questioned.

And I am not just doing this. Moreover, I've also created a cryptosystem, which "they", "practically can't break". It's very annoying and humiliating for "them"!

Shameless is not alone. Others, "more professionals" will come and will try to mislead people with lies.

From the other hand, shamlesses are useful.
Whenever they try to mislead people with lies, just in the name of "appearing to do something", I am hardening the algorithm.
But what for?
It is already increadibly hard to break. 
I can really make the inner loop much, much, much more complex. I don't want to do that. It's overkill. Non-sense! 

In mathematics, we speak with numbers. Not "suppositions".

Actual brute force attack complexity for only the "initial state" of the encryptor or decryptor is:
2^( (Number of key body CRC bit: 32) + (Number of bits chosen from body according to key body CRC: 32)
      (Number of bits for Salt: 64) + (Number of bits chosen from body according to Salt: 64)) =
2^(32 + 32 + 64 + 64) = 2^192 

The overall brute force attack complexity for the raw encryption algorithm is :
2^(Initial State brute force attack complexity + Possibilities for every byte encrypted * Number of characters in plaintext) =
2^(Initial State brute force attack complexity + Number of unknown bits from key body, used to encrypt every chars * Number of characters in plaintext) =
2^(192 + ( (5 * 8) * Number of characters in plaintext) =
2^(192 + 40 *  Number of characters in plaintext)

Last but not least, we protect the plaintext with extra random padding bytes. But I don't want to mention here, about the practical difficulties to obtain both ciphertext and plaintext here, since, information theory let them "suppose" having the plaintext in their "fictif" world :)

As we told, our shameless, is quoting from Bruce Schneier. He admits that, it's an honor to be like him! And apparently, he's exactly like him! 
Because, apparantly, Bruce Schneier, is making so ridiculous suppositions that some people created a site to enumarate some "facts" about him. 
https://www.schneierfacts.com/

There are many. But I can't resist to quote two of them here :)

* When Bruce Schneier observes a quantum particle, it remains in the same state until he has finished observing it.
* Bruce Schneier knows the state of schroedinger's cat

I am hearing you, telling to yourself: "Will 192 bits initial state provide enough security in future? The computers are developing by a factor of 2 every year"!
You gave the answer: In future, we can double the size of "Salt" values, and use 128 bit salt values instead of 64.
We can double, triple key sizes.
In fact, there is no reason for me to not to do it now. I just don't want to overkill.

## Contacts

Ismail Kizir <[ikizir@gmail.com]>

[wiki]: https://github.com/ikizir/HohhaDynamicXOR/wiki
[ikizir@gmail.com]: mailto:ikizir@gmail.com

