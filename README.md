
# HohhaDynamicXOR

This is a C implementation of Hohha Dynamic XOR algorithm.

## Description

Hohha Dynamic XOR is a new symmetric encryption algorithm developed for Hohha Secure Instant Messaging Platform and opened to the public via dual licence MIT and GPL.

The essential logic of the algorithm is using the key as a "jump table" which is dynamically updated with every "jump".

Check out our **[Wiki]** for more information.

## Download & Compilation

First, download base64 library with this command:
```
git clone https://github.com/aklomp/base64
```

Then, read installation instructions and compile base64 library.
A typical build command is:
```
AVX2_CFLAGS=-mavx2 SSSE3_CFLAGS=-mssse3 SSE41_CFLAGS=-msse4.1 SSE42_CFLAGS=-msse4.2 AVX_CFLAGS=-mavx make lib/libbase64.o
```

Then, you can compile and run benchmark program with:
```
cmake .
make
./HohhaBench -r 100000
```
Will run the integrity checks, and print out the benchmarks with 100000 iterations.

## Creating a standalone library:
By removing Benchmain.c from compilation and replacing GetRandomNumbers function by a 
cryprographically secure random number generator, you can create your own encryption library.
Hohha is designed with its own packet format and authentication codes. 
You don't need to send nonce values separately.
You don't need other signature schemes for verification.
Those functions are enough for a reliable encyrption&decryption&authentication:

```
int xorGetKey(uint8_t NumJumps, uint32_t BodyLen, uint8_t *KeyBuf);
unsigned int CheckKeyIntegrity(uint8_t *K, size_t TotalKeyBufLen);
void xorEncryptAndSign2(uint8_t *K, size_t InDataLen, const uint8_t *InBuf, uint32_t DataAlignment, uint8_t *OutBuf);
uint8_t *xorEncryptAndSign(uint8_t *K, size_t InDataLen, uint8_t *InBuf, uint32_t DataAlignment);
uint8_t *xorDecryptAndVerify(uint8_t *K, size_t TotalPacketLen, uint8_t *InOutBuf, ssize_t *PlainTextLen);
```

Code is self documented. In HohhaXor.c, you can find meanings of parameters.
And in HohhaBench.c you can find usages.
I will write a more detailed documentation in future.

* With <= 64 bytes key body length, all key body is expected to be kept in L1 cache.

  Encryption uses only bitwise instructions and operates in constant time.
  
  Consequently, it is expected to be resistant to side channel and timing attacks.
  
  I tried to update the algorithm according to D.J. Bernstein's paper at:
  
  https://cr.yp.to/antiforgery/cachetiming-20050414.pdf
  
  
* It encrypts 32 bit blocks. It is faster(at least by a factor of 2). 

* The authentication signature is 16 bytes. Even more secure than before.

Note that HohhaDynamicXor.c is now obsolete!


## Contacts

Ismail Kizir <[ikizir@gmail.com]>

[wiki]: https://github.com/ikizir/HohhaDynamicXOR/wiki
[ikizir@gmail.com]: mailto:ikizir@gmail.com
[http://ismail-kizir.blogspot.com.tr/]: http://ismail-kizir.blogspot.com.tr/

