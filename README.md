# HohhaDynamicXOR
Hohha Dynamic XOR Encryption Algorithm and C implementation:

Hohha Dynamic XOR is a new symmetric encryption algorithm developed for Hohha Secure Instant Messaging Platform and opened to public with MIT&GPL Dual License.

The essential logic of the algorithm is using the key as a "jump table" which is dynamically updated with every "jump" we make.

To understand better how it functions, suppose that we don't have a complex function.

Given the key body length(L) is a power of 2, and M is an integer to tell us where we are in the "key body":

We just take the byte at position M of the key body, we XOR that byte with the byte to be encrypted(X).
We increase the byte at position M and "jump to" (M+X)%L

So, every time we encrypt a byte, we also change the key. It's a bit more complicated than this. But essentially this is the base logic. In real function, we do more complex operations with more variables like the salt(or nonce) value, the last byte we encrypted, the key checksum(against related key attacks) etc.

Briefly, to decypher a ciphertext, a cracker needs to find out the key, and, to find out the key, cracker needs to find out the plaintext, because the key is dynamically updated according to plaintext during encryption process: Maybe not impossible theoretically, but surely very very difficult practically!

I believe this algorithm is the future of the encryption. Maybe it is not perfect. But, I believe, this "dynamic key" model is the right way for the encryption. It is in public domain. It is public property. And we all need it. Let's try to get it more secure and faster together, if possible.

The code is constantly updated and improved. 

Use it! And please, let me know if you use: ikizir@gmail.com

# Usage

void xorGetKey(uint8_t NumJumps, uint32_t BodyLen, uint8_t *KeyBuf);

Creates an encryption key.
NumJumps is the number of jumps(or rounds) to encrypt or decrypt a data. The actual maximum value is 4(But if you find it weak, I can increase that limit. I just have to write hand optimized functions). This parameter directly affects speed and strength of the algorithm. If you choose higher values, the encryption will be more secure but slower.

BodyLen is the number of bytes in the key body. It must be a power of 2 e.g. 64,128,256,512 ...
It has no influence on the speed of the algorithm. 
This parameter affects only the strength of the algorithm. Higher values you choose, higher security you get. Choose large numbers especially if you are going to encrypt large files.

KeyBuf is pointer to an "already allocated" buffer to hold the entire key. To compute the size of the resulting key, you may use xorComputeKeyBufLen macro.

Suppose that we want to create a key with 4 jumps and a body size of 1024 bytes. The code will be:

#define BODY_LEN 1024
#define NUM_JUMPS 4

uint8_t KeyCheckSum;
unsigned RawKeyLen = xorComputeKeyBufLen(BODY_LEN);
uint8_t *KeyBuf = (uint8_t *)malloc(RawKeyLen);
xorGetKey(NumJumps, BodyLen, KeyBuf);
KeyCheckSum = xorComputeKeyCheckSum(KeyBuf);

KeyCheckSum is the 8 bit CRC checksum of the key. Every time you create a key, you must also compute its checksum. In order to use the key for encryption, or decryption, we must give that checksum as a parameter.
Now, we have the key and the checksum. We want to encrypt our data.

... I am still writing the documentation --- to be continued ---
