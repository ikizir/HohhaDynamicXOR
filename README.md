This version is leaking keys. We are working on random distribution.
# HohhaDynamicXOR
Hohha Dynamic XOR Encryption Algorithm Theory and its C implementation:

I would really want, to promise my customers "An approved Standart Security". 
But a real "security" on which they could rely on; and focus on my commercial products.
What I am doing, is not something I desire.
The history of "approved standards" is a proof to not to trust to so called "Security Authorities", "Experts" or "Cryptography Gods".
Do you want proof:
https://en.wikipedia.org/wiki/Transport_Layer_Security
This is a "proof"! A real proof to not to trust to "approved standarts"!

SSL 3.0 doesn't include "any" secure encryption implementation.
AES 256 CBC is not included in TLS 1.3 draft.
All others are slow and again, untrustable considering the history.

I'd rather prefer to try to develop my own and improve it by seeing my mistakes and my bottlenecks with the transparent help from the community.

I am not a "crypto expert", I haven't mathematical background to prove that's "secure", as the "authorities" do!  
But I believe in common sense and collaboration.
I'd rather prefer to try to improve transparently a collaborative work, instead of relying on suspicious "Cryptoanalysis Gods" and "Authorities"!
If you think it is breakable, you're welcome, this is why it's in public domain. Please tell us "how"! Let's think together and improve it. 
We will all use this for our specific needs. And if we think carefully, we can adapt it to different requirements. Nobody prevents us from creating derivatives. This is freedom and the spirit of "open source".

## Algorithm

Hohha Dynamic XOR is a new symmetric encryption algorithm developed for Hohha Secure Instant Messaging Platform and opened to the public via dual licence MIT and GPL.

The essential logic of the algorithm is using the key as a "jump table" which is dynamically updated with every "jump".

To better understand how the code functions, suppose that we don't have a complex function.

Given the key body length(L) is a power of 2, and M is an integer that tell us where we are in the "key body":

We just take the byte at position M of the key body, we XOR that byte with the byte to be encrypted(X).
We increase the byte at position M and "jump to" (M+X)%L

So, every time we encrypt a byte, we also change the key. *It's a bit more complicated than this*. But this is fundamentally the basic logic. In a real function, we do more complex operations with more variables like the salt(or nonce) value, the last byte we encrypted, the key checksum(against related key attacks) etc.

Here is the encryption code:
```C
uint64_t xorEncrypt(uint8_t *K, uint8_t *Salt, uint8_t KeyCheckSum, size_t InOutDataLen, uint8_t *InOutBuf)
{ // Encrypts message and returns checksum of the InOutBuf BEFORE encyption
  // SaltData is a 8 bytes uint8 array! IT IS NOT READ ONLY! IT WILL BE MANIPULATED BY THE FUNCTION!
  register uint32_t tt, M;
  register size_t t;
  register uint8_t XORVal, LastVal = 0,TmpVal; // Last PLAINTEXT byte processed. It will be an input parameter for the next encryption
  register uint64_t Checksum=0;
  register uint32_t BodyMask = GetBodyLen(K); // +1 because we will use this "Mersenne number" for & operation instead of modulus operation
  uint8_t Body[MAX_BODY_SIZE];
  
  memcpy(Body,K+SP_BODY,BodyMask);
  BodyMask--;
  
  Salt[0] ^= KeyCheckSum; LastVal += Salt[0];
  Salt[1] ^= KeyCheckSum; LastVal += Salt[1]; 
  Salt[2] ^= KeyCheckSum; LastVal += Salt[2]; 
  Salt[3] ^= KeyCheckSum; LastVal += Salt[3]; 
  Salt[4] ^= KeyCheckSum; LastVal += Salt[4]; 
  Salt[5] ^= KeyCheckSum; LastVal += Salt[5]; 
  Salt[6] ^= KeyCheckSum; LastVal += Salt[6]; 
  Salt[7] ^= KeyCheckSum; LastVal += Salt[7]; 
  
  // Initial position of the pointer depends on actual salt value
  M = (BodyMask & Salt[LastVal&(SALT_SIZE-1)]);
  //printf("xorEncrypt BodyLen: %u KeyCheckSum: %u Salt: %u\n",BodyLen, KeyCheckSum,Salt);
  
  for (t=0; t<InOutDataLen; t++)
  {
    // In first two jumps, we take 4 bits of each key body element
    XORVal = Body[M] & 0b11110000U; 
    M = (M ^ LastVal) & BodyMask; 
    XORVal |= (Body[M] & 0b00001111U); 
    M = (M ^ LastVal) & BodyMask; 
    
    for (tt=2; tt < GetNumJumps(K); tt++)
    {
      // All following jumps are based on body values
      XORVal ^= Body[M]; 
      M = (M ^ Body[M]) & BodyMask; 
    }
    Checksum += InOutBuf[t]; 
    TmpVal = InOutBuf[t]; 
    XORVal ^= LastVal; 
    XORVal ^= *(Salt + (LastVal&(SALT_SIZE-1)));
    InOutBuf[t] ^= ((uint8_t)(XORVal));
    LastVal = TmpVal; 

    Body[M] = ROL32_1(Body[M]); 
    Body[M]++;
    Body[M] ^= LastVal;
  }
  return Checksum;
} 

```

Briefly, to decypher a ciphertext, a cracker needs to find out the key, and, to find out the key, cracker needs to find out the plaintext, because the key is dynamically updated according to plaintext and the jump path is chosen accoding to plaintext+encrypted text during encryption process; Probably not impossible, in theory, but in practice very difficult!

I believe this algorithm is the future of encryption. It may not be perfect. However, I believe, this "dynamic key" model is the right way for encryption security. This project is in the public domain, thus public property, and I believe we all can benefit greatly from it. By Open Sourcing this code, I hope to make it faster and stronger together.

The code is constantly updated and improved. 

Please feel free to test it and share your success or faux-pas: ikizir@gmail.com

## Reliability

Some people ask me, how reliable it is and why I don't use approved algorithm.
A "really professional" guy, on an encryption mailing list, full of "Security Gods"(One of them wrote me privately and he was the head of cryptology chair on a reputable US Univesity for example), asked me "why don't I use DES for example. What is the difference, why is it more secure?"

Here is why.
Let's have a key body of just 128 random bytes, and 3 as the number of jumps. Forget the key body length now. 
For "every transaction", we send 8 bytes of Salt(or nonce) data unique for that transaction! Which adds 2^64 complexity.
For every transaction, we also use 1 byte of crc key checksum data. Which adds 2^8 complexity. Which makes, 2^72 as the lowest limit for any meaningful attack. Because, anytime, any bit of this values change, entire "jump path" and the "entire" ciphertext will be different! Those are the essential parameters besides key body elements for each byte to be encrypted! At least 2^72 complexity brute force attack is necessary just to make any meaningful analysis. Not breaking! Just for being sure to having eliminated the random data added to every encryption&decryption process. 

Hey! We don't take the key body into consideration yet! That was just for the randomness we add to encyrption for each operation. 
And huh! Even without taking key body into consideration; we are above the security level provided by DES; which has 2^56 complexity for brute force attacks and approved by "authorities" to protect sensible data unce open a time!

The "starting" point of the data is randomly chosen upon the salt value.
So, just to "anaylyze" or "detect" which is the "starting" position of the jump for an encryption or decryption process, we must add 2^7 possibilities.

Now, we have 2^79 brute force algorithmic complexity just to know "the jump starting point"! Again! Without taking into consideration key body! Just to start to a "meaningful attack"!

Considering we have only the key body, for every byte to be encrypted, there are 128 * 128 * 128 possibilities to obtain the number to be finally XORed with plaintext byte! 
And every time we encrypt a byte from plaintext, we encrypt a byte from key body!

When the "analyze" begins: I don't want to give huge numbers, but the rest of analyze, considering 128^3 possibilities on key body, for every byte encrypted, seems "enough hard". Am I wrong?

As I told you, I am not an expert.
I don't claim it is "impossible" to break.But those are the base numbers. I may be wrong. And this is a public place. Correct me if I am wrong please!
I just tell, for example, for my specific needs in a chat application, where the keys are not used for a very long time, it seems enough. 
Each user pair will use 4 jump level keys with 1024 byte key body for their private chats. I think, it is fairly enough.
It is up to you to decide. Take your own risk! Think carefully when to use, where to use it! All I can do is to share my ideas transparently.

The algorithm is not safe against side channel or any physical type of attack. You must take care of your phone or computer.

## Usage
```C
void xorGetKey(uint8_t NumJumps, uint32_t BodyLen, uint8_t *KeyBuf);
```
Creates an encryption key.
NumJumps is the number of jumps(or rounds) to encrypt or decrypt data. The actual maximum value is 4(But if you find it weak, I(or you) can increase that limit. I just have to write hand optimized functions). This parameter directly affects speed and strength of the algorithm. If you choose higher values, the encryption will be more secure but slower.

BodyLen is the number of bytes in the key body. It must be a power of 2 (e.g. 64,128,256,512 ...)
It has negligible impact on the speed of the algorithm, but a direct impact on strength: Higher values you choose, higher security you get. Choose large numbers especially if you are going to encrypt large files.

KeyBuf is pointer to an "already allocated" buffer to hold the entire key. To compute the size of the resulting key, you may use xorComputeKeyBufLen macro.

Suppose that we want to create a key with 4 jumps and a body size of 1024 bytes. The code will be:

```C
#define BODY_LEN 1024
#define NUM_JUMPS 4

uint8_t KeyCheckSum;
unsigned RawKeyLen = xorComputeKeyBufLen(BODY_LEN);
uint8_t *KeyBuf = (uint8_t *)malloc(RawKeyLen);
xorGetKey(NumJumps, BodyLen, KeyBuf);
KeyCheckSum = xorComputeKeyCheckSum(KeyBuf);
```

KeyCheckSum is the 8 bit CRC checksum of the key. Every time you create a key, you must also compute its checksum. In order to use the key for encryption, or decryption, we must give that checksum as a parameter.
Now, we have the key and the checksum. We want to encrypt our data.

#### Encryption and decryption

We have generic functions to encrypt or decrypt data, but, we don't suggest using them in real life. Instead, use, hand optimized HOPx versions. For 2 jump keys, use HOP2 versions, for 3 jumps use HOP3 etc.

```C
uint64_t xorEncrypt(uint8_t *K, uint8_t *Salt, uint8_t KeyCheckSum, size_t InOutDataLen, uint8_t *InOutBuf);
uint64_t xorDecrypt(uint8_t *K, uint8_t *Salt, uint8_t KeyCheckSum, size_t InOutDataLen, uint8_t *InOutBuf)
uint64_t xorEncryptHOP2(uint8_t *K, uint8_t *Salt, uint8_t KeyCheckSum, size_t InOutDataLen, uint8_t *InOutBuf);
uint64_t xorDecryptHOP2(uint8_t *K, uint8_t *Salt, uint8_t KeyCheckSum, size_t InOutDataLen, uint8_t *InOutBuf);
uint64_t xorEncryptHOP3(uint8_t *K, uint8_t *Salt, uint8_t KeyCheckSum, size_t InOutDataLen, uint8_t *InOutBuf);
uint64_t xorDecryptHOP3(uint8_t *K, uint8_t *Salt, uint8_t KeyCheckSum, size_t InOutDataLen, uint8_t *InOutBuf);
uint64_t xorEncryptHOP4(uint8_t *K, uint8_t *Salt, uint8_t KeyCheckSum, size_t InOutDataLen, uint8_t *InOutBuf);
uint64_t xorDecryptHOP4(uint8_t *K, uint8_t *Salt, uint8_t KeyCheckSum, size_t InOutDataLen, uint8_t *InOutBuf);
```
xorEncrypt encrypts data:
K is the key buffer we created earlier as shown in the example above.
Salt(or nonce, or iv whatever you want to call) is a 8 bytes long random value array. For each encryption, we must create a random 8 byte value. To obtain cryptographycally secure numbers from /dev/urandom under Linux, you can use the GetRandomNumbers function:
```C
void GetRandomNumbers(uint32_t ByteCount, uint8_t *Buffer)
```

KeyCheckSum is the 8 bit CRC we obtained via xorComputeKeyCheckSum macro as shown in the example
InOutDataLen is the number of bytes to be encrypted.
InOutBuf is the input and also output buffer. 
On return, functions return a uint64_t checksum of the plaintext.

xorDecrypt decrypts data:
K is the key buffer we created earlier as shown in the example above.
Salt(or nonce, or iv whatever you want to call) must be the same value we used to encrypt data.
KeyCheckSum is the 8 bit CRC we obtained via xorComputeKeyCheckSum macro as shown in the example
InOutDataLen is the number of bytes to be encrypted.
InOutBuf is the input and also output buffer. 
On return, functions return a uint64_t checksum of the plaintext.

Here is the code snippet taken from benchmark program to encrypt, decrypt and verify data:

```C
void Test1(unsigned NumJumps, unsigned BodyLen)
{
  unsigned long long int DLen, OriginalPlainTextCheckSum, CheckSumReturnedFromEncryptor, CheckSumReturnedFromDecryptor;
  unsigned RawKeyLen = xorComputeKeyBufLen(BodyLen);
  uint8_t *KeyBuf = (uint8_t *)malloc(RawKeyLen);
  uint8_t Data[2048],Data2[2048];
  char *Base64EncodedKeyStr, *Base64CipherText;
  uint8_t KeyCheckSum;
  uint64_t SaltData=1234;
  
  printf("----------- TEST 1: BASIC FUNCTIONALITY(%u Jumps) --------------\n",NumJumps);
  xorGetKey(NumJumps, BodyLen, KeyBuf);
  KeyCheckSum = xorComputeKeyCheckSum(KeyBuf);
  Base64EncodedKeyStr = Base64Encode((const char *)KeyBuf, RawKeyLen);
  printf("Base64 encoded key: %s\n", Base64EncodedKeyStr);

  xorAnalyzeKey(KeyBuf);
  memset(&Data, 0, sizeof(Data));
  memset(&Data2, 0, sizeof(Data2));
  DLen = TESTSTR1_LEN; 
  memcpy(Data, TESTSTR1, DLen);
  memcpy(Data2, TESTSTR1, DLen);
  OriginalPlainTextCheckSum = BufCheckSum(Data, DLen);
  CheckSumReturnedFromEncryptor = xorEncrypt(KeyBuf, (uint8_t *)(&SaltData), KeyCheckSum, DLen, Data); // We encrypt with non-optimized version
  if (OriginalPlainTextCheckSum != CheckSumReturnedFromEncryptor)
  {
    printf("Original Checksum %llu returned from BufChecksum fnc <> Checksum %llu returned from non-optimized encryptor\n",OriginalPlainTextCheckSum,CheckSumReturnedFromEncryptor);
    exit(-1);
  } else printf("OriginalPlainTextCheckSum %llu = CheckSumReturnedFromEncryptor %llu :: SUCCESS!\n",OriginalPlainTextCheckSum,CheckSumReturnedFromEncryptor);
  // Now let's encrypt with the optimized encryptor
  SaltData=1234;
  
  if (NumJumps == 2)
    CheckSumReturnedFromEncryptor = xorEncryptHOP2(KeyBuf, (uint8_t *)(&SaltData), KeyCheckSum, DLen, Data2); 
  else if (NumJumps == 3)
    CheckSumReturnedFromEncryptor = xorEncryptHOP3(KeyBuf, (uint8_t *)(&SaltData), KeyCheckSum, DLen, Data2); 
  else if (NumJumps == 4)
    CheckSumReturnedFromEncryptor = xorEncryptHOP4(KeyBuf, (uint8_t *)(&SaltData), KeyCheckSum, DLen, Data2); 
  else exit(-1);
  
  
  if (OriginalPlainTextCheckSum != CheckSumReturnedFromEncryptor)
  {
    printf("Original Checksum %llu returned from BufChecksum fnc <> Checksum %llu returned from optimized encryptor\n",OriginalPlainTextCheckSum,CheckSumReturnedFromEncryptor);
    exit(-1);
  } else printf("OriginalPlainTextCheckSum %llu = CheckSumReturnedFromOptimizedEncryptor %llu :: SUCCESS!\n",OriginalPlainTextCheckSum,CheckSumReturnedFromEncryptor);  
  if (memcmp((char *)Data, Data2, DLen) != 0)
  {
    printf("Non-optimized and optimized encryptor functions outputs are different! FAILED! FAILED!\n");
    exit(-1);
  }
    
  Base64CipherText = Base64Encode((const char *)Data, DLen);
  printf("Base64CipherText: %s\n", Base64CipherText);
  printf("\n\nDecryption process:\n\n");
  SaltData=1234;
  uint8_t *K = (uint8_t *)Base64Decode(Base64EncodedKeyStr);
  
  if (memcmp((char *)KeyBuf, (char *)K, RawKeyLen) != 0)
  {
    printf("Original key and base64 encoded and decoded keys are different!!!!!\n");
    exit(-1);
  }
  
  if (NumJumps == 2)
    CheckSumReturnedFromDecryptor = xorDecryptHOP2(K, (uint8_t *)(&SaltData), KeyCheckSum, DLen, Data);
  else if (NumJumps == 3)
    CheckSumReturnedFromDecryptor = xorDecryptHOP3(K, (uint8_t *)(&SaltData), KeyCheckSum, DLen, Data);
  else if (NumJumps == 4)
    CheckSumReturnedFromDecryptor = xorDecryptHOP4(K, (uint8_t *)(&SaltData), KeyCheckSum, DLen, Data);
  else exit(-1);
  
  if (OriginalPlainTextCheckSum != CheckSumReturnedFromDecryptor)
  {
    printf("Original Checksum %llu returned from BufChecksum fnc <> Checksum %llu returned from HOP decyptor\n",OriginalPlainTextCheckSum,CheckSumReturnedFromDecryptor);
    exit(-1);
  } else printf("OriginalPlainTextCheckSum %llu = CheckSumReturnedFromDecryptor %llu :: SUCCESS!\n",OriginalPlainTextCheckSum,CheckSumReturnedFromDecryptor);
  
  if (memcmp((char *)Data, TESTSTR1, DLen) == 0)
  {
    printf("String: %s ... Test1 result: SUCCESSFUL!!!!\n----------------------------------------\n", Data);
  }
  else {
    printf("String: %s ... Test1 result: FAILED!!!!\n----------------------------------------\n", Data);
    exit(-1);
  }
  //exit(-1);
}
```

... I am still writing the documentation --- to be continued ---
