# HohhaDynamicXOR
Hohha Dynamic XOR Encryption Algorithm Theory and its C implementation:

I would really want, to promise my customers "An approved Standart Security". 
But a real "security" on which they could rely on; and focus on my commercial products.
What I am doing, is not something I desire.
The history of "approved standards" is a proof to not to trust to so called "Security Authorities", "Experts" or "Cryptography Gods".
Do you want proof:
https://en.wikipedia.org/wiki/Transport_Layer_Security
This is a "proof"! A real proof to not to trust to "approved standarts"! Not enough? Try this one:
https://vikingvpn.com/blogs/security/visualizing-weak-encryption-experiments-with-aes
and see with your own eyes what "protected" our secrecy for years!

SSL 3.0 doesn't include "any" secure encryption implementation.
AES 256 CBC is not included in TLS 1.3 draft.
All others are slow and again, untrustable considering the history.

I'd rather prefer to try to develop my own and improve it by seeing my mistakes and my bottlenecks with the transparent help from the community.

I am not a "crypto expert", I haven't mathematical background to prove that's "secure", as the "authorities" do!  
But I believe in common sense and collaboration.
I'd rather prefer to try to improve transparently a collaborative work, than relying on suspicious "Cryptoanalysis Gods" and "Authorities"!
If you think it is breakable, you're welcome, this is why it's in public domain. Please tell us "how"! Let's think together and improve it. 
We will all use this for our specific needs. And if we think carefully, we can adapt it to different requirements. Nobody prevents us from creating derivatives. This is freedom and the spirit of "open source".

## Algorithm

Hohha Dynamic XOR is a new symmetric encryption algorithm developed for Hohha Secure Instant Messaging Platform and opened to the public via dual licence MIT and GPL.

The essential logic of the algorithm is using the key as a "jump table" which is dynamically updated with every "jump".
Our aim is to create maximum random output from "any" input. It may an all 0 file or all random distribution. It doesn't matter. In order to do this, we have : 

* Salt: 8 bytes of random salt data
* KeyCheckSum(or KC): 4 bytes of key body crc
* Body: KeyBody bytes of key body
* M: Our moving pointer on the key body, which tells us where we are
* InOutBuf: Plaintext(or ciphertext for decryption)
* We must use those variables in order to:
*   Create maximum random output to prevent detecting a pattern on ciphertext
*   Hide the key body even if the attacker knows both the ciphertext and the plaintext

Method:

*   Our first number to be XORed with the first plaintext byte completely depends on the random salt value
*   Our starting point on the key body completely depends on the random salt value
*   All subsequent ciphertext outputs depend on the starting values: Even attacker intercepts the ciphertext and plaintext,
*       the data gathered will not be useful for subsequent encryptions. Because, they will use different salt data.
*   To hide our key body elements
*     We XOR at least two body elements(jumps) with each other.
*     We change 2 pseudo random bits of two random positions of this XOR result according to our salt data
*     We change 1 pseudo random bit at a pseudo random position of this XOR result according to our jump position; 
*     Our jump start point and steps are hidden
*     We update our key body according the last XOR value, in order to add a pseudo randomness and to be sure it follows a different path, 
*     we add 1 bit of pseudo randomness according to key body crc which is not used for anything else in the function
*     So, for every byte encrypted, one key body element(at an unknown position to attacker) is set to a different value
*     We use the previous XOR value obtained to XOR with the next XOR value(chaining)
  
Briefly, we start from a random position, we make random steps, we xor hidden body values and every time we encrypt a byte, we also change this unknown body values. And the result of the next encrypted ciphertext depends on the previous one. This is fundamentally the basic logic. 
</pre>
Here is the encryption code:
```C
uint64_t xorEncrypt(uint8_t *K, uint8_t *Salt, uint32_t KeyCheckSum, size_t InOutDataLen, uint8_t *InOutBuf)
{ // Encrypts message and returns checksum of the PLAINTEXT
  // SaltData is a 8 bytes uint8 array! IT IS NOT READ ONLY! IT WILL BE MANIPULATED BY THE FUNCTION!
  // Our aim is to create maximum random output from "any" input. It may an all 0 file or all random distribution. It doesn't matter
  // In order to do this, we have : 
  //   Salt: 8 bytes of random salt data
  //   KeyCheckSum(or KC): 4 bytes of key body crc
  //   Body: KeyBody bytes of key body
  //   M: Our moving pointer on the key body, which tells us where we are
  //   InOutBuf: Plaintext(or ciphertext for decryption)
  // We must use those variables in order to:
  //   Create maximum random output to prevent detecting a pattern on ciphertext
  //   Hide the key body even if the attacker knows both the ciphertext and the plaintext
  // Method:
  //   Our first number to be XORed with the first plaintext byte completely depends on the random salt value
  //   Our starting point on the key body completely depends on the random salt value
  //   All subsequent ciphertext outputs completely depend on the starting values: Even attacker intercepts the ciphertext and plaintext,
  //       the data gathered will not be useful for subsequent encryptions. Because, they will use different salt data.
  //   To hide our key body elements
  //     We XOR at least two body elements(jumps) with each others.
  //     We change 2 pseudo random bits of two random positions of this XOR result according to our salt data
  //     We change 1 pseudo random bit at a pseudo random position of this XOR result according to our jump position; 
  //     Our jump start point and steps are hidden
  //     We update our key body according the last XOR value; but to add a pseudo randomness and to ensure to follow a different path, 
  //        we add 1 bit of pseudo randomness according to key body crc which is not used for anything else in the function
  //        So, for every byte encrypted, one key body element(at an unknown position to attacker) is set to a different value
  //     We use the previous XOR value obtained to XOR with the next XOR value(chaining)
  
  register uint32_t Salt1,Salt2;
  register uint8_t tt;
  register size_t t;
  register uint32_t XORVal; 
  register uint32_t M; // This is our moving pointer on key body bytes
  register uint32_t KC=KeyCheckSum; 
  register uint64_t Checksum=0;
  register uint32_t BodyMask = GetBodyLen(K)-1; // +1 because we will use this "Mersenne number" for & operation instead of modulus operation
  register uint8_t *p = InOutBuf, *bp;
  uint8_t Body[MAX_BODY_SIZE];
  
  memcpy(Body,K+SP_BODY, BodyMask+1);
  
  // We compute our start values as much randomly as possible upon salt(or nonce or iv) value which is transmitted with every data to be encrypted or decrypted
  XORVal = (((Salt[0] ^ Salt[1]) & (Salt[2] | Salt[3])) & ((Salt[4] ^ Salt[7]) ^ (Salt[5] ^ Salt[6]))) & 255;
  Salt1 = (uint32_t)(Salt[0]) & ((uint32_t)(Salt[1]) << 8) & ((uint32_t)(Salt[2]) << 16) & ((uint32_t)(Salt[3]) << 24);
  Salt2 = (uint32_t)(Salt[4]) & ((uint32_t)(Salt[5]) << 8) & ((uint32_t)(Salt[6]) << 16) & ((uint32_t)(Salt[7]) << 24);
  
  // Our initial jump position in the key body depends on a random value
  M = (BodyMask & Salt2);
  
  for (t=0; t<InOutDataLen; t++)
  { 
    XORVal &= 0xff;
    bp = (Body + M);
    Checksum += *p; 
    *bp ^= (uint8_t)(XORVal) ^ (uint8_t)(1 << (KC&7));  // Add a pseudo-random bit based on key crc
    ROL32_1(KC); 
    *p ^= ((uint8_t)(XORVal));

    // First jump
    XORVal ^=  *bp; 
    XORVal ^= (uint8_t)((uint8_t)1 << (uint8_t)(Salt1&7)); ROL32_1(Salt2); // Add a pseudo-random bit based on first part of the Salt
    M = (M ^ XORVal) & BodyMask; 
    XORVal ^= (uint8_t)((uint8_t)1 << (uint8_t)(Salt2&7)); ROL32_1(Salt1); // Add another pseudo-random bit based on second part of the Salt
    
    // Second jump
    bp = (Body + M);
    XORVal ^= *bp; 
    M = (M ^ Salt1) & BodyMask;
    XORVal ^= (1 << (M&7)); // Add another pseudo-random bit based on our position on key body
    
    for (tt=2; tt < GetNumJumps(K); tt++)
    {
      // All following jumps are based on body values
      bp = (Body + M); 
      XORVal ^= *bp; 
      M = (M ^ XORVal) & BodyMask;;  
    }
    p++;
  }
  return Checksum;
} 

```

Briefly, to decypher a ciphertext, a cracker needs to find out the key, and, to find out the key, cracker needs to find out the plaintext and the random value which, isi different for every encryption. The key is also dynamically updated according to plaintext and the random value and the jump path is chosen accoding to plaintext+encrypted text during encryption process; Probably not impossible, in theory, but in practice very difficult!

I believe this algorithm is the future of encryption. It may not be perfect. However, I believe, this "dynamic key" model is the right way for encryption security. This project is in the public domain, thus public property, and I believe we all can benefit greatly from it. By Open Sourcing this code, I hope to make it faster and stronger together.

The algorithm is quite young, but, as demonstrated by the visual proofs at my blog http://ismail-kizir.blogspot.com.tr/2015/11/visual-proofs-of-hohha-dynamic-xor.html
, it seems to have a good random distribution and to be promising. 
The algorithm is considered to be stable unless proven otherwise by the tests we will apply.


Please feel free to test it and share your success or faux-pas: ikizir@gmail.com

## Reliability

Better see it yourself first: http://ismail-kizir.blogspot.com.tr/2015/11/visual-proofs-of-hohha-dynamic-xor.html

Some people ask me, how reliable it is and why I don't use approved algorithm.
A "really professional" guy, on an encryption mailing list, full of "Security Gods"(One of them wrote me privately and he was the head of cryptology chair on a reputable US Univesity for example), asked me "why don't I use DES for example. What is the difference, why is it more secure?"

Here is why.
Let's have a key body of just 128 random bytes, and 3 as the number of jumps. Forget the key body length now. 
For "every transaction", we send 8 bytes of Salt(or nonce) data unique for that transaction! Which adds 2^64 complexity.
For every transaction, we also use 4 byte of crc key checksum data. Which adds 2^32 complexity. Which makes, 2^96 as the lowest limit for any meaningful attack. Because, anytime, any bit of this values change, entire "jump path" and the "entire" ciphertext will be different! Those are the essential parameters besides key body elements for each byte to be encrypted! At least 2^96 complexity brute force attack is necessary just to make any meaningful analysis. Not breaking! Just for being sure to having eliminated the random data added to every encryption&decryption process. 

Hey! We don't take the key body into consideration yet! That was just for the randomness we add to encyrption for each operation. 
And huh! Even without taking key body into consideration; we are above the security level provided by DES; which has 2^56 complexity for brute force attacks and approved by "authorities" to protect sensible data unce open a time!

Now, we have 2^96 brute force algorithmic complexity just to know "the jump starting point"! Again! Without taking into consideration key body! Just to start to a "meaningful attack"!

Considering we have only the key body, for every byte to be encrypted, there are 128 * 128 * 128 possibilities to obtain the number to be finally XORed with plaintext byte! 
And every time we encrypt a byte from plaintext, we encrypt a byte from key body!

When the "analyze" begins: I don't want to give huge numbers, but the rest of analyze, considering 128^3 possibilities on key body, for every byte encrypted, seems "enough hard". Am I wrong?

If you want me to give a number: The brute force attack complexity to break this algorithm is: 
  2^64 * 2^(KeyBodyLen*8) for key: 2^1112 for 256 bytes key body length. 

As I told you, I am not an expert.
I don't claim it is "impossible" to break.But those are the base numbers. I may be wrong. And this is a public place. Correct me if I am wrong please!
I just tell, for example, for my specific needs in a chat application, where the keys are not used for a very long time, it seems enough. 
Each user pair will use 4 jump level keys with 256 byte key body for their private chats. I think, it is fairly enough.
It is up to you to decide. Take your own risk! Think carefully when to use, where to use it! All I can do is to share my ideas transparently. 

There isn't any specific precautions against side channel or any physical type of attack. You must take care of your phone or computer.
Physical attacks are usually applied by Intelligence Services for highly suspicious persons; it is not my concern, -and I don't want- to protect this kind of people. Even if they are innocent, they can use another algorithm. My goal is to prevent technical surveilance of ordinary people in order to protect their personal privacy; not to protect criminals. 
Intelligence services don't spend resources to physically follow anyone without reasonable suspicion. Even if they do, I don't want to confront with Intelligence Services for criminals. Even trying to block their "technical surveilance of ordinary people" is a "dangerous act". 

So far, we detected a "unique" vulnarability, which can be "theoretically" defended by the "Crypto Experts": Intercepting both the plaintext AND the salt(nonce). But we consider it only "theoretical" because, key's original salt value is only used to encrypt&decrypt salt values to be transmitted with each ciphertext. Salt values are random by nature. If someone claims this "theoretical possibility", he must also explain us "how" he can intercept the nonce value! But anyway, a "theoretical possibility" is still a threat and you must consider this possibility in your real life applications.

But, we have also found a way to turn this "theoretical disadvantage" into a "practical advantage", by changing "Key's original salt value regularly". We will elaborate this in detail; later in the documentation(Sorry the documentation is still incomplete).

## Usage
```C
int xorGetKey(uint8_t NumJumps, uint32_t BodyLen, uint8_t *KeyBuf)
{
  // Creates XOR key
  // The first byte will be equal to NumJumps
  // Following 2 bytes is key body length
  // Following 4 bytes are random salt data
  // Following BodyLen bytes are random numbers obtained from buffered /dev/urandom data. BODYLEN MUST BE A POWER OF 2!
  // Result buffer must be enough to store key!! No error checking is done!!!
  // Return negative on error; zero if successfull

  if (((BodyLen-1) & BodyLen) != 0)
    return -1; // Key body length must be a power of 2!
  if (NumJumps < 2)
    return -2; // Number of jumps must be greater than or equal to 2
  if (NumJumps > MAX_NUM_JUMPS)
    return -3;
  if (BodyLen < 16)
    return -4;
  if (BodyLen > MAX_BODY_SIZE)
    return -5;
  KeyBuf[SP_NUM_JUMPS] = (uint8_t)(NumJumps&255);
  KeyBuf[SP_BODY_LEN] = (uint8_t)((BodyLen % 256) & 0xff);
  KeyBuf[SP_BODY_LEN+1] = (uint8_t)((BodyLen / 256) & 0xff);
  GetRandomNumbers(SALT_SIZE + BodyLen, KeyBuf + SP_SALT_DATA); // Fill 8 bytes salt + key body data with random numbers
  return 0;
}

```
Creates an encryption key.
NumJumps is the number of jumps(or rounds) to encrypt or decrypt data. The actual maximum value is 4(But if you find it weak, We(or you) can increase that limit. We just have to write hand optimized functions). This parameter directly affects speed and strength of the algorithm. If you choose higher values, the encryption will be more secure but slower. 
For a busy site with no critical data, 2 jumps is ideal.
We suggest using minimum 3 jumps for critical data. 

BodyLen is the number of bytes in the key body. It must be a power of 2 (e.g. 64,128,256 ...). 
We set current key body "hard" maximum limit to 256 due to our algorithm design. If you want to create derivatives to use higher key body lengths, you must make some minor modifications on encryptor and decryptor function to assure right key coverage. 
It has negligible impact on the speed of the algorithm, but a direct impact on strength: Higher values you choose, higher security you get. Choose large numbers especially if you are going to encrypt large files.

KeyBuf is pointer to an "already allocated" buffer to hold the entire key. To compute the size of the resulting key, you may use xorComputeKeyBufLen macro.

Suppose that we want to create a key with 2 jumps and a body size of 128 bytes, which are fairly enough for most cases. The code will be:

```C
#define BODY_LEN 128
#define NUM_JUMPS 2

uint32_t KeyCheckSum;
unsigned RawKeyLen = xorComputeKeyBufLen(BODY_LEN);
uint8_t *KeyBuf = (uint8_t *)malloc(RawKeyLen);
Err = xorGetKey(NumJumps, BodyLen, KeyBuf);
if (Err != 0)
{
  printf("Couldn't create the key. Error: %d\n",Err);
  exit(-1);
}
KeyCheckSum = xorComputeKeyCheckSum(KeyBuf);
```

KeyCheckSum is the 32 bit CRC checksum of the key. Every time you create a key, you must also compute its checksum. In order to use the key for encryption, or decryption, we must give that checksum as a parameter.
Now, we have the key and the checksum. We want to encrypt our data.

Every key is created with it's own Salt(or iv) value.
This Salt must "only" be used to encrypt salt values. For each encryption.
When you want to encrypt a data, you must first create an 8 random bytes as Salt value of that encryption. Let's call it Nonce.
You must encrypt your data with Nonce; you must encrypt Nonce with key's original salt and transmit ciphertext and salt to receiver.
It is extremely crucial to transmit Nonce secretly. Or, your encryption is nearly useless. This is the unique weakness of algorithm I've detected so far: If the attacker intercepts both the plaintext AND the actual salt(nonce) used for encryption, algorithm will be vulnerable.
If the attacker intercepts just the plaintext, but not the nonce; it is not an issue. 

#### Encryption and decryption

We have generic functions to encrypt or decrypt data, but, we don't suggest using them in real life. Instead, use, hand optimized HOPx versions. For 2 jump keys, use HOP2 versions, for 3 jumps use HOP3 etc.

```C
uint64_t xorEncrypt(uint8_t *K, uint8_t *Salt, uint32_t KeyCheckSum, size_t InOutDataLen, uint8_t *InOutBuf);
uint64_t xorDecrypt(uint8_t *K, uint8_t *Salt, uint32_t KeyCheckSum, size_t InOutDataLen, uint8_t *InOutBuf)
uint64_t xorEncryptHOP2(uint8_t *K, uint8_t *Salt, uint32_t KeyCheckSum, size_t InOutDataLen, uint8_t *InOutBuf);
uint64_t xorDecryptHOP2(uint8_t *K, uint8_t *Salt, uint32_t KeyCheckSum, size_t InOutDataLen, uint8_t *InOutBuf);
uint64_t xorEncryptHOP3(uint8_t *K, uint8_t *Salt, uint32_t KeyCheckSum, size_t InOutDataLen, uint8_t *InOutBuf);
uint64_t xorDecryptHOP3(uint8_t *K, uint8_t *Salt, uint32_t KeyCheckSum, size_t InOutDataLen, uint8_t *InOutBuf);
uint64_t xorEncryptHOP4(uint8_t *K, uint8_t *Salt, uint32_t KeyCheckSum, size_t InOutDataLen, uint8_t *InOutBuf);
uint64_t xorDecryptHOP4(uint8_t *K, uint8_t *Salt, uint32_t KeyCheckSum, size_t InOutDataLen, uint8_t *InOutBuf);
```
xorEncrypt encrypts data:
K is the key buffer we created earlier as shown in the example above.
Salt(or nonce, or iv whatever you want to call) is a 8 bytes long random value array. For each encryption, we must create a random 8 byte value. To obtain cryptographycally secure numbers from /dev/urandom under Linux, you can use the GetRandomNumbers function:
```C
void GetRandomNumbers(uint32_t ByteCount, uint8_t *Buffer)
```

KeyCheckSum is the 32 bit CRC we obtained via xorComputeKeyCheckSum macro as shown in the example
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
  uint32_t KeyCheckSum;
  uint64_t OriginalSaltData, SaltData;
  
  
  GetRandomNumbers(SALT_SIZE, (uint8_t *)&OriginalSaltData); // Fill salt data with random numbers
  SaltData = OriginalSaltData;
  
  printf("----------- TEST 1: BASIC FUNCTIONALITY(%u Jumps) --------------\n",NumJumps);
  int Err = xorGetKey(NumJumps, BodyLen, KeyBuf);
  if (Err != 0)
  {
    printf("Couldn't create the key. Error: %d\n",Err);
    exit(-1);
  }
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
  SaltData=OriginalSaltData;
  
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
  SaltData=OriginalSaltData;
  uint8_t *K = (uint8_t *)Base64Decode(Base64EncodedKeyStr);
  
  if (memcmp((char *)KeyBuf, (char *)K, RawKeyLen) != 0)
  {
    printf("Original key and base64 encoded and decoded keys are different!!!!!\n");
    exit(-1);
  }
  //CheckSumReturnedFromDecryptor = xorDecrypt(K, (uint8_t *)(&SaltData), KeyCheckSum, DLen, Data);
  
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
In real life scenarios, it is crucial to transmit Salt data secretly.
In order to realize this, you must create a random salt; use that random salt to encrypt the plaintext and you must encrypt the salt with the key, using key's original salt data.
The receiver will first decrypt the salt data using key's original salt data in order to obtain actual salt data, then will decrypt the ciphertext using this actual salt data. I am going to publish source code examples here.

I will put here the real life code samples from my own applications.
... I am still writing the documentation --- to be continued ---
