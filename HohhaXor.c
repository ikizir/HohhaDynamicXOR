// B.
/*B.
Hohha Dynamic XOR Algorithm. Copyright (c) 2015 İsmail Kizir
Permission is hereby granted, free of charge, to any person obtaining a copy of this software 
and associated documentation files (the "Software"), to deal in the Software without restriction, 
including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, 
subject to the following conditions:
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
Alternatively you can use and distribute this file under the terms of the GNU General Public License
 */
#include <stdio.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <ctype.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/time.h>

#include <inttypes.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include "libbase64.h"
#include "HohhaXor.h"
#include "VarInt.h"

// A VERY SIMPLE RNG IMPLEMENTATION FROM WIKIPEDIA:
// NOTE : GetRandomNumbers is NOT CRYPTOGRAPHYCALLY SECURE
// FOR REAL WORLD APPLICATIONS, CHANGE GetRandomNumbers function with a cryptographically secure random number implementation
// You can find good NIST implementation in libntru source at: https://github.com/tbuktu/libntru

#define PHI 0x9e3779b9

static uint32_t Q[4096], c = 362436;

void init_rand(uint32_t x)
{
    int i;

    Q[0] = x;
    Q[1] = x + PHI;
    Q[2] = x + PHI + PHI;

    for (i = 3; i < 4096; i++)
            Q[i] = Q[i - 3] ^ Q[i - 2] ^ PHI ^ i;
}

uint32_t Rand32(void)
{
    uint64_t t, a = 18782LL;
    static uint32_t i = 4095;
    uint32_t x, r = 0xfffffffe;
    i = (i + 1) & 4095;
    t = a * Q[i] + c;
    c = (t >> 32);
    x = t + c;
    if (x < c) {
            x++;
            c++;
    }
    return (Q[i] = r - x);
}

void GetRandomNumbers(uint32_t ByteCount, void *Buffer)
{
  uint8_t *dp = Buffer;
  while (ByteCount >= sizeof(uint64_t))
  {
    *((uint64_t *)dp) = Rand32();
    dp += sizeof(uint32_t);
    ByteCount -= sizeof(uint32_t);
  }
  if (ByteCount)
  {
    uint64_t R = Rand32();
    while (ByteCount)
    {
      *dp = *(((uint8_t *)&R)+ByteCount);
      dp++;
      ByteCount--;
    }
  }
}
// ******* END OF RNG IMPLEMENTATION ***************
#define GetRandomNumbersForPadding GetRandomNumbers

//define VERBOSE
/**
 * xorGetKey creates XOR key
    The first byte will be equal to NumJumps
    Following 2 bytes is key body length
    Following SALT_SIZE(8) bytes are random nonce data(used only to encrypt packet header values like authentication codes&nonces)
    Following BodyLen bytes are random numbers  
    Result buffer must be enough to store key!! No error checking is done!!!
    Return negative on error; zero if successfull
 * @param NumJumps Number of jumps for encryption
 * @param BodyLen is the key body length.
 *        BODYLEN MUST BE A POWER OF 2.
 *        Best values are 16,32 and 64 bytes.
 *        Body lengths larger than 64 bytes(256 bits) may be vulnarable for cache&timing attacks!
 * @param KeyBuf Already allocated key buffer enough to hold key
 *        You can use xorComputeKeyBufLen(BodyLen) macro!
 * @return 0 on success non zero for errors(see HOHHA_ERROR_XXX macros)
 */
int xorGetKey(uint8_t NumJumps, uint32_t BodyLen, uint8_t *KeyBuf)
{
  if (((BodyLen-1) & BodyLen) != 0)
    return HOHHA_ERROR_KEY_BODY_LEN_MUST_BE_POWER_OF_TWO; // Key body length must be a power of 2!
  if (NumJumps < 2)
    return HOHHA_ERROR_KEY_JUMPS_MUST_BE_GREATER_THAN_ONE; // Number of jumps must be greater than or equal to 2
  if (NumJumps > MAX_NUM_JUMPS)
    return HOHHA_ERROR_KEY_MAX_NUM_JUMPS_LIMIT_EXCEEDED;
  if (BodyLen < MIN_BODY_SIZE)
    return HOHHA_ERROR_KEY_BODY_SIZE_TOO_SHORT;
  if (BodyLen > MAX_BODY_SIZE)
    return HOHHA_ERROR_KEY_BODY_SIZE_TOO_LONG;
  
#ifdef VERBOSE
  printf("Generating key ... BodyLen: %u NumJumps: %u\n",BodyLen,NumJumps);
#endif
  KeyBuf[SP_NUM_JUMPS] = (uint8_t)(NumJumps&255);
  KeyBuf[SP_BODY_LEN] = (uint8_t)((BodyLen % 256) & 0xff);
  KeyBuf[SP_BODY_LEN+1] = (uint8_t)((BodyLen / 256) & 0xff);
  GetRandomNumbers(SALT_SIZE + BodyLen, KeyBuf + SP_SALT_DATA); // Fill 4 bytes salt data with random numbers
  return 0;
}

/**
 * xorGetKey2 creates an hohha xor key with a proper header from following data
 * @param NumJumps Number of jumps
 * @param BodyLen Body length of the key
 * @param Body A buffer containing of BodyLen bytes to set a as key body
 * @param Salt A buffer containing of SALT_SIZE(8 default) bytes to set a as original key salt
 * @param KeyBuf A buffer which will contain xor key on return
 *        You can use xorComputeKeyBufLen(BodyLen) macro to compute required space for a key
 * @return 0 on success or HOHHA_ERROR_KEYXXX constants as error code 
 */
int xorGetKey2(uint8_t NumJumps, uint32_t BodyLen, uint8_t *Body, uint8_t *Salt, uint8_t *KeyBuf)
{
  if (((BodyLen-1) & BodyLen) != 0)
    return HOHHA_ERROR_KEY_BODY_LEN_MUST_BE_POWER_OF_TWO; // Key body length must be a power of 2!
  if (NumJumps < 2)
    return HOHHA_ERROR_KEY_JUMPS_MUST_BE_GREATER_THAN_ONE; // Number of jumps must be greater than or equal to 2
  if (NumJumps > MAX_NUM_JUMPS)
    return HOHHA_ERROR_KEY_MAX_NUM_JUMPS_LIMIT_EXCEEDED;
  if (BodyLen < MIN_BODY_SIZE)
    return HOHHA_ERROR_KEY_BODY_SIZE_TOO_SHORT;
  if (BodyLen > MAX_BODY_SIZE)
    return HOHHA_ERROR_KEY_BODY_SIZE_TOO_LONG;
  
#ifdef VERBOSE
  printf("Generating key ... BodyLen: %u NumJumps: %u\n",BodyLen,NumJumps);
#endif
  KeyBuf[SP_NUM_JUMPS] = (uint8_t)(NumJumps&255);
  KeyBuf[SP_BODY_LEN] = (uint8_t)((BodyLen % 256) & 0xff);
  KeyBuf[SP_BODY_LEN+1] = (uint8_t)((BodyLen / 256) & 0xff);
  memcpy(KeyBuf + SP_SALT_DATA, Salt, SALT_SIZE);
  memcpy(KeyBuf + SP_SALT_DATA + SALT_SIZE, Body, BodyLen);
  return 0;
}

// Checks key integrity and returns 0 for erronous keys
unsigned int xorCheckKeyIntegrity(const uint8_t *K, size_t TotalKeyBufLen)
{
  unsigned int BodyLen = xorGetKeyBodyLen(K);
  return ( 
    ((SP_BODY + BodyLen) == TotalKeyBufLen) &&
    (((BodyLen-1) & BodyLen) == 0) && // Key body must be a multiple of two
    (BodyLen >= MIN_BODY_SIZE && BodyLen <= MAX_BODY_SIZE) &&
    (xorGetKeyNumJumps(K) >= 2 && xorGetKeyNumJumps(K) <= MAX_NUM_JUMPS)
  );
}

void xorAnalyzeKey(const uint8_t *K)
{
  uint32_t t;
    
  printf("-------------------------- Shifting xor key analyze ----------------------------\n"
         "NumJumps: %u\nBodyLen: %u\nSalt: ", 
         (unsigned)K[0], (unsigned)xorGetKeyBodyLen(K));
  for (t=0; t < SALT_SIZE; t++)
  {
    printf(" %u", (unsigned)K[SP_SALT_DATA+t]);
  }
  printf("\n");
}

#if (!defined(PrefetchForWrite))
#define PrefetchForWrite(Addr,Locality) __builtin_prefetch(Addr, 1, Locality)
#define PrefetchForRead(Addr,Locality) __builtin_prefetch(Addr, 0, Locality)
#endif

#if SALT_SIZE != 8
#error SALT_SIZE is not supported
#endif
#define INITIAL_CHECKSUM_VAL 0xedb88320
//#define DoCheckSumInternal(xCchx, Byte) xCchx=CRC32Table[((Byte) ^ ((xCchx) >> 24)) & 0xff] ^ ((xCchx) << 8)
#define DoCheckSumInternal(xCchx, PText) { xCchx^=(PText); ROR32_1(xCchx); }

/* UNOPTIMIZED VERSION for BETTER UNDERSTANDING OF THE FUNCTIONING OF THE ALGORITHM. IT IS NOT USED IN REAL LIFE. USE OPTIMIZED VERSIONS!
 * Encrypts or decrypts InOutBuf 
 * KeyBuf is the raw key buffer
 * InOutDataLen is the length of the data to be encrypted or decrypted
 * InOutBuf is the pointer to the data to be encrypted or decrypted
 * Salt(or nonce) is a 8 bytes random number array.
 * This logic ensures us this: An original key is created with an original salt value, for example for an online communication
 * for each distinct packet, in the packet header, we can transmit a specific salt value for that packet and we can encrypt it with original key and salt
 * when the receiver receives the packet, decrypts the new salt value with the original salt value of the key and passes that salt value to function,
 * and decrypts packet body with that salt value. This method prevents "known plaintext" attacks amongst others.
 */
//define DISABLE_HAND_OPTIMIZED_FNCS
THohhaAuthCode xorEncrypt(uint8_t *K, uint8_t *Salt, size_t InOutDataLen, uint8_t *InOutBuf)
{ // Encrypts message and returns messages's 16 byte authentication code
  // SaltData is a SALT_SIZE bytes uint8 array! 
  // Our aim is to create maximum random output from "any" input. It may an all 0 file or all random distribution. It doesn't matter
  // In order to do this, we have : 
  //   Salt: 8 bytes of random salt data
  //   Body: KeyBody bytes of key body
  //   M: Our moving pointer on the key body, which tells us where we are
  //   InOutBuf: Plaintext(or ciphertext for decryption)
  // We must use those variables in order to:
  //   Create maximum random output to prevent detecting a pattern on ciphertext
  //   Hide the key body even if the attacker knows both the ciphertext and the plaintext
  // Method:
  //   Our first number to be XORed with the first plaintext byte depends on the random salt value
  //   Our starting point on the key body depends on the random salt value
  //   All subsequent ciphertext outputs depend on the starting values: Even attacker intercepts the ciphertext and plaintext,
  //       the data gathered will not be useful to deciphher subsequent encryptions. Because, they will use different salt data.
  //   To hide our key body elements
  //     We XOR at least two body elements(jumps) with each other.
  //     We create two distinct uint32 variables from Salt data: Salt1 and Salt which are dynamically updated during jumps
  //     We create two another uint32 variable  X and Y, by combining randomly chosen body elements according to salt
  //     We update key body elements according to Salt values
  //     We update salt data according to key body elements
  //     Our jump start point and steps are hidden
  //     We use the previous XOR values obtained to XOR with the next XOR values(chaining)
  // Normally, using tables are susceptible for cache timing attacks
  // Key body is copied on the stack, and it's expected be on L1 cache during whole operations. There may be rare exceptions(interruptions by the OS)
  // On modern intel processors, L1 cache accesses are 3 cycles
  // For 64 byte key body with 2 jumps, encryption and decryption are expected to run at constant time
  // We advise using 64 byte keys
  // For more info, read: http://cr.yp.to/antiforgery/cachetiming-20050414.pdf
  const uint32_t BodyMask = xorGetKeyBodyLen(K)-1; // +1 because we will use this "Mersenne number" for & operation instead of modulus operation
  uint8_t Body[BodyMask+1]; // Aligning decreased speed __attribute__((aligned(64)));
  register uint32_t Salt1,Salt2, X, Y;
  register size_t t = InOutDataLen/sizeof(uint32_t);
  register uint8_t tt;
  register uint32_t M; // This is our moving pointer on key body bytes
  register uint32_t V=INITIAL_CHECKSUM_VAL;
  register uint8_t *p;
  
  assert((InOutDataLen&3) == 0); // DataSize MUST BE ALWAYS MULTIPLE OF 4!!!
  memcpy(Body, K+SP_BODY, sizeof(Body));
  p = InOutBuf;
  // We compute our start values as much randomly as possible upon salt(or nonce or iv) value which is transmitted with every data to be encrypted or decrypted
  Salt1 = ((uint32_t)(Salt[0]) | ((uint32_t)(Salt[1]) << 8) | ((uint32_t)(Salt[2]) << 16) | ((uint32_t)(Salt[3]) << 24));
  Salt2 = ((uint32_t)(Salt[4]) | ((uint32_t)(Salt[5]) << 8) | ((uint32_t)(Salt[6]) << 16) | ((uint32_t)(Salt[7]) << 24));
  
  X = ~(((uint32_t)(Body[Salt[3]&BodyMask]) | ((uint32_t)(Body[Salt[4]&BodyMask]) << 8) | ((uint32_t)(Body[Salt[0]&BodyMask]) << 16) | ((uint32_t)(Body[Salt[6]&BodyMask]) << 24)));
  Y = ~((uint32_t)(Body[Salt[7]&BodyMask]) | ((uint32_t)(Body[Salt[2]&BodyMask]) << 8) | ((uint32_t)(Body[Salt[1]&BodyMask]) << 16) | ((uint32_t)(Body[Salt[5]&BodyMask]) << 24));
  V ^= (((uint32_t)(Body[(~Salt[5])&BodyMask]) | ((uint32_t)(Body[(~Salt[0])&BodyMask]) << 8) | ((uint32_t)(Body[(~Salt[2])&BodyMask]) << 16) | ((uint32_t)(Body[(~Salt[4])&BodyMask]) << 24)));
  // Our initial jump position in the key body depends on a random value
  M = (X^Y) & BodyMask;
  //printf("X: %u Y: %u V: %u\n", X,Y,V);
  while (t--) 
  { 
    // First jump point
    Salt1 ^= (uint32_t)(Body[M]) << 8;
    Body[M] ^= (uint8_t)(Salt2);
    M = (M^Salt2) & BodyMask; 
    ROL32_1(Salt2);
    
    // Second jump point
    Salt2 ^= (uint32_t)(Body[M]) << 16;
    Body[M] ^= (uint8_t)(Salt1);
    M = (M^V) & BodyMask; 
    ROR32_1(Salt1);
    
    // Following jumps
    for (tt=2; tt<xorGetKeyNumJumps(K); tt++)
    {
      Salt2 ^= (uint32_t)(Body[M]);
      //Body[M] = (uint8_t)(Salt1) ^ X; 
      M = (M^Salt1) & BodyMask; 
      ROR32_1(Salt1);
    }
    
    DoCheckSumInternal(V, *((uint32_t *)p));
    *((uint32_t *)p) ^= (Salt1 ^ Salt2 ^ X ^ Y);
    X ^= (uint32_t)((Body[Salt2 & BodyMask])) << 24; ROL32_1(X);
    Y ^= (uint32_t)(Body[V & BodyMask]); ROR32_1(Y);
    Salt1 ^= V;
    p += sizeof(uint32_t);
  }
  
  THohhaAuthCode Res;
  Res.S1 = htole32(Salt1);
  Res.S2 = htole32(Salt2);
  Res.X = htole32(X);
  Res.Y = htole32(Y);
  return Res;
}

THohhaAuthCode xorDecrypt(uint8_t *K, uint8_t *Salt, size_t InOutDataLen, uint8_t *InOutBuf)
{ // Decrypts message and returns CRC32 of the PLAINTEXT
  // SaltData is a 8 bytes uint8 array! 
  const uint32_t BodyMask = xorGetKeyBodyLen(K)-1; // +1 because we will use this "Mersenne number" for & operation instead of modulus operation
  uint8_t Body[BodyMask+1]; // Aligning decreased speed __attribute__((aligned(64)));
  register uint32_t Salt1,Salt2, X, Y;
  register size_t t = InOutDataLen/sizeof(uint32_t);
  register uint8_t tt;
  register uint32_t M; // This is our moving pointer on key body bytes
  register uint32_t V=INITIAL_CHECKSUM_VAL;
  register uint8_t *p;
  
  assert((InOutDataLen&3) == 0); // DataSize MUST BE ALWAYS MULTIPLE OF 4!!!
  memcpy(Body, K+SP_BODY, sizeof(Body));
  p = InOutBuf;
  // We compute our start values as much randomly as possible upon salt(or nonce or iv) value which is transmitted with every data to be encrypted or decrypted
  Salt1 = ((uint32_t)(Salt[0]) | ((uint32_t)(Salt[1]) << 8) | ((uint32_t)(Salt[2]) << 16) | ((uint32_t)(Salt[3]) << 24));
  Salt2 = ((uint32_t)(Salt[4]) | ((uint32_t)(Salt[5]) << 8) | ((uint32_t)(Salt[6]) << 16) | ((uint32_t)(Salt[7]) << 24));
  
  X = ~(((uint32_t)(Body[Salt[3]&BodyMask]) | ((uint32_t)(Body[Salt[4]&BodyMask]) << 8) | ((uint32_t)(Body[Salt[0]&BodyMask]) << 16) | ((uint32_t)(Body[Salt[6]&BodyMask]) << 24)));
  Y = ~((uint32_t)(Body[Salt[7]&BodyMask]) | ((uint32_t)(Body[Salt[2]&BodyMask]) << 8) | ((uint32_t)(Body[Salt[1]&BodyMask]) << 16) | ((uint32_t)(Body[Salt[5]&BodyMask]) << 24));
  V ^= (((uint32_t)(Body[(~Salt[5])&BodyMask]) | ((uint32_t)(Body[(~Salt[0])&BodyMask]) << 8) | ((uint32_t)(Body[(~Salt[2])&BodyMask]) << 16) | ((uint32_t)(Body[(~Salt[4])&BodyMask]) << 24)));
  // Our initial jump position in the key body depends on a random value
  M = (X^Y) & BodyMask;
  //printf("X: %u Y: %u V: %u\n", X,Y,V);
  while (t--) 
  { 
      // First jump point
      Salt1 ^= (uint32_t)(Body[M]) << 8;
      Body[M] ^= (uint8_t)(Salt2);
      M = (M^Salt2) & BodyMask;
      ROL32_1(Salt2);

      // Second jump point
      Salt2 ^= (uint32_t)(Body[M]) << 16;
      Body[M] ^= (uint8_t)(Salt1);
      M = (M^V) & BodyMask;
      ROR32_1(Salt1);

      // Following jumps
      for (tt=2; tt<xorGetKeyNumJumps(K); tt++)
      {
        Salt2 ^= (uint32_t)(Body[M]);
        //Body[M] = (uint8_t)(Salt1) ^ X;
        M = (M^Salt1) & BodyMask;
        ROR32_1(Salt1);
      }

      *((uint32_t *)p) ^= (Salt1 ^ Salt2 ^ X ^ Y);
      DoCheckSumInternal(V, *((uint32_t *)p));
      X ^= (uint32_t)((Body[Salt2 & BodyMask])) << 24; ROL32_1(X);
      Y ^= (uint32_t)(Body[V & BodyMask]); ROR32_1(Y);
      Salt1 ^= V;
      p += sizeof(uint32_t);
  }
  
  THohhaAuthCode Res;
  Res.S1 = htole32(Salt1);
  Res.S2 = htole32(Salt2);
  Res.X = htole32(X);
  Res.Y = htole32(Y);
  return Res;
} 

#ifdef DISABLE_HAND_OPTIMIZED_FNCS
inline THOPEncryptorFnc xorGetProperHOPEncryptorFnc(uint8_t *Key)
{
  return &xorEncrypt;
}
inline THOPDecryptorFnc xorGetProperHOPDecryptorFnc(uint8_t *Key)
{
  return &xorDecrypt;
}
#else
THohhaAuthCode xorEncryptHOP2(uint8_t *K, uint8_t *Salt, size_t InOutDataLen, uint8_t *InOutBuf)
{
  const uint32_t BodyMask = xorGetKeyBodyLen(K)-1; // +1 because we will use this "Mersenne number" for & operation instead of modulus operation
  uint8_t Body[BodyMask+1]; // Aligning decreased speed __attribute__((aligned(64)));
  register uint32_t Salt1,Salt2, X, Y;
  register size_t t = InOutDataLen/sizeof(uint32_t);
  register uint32_t M; // This is our moving pointer on key body bytes
  register uint32_t V=INITIAL_CHECKSUM_VAL;
  register uint8_t *p;
  
  assert((InOutDataLen&3) == 0); // DataSize MUST BE ALWAYS MULTIPLE OF 4!!!
  memcpy(Body, K+SP_BODY, sizeof(Body));
  p = InOutBuf;
  // We compute our start values as much randomly as possible upon salt(or nonce or iv) value which is transmitted with every data to be encrypted or decrypted
  Salt1 = ((uint32_t)(Salt[0]) | ((uint32_t)(Salt[1]) << 8) | ((uint32_t)(Salt[2]) << 16) | ((uint32_t)(Salt[3]) << 24));
  Salt2 = ((uint32_t)(Salt[4]) | ((uint32_t)(Salt[5]) << 8) | ((uint32_t)(Salt[6]) << 16) | ((uint32_t)(Salt[7]) << 24));
  
  X = ~(((uint32_t)(Body[Salt[3]&BodyMask]) | ((uint32_t)(Body[Salt[4]&BodyMask]) << 8) | ((uint32_t)(Body[Salt[0]&BodyMask]) << 16) | ((uint32_t)(Body[Salt[6]&BodyMask]) << 24)));
  Y = ~((uint32_t)(Body[Salt[7]&BodyMask]) | ((uint32_t)(Body[Salt[2]&BodyMask]) << 8) | ((uint32_t)(Body[Salt[1]&BodyMask]) << 16) | ((uint32_t)(Body[Salt[5]&BodyMask]) << 24));
  V ^= (((uint32_t)(Body[(~Salt[5])&BodyMask]) | ((uint32_t)(Body[(~Salt[0])&BodyMask]) << 8) | ((uint32_t)(Body[(~Salt[2])&BodyMask]) << 16) | ((uint32_t)(Body[(~Salt[4])&BodyMask]) << 24)));
  // Our initial jump position in the key body depends on a random value
  M = (X^Y) & BodyMask;
  //printf("X: %u Y: %u V: %u\n", X,Y,V);
  while (t--) 
  { 
      // First jump point
      Salt1 ^= (uint32_t)(Body[M]) << 8;
      Body[M] ^= (uint8_t)(Salt2);
      M = (M^Salt2) & BodyMask;
      ROL32_1(Salt2);

      // Second jump point
      Salt2 ^= (uint32_t)(Body[M]) << 16;
      Body[M] ^= (uint8_t)(Salt1);
      M = (M^V) & BodyMask;
      ROR32_1(Salt1);

      DoCheckSumInternal(V, *((uint32_t *)p));
      *((uint32_t *)p) ^= (Salt1 ^ Salt2 ^ X ^ Y);
      X ^= (uint32_t)((Body[Salt2 & BodyMask])) << 24; ROL32_1(X);
      Y ^= (uint32_t)(Body[V & BodyMask]); ROR32_1(Y);
      Salt1 ^= V;
      p += sizeof(uint32_t);
  }
  
  THohhaAuthCode Res;
  Res.S1 = htole32(Salt1);
  Res.S2 = htole32(Salt2);
  Res.X = htole32(X);
  Res.Y = htole32(Y);
  return Res;
} 

THohhaAuthCode xorDecryptHOP2(uint8_t *K, uint8_t *Salt, size_t InOutDataLen, uint8_t *InOutBuf)
{
  const uint32_t BodyMask = xorGetKeyBodyLen(K)-1; // +1 because we will use this "Mersenne number" for & operation instead of modulus operation
  uint8_t Body[BodyMask+1]; // Aligning decreased speed __attribute__((aligned(64)));
  register uint32_t Salt1,Salt2, X, Y;
  register size_t t = InOutDataLen/sizeof(uint32_t);
  register uint32_t M; // This is our moving pointer on key body bytes
  register uint32_t V=INITIAL_CHECKSUM_VAL;
  register uint8_t *p;
  
  assert((InOutDataLen&3) == 0); // DataSize MUST BE ALWAYS MULTIPLE OF 4!!!
  memcpy(Body, K+SP_BODY, sizeof(Body));
  p = InOutBuf;
  // We compute our start values as much randomly as possible upon salt(or nonce or iv) value which is transmitted with every data to be encrypted or decrypted
  Salt1 = ((uint32_t)(Salt[0]) | ((uint32_t)(Salt[1]) << 8) | ((uint32_t)(Salt[2]) << 16) | ((uint32_t)(Salt[3]) << 24));
  Salt2 = ((uint32_t)(Salt[4]) | ((uint32_t)(Salt[5]) << 8) | ((uint32_t)(Salt[6]) << 16) | ((uint32_t)(Salt[7]) << 24));
  
  X = ~(((uint32_t)(Body[Salt[3]&BodyMask]) | ((uint32_t)(Body[Salt[4]&BodyMask]) << 8) | ((uint32_t)(Body[Salt[0]&BodyMask]) << 16) | ((uint32_t)(Body[Salt[6]&BodyMask]) << 24)));
  Y = ~((uint32_t)(Body[Salt[7]&BodyMask]) | ((uint32_t)(Body[Salt[2]&BodyMask]) << 8) | ((uint32_t)(Body[Salt[1]&BodyMask]) << 16) | ((uint32_t)(Body[Salt[5]&BodyMask]) << 24));
  V ^= (((uint32_t)(Body[(~Salt[5])&BodyMask]) | ((uint32_t)(Body[(~Salt[0])&BodyMask]) << 8) | ((uint32_t)(Body[(~Salt[2])&BodyMask]) << 16) | ((uint32_t)(Body[(~Salt[4])&BodyMask]) << 24)));
  // Our initial jump position in the key body depends on a random value
  M = (X^Y) & BodyMask;
  //printf("X: %u Y: %u V: %u\n", X,Y,V);
  while (t--) 
  { 
      // First jump point
      Salt1 ^= (uint32_t)(Body[M]) << 8;
      Body[M] ^= (uint8_t)(Salt2);
      M = (M^Salt2) & BodyMask;
      ROL32_1(Salt2);

      // Second jump point
      Salt2 ^= (uint32_t)(Body[M]) << 16;
      Body[M] ^= (uint8_t)(Salt1);
      M = (M^V) & BodyMask;
      ROR32_1(Salt1);

      *((uint32_t *)p) ^= (Salt1 ^ Salt2 ^ X ^ Y);
      DoCheckSumInternal(V, *((uint32_t *)p));
      X ^= (uint32_t)((Body[Salt2 & BodyMask])) << 24; ROL32_1(X);
      Y ^= (uint32_t)(Body[V & BodyMask]); ROR32_1(Y);
      Salt1 ^= V;
      p += sizeof(uint32_t);
  }
  
  THohhaAuthCode Res;
  Res.S1 = htole32(Salt1);
  Res.S2 = htole32(Salt2);
  Res.X = htole32(X);
  Res.Y = htole32(Y);
  return Res;
} 

THohhaAuthCode xorEncryptHOP3(uint8_t *K, uint8_t *Salt, size_t InOutDataLen, uint8_t *InOutBuf)
{
  const uint32_t BodyMask = xorGetKeyBodyLen(K)-1; // +1 because we will use this "Mersenne number" for & operation instead of modulus operation
  uint8_t Body[BodyMask+1]; // Aligning decreased speed __attribute__((aligned(64)));
  register uint32_t Salt1,Salt2, X, Y;
  register size_t t = InOutDataLen/sizeof(uint32_t);
  register uint32_t M; // This is our moving pointer on key body bytes
  register uint32_t V=INITIAL_CHECKSUM_VAL;
  register uint8_t *p;
  
  assert((InOutDataLen&3) == 0); // DataSize MUST BE ALWAYS MULTIPLE OF 4!!!
  memcpy(Body, K+SP_BODY, sizeof(Body));
  p = InOutBuf;
  // We compute our start values as much randomly as possible upon salt(or nonce or iv) value which is transmitted with every data to be encrypted or decrypted
  Salt1 = ((uint32_t)(Salt[0]) | ((uint32_t)(Salt[1]) << 8) | ((uint32_t)(Salt[2]) << 16) | ((uint32_t)(Salt[3]) << 24));
  Salt2 = ((uint32_t)(Salt[4]) | ((uint32_t)(Salt[5]) << 8) | ((uint32_t)(Salt[6]) << 16) | ((uint32_t)(Salt[7]) << 24));
  
  X = ~(((uint32_t)(Body[Salt[3]&BodyMask]) | ((uint32_t)(Body[Salt[4]&BodyMask]) << 8) | ((uint32_t)(Body[Salt[0]&BodyMask]) << 16) | ((uint32_t)(Body[Salt[6]&BodyMask]) << 24)));
  Y = ~((uint32_t)(Body[Salt[7]&BodyMask]) | ((uint32_t)(Body[Salt[2]&BodyMask]) << 8) | ((uint32_t)(Body[Salt[1]&BodyMask]) << 16) | ((uint32_t)(Body[Salt[5]&BodyMask]) << 24));
  V ^= (((uint32_t)(Body[(~Salt[5])&BodyMask]) | ((uint32_t)(Body[(~Salt[0])&BodyMask]) << 8) | ((uint32_t)(Body[(~Salt[2])&BodyMask]) << 16) | ((uint32_t)(Body[(~Salt[4])&BodyMask]) << 24)));
  // Our initial jump position in the key body depends on a random value
  M = (X^Y) & BodyMask;
  //printf("X: %u Y: %u V: %u\n", X,Y,V);
  while (t--) 
  { 
      // First jump point
      Salt1 ^= (uint32_t)(Body[M]) << 8;
      Body[M] ^= (uint8_t)(Salt2);
      M = (M^Salt2) & BodyMask;
      ROL32_1(Salt2);

      // Second jump point
      Salt2 ^= (uint32_t)(Body[M]) << 16;
      Body[M] ^= (uint8_t)(Salt1);
      M = (M^V) & BodyMask;
      ROR32_1(Salt1);

      Salt2 ^= (uint32_t)(Body[M]);
      //Body[M] = (uint8_t)(Salt1) ^ X;
      M = (M^Salt1) & BodyMask;
      ROR32_1(Salt1);

      DoCheckSumInternal(V, *((uint32_t *)p));
      *((uint32_t *)p) ^= (Salt1 ^ Salt2 ^ X ^ Y);
      X ^= (uint32_t)((Body[Salt2 & BodyMask])) << 24; ROL32_1(X);
      Y ^= (uint32_t)(Body[V & BodyMask]); ROR32_1(Y);
      Salt1 ^= V;
      p += sizeof(uint32_t);
  }
  
  THohhaAuthCode Res;
  Res.S1 = htole32(Salt1);
  Res.S2 = htole32(Salt2);
  Res.X = htole32(X);
  Res.Y = htole32(Y);
  return Res;
} 

THohhaAuthCode xorDecryptHOP3(uint8_t *K, uint8_t *Salt, size_t InOutDataLen, uint8_t *InOutBuf)
{
  const uint32_t BodyMask = xorGetKeyBodyLen(K)-1; // +1 because we will use this "Mersenne number" for & operation instead of modulus operation
  uint8_t Body[BodyMask+1]; // Aligning decreased speed __attribute__((aligned(64)));
  register uint32_t Salt1,Salt2, X, Y;
  register size_t t = InOutDataLen/sizeof(uint32_t);
  register uint32_t M; // This is our moving pointer on key body bytes
  register uint32_t V=INITIAL_CHECKSUM_VAL;
  register uint8_t *p;
  
  assert((InOutDataLen&3) == 0); // DataSize MUST BE ALWAYS MULTIPLE OF 4!!!
  memcpy(Body, K+SP_BODY, sizeof(Body));
  p = InOutBuf;
  // We compute our start values as much randomly as possible upon salt(or nonce or iv) value which is transmitted with every data to be encrypted or decrypted
  Salt1 = ((uint32_t)(Salt[0]) | ((uint32_t)(Salt[1]) << 8) | ((uint32_t)(Salt[2]) << 16) | ((uint32_t)(Salt[3]) << 24));
  Salt2 = ((uint32_t)(Salt[4]) | ((uint32_t)(Salt[5]) << 8) | ((uint32_t)(Salt[6]) << 16) | ((uint32_t)(Salt[7]) << 24));
  
  X = ~(((uint32_t)(Body[Salt[3]&BodyMask]) | ((uint32_t)(Body[Salt[4]&BodyMask]) << 8) | ((uint32_t)(Body[Salt[0]&BodyMask]) << 16) | ((uint32_t)(Body[Salt[6]&BodyMask]) << 24)));
  Y = ~((uint32_t)(Body[Salt[7]&BodyMask]) | ((uint32_t)(Body[Salt[2]&BodyMask]) << 8) | ((uint32_t)(Body[Salt[1]&BodyMask]) << 16) | ((uint32_t)(Body[Salt[5]&BodyMask]) << 24));
  V ^= (((uint32_t)(Body[(~Salt[5])&BodyMask]) | ((uint32_t)(Body[(~Salt[0])&BodyMask]) << 8) | ((uint32_t)(Body[(~Salt[2])&BodyMask]) << 16) | ((uint32_t)(Body[(~Salt[4])&BodyMask]) << 24)));
  // Our initial jump position in the key body depends on a random value
  M = (X^Y) & BodyMask;
  //printf("X: %u Y: %u V: %u\n", X,Y,V);
  while (t--) 
  { 
      // First jump point
      Salt1 ^= (uint32_t)(Body[M]) << 8;
      Body[M] ^= (uint8_t)(Salt2);
      M = (M^Salt2) & BodyMask;
      ROL32_1(Salt2);

      // Second jump point
      Salt2 ^= (uint32_t)(Body[M]) << 16;
      Body[M] ^= (uint8_t)(Salt1);
      M = (M^V) & BodyMask;
      ROR32_1(Salt1);

      Salt2 ^= (uint32_t)(Body[M]);
      //Body[M] = (uint8_t)(Salt1) ^ X;
      M = (M^Salt1) & BodyMask;
      ROR32_1(Salt1);


      *((uint32_t *)p) ^= (Salt1 ^ Salt2 ^ X ^ Y);
      DoCheckSumInternal(V, *((uint32_t *)p));
      X ^= (uint32_t)((Body[Salt2 & BodyMask])) << 24; ROL32_1(X);
      Y ^= (uint32_t)(Body[V & BodyMask]); ROR32_1(Y);
      Salt1 ^= V;
      p += sizeof(uint32_t);
  }
  
  THohhaAuthCode Res;
  Res.S1 = htole32(Salt1);
  Res.S2 = htole32(Salt2);
  Res.X = htole32(X);
  Res.Y = htole32(Y);
  return Res;
} 

THohhaAuthCode xorEncryptHOP4(uint8_t *K, uint8_t *Salt, size_t InOutDataLen, uint8_t *InOutBuf)
{
  const uint32_t BodyMask = xorGetKeyBodyLen(K)-1; // +1 because we will use this "Mersenne number" for & operation instead of modulus operation
  uint8_t Body[BodyMask+1]; // Aligning decreased speed __attribute__((aligned(64)));
  register uint32_t Salt1,Salt2, X, Y;
  register size_t t = InOutDataLen/sizeof(uint32_t);
  register uint32_t M; // This is our moving pointer on key body bytes
  register uint32_t V=INITIAL_CHECKSUM_VAL;
  register uint8_t *p;
  
  assert((InOutDataLen&3) == 0); // DataSize MUST BE ALWAYS MULTIPLE OF 4!!!
  memcpy(Body, K+SP_BODY, sizeof(Body));
  p = InOutBuf;
  // We compute our start values as much randomly as possible upon salt(or nonce or iv) value which is transmitted with every data to be encrypted or decrypted
  Salt1 = ((uint32_t)(Salt[0]) | ((uint32_t)(Salt[1]) << 8) | ((uint32_t)(Salt[2]) << 16) | ((uint32_t)(Salt[3]) << 24));
  Salt2 = ((uint32_t)(Salt[4]) | ((uint32_t)(Salt[5]) << 8) | ((uint32_t)(Salt[6]) << 16) | ((uint32_t)(Salt[7]) << 24));
  
  X = ~(((uint32_t)(Body[Salt[3]&BodyMask]) | ((uint32_t)(Body[Salt[4]&BodyMask]) << 8) | ((uint32_t)(Body[Salt[0]&BodyMask]) << 16) | ((uint32_t)(Body[Salt[6]&BodyMask]) << 24)));
  Y = ~((uint32_t)(Body[Salt[7]&BodyMask]) | ((uint32_t)(Body[Salt[2]&BodyMask]) << 8) | ((uint32_t)(Body[Salt[1]&BodyMask]) << 16) | ((uint32_t)(Body[Salt[5]&BodyMask]) << 24));
  V ^= (((uint32_t)(Body[(~Salt[5])&BodyMask]) | ((uint32_t)(Body[(~Salt[0])&BodyMask]) << 8) | ((uint32_t)(Body[(~Salt[2])&BodyMask]) << 16) | ((uint32_t)(Body[(~Salt[4])&BodyMask]) << 24)));
  // Our initial jump position in the key body depends on a random value
  M = (X^Y) & BodyMask;
  //printf("X: %u Y: %u V: %u\n", X,Y,V);
  while (t--) 
  { 
      // First jump point
      Salt1 ^= (uint32_t)(Body[M]) << 8;
      Body[M] ^= (uint8_t)(Salt2);
      M = (M^Salt2) & BodyMask;
      ROL32_1(Salt2);

      // Second jump point
      Salt2 ^= (uint32_t)(Body[M]) << 16;
      Body[M] ^= (uint8_t)(Salt1);
      M = (M^V) & BodyMask;
      ROR32_1(Salt1);

      Salt2 ^= (uint32_t)(Body[M]);
      //Body[M] = (uint8_t)(Salt1) ^ X;
      M = (M^Salt1) & BodyMask;
      ROR32_1(Salt1);

      Salt2 ^= (uint32_t)(Body[M]);
      //Body[M] = (uint8_t)(Salt1) ^ X;
      M = (M^Salt1) & BodyMask;
      ROR32_1(Salt1);

      DoCheckSumInternal(V, *((uint32_t *)p));
      *((uint32_t *)p) ^= (Salt1 ^ Salt2 ^ X ^ Y);
      X ^= (uint32_t)((Body[Salt2 & BodyMask])) << 24; ROL32_1(X);
      Y ^= (uint32_t)(Body[V & BodyMask]); ROR32_1(Y);
      Salt1 ^= V;
      p += sizeof(uint32_t);
  }
  
  THohhaAuthCode Res;
  Res.S1 = htole32(Salt1);
  Res.S2 = htole32(Salt2);
  Res.X = htole32(X);
  Res.Y = htole32(Y);
  return Res;
} 

THohhaAuthCode xorDecryptHOP4(uint8_t *K, uint8_t *Salt, size_t InOutDataLen, uint8_t *InOutBuf)
{
  const uint32_t BodyMask = xorGetKeyBodyLen(K)-1; // +1 because we will use this "Mersenne number" for & operation instead of modulus operation
  uint8_t Body[BodyMask+1]; // Aligning decreased speed __attribute__((aligned(64)));
  register uint32_t Salt1,Salt2, X, Y;
  register size_t t = InOutDataLen/sizeof(uint32_t);
  register uint32_t M; // This is our moving pointer on key body bytes
  register uint32_t V=INITIAL_CHECKSUM_VAL;
  register uint8_t *p;
  
  assert((InOutDataLen&3) == 0); // DataSize MUST BE ALWAYS MULTIPLE OF 4!!!
  memcpy(Body, K+SP_BODY, sizeof(Body));
  p = InOutBuf;
  // We compute our start values as much randomly as possible upon salt(or nonce or iv) value which is transmitted with every data to be encrypted or decrypted
  Salt1 = ((uint32_t)(Salt[0]) | ((uint32_t)(Salt[1]) << 8) | ((uint32_t)(Salt[2]) << 16) | ((uint32_t)(Salt[3]) << 24));
  Salt2 = ((uint32_t)(Salt[4]) | ((uint32_t)(Salt[5]) << 8) | ((uint32_t)(Salt[6]) << 16) | ((uint32_t)(Salt[7]) << 24));
  
  X = ~(((uint32_t)(Body[Salt[3]&BodyMask]) | ((uint32_t)(Body[Salt[4]&BodyMask]) << 8) | ((uint32_t)(Body[Salt[0]&BodyMask]) << 16) | ((uint32_t)(Body[Salt[6]&BodyMask]) << 24)));
  Y = ~((uint32_t)(Body[Salt[7]&BodyMask]) | ((uint32_t)(Body[Salt[2]&BodyMask]) << 8) | ((uint32_t)(Body[Salt[1]&BodyMask]) << 16) | ((uint32_t)(Body[Salt[5]&BodyMask]) << 24));
  V ^= (((uint32_t)(Body[(~Salt[5])&BodyMask]) | ((uint32_t)(Body[(~Salt[0])&BodyMask]) << 8) | ((uint32_t)(Body[(~Salt[2])&BodyMask]) << 16) | ((uint32_t)(Body[(~Salt[4])&BodyMask]) << 24)));
  // Our initial jump position in the key body depends on a random value
  M = (X^Y) & BodyMask;
  //printf("X: %u Y: %u V: %u\n", X,Y,V);
  while (t--) 
  { 
      // First jump point
      Salt1 ^= (uint32_t)(Body[M]) << 8;
      Body[M] ^= (uint8_t)(Salt2);
      M = (M^Salt2) & BodyMask;
      ROL32_1(Salt2);

      // Second jump point
      Salt2 ^= (uint32_t)(Body[M]) << 16;
      Body[M] ^= (uint8_t)(Salt1);
      M = (M^V) & BodyMask;
      ROR32_1(Salt1);

      Salt2 ^= (uint32_t)(Body[M]);
      //Body[M] = (uint8_t)(Salt1) ^ X;
      M = (M^Salt1) & BodyMask;
      ROR32_1(Salt1);

      Salt2 ^= (uint32_t)(Body[M]);
      //Body[M] = (uint8_t)(Salt1) ^ X;
      M = (M^Salt1) & BodyMask;
      ROR32_1(Salt1);

      *((uint32_t *)p) ^= (Salt1 ^ Salt2 ^ X ^ Y);
      DoCheckSumInternal(V, *((uint32_t *)p));
      X ^= (uint32_t)((Body[Salt2 & BodyMask])) << 24; ROL32_1(X);
      Y ^= (uint32_t)(Body[V & BodyMask]); ROR32_1(Y);
      Salt1 ^= V;
      p += sizeof(uint32_t);
  }
  
  THohhaAuthCode Res;
  Res.S1 = htole32(Salt1);
  Res.S2 = htole32(Salt2);
  Res.X = htole32(X);
  Res.Y = htole32(Y);
  return Res;
} 

inline THOPEncryptorFnc xorGetProperHOPEncryptorFnc(uint8_t *Key)
{
  if (xorGetKeyNumJumps(Key) == 4)
    return &xorEncryptHOP4;
  if (xorGetKeyNumJumps(Key) == 3)
    return &xorEncryptHOP3;
  if (xorGetKeyNumJumps(Key) == 2)
    return &xorEncryptHOP2;
  
  return &xorEncrypt;
}
inline THOPDecryptorFnc xorGetProperHOPDecryptorFnc(uint8_t *Key)
{
  if (xorGetKeyNumJumps(Key) == 4)
    return &xorDecryptHOP4;
  if (xorGetKeyNumJumps(Key) == 3)
    return &xorDecryptHOP3;
  if (xorGetKeyNumJumps(Key) == 2)
    return &xorDecryptHOP2;
  
  return &xorDecrypt;
}
#endif
/* --------------------- PACKET CREATION FUNCTIONS: USE THESE FUNCTIONS IN YOUR APP. DON'T USE RAW ENCRYPTION --------------- */

#if defined(OBSOLETE_XOR_FNCS)
static inline uint8_t GetAlignedLenSize(size_t AlignedLen)
{
  if (AlignedLen < (1<<8))
    return 1;
  if (AlignedLen < (1<<16))
    return 2;
  if (AlignedLen < (1<<24))
    return 3;
  if (AlignedLen <= 0xffffffff)
    return 4;
  return 8;
}

static inline size_t GetCommHeaderLenByAlignedLenSize(uint8_t AlignedLenSize) 
{
  return sizeof(THohhaPacketHeader) - 8 + AlignedLenSize;
}
static inline unsigned int GetCommHeaderLenByAlignedLen(unsigned int AlignedLen)
{
  return GetCommHeaderLenByAlignedLenSize(GetAlignedLenSize(AlignedLen));
}
static inline unsigned int GetCommHeaderLenByHeader(THohhaPacketHeader *Hdr)
{
  return GetCommHeaderLenByAlignedLenSize(Hdr->AlignedLenSize & 7);
}
// This function sets the exact ciphertext or plaintext length on the hohha communication header
static inline void SetHeaderAlignedLenValue(THohhaPacketHeader *PacketHeader, size_t AlignedDataLen)
{
  uint8_t AlignedLenSize = GetAlignedLenSize(AlignedDataLen);
  
  PacketHeader->AlignedLenSize = AlignedLenSize;
  if (AlignedLenSize == 1)
    PacketHeader->AlignedLen[0] = (uint8_t)AlignedDataLen;
  else if (AlignedLenSize == 2)
  {
    PacketHeader->AlignedLen[0] = (uint8_t)(AlignedDataLen >> 8);
    PacketHeader->AlignedLen[1] = (uint8_t)(AlignedDataLen & 0xff);
  }
  else if (AlignedLenSize == 3)
  {
    PacketHeader->AlignedLen[0] = (uint8_t)((AlignedDataLen >> 16) & 0xff);
    PacketHeader->AlignedLen[1] = (uint8_t)((AlignedDataLen >> 8) & 0xff);
    PacketHeader->AlignedLen[2] = (uint8_t)(AlignedDataLen & 0xff);
  }
  else 
  {
    PacketHeader->AlignedLen[0] = (uint8_t)((AlignedDataLen >> 24) & 0xff);
    PacketHeader->AlignedLen[1] = (uint8_t)((AlignedDataLen >> 16) & 0xff);
    PacketHeader->AlignedLen[2] = (uint8_t)((AlignedDataLen >> 8) & 0xff);
    PacketHeader->AlignedLen[3] = (uint8_t)(AlignedDataLen & 0xff);
  }
}
// This function gets the Aligned ciphertext or plaintext length from the hohha communication header
static inline ssize_t GetHeaderAlignedLenValue(THohhaPacketHeader *PacketHeader)
{
  uint8_t V = PacketHeader->AlignedLenSize & 7;
  
  if (V == 1)
    return PacketHeader->AlignedLen[0];
  
  if (V == 2)
    return ((size_t)(PacketHeader->AlignedLen[0]) << 8) | PacketHeader->AlignedLen[1];
  
  if (V == 3)
    return ((size_t)(PacketHeader->AlignedLen[0]) << 16) | ((size_t)(PacketHeader->AlignedLen[1]) << 8) | PacketHeader->AlignedLen[2];
  
  if (V == 4)
    return ((size_t)(PacketHeader->AlignedLen[0]) << 24) | ((size_t)(PacketHeader->AlignedLen[1]) << 16) | ((size_t)(PacketHeader->AlignedLen[2]) << 8) | PacketHeader->AlignedLen[3];
  
  return -1;
}
#endif

/**
 * xorEncryptAndSign2 encrypts InBuf and creates a communication packet with a proper header
 * A communcation packet contains an padded data ciphertext and padded header ciphertext
 * Header is also encrypted (with original salt(or iv) on the key.
 * Header contains:
 *   4 bytes random padding data for better protection
 *   12 bytes Message Authentication code (first MAC then encyrpt method. But it's well protected by a second encryption)
 *   8 bytes random salt value used to encrypt this data
 *   Original message and padding lengths
 * @param K Key buffer in binary form
 * @param KeyCheckSum Key checksum
 * @param InDataLen Input data length(plaintext length)
 * @param InBuf Input buffer
 * @param DataAlignment Data alignment for better protection. Can be 8, 16, 32(64 is not implemented)
 * @param OutBuf output buffer. 
 *        Must be already allocated.
 *        Mmust be enough large to store (InDataLen-1 + HOHHA_PACKET_ALIGNMENT + HHLEN) bytes
 *        You can use GetHohhaExactEncryptedPacketSize(InDataLen, DataAlignment) macro to compute required memory
 */
void xorEncryptAndSign2(uint8_t *K, size_t InDataLen, const uint8_t *InBuf, uint32_t DataAlignment, uint8_t *OutBuf)
{ 
  if (!OutBuf || !(DataAlignment == 8 || DataAlignment == 16 || DataAlignment == 32 || DataAlignment == 64 || InDataLen > MAX_HOHHA_ENCRYPTION_DATA_LEN))
  { 
    //printf("INVALID DATAALIGNMENT: %d\n", DataAlignment);
    return;
  }
  
  uint8_t *OriginalSalt = K + SP_SALT_DATA;
  size_t AlignedDataLen = ALIGN_TO_ROUND_UP64(InDataLen+1,DataAlignment);
  THOPEncryptorFnc EncryptorFnc = xorGetProperHOPEncryptorFnc(K);
  uint8_t RPad;
  ssize_t LPad;
  
  THohhaPacketHeader *PacketHeader = (THohhaPacketHeader *)OutBuf;
  //*((uint64_t *)&(PacketHeader->AlignedLen)) = Rand64();
  GetRandomNumbers(8, (void *)&(PacketHeader->AlignedLen));
  uint8_t *OBufStart = OutBuf + HOHHA_PACKET_HEADER_LEN;
  
  PacketHeader->Padding = (uint8_t)(AlignedDataLen-InDataLen);
  RPad = PacketHeader->Padding >> 1;
  LPad = PacketHeader->Padding - RPad;
  
  // First, let's create a new salt value and its padding data, unique for this transmission and copy original salt data to a buffer
/*#if (SALT_SIZE == 8 && HEADER_SALT_PADDING_SIZE == 4)
  *((uint32_t *)&(PacketHeader->SaltProtectionPadding)) = Rand64();
  *((uint64_t *)&(PacketHeader->Salt)) = Rand64();
#else*/
  GetRandomNumbers(SALT_SIZE+HEADER_SALT_PADDING_SIZE, (uint8_t *)&(PacketHeader->SaltProtectionPadding));
//#endif

  // Then, let's encode aligned data size as a variable unsigned integer
  EncodeVarUInt64(AlignedDataLen, (uint8_t *)&PacketHeader->AlignedLen);
  // Fill padding data if necessary
  if (LPad)
  {
    GetRandomNumbersForPadding(LPad, OBufStart);
    // Then, we put right padding characters if necessary
    if (RPad)
      GetRandomNumbersForPadding(RPad, OBufStart + LPad + InDataLen);
  }
  
  // Now, let's copy our plaintext to new packet
  memcpy(OBufStart + LPad, InBuf, InDataLen);
  
  // Now, let's encrypt our data
  PacketHeader->AuthCode = EncryptorFnc(K, PacketHeader->Salt, AlignedDataLen, OBufStart);
  //printf("PacketHeader->PlaintextCRC: %u\n",PacketHeader->PlaintextCRC);
  // We encrypted our packet. Now, let's encrypt packet header with original salt and key
  EncryptorFnc(K, OriginalSalt, HOHHA_PACKET_HEADER_LEN, OutBuf);
}

uint8_t *xorEncryptAndSign(uint8_t *K, size_t InDataLen, uint8_t *InBuf, uint32_t DataAlignment)
{ // This function encrypts InBuf and creates a communication packet with a proper header
  // Allocates and returns encrypted packet data with size equal to HOHHA_TOTAL_COMM_PACKET_SIZE(DataSize)
  // If DoNotEncrypt is true, data will not be encrypted and copied into the packet as plaintext
  if (!(DataAlignment == 8 || DataAlignment == 16 || DataAlignment == 32 || DataAlignment == 64))
  {
    //printf("INVALID DATAALIGNMENT: %d\n", DataAlignment);
    return NULL;
  }
  
  uint8_t *OutBuf = malloc(GetHohhaExactEncryptedPacketSize(InDataLen, DataAlignment));
  
  if (OutBuf)
    xorEncryptAndSign2(K, InDataLen, InBuf, DataAlignment, OutBuf);
  return OutBuf;
}

uint8_t *xorDecryptAndVerify(uint8_t *K, size_t TotalPacketLen, uint8_t *InOutBuf, ssize_t *PlainTextLen)
{ // Decrypts the packet and returns a pointer to decrypted data(NULL on error)
  // On return, PlainTextLen will contain length of the plaintext on success or negative on error
  THohhaPacketHeader *PacketHeader = (THohhaPacketHeader *)InOutBuf;
  uint8_t *tp = (uint8_t *)&PacketHeader->AlignedLen;

  if (TotalPacketLen < (HOHHA_PACKET_HEADER_LEN + 8))
  {
    *PlainTextLen = HOHHA_ERROR_INVALID_HEADER;
    return NULL; 
  }
  //printf("PacketHeader->AlignedLenSize: %u\n", PacketHeader->AlignedLenSize);
  
  uint8_t *OriginalSalt = K + SP_SALT_DATA;
  THOPDecryptorFnc DecryptorFnc = xorGetProperHOPDecryptorFnc(K);

  // First, we must decrypt the header with key and original salt value
  DecryptorFnc(K, OriginalSalt, HOHHA_PACKET_HEADER_LEN, InOutBuf);
  // Then, let's read varint encoded packet length from decrypted header
  *PlainTextLen = DecodeVarUInt64(&tp, 7);
/*  printf("#xorDecryptAndVerify: Packet header: [PlainTextLen: %lld Packet Salt: ", (long long int)(*PlainTextLen));
  for (unsigned t=0; t < SALT_SIZE; t++)
  {
    printf(" %u", PacketHeader->Salt[t]);
  }
  printf("\n");*/


  // Let's check if it matches length of the packet given as parameter
  if ((TotalPacketLen-HOHHA_PACKET_HEADER_LEN) != *PlainTextLen)
  {
    *PlainTextLen = HOHHA_ERROR_INVALID_PLAINTEXT_LEN_CORRUPTED_PACKET; // Invalid plaintext length. Corrupted packet
    return NULL; 
  }
  // Then, we must decrypt the packet with salt value obtained from header
  THohhaAuthCode AuthCode = DecryptorFnc(K, PacketHeader->Salt, *PlainTextLen, InOutBuf + HOHHA_PACKET_HEADER_LEN);
  // Now, let's compute exact plaintext size. Because *PlainTextLen still contains aligned data length
  size_t LeftPad = PacketHeader->Padding - (PacketHeader->Padding >> 1);
  //size_t RightPad = PacketHeader->Padding - LeftPad;
  *PlainTextLen -= PacketHeader->Padding;
  //printf("Real data size: %lld Pad: %u Decrypted data from encrypted packet:::  %s\n",(long long int)(*PlainTextLen), PacketHeader->Padding, InOutBuf+HHLEN+((THohhaPacketHeader *)InOutBuf)->LeftPadding);
  // Let's make integrity checks:
  if (AuthCodesMatch(&PacketHeader->AuthCode, &AuthCode))
    return InOutBuf+HOHHA_PACKET_HEADER_LEN+LeftPad;

  *PlainTextLen = HOHHA_ERROR_CRC_MISMATCH_CORRUPTED_PACKET; // CRC mismatch
  return NULL; 
}
