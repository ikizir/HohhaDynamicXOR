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

/* ---------------------------- BASE64 ENCODE/DECODE FUNCTIONS -------------------------------------
 */
/*
cencoder.c - c source to a base64 encoding algorithm implementation

This is part of the libb64 project, and has been placed in the public domain.
For details, see http://sourceforge.net/projects/libb64
*/

typedef enum
{
	step_A, step_B, step_C
} base64_encodestep;

typedef struct
{
	base64_encodestep step;
	char result;
	int stepcount;
} base64_encodestate;
typedef enum
{
	step_a, step_b, step_c, step_d
} base64_decodestep;

typedef struct
{
	base64_decodestep step;
	char plainchar;
} base64_decodestate;
const int CHARS_PER_LINE = 72;

void base64_init_encodestate(base64_encodestate* state_in)
{
	state_in->step = step_A;
	state_in->result = 0;
	state_in->stepcount = 0;
}

char base64_encode_value(char value_in)
{
	static const char* encoding = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	if (value_in > 63) return '=';
	return encoding[(int)value_in];
}

int base64_encode_block(const char* plaintext_in, int length_in, char* code_out, base64_encodestate* state_in)
{
	const char* plainchar = plaintext_in;
	const char* const plaintextend = plaintext_in + length_in;
	char* codechar = code_out;
	char result;
	char fragment;
	
	result = state_in->result;
	
	switch (state_in->step)
	{
		while (1)
		{
	case step_A:
			if (plainchar == plaintextend)
			{
				state_in->result = result;
				state_in->step = step_A;
				return codechar - code_out;
			}
			fragment = *plainchar++;
			result = (fragment & 0x0fc) >> 2;
			*codechar++ = base64_encode_value(result);
			result = (fragment & 0x003) << 4;
	case step_B:
			if (plainchar == plaintextend)
			{
				state_in->result = result;
				state_in->step = step_B;
				return codechar - code_out;
			}
			fragment = *plainchar++;
			result |= (fragment & 0x0f0) >> 4;
			*codechar++ = base64_encode_value(result);
			result = (fragment & 0x00f) << 2;
	case step_C:
			if (plainchar == plaintextend)
			{
				state_in->result = result;
				state_in->step = step_C;
				return codechar - code_out;
			}
			fragment = *plainchar++;
			result |= (fragment & 0x0c0) >> 6;
			*codechar++ = base64_encode_value(result);
			result  = (fragment & 0x03f) >> 0;
			*codechar++ = base64_encode_value(result);
			
			++(state_in->stepcount);
			if (state_in->stepcount == CHARS_PER_LINE/4)
			{
				//*codechar++ = '\n';
				state_in->stepcount = 0;
			}
		}
	}
	/* control should not reach here */
	return codechar - code_out;
}

int base64_encode_blockend(char* code_out, base64_encodestate* state_in)
{
	char* codechar = code_out;
	
	switch (state_in->step)
	{
	case step_B:
		*codechar++ = base64_encode_value(state_in->result);
		*codechar++ = '=';
		*codechar++ = '=';
		break;
	case step_C:
		*codechar++ = base64_encode_value(state_in->result);
		*codechar++ = '=';
		break;
	case step_A:
		break;
	}
	//*codechar++ = '\n';
	
	return codechar - code_out;
}

int base64_decode_value(char value_in)
{
	static const char decoding[] = {62,-1,-1,-1,63,52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-2,-1,-1,-1,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,-1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51};
	static const char decoding_size = sizeof(decoding);
	value_in -= 43;
	if (value_in < 0 || value_in >= decoding_size) return -1;
	return decoding[(int)value_in];
}

void base64_init_decodestate(base64_decodestate* state_in)
{
	state_in->step = step_a;
	state_in->plainchar = 0;
}

int base64_decode_block(const char* code_in, const int length_in, char* plaintext_out, base64_decodestate* state_in)
{
	const char* codechar = code_in;
	char* plainchar = plaintext_out;
	char fragment;
	
	*plainchar = state_in->plainchar;
	
	switch (state_in->step)
	{
		while (1)
		{
	case step_a:
			do {
				if (codechar == code_in+length_in)
				{
					state_in->step = step_a;
					state_in->plainchar = *plainchar;
					return plainchar - plaintext_out;
				}
				fragment = (char)base64_decode_value(*codechar++);
			} while (fragment < 0);
			*plainchar    = (fragment & 0x03f) << 2;
	case step_b:
			do {
				if (codechar == code_in+length_in)
				{
					state_in->step = step_b;
					state_in->plainchar = *plainchar;
					return plainchar - plaintext_out;
				}
				fragment = (char)base64_decode_value(*codechar++);
			} while (fragment < 0);
			*plainchar++ |= (fragment & 0x030) >> 4;
			*plainchar    = (fragment & 0x00f) << 4;
	case step_c:
			do {
				if (codechar == code_in+length_in)
				{
					state_in->step = step_c;
					state_in->plainchar = *plainchar;
					return plainchar - plaintext_out;
				}
				fragment = (char)base64_decode_value(*codechar++);
			} while (fragment < 0);
			*plainchar++ |= (fragment & 0x03c) >> 2;
			*plainchar    = (fragment & 0x003) << 6;
	case step_d:
			do {
				if (codechar == code_in+length_in)
				{
					state_in->step = step_d;
					state_in->plainchar = *plainchar;
					return plainchar - plaintext_out;
				}
				fragment = (char)base64_decode_value(*codechar++);
			} while (fragment < 0);
			*plainchar++   |= (fragment & 0x03f);
		}
	}
	/* control should not reach here */
	return plainchar - plaintext_out;
}


char *Base64Encode(const char* input, uint32_t inputlen)
{
  /* set up a destination buffer large enough to hold the encoded data */
  char* output = (char*)malloc(8 + (inputlen * 4)/3);
  /* keep track of our encoded position */
  char* c = output;
  /* store the number of bytes encoded by a single call */
  int cnt = 0;
  /* we need an encoder state */
  base64_encodestate s;

  /*---------- START ENCODING ----------*/
  /* initialise the encoder state */
  base64_init_encodestate(&s);
  /* gather data from the input and send it to the output */
  cnt = base64_encode_block(input, inputlen, c, &s);
  c += cnt;
  /* since we have encoded the entire input string, we know that 
     there is no more input data; finalise the encoding */
  cnt = base64_encode_blockend(c, &s);
  c += cnt;
  /*---------- STOP ENCODING  ----------*/

  /* we want to print the encoded data, so null-terminate it: */
  *c = 0;

  return output;
}

char *Base64Decode(const char* input)
{
  /* set up a destination buffer large enough to hold the encoded data */
  unsigned ilen = strlen(input);
  char* output = (char*)malloc(ilen);
  /* keep track of our decoded position */
  char* c = output;
  /* store the number of bytes decoded by a single call */
  int cnt = 0;
  /* we need a decoder state */
  base64_decodestate s;

  /*---------- START DECODING ----------*/
  /* initialise the decoder state */
  base64_init_decodestate(&s);
  /* decode the input data */
  cnt = base64_decode_block(input, ilen, c, &s);
  c += cnt;
  /* note: there is no base64_decode_blockend! */
  /*---------- STOP DECODING  ----------*/

  /* we want to print the decoded data, so null-terminate it: */
  *c = 0;

  return output;
}


/* ---------------------------- BASE64 ENCODE/DECODE FUNCTIONS ENDS HERE -------------------------------------
 */

/* ---------------- utility fncs */
uint32_t GetElapsedTimeInMilliSeconds(struct timeval *StartTime)
{
  struct timeval Now;

  gettimeofday (&Now, NULL); 
  return (Now.tv_sec - StartTime->tv_sec) * 1000 + (Now.tv_usec - StartTime->tv_usec) / 1000;
}
double PrintElapsedTime(struct timeval *StartTime, unsigned long long int TotalProcessedBytes)
{
  double TotalMBytes = ((double)TotalProcessedBytes/(1024.0*1024)); 
  unsigned EInMs = GetElapsedTimeInMilliSeconds(StartTime);
  double Average = TotalMBytes / (1.0 * EInMs) * 1000.0;
  printf("\n\tTotal data processed: %6.2f MBytes\n\tElapsed Time: %u ms.\n\tAverage: %10.4f MBytes/secs \n",TotalMBytes, EInMs, Average);
  return Average;
}

void IncByOne(uint8_t *Buf, uint32_t BufLen)
{
  unsigned t;
  for (t=0; t<BufLen; t++)
    Buf[t]++;
}
uint8_t *CreateDataBuf(Size)
{
  return (uint8_t *)calloc(1, Size);
}

/* 8-bit CRC with polynomial x^8+x^6+x^3+x^2+1, 0x14D.
   Chosen based on Koopman, et al. (0xA6 in his notation = 0x14D >> 1):
   http://www.ece.cmu.edu/~koopman/roses/dsn04/koopman04_crc_poly_embedded.pdf
 */
static uint8_t crc8_table[] = {
    0x00, 0x3e, 0x7c, 0x42, 0xf8, 0xc6, 0x84, 0xba, 0x95, 0xab, 0xe9, 0xd7,
    0x6d, 0x53, 0x11, 0x2f, 0x4f, 0x71, 0x33, 0x0d, 0xb7, 0x89, 0xcb, 0xf5,
    0xda, 0xe4, 0xa6, 0x98, 0x22, 0x1c, 0x5e, 0x60, 0x9e, 0xa0, 0xe2, 0xdc,
    0x66, 0x58, 0x1a, 0x24, 0x0b, 0x35, 0x77, 0x49, 0xf3, 0xcd, 0x8f, 0xb1,
    0xd1, 0xef, 0xad, 0x93, 0x29, 0x17, 0x55, 0x6b, 0x44, 0x7a, 0x38, 0x06,
    0xbc, 0x82, 0xc0, 0xfe, 0x59, 0x67, 0x25, 0x1b, 0xa1, 0x9f, 0xdd, 0xe3,
    0xcc, 0xf2, 0xb0, 0x8e, 0x34, 0x0a, 0x48, 0x76, 0x16, 0x28, 0x6a, 0x54,
    0xee, 0xd0, 0x92, 0xac, 0x83, 0xbd, 0xff, 0xc1, 0x7b, 0x45, 0x07, 0x39,
    0xc7, 0xf9, 0xbb, 0x85, 0x3f, 0x01, 0x43, 0x7d, 0x52, 0x6c, 0x2e, 0x10,
    0xaa, 0x94, 0xd6, 0xe8, 0x88, 0xb6, 0xf4, 0xca, 0x70, 0x4e, 0x0c, 0x32,
    0x1d, 0x23, 0x61, 0x5f, 0xe5, 0xdb, 0x99, 0xa7, 0xb2, 0x8c, 0xce, 0xf0,
    0x4a, 0x74, 0x36, 0x08, 0x27, 0x19, 0x5b, 0x65, 0xdf, 0xe1, 0xa3, 0x9d,
    0xfd, 0xc3, 0x81, 0xbf, 0x05, 0x3b, 0x79, 0x47, 0x68, 0x56, 0x14, 0x2a,
    0x90, 0xae, 0xec, 0xd2, 0x2c, 0x12, 0x50, 0x6e, 0xd4, 0xea, 0xa8, 0x96,
    0xb9, 0x87, 0xc5, 0xfb, 0x41, 0x7f, 0x3d, 0x03, 0x63, 0x5d, 0x1f, 0x21,
    0x9b, 0xa5, 0xe7, 0xd9, 0xf6, 0xc8, 0x8a, 0xb4, 0x0e, 0x30, 0x72, 0x4c,
    0xeb, 0xd5, 0x97, 0xa9, 0x13, 0x2d, 0x6f, 0x51, 0x7e, 0x40, 0x02, 0x3c,
    0x86, 0xb8, 0xfa, 0xc4, 0xa4, 0x9a, 0xd8, 0xe6, 0x5c, 0x62, 0x20, 0x1e,
    0x31, 0x0f, 0x4d, 0x73, 0xc9, 0xf7, 0xb5, 0x8b, 0x75, 0x4b, 0x09, 0x37,
    0x8d, 0xb3, 0xf1, 0xcf, 0xe0, 0xde, 0x9c, 0xa2, 0x18, 0x26, 0x64, 0x5a,
    0x3a, 0x04, 0x46, 0x78, 0xc2, 0xfc, 0xbe, 0x80, 0xaf, 0x91, 0xd3, 0xed,
    0x57, 0x69, 0x2b, 0x15};

uint8_t crc8(uint8_t crc, uint8_t *data, size_t len)
{
  uint8_t *end;

  if (len == 0)
    return crc;
  crc ^= 0xff;
  end = data + len;
  do {
    crc = crc8_table[crc ^ *data++];
  } while (data < end);
  return crc ^ 0xff;
}

#define RANDOM_BUF_SIZE 8192
uint8_t RandomBuf[RANDOM_BUF_SIZE];

uint32_t RandomBufStartPos=999999999; // It must be a number greater than RANDOM_BUF_SIZE for initialization

void ReadRandomBytesFromUDEv(uint32_t ByteCount, uint8_t *Buffer)
{
  FILE *fp;
  
  fp = fopen("/dev/urandom", "r");
  if (!fp)
  {
    fprintf(stderr, "\n\nERROR OPENING /dev/urandom!!!!\n\n");
    exit(-1);
  }
  
  fread(Buffer, ByteCount, 1, fp);
  fclose(fp);
}
void RandomizeBuffer()
{
#ifdef VERBOSE
  printf("Randomizing ... \n");
#endif
  RandomBufStartPos=0;
  ReadRandomBytesFromUDEv(RANDOM_BUF_SIZE, RandomBuf);
  
#ifdef OVERLY_VERBOSE
  int t;
  for (t=0; t<RANDOM_BUF_SIZE; t++)
    printf("%u ",RandomBuf[t]);
  printf("\n\n");
#endif
}

void GetRandomNumbers(uint32_t ByteCount, uint8_t *Buffer)
{
  if (RANDOM_BUF_SIZE < ByteCount)
  {
    ReadRandomBytesFromUDEv(ByteCount, Buffer);
    return;
  }
  if (RANDOM_BUF_SIZE < RandomBufStartPos+ByteCount)
    RandomizeBuffer();
  if (ByteCount == 1)
  {
    Buffer[0] = RandomBuf[RandomBufStartPos++];
    return;
  }
  memcpy(Buffer, RandomBuf + RandomBufStartPos, ByteCount);
  RandomBufStartPos += ByteCount;
}
uint8_t GetRandomUInt8(void)
{
  if (RandomBufStartPos >= RANDOM_BUF_SIZE)
    RandomizeBuffer();
  return RandomBuf[RandomBufStartPos++];
}

// Standart C has not ROL or ROR function, but most modern cpus has instructions for circular shift operations
// This is a quick and dirty code for standart C versions and Intel Family cpu assembler optimized versions

#define GCC_INTEL_OPTIMIZED 

static inline int ROL32_1(int v) 
{
  #if defined(__GNUC__)  
    #if defined(GCC_INTEL_OPTIMIZED)
      asm ("rol %0;" :"=r"(v) /* output */ :"0"(v) /* input */ );
      return v;
    #else 
      return (((v) << 1) | ((v) >> 31));
    #endif
  #endif
}
static inline int ROR32_1(int v) {
  #if defined(__GNUC__)  
    #if defined(GCC_INTEL_OPTIMIZED)
      asm ("ror %0;" :"=r"(v) /* output */ :"0"(v) /* input */ );
      return v;
    #else 
      return (((v) >> 1) | ((v) << 31))
    #endif
  #endif
}

/* ---------------- end utility fncs */

#define SALT_SIZE 8 // 
#define MAX_NUM_JUMPS 64
#define FALSE (0U)
#define TRUE (!(FALSE))
#define VERBOSE
//#define OVERLY_VERBOSE

/* Function used to determine if V is unique among the first Pos elements
 * Used by the xorGetKey function to check particle length uniqueness
 */
#define MAX_BODY_SIZE 1024

#define SP_NUM_JUMPS 0
#define SP_BODY_LEN 1
#define SP_SALT_DATA 3
#define SP_BODY (SP_SALT_DATA+SALT_SIZE)
#define GetBodyLen(K) (K[SP_BODY_LEN] + 256 * K[SP_BODY_LEN+1])
#define GetBodyPtr(K) (K + SP_BODY)
#define GetNumJumps(K) (K[SP_NUM_JUMPS])
#define xorComputeKeyBufLen(BodyLen) (SP_BODY+BodyLen)

// Creates XOR key
// The first byte will be equal to NumJumps
// Following 2 bytes is key body length
// Following 4 bytes are random salt data
// Following BodyLen bytes are random numbers obtained from buffered /dev/urandom data. BODYLEN MUST BE A POWER OF 2!
// Result buffer must be enough to store key!! No error checking is done!!!
void xorGetKey(uint8_t NumJumps, uint32_t BodyLen, uint8_t *KeyBuf)
{
  assert(NumJumps > 1 && BodyLen > 15 && NumJumps<MAX_NUM_JUMPS && ((BodyLen-1)&BodyLen) == 0);
  
#ifdef VERBOSE
  printf("Generating key ... BodyLen: %u NumJumps: %u\n",BodyLen,NumJumps);
#endif
  KeyBuf[SP_NUM_JUMPS] = (uint8_t)(NumJumps&255);
  KeyBuf[SP_BODY_LEN] = (uint8_t)((BodyLen % 256) & 0xff);
  KeyBuf[SP_BODY_LEN+1] = (uint8_t)((BodyLen / 256) & 0xff);
  GetRandomNumbers(SALT_SIZE + BodyLen, KeyBuf + SP_SALT_DATA); // Fill 4 bytes salt data with random numbers
}

void xorAnalyzeKey(uint8_t *K)
{
  uint32_t t;
  
  printf("-------------------------- Shifting xor key analyze ----------------------------\nNumJumps: %u\nBodyLen: %u nSalt: ", 
         K[0], GetBodyLen(K));
  for (t=0; t < SALT_SIZE; t++)
  {
    printf(" %u", K[SP_SALT_DATA+t]);
  }
  printf("\n");
}

/* UNOPTIMIZED VERSION for BETTER UNDERSTANDING OF THE FUNCTIONING OF THE ALGORITHM. IT IS NOT USED IN REAL LIFE. USE OPTIMIZED VERSIONS!
 * Encrypts or decrypts InOutBuf 
 * KeyBuf is the raw key buffer
 * KeyCheckSum is 8 bit CRC checksum: Used to prevent "Related key attacks". If some bits of the key changes, entire cyphertext changes
 * InOutDataLen is the length of the data to be encrypted or decrypted
 * InOutBuf is the pointer to the data to be encrypted or decrypted
 * Salt(or nonce) is a 4 bytes random number array.
 * This logic ensures us this: An original key is created with an original salt value, for example for an online communication
 * for each distinct packet, in the packet header, we can transmit a specific salt value for that packet and we can encrypt it with original key and salt
 * when the receiver receives the packet, decrypts the new salt value with the original salt value of the key and passes that salt value to function,
 * and decrypts packet body with that salt value. This method prevents "known plaintext" attacks amongst others.
 */

#define MakeXOREnc(InOutBuf,XORVal,Salt,KeyCheckSum,PlainTextChecksum,LastVal,TmpVal,Counter)\
PlainTextChecksum += InOutBuf[Counter]; \
TmpVal = InOutBuf[Counter]; \
XORVal ^= LastVal; \
XORVal ^= *(Salt + (LastVal&(SALT_SIZE-1))); \
InOutBuf[Counter] ^= ((uint8_t)(XORVal)); \
LastVal = TmpVal; 

#define MakeXORDec(InOutBuf,XORVal,Salt,KeyCheckSum,PlainTextChecksum,LastVal,Counter)\
XORVal ^= LastVal; \
XORVal ^= *(Salt + (LastVal&(SALT_SIZE-1))); \
InOutBuf[Counter] ^= ((uint8_t)(XORVal)); \
LastVal = InOutBuf[Counter]; \
PlainTextChecksum += LastVal; 

//Salt[Counter&SALT_SIZE]++; XORVal ^= (KeyCheckSum ^ Salt[Counter&SALT_SIZE]); 

#define xorComputeKeyCheckSum(K) crc8(0, K, SP_BODY + GetBodyLen(K))

uint64_t xorEncrypt(uint8_t *K, uint8_t *Salt, uint8_t KeyCheckSum, size_t InOutDataLen, uint8_t *InOutBuf)
{ // Encrypts message and returns checksum of the InOutBuf BEFORE encyption
  // SaltData is a 4 bytes uint8 array! IT IS NOT READ ONLY! IT WILL BE MANIPULATED BY THE FUNCTION!
  register uint32_t tt, M;
  register size_t t;
  register uint8_t XORVal, LastVal = 0,TmpVal; // Last PLAINTEXT byte processed. It will be an input parameter for the next encryption
  register uint64_t Checksum=0;
  register uint32_t BodyMask = GetBodyLen(K); // +1 because we will use this "Mersenne number" for & operation instead of modulus operation
  uint8_t Body[MAX_BODY_SIZE];
  
  memcpy(Body,K+SP_BODY,BodyMask);
  BodyMask--;
  
  Salt[0] ^= KeyCheckSum;
  Salt[1] ^= KeyCheckSum;
  Salt[2] ^= KeyCheckSum;
  Salt[3] ^= KeyCheckSum;
  Salt[4] ^= KeyCheckSum;
  Salt[5] ^= KeyCheckSum;
  Salt[6] ^= KeyCheckSum;
  Salt[7] ^= KeyCheckSum;
  
  // Initial position of the pointer depends on actual salt value
  M = (BodyMask & Salt[Salt[0]&(SALT_SIZE-1)]);
  //printf("xorEncrypt BodyLen: %u KeyCheckSum: %u Salt: %u\n",BodyLen, KeyCheckSum,Salt);
  
  for (t=0; t<InOutDataLen; t++)
  {
    // First jump step is previous plaintext byte
    XORVal = Body[M]; 
    M = (M ^ LastVal) & BodyMask; 

    for (tt=1; tt < GetNumJumps(K); tt++)
    {
      // All following jumps are based on body values
      XORVal ^= Body[M]; 
      M = (M ^ Body[M]) & BodyMask; 
    }
    MakeXOREnc(InOutBuf,XORVal,Salt,KeyCheckSum,Checksum,LastVal,TmpVal,t);
    Body[M] = ROL32_1(Body[M]); 
    Body[M] ^= LastVal;
  }
  return Checksum;
} 
uint64_t xorDecrypt(uint8_t *K, uint8_t *Salt, uint8_t KeyCheckSum, size_t InOutDataLen, uint8_t *InOutBuf)
{ // Decrypts message and returns checksum of the InOutBuf AFTER encyption
  // SaltData is a 4 bytes uint8 array! IT IS NOT READ ONLY! IT WILL BE MANIPULATED BY THE FUNCTION!
  register uint32_t tt, M;
  register size_t t;
  register uint8_t XORVal, LastVal = 0; // Last PLAINTEXT byte processed. It will be an input parameter for the next encrytpion
  register uint64_t Checksum=0;
  register uint32_t BodyMask = GetBodyLen(K); // +1 because we will use this "Mersenne number" for & operation instead of modulus operation
  uint8_t Body[MAX_BODY_SIZE];
  
  memcpy(Body,K+SP_BODY,BodyMask);
  BodyMask--;
  
  Salt[0] ^= KeyCheckSum;
  Salt[1] ^= KeyCheckSum;
  Salt[2] ^= KeyCheckSum;
  Salt[3] ^= KeyCheckSum;
  Salt[4] ^= KeyCheckSum;
  Salt[5] ^= KeyCheckSum;
  Salt[6] ^= KeyCheckSum;
  Salt[7] ^= KeyCheckSum;
  
  // Initial position of the pointer is dependent on actual salt value
  M = (BodyMask & Salt[Salt[0]&(SALT_SIZE-1)]);
  //printf("xorEncrypt BodyLen: %u KeyCheckSum: %u Salt: %u\n",BodyLen, KeyCheckSum,Salt);
  
  for (t=0; t<InOutDataLen; t++)
  {
    // First jump step is previous plaintext byte
    XORVal = Body[M]; 
    M = (M + LastVal) & BodyMask; 

    for (tt=1; tt < GetNumJumps(K); tt++)
    {
      // All following jumps are based on body values
      XORVal ^= Body[M]; 
      M = (M + Body[M]) & BodyMask; 
    }
    MakeXORDec(InOutBuf,XORVal,Salt,KeyCheckSum,Checksum,LastVal,t);
    Body[M] = ROL32_1(Body[M]); 
    Body[M] ^= LastVal;
  }
  return Checksum;
} 

uint64_t xorEncryptHOP2(uint8_t *K, uint8_t *Salt, uint8_t KeyCheckSum, size_t InOutDataLen, uint8_t *InOutBuf)
{ // Encrypts message and returns checksum of the InOutBuf BEFORE encyption
  // SaltData is a 4 bytes uint8 array! IT IS NOT READ ONLY! IT WILL BE MANIPULATED BY THE FUNCTION!
  register uint32_t M;
  register size_t t;
  register uint8_t XORVal, LastVal = 0,TmpVal; // Last PLAINTEXT byte processed. It will be an input parameter for the next encrytpion
  register uint64_t Checksum=0;
  register uint32_t BodyMask = GetBodyLen(K); // +1 because we will use this "Mersenne number" for & operation instead of modulus operation
  uint8_t Body[MAX_BODY_SIZE];
  
  memcpy(Body,K+SP_BODY,BodyMask);
  BodyMask--;
  
  Salt[0] ^= KeyCheckSum;
  Salt[1] ^= KeyCheckSum;
  Salt[2] ^= KeyCheckSum;
  Salt[3] ^= KeyCheckSum;
  Salt[4] ^= KeyCheckSum;
  Salt[5] ^= KeyCheckSum;
  Salt[6] ^= KeyCheckSum;
  Salt[7] ^= KeyCheckSum;
  
  // Initial position of the pointer is dependent on actual salt value
  M = (BodyMask & Salt[Salt[0]&(SALT_SIZE-1)]);
  //printf("xorEncrypt BodyLen: %u KeyCheckSum: %u Salt: %u\n",BodyLen, KeyCheckSum,Salt);
  for (t=0; t<InOutDataLen; t++)
  {
    // First jump step is previous plaintext byte
    XORVal = Body[M]; 
    M = (M ^ LastVal) & BodyMask; 
    // All following jump steps are based on body values
    XORVal ^= Body[M]; 
    M = (M ^ Body[M]) & BodyMask; 
    MakeXOREnc(InOutBuf,XORVal,Salt,KeyCheckSum,Checksum,LastVal,TmpVal,t);
    Body[M] = ROL32_1(Body[M]); 
    Body[M] ^= LastVal;
  }
  return Checksum;
} 

uint64_t xorDecryptHOP2(uint8_t *K, uint8_t *Salt, uint8_t KeyCheckSum, size_t InOutDataLen, uint8_t *InOutBuf)
{ // Decrypts message and returns checksum of the InOutBuf BEFORE encyption
  // SaltData is a 4 bytes uint8 array! IT IS NOT READ ONLY! IT WILL BE MANIPULATED BY THE FUNCTION!
  register uint32_t M;
  register size_t t;
  register uint8_t XORVal, LastVal = 0; // Last PLAINTEXT byte processed. It will be an input parameter for the next encrytpion
  register uint64_t Checksum=0;
  register uint32_t BodyMask = GetBodyLen(K); // +1 because we will use this "Mersenne number" for & operation instead of modulus operation
  uint8_t Body[MAX_BODY_SIZE];
  
  memcpy(Body,K+SP_BODY,BodyMask);
  BodyMask--;
  
  Salt[0] ^= KeyCheckSum;
  Salt[1] ^= KeyCheckSum;
  Salt[2] ^= KeyCheckSum;
  Salt[3] ^= KeyCheckSum;
  Salt[4] ^= KeyCheckSum;
  Salt[5] ^= KeyCheckSum;
  Salt[6] ^= KeyCheckSum;
  Salt[7] ^= KeyCheckSum;
  
  // Initial position of the pointer is dependent on actual salt value
  M = (BodyMask & Salt[Salt[0]&(SALT_SIZE-1)]);
  //printf("xorEncrypt BodyLen: %u KeyCheckSum: %u Salt: %u\n",BodyLen, KeyCheckSum,Salt);
  
  for (t=0; t<InOutDataLen; t++)
  {
    // First jump step is previous plaintext byte
    XORVal = Body[M]; 
    M = (M ^ LastVal) & BodyMask; 
    // All following jumps are based on body values
    XORVal ^= Body[M]; 
    M = (M ^ Body[M]) & BodyMask; 
    MakeXORDec(InOutBuf,XORVal,Salt,KeyCheckSum,Checksum,LastVal,t);
    Body[M] = ROL32_1(Body[M]); 
    Body[M] ^= LastVal;
  }
  return Checksum;
} 
uint64_t xorEncryptHOP3(uint8_t *K, uint8_t *Salt, uint8_t KeyCheckSum, size_t InOutDataLen, uint8_t *InOutBuf)
{ // Encrypts or decrypts message and returns checksum of the InOutBuf BEFORE encyption
  // SaltData is a 4 bytes uint8 array! IT IS NOT READ ONLY! IT WILL BE MANIPULATED BY THE FUNCTION!
  register uint32_t M;
  register size_t t;
  register uint8_t XORVal, LastVal = 0,TmpVal; // Last PLAINTEXT byte processed. It will be an input parameter for the next encrytpion
  register uint64_t Checksum=0;
  register uint32_t BodyMask = GetBodyLen(K); // +1 because we will use this "Mersenne number" for & operation instead of modulus operation
  uint8_t Body[MAX_BODY_SIZE];
  
  memcpy(Body,K+SP_BODY,BodyMask);
  BodyMask--;
  
  Salt[0] ^= KeyCheckSum;
  Salt[1] ^= KeyCheckSum;
  Salt[2] ^= KeyCheckSum;
  Salt[3] ^= KeyCheckSum;
  Salt[4] ^= KeyCheckSum;
  Salt[5] ^= KeyCheckSum;
  Salt[6] ^= KeyCheckSum;
  Salt[7] ^= KeyCheckSum;
  
  // Initial position of the pointer is dependent on actual salt value
  M = (BodyMask & Salt[Salt[0]&(SALT_SIZE-1)]);
  //printf("xorEncrypt BodyLen: %u KeyCheckSum: %u Salt: %u\n",BodyLen, KeyCheckSum,Salt);
  for (t=0; t<InOutDataLen; t++)
  {
    // First jump step is previous plaintext byte
    XORVal = Body[M]; 
    M = (M ^ LastVal) & BodyMask; 
    // All following jumps are based on body values
    XORVal ^= Body[M]; 
    M = (M ^ Body[M]) & BodyMask; 
    XORVal ^= Body[M]; 
    M = (M ^ Body[M]) & BodyMask; 
    MakeXOREnc(InOutBuf,XORVal,Salt,KeyCheckSum,Checksum,LastVal,TmpVal,t);
    Body[M] = ROL32_1(Body[M]); 
    Body[M] ^= LastVal;
  }
  return Checksum;
} 

uint64_t xorDecryptHOP3(uint8_t *K, uint8_t *Salt, uint8_t KeyCheckSum, size_t InOutDataLen, uint8_t *InOutBuf)
{ // Encrypts or decrypts message and returns checksum of the InOutBuf BEFORE encyption
  // SaltData is a 4 bytes uint8 array! IT IS NOT READ ONLY! IT WILL BE MANIPULATED BY THE FUNCTION!
  register uint32_t M;
  register size_t t;
  register uint8_t XORVal, LastVal = 0; // Last PLAINTEXT byte processed. It will be an input parameter for the next encrytpion
  register uint64_t Checksum=0;
  register uint32_t BodyMask = GetBodyLen(K); // +1 because we will use this "Mersenne number" for & operation instead of modulus operation
  uint8_t Body[MAX_BODY_SIZE];
  
  memcpy(Body,K+SP_BODY,BodyMask);
  BodyMask--;
  
  Salt[0] ^= KeyCheckSum;
  Salt[1] ^= KeyCheckSum;
  Salt[2] ^= KeyCheckSum;
  Salt[3] ^= KeyCheckSum;
  Salt[4] ^= KeyCheckSum;
  Salt[5] ^= KeyCheckSum;
  Salt[6] ^= KeyCheckSum;
  Salt[7] ^= KeyCheckSum;
  
  // Initial position of the pointer is dependent on actual salt value
  M = (BodyMask & Salt[Salt[0]&(SALT_SIZE-1)]);
  //printf("xorEncrypt BodyLen: %u KeyCheckSum: %u Salt: %u\n",BodyLen, KeyCheckSum,Salt);
  
  for (t=0; t<InOutDataLen; t++)
  {
    // First jump step is previous plaintext byte
    XORVal = Body[M]; 
    M = (M ^ LastVal) & BodyMask; 
    // All following jumps are based on body values
    XORVal ^= Body[M]; 
    M = (M ^ Body[M]) & BodyMask; 
    XORVal ^= Body[M]; 
    M = (M ^ Body[M]) & BodyMask; 
    MakeXORDec(InOutBuf,XORVal,Salt,KeyCheckSum,Checksum,LastVal,t);
    Body[M] = ROL32_1(Body[M]); 
    Body[M] ^= LastVal;
  }
  return Checksum;
} 

uint64_t xorEncryptHOP4(uint8_t *K, uint8_t *Salt, uint8_t KeyCheckSum, size_t InOutDataLen, uint8_t *InOutBuf)
{ // Encrypts or decrypts message and returns checksum of the InOutBuf BEFORE encyption
  // SaltData is a 4 bytes uint8 array! IT IS NOT READ ONLY! IT WILL BE MANIPULATED BY THE FUNCTION!
  register uint32_t M;
  register size_t t;
  register uint8_t XORVal, LastVal = 0,TmpVal; // Last PLAINTEXT byte processed. It will be an input parameter for the next encrytpion
  register uint64_t Checksum=0;
  register uint32_t BodyMask = GetBodyLen(K); // +1 because we will use this "Mersenne number" for & operation instead of modulus operation
  uint8_t Body[MAX_BODY_SIZE];
  
  memcpy(Body,K+SP_BODY,BodyMask);
  BodyMask--;
  
  Salt[0] ^= KeyCheckSum;
  Salt[1] ^= KeyCheckSum;
  Salt[2] ^= KeyCheckSum;
  Salt[3] ^= KeyCheckSum;
  Salt[4] ^= KeyCheckSum;
  Salt[5] ^= KeyCheckSum;
  Salt[6] ^= KeyCheckSum;
  Salt[7] ^= KeyCheckSum;
  
  // Initial position of the pointer is dependent on actual salt value
  M = (BodyMask & Salt[Salt[0]&(SALT_SIZE-1)]);
  //printf("xorEncrypt BodyLen: %u KeyCheckSum: %u Salt: %u\n",BodyLen, KeyCheckSum,Salt);
  for (t=0; t<InOutDataLen; t++)
  {
    // First jump step is previous plaintext byte
    XORVal = Body[M]; 
    M = (M ^ LastVal) & BodyMask; 
    // All following jumps are based on body values
    XORVal ^= Body[M]; 
    M = (M ^ Body[M]) & BodyMask; 
    XORVal ^= Body[M]; 
    M = (M ^ Body[M]) & BodyMask; 
    XORVal ^= Body[M]; 
    M = (M ^ Body[M]) & BodyMask; 
    MakeXOREnc(InOutBuf,XORVal,Salt,KeyCheckSum,Checksum,LastVal,TmpVal,t);
    Body[M] = ROL32_1(Body[M]); 
    Body[M] ^= LastVal;
  }
  return Checksum;
} 

uint64_t xorDecryptHOP4(uint8_t *K, uint8_t *Salt, uint8_t KeyCheckSum, size_t InOutDataLen, uint8_t *InOutBuf)
{ // Encrypts or decrypts message and returns checksum of the InOutBuf BEFORE encyption
  // SaltData is a 4 bytes uint8 array! IT IS NOT READ ONLY! IT WILL BE MANIPULATED BY THE FUNCTION!
  register uint32_t M;
  register size_t t;
  register uint8_t XORVal, LastVal = 0; // Last PLAINTEXT byte processed. It will be an input parameter for the next encrytpion
  register uint64_t Checksum=0;
  register uint32_t BodyMask = GetBodyLen(K); // +1 because we will use this "Mersenne number" for & operation instead of modulus operation
  uint8_t Body[MAX_BODY_SIZE];
  
  memcpy(Body,K+SP_BODY,BodyMask);
  BodyMask--;
  
  Salt[0] ^= KeyCheckSum;
  Salt[1] ^= KeyCheckSum;
  Salt[2] ^= KeyCheckSum;
  Salt[3] ^= KeyCheckSum;
  Salt[4] ^= KeyCheckSum;
  Salt[5] ^= KeyCheckSum;
  Salt[6] ^= KeyCheckSum;
  Salt[7] ^= KeyCheckSum;
  
  // Initial position of the pointer is dependent on actual salt value
  M = (BodyMask & Salt[Salt[0]&(SALT_SIZE-1)]);
  //printf("xorEncrypt BodyLen: %u KeyCheckSum: %u Salt: %u\n",BodyLen, KeyCheckSum,Salt);
  
  for (t=0; t<InOutDataLen; t++)
  {
    // First jump step is previous plaintext byte
    XORVal = Body[M]; 
    M = (M ^ LastVal) & BodyMask; 
    // All following jumps are based on body values
    XORVal ^= Body[M]; 
    M = (M ^ Body[M]) & BodyMask; 
    XORVal ^= Body[M]; 
    M = (M ^ Body[M]) & BodyMask; 
    XORVal ^= Body[M]; 
    M = (M ^ Body[M]) & BodyMask; 
    MakeXORDec(InOutBuf,XORVal,Salt,KeyCheckSum,Checksum,LastVal,t);
    Body[M] = ROL32_1(Body[M]); 
    Body[M] ^= LastVal;
  }
  return Checksum;
} 

//#define xorEncryptDecrypt xorEncryptDecryptHOP5
/* Memcpy Benchmark1 : 
 * This function 
 *   Creates a N bytes random data buffer 
 *   Creates another N bytes zero filled buffer (DestBuf)
 *   Starts an iteration 
 *   For each iteration, increases every byte of the data by 1
 *   Copies the data buffer to DestBuf
 *   Prints the elapsed time 
 */
void MemCpyBenchmark1(uint32_t TestSampleLength, uint32_t NumIterations)
{
  uint8_t *Data = CreateDataBuf(TestSampleLength);
  uint8_t *DestBuf = CreateDataBuf(TestSampleLength);
  unsigned long long int TotalProcessedBytes = 0;
  unsigned t;
  
  /*printf("-------------------- MemCpyBenchmark1 1: BASIC FUNCTIONALITY -------------------------\n"
        "This function\n 1.Creates a %u bytes random data buffer\nCreates another buffer(DestBuf) with the same size\nMakes %u iteration\n"
         "For each iteration, increases every byte of the data by 1\nCopies the data buffer to DestBuf\nPrints the elapsed time",TestSampleLength,NumIterations);*/
  printf("MemCpyBenchmark1\n\tTestSampleLength: %u\n\tNumIterations: %u ... ",TestSampleLength,NumIterations);  
  struct timeval StartTime;
  gettimeofday (&StartTime, NULL); 
  
  for (t=0; t<NumIterations; t++)
  {
    IncByOne(Data, TestSampleLength);
    memcpy(DestBuf, Data, TestSampleLength);
    TotalProcessedBytes += TestSampleLength;
  }
  PrintElapsedTime(&StartTime,TotalProcessedBytes);
  free(Data);
  free(DestBuf);
}

/* Benchmark1 : 
 * This function 
 *   Creates a key with NumJumps particles and with a body length of BodyLen
 *   Creates a N bytes random zero filled buffer 
 *   Starts an iteration of NumIterations times
 *   For each iteration, increases every byte of the data by 1
 *   Encrypts the data
 *   Prints the elapsed time 
 */
double Benchmark1(uint8_t NumJumps, uint32_t BodyLen, uint32_t TestSampleLength, uint32_t NumIterations)
{
  uint8_t *KeyBuf = (uint8_t *)malloc(xorComputeKeyBufLen(BodyLen));
  uint8_t *Data = CreateDataBuf(TestSampleLength);
  unsigned long long int TotalProcessedBytes = 0;
  uint32_t t,Salt;
  uint8_t KeyCheckSum;
  
  printf("Benchmark1\n\tNumJumps: %u\n\tBodyLen: %u\n\tTestSampleLength: %u\n\tNumIterations: %u ... ",NumJumps,BodyLen,TestSampleLength,NumIterations);  
  
  GetRandomNumbers(TestSampleLength, Data);
  xorGetKey(NumJumps, BodyLen, KeyBuf);
  KeyCheckSum = xorComputeKeyCheckSum(KeyBuf);
  xorAnalyzeKey(KeyBuf);
  struct timeval StartTime;
  gettimeofday (&StartTime, NULL); 
  
  for (t=0; t<NumIterations; t++)
  {
    IncByOne(Data, TestSampleLength);
    Salt=1234;
    xorEncrypt(KeyBuf, (uint8_t *)(&Salt), KeyCheckSum, TestSampleLength, Data);
    TotalProcessedBytes += TestSampleLength;
  }
  double Average = PrintElapsedTime(&StartTime,TotalProcessedBytes);
  free(Data);
  free(KeyBuf);
  return Average;
}
static inline uint64_t BufCheckSum(uint8_t *Buf, uint64_t BufLen)
{
  uint64_t t, CheckSum = 0;
  
  for (t=0; t<BufLen; t++)
    CheckSum += Buf[t];
  return CheckSum;
}
double BenchmarkHOP2(uint8_t NumJumps, uint32_t BodyLen, uint32_t TestSampleLength, uint32_t NumIterations)
{
  uint8_t *KeyBuf = (uint8_t *)malloc(xorComputeKeyBufLen(BodyLen));
  uint8_t *Data = CreateDataBuf(TestSampleLength);
  unsigned long long int TotalProcessedBytes = 0;
  uint32_t t;
  uint8_t KeyCheckSum;
  uint32_t  SaltData=1245;
  
  printf("BenchmarkHop2\n\tNumJumps: %u\n\tBodyLen: %u\n\tTestSampleLength: %u\n\tNumIterations: %u ... ",NumJumps,BodyLen,TestSampleLength,NumIterations);  
  
  GetRandomNumbers(TestSampleLength, Data);
  xorGetKey(NumJumps, BodyLen, KeyBuf);
  KeyCheckSum = xorComputeKeyCheckSum(KeyBuf);
  xorAnalyzeKey(KeyBuf);
  struct timeval StartTime;
  gettimeofday (&StartTime, NULL); 
  
  BufCheckSum(Data, TestSampleLength);  
  for (t=0; t<NumIterations; t++)
  {
    IncByOne(Data, TestSampleLength);
    xorEncryptHOP2(KeyBuf, (uint8_t *)(&SaltData), KeyCheckSum, TestSampleLength, Data);
    TotalProcessedBytes += TestSampleLength;
  }
  double Average = PrintElapsedTime(&StartTime,TotalProcessedBytes);
  free(Data);
  free(KeyBuf);
  return Average;
}

double BenchmarkHOP3(uint8_t NumJumps, uint32_t BodyLen, uint32_t TestSampleLength, uint32_t NumIterations)
{
  uint8_t *KeyBuf = (uint8_t *)malloc(xorComputeKeyBufLen(BodyLen));
  uint8_t *Data = CreateDataBuf(TestSampleLength);
  unsigned long long int TotalProcessedBytes = 0;
  uint32_t t;
  uint8_t KeyCheckSum;
  uint64_t SaltData;
  
  printf("BenchmarkHop3\n\tNumJumps: %u\n\tBodyLen: %u\n\tTestSampleLength: %u\n\tNumIterations: %u ... ",NumJumps,BodyLen,TestSampleLength,NumIterations);  
  
  GetRandomNumbers(TestSampleLength, Data);
  xorGetKey(NumJumps, BodyLen, KeyBuf);
  KeyCheckSum = xorComputeKeyCheckSum(KeyBuf);
  xorAnalyzeKey(KeyBuf);
  struct timeval StartTime;
  gettimeofday (&StartTime, NULL); 
  
  BufCheckSum(Data, TestSampleLength);  
  for (t=0; t<NumIterations; t++)
  {
    IncByOne(Data, TestSampleLength);
    xorEncryptHOP3(KeyBuf, (uint8_t *)(&SaltData), KeyCheckSum, TestSampleLength, Data);
    TotalProcessedBytes += TestSampleLength;
  }
  double Average = PrintElapsedTime(&StartTime,TotalProcessedBytes);
  free(Data);
  free(KeyBuf);
  return Average;
}

double BenchmarkHOP4(uint8_t NumJumps, uint32_t BodyLen, uint32_t TestSampleLength, uint32_t NumIterations)
{
  uint8_t *KeyBuf = (uint8_t *)malloc(xorComputeKeyBufLen(BodyLen));
  uint8_t *Data = CreateDataBuf(TestSampleLength);
  unsigned long long int TotalProcessedBytes = 0;
  uint32_t t;
  uint8_t KeyCheckSum;
  uint64_t SaltData;
  
  printf("BenchmarkHop4\n\tNumJumps: %u\n\tBodyLen: %u\n\tTestSampleLength: %u\n\tNumIterations: %u ... ",NumJumps,BodyLen,TestSampleLength,NumIterations);  
  
  GetRandomNumbers(TestSampleLength, Data);
  xorGetKey(NumJumps, BodyLen, KeyBuf);
  KeyCheckSum = xorComputeKeyCheckSum(KeyBuf);
  xorAnalyzeKey(KeyBuf);
  struct timeval StartTime;
  gettimeofday (&StartTime, NULL); 
  
  BufCheckSum(Data, TestSampleLength);  
  for (t=0; t<NumIterations; t++)
  {
    IncByOne(Data, TestSampleLength);
    xorEncryptHOP4(KeyBuf, (uint8_t *)(&SaltData), KeyCheckSum, TestSampleLength, Data);
    TotalProcessedBytes += TestSampleLength;
  }
  double Average = PrintElapsedTime(&StartTime,TotalProcessedBytes);
  free(Data);
  free(KeyBuf);
  return Average;
}

#define TESTSTR1 "TÜRKÇE karakter kullanınız DENEME. TÜRKÇE karakter kullanınız DENEME. uzuuuuuuun. TÜRKÇE karakter kullanınız DENEME. Çok uzun çok!222TÜRKÇE karakter kullanınız DENEME. TÜRKÇE karakter kullanınız DENEME. uzuuuuuuun. TÜRKÇE karakter kullanınız DENEME. Çok uzun çok!frfrTÜRKÇE karakter kullanınız DENEME. TÜRKÇE karakter kullanınız DENEME. uzuuuuuuun. TÜRKÇE karakter kullanınız DENEME. Çok uzun çok!"
#define TESTSTR1_LEN strlen(TESTSTR1)
void CheckOptimizedVersion(unsigned NumJumps, unsigned BodyLen)
{
  unsigned long long int DLen, OriginalPlainTextCheckSum, CheckSumReturnedFromEncryptor, CheckSumReturnedFromDecryptor;
  unsigned RawKeyLen = xorComputeKeyBufLen(BodyLen);
  uint8_t *KeyBuf = (uint8_t *)malloc(RawKeyLen);
  uint8_t PlainTextBuf[132000], Data[132000];
  unsigned long long int KeyCheckSum;
  uint64_t SaltData;
  
  printf("-------------------- TESTING OPTIMIZED VERSION FOR %u PARTICLES -------------------------\n",NumJumps);
  xorGetKey(NumJumps, BodyLen, KeyBuf);
  KeyCheckSum = xorComputeKeyCheckSum(KeyBuf);
  DLen = TESTSTR1_LEN; 
  memcpy(Data, TESTSTR1, DLen);
  memcpy(PlainTextBuf, TESTSTR1, DLen);
  
  for (DLen = 0; DLen < TESTSTR1_LEN; DLen++)
  {
    PlainTextBuf[DLen] = (uint8_t)(DLen & 255);
    Data[DLen] = PlainTextBuf[DLen];
    OriginalPlainTextCheckSum = BufCheckSum(Data, DLen+1);
    SaltData=1234;
    CheckSumReturnedFromEncryptor = xorEncrypt(KeyBuf, (uint8_t *)(&SaltData), KeyCheckSum, DLen+1, Data); // We encrypt with non-optimized version
    if (OriginalPlainTextCheckSum != CheckSumReturnedFromEncryptor)
    {
      printf("Original Checksum %llu returned from BufChecksum fnc <> Checksum %llu returned from xorEncryptDecrypt\n",OriginalPlainTextCheckSum,CheckSumReturnedFromEncryptor);
      exit(-1);
    }
    // Salt data changes with every encrypt decrypt! 
    SaltData=1234;
    if (NumJumps == 2)
      CheckSumReturnedFromDecryptor = xorDecryptHOP2(KeyBuf, (uint8_t *)(&SaltData), KeyCheckSum, DLen+1, Data);
    else if (NumJumps == 3)
      CheckSumReturnedFromDecryptor = xorDecryptHOP3(KeyBuf, (uint8_t *)(&SaltData), KeyCheckSum, DLen+1, Data);
    else if (NumJumps == 4)
      CheckSumReturnedFromDecryptor = xorDecryptHOP4(KeyBuf, (uint8_t *)(&SaltData), KeyCheckSum, DLen+1, Data);
    else exit(-1);
    
    if (OriginalPlainTextCheckSum != CheckSumReturnedFromDecryptor)
    {
      printf("Original Checksum %llu returned from BufChecksum fnc <> Checksum %llu returned from HOP decyptor\n",OriginalPlainTextCheckSum,CheckSumReturnedFromDecryptor);
      exit(-1);
    }
    if (memcmp((char *)Data, (char *)PlainTextBuf, DLen+1) != 0)
    {
      printf("String: %s ... Test1 result: FAILED!!!!\n----------------------------------------\n", Data);
      exit(-1);
    }
  }
  printf("xorEncryptDecryptHOP%u SUCCESSFUL!\n",NumJumps);
}
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
#ifdef OVERLY_VERBOSE
  printf("Analyzing raw key data:\n");
  TParsedKey *PK0 = xorParseKey(KeyBuf);
  xorAnalyzeKey(PK0);
  free(PK0);
  free(KeyBuf);
#endif
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
void D1()
{
  int t;
  register uint8_t V=0;
  for (t=0;t<128;t++)
  {
    printf("%u ",V);
    V += t;
  }
}
char *GetBinStr(uint32_t val, char *ResBuf)
{
  char *p;
  unsigned int t;
  p = ResBuf;
  t = 0x80000000; // scan 32 bits
  for ( ; t > 0; t = t >> 1) 
  {
    if (val & t)
      *p++ = '1';
    else *p++ = '0';
  }
  *p = 0;
  return ResBuf;
}
void CircularShiftTest()
{
  uint32_t t, Nn = (uint32_t)(0b10000000000000000000000000000010U);
  char Buf[256];
  printf("Circular shift left:\n");
  for (t=0; t<5; t++)
  {
    printf("%s\n", GetBinStr(Nn,Buf));  
    Nn = ROL32_1(Nn);
  }
  printf("Circular shift right:\n");
  for (t=0; t<6; t++)
  {
    printf("%s\n", GetBinStr(Nn,Buf));  
    Nn = ROR32_1(Nn);
  }
}

int main()
{
  uint32_t BodyLen = 128;
  
  //CircularShiftTest();
  //uint32_t TestSampleLength = 8192;
  uint32_t NumIterations = 1000000;
  //D1();
  Test1(2, BodyLen);
  Test1(3, BodyLen);
  Test1(4, BodyLen);
  //Test1(4, BodyLen);
  //Test1(5, BodyLen);
  
  //  exit(-1);
  //MemCpyBenchmark1(TestSampleLength, NumIterations);
  CheckOptimizedVersion(2, BodyLen);
  CheckOptimizedVersion(3, BodyLen);
  CheckOptimizedVersion(4, BodyLen);
  //CheckOptimizedVersion(5, BodyLen);
  
  
  double Average16H2,Average64H2,Average256H2,Average1024H2,Average8192H2;
  double Average16H3,Average64H3,Average256H3,Average1024H3,Average8192H3;
  double Average16H4,Average64H4,Average256H4,Average1024H4,Average8192H4;
  
  /*
  double Average16,Average64,Average256,Average1024,Average8192;
  Average16 = Benchmark1(NumJumps, BodyLen, 16, NumIterations);
  Average64 = Benchmark1(NumJumps, BodyLen, 64, NumIterations);
  Average256 = Benchmark1(NumJumps, BodyLen, 256, NumIterations);
  Average1024 = Benchmark1(NumJumps, BodyLen, 1024, NumIterations);
  Average8192 = Benchmark1(NumJumps, BodyLen, 8192, NumIterations);
  printf("\n\nNON-HAND-OPTIMIZED VERSION BENCHMARKS:\n"
         "16                  64                  256                 1024                 8192\n"
         "------------------- ------------------- ------------------- -------------------- --------------------\n"
         "%19.2f %19.2f %19.2f %19.2f %19.2f\n\n", Average16, Average64, Average256, Average1024, Average8192);
  */
  Average16H2 = BenchmarkHOP2(2, BodyLen, 16, NumIterations);
  Average64H2 = BenchmarkHOP2(2, BodyLen, 64, NumIterations);
  Average256H2 = BenchmarkHOP2(2, BodyLen, 256, NumIterations);
  Average1024H2 = BenchmarkHOP2(2, BodyLen, 1024, NumIterations);
  Average8192H2 = BenchmarkHOP2(2, BodyLen, 8192, NumIterations);
  
  Average16H3 = BenchmarkHOP3(3, BodyLen, 16, NumIterations);
  Average64H3 = BenchmarkHOP3(3, BodyLen, 64, NumIterations);
  Average256H3 = BenchmarkHOP3(3, BodyLen, 256, NumIterations);
  Average1024H3 = BenchmarkHOP3(3, BodyLen, 1024, NumIterations);
  Average8192H3 = BenchmarkHOP3(3, BodyLen, 8192, NumIterations);
  
  Average16H4 = BenchmarkHOP4(4, BodyLen, 16, NumIterations);
  Average64H4 = BenchmarkHOP4(4, BodyLen, 64, NumIterations);
  Average256H4 = BenchmarkHOP4(4, BodyLen, 256, NumIterations);
  Average1024H4 = BenchmarkHOP4(4, BodyLen, 1024, NumIterations);
  Average8192H4 = BenchmarkHOP4(4, BodyLen, 8192, NumIterations);
  
  printf("\n\n2-Jumps BENCHMARKS(Real life usage):\n"
         "16                  64                  256                 1024                8192               \n"
         "------------------- ------------------- ------------------- ------------------- -------------------\n"
         "%19.2f %19.2f %19.2f %19.2f %19.2f\n\n", Average16H2, Average64H2, Average256H2, Average1024H2, Average8192H2);
  printf("\n\n3-Jumps BENCHMARKS(Real life usage):\n"
         "16                  64                  256                 1024                8192               \n"
         "------------------- ------------------- ------------------- ------------------- -------------------\n"
         "%19.2f %19.2f %19.2f %19.2f %19.2f\n\n", Average16H3, Average64H3, Average256H3, Average1024H3, Average8192H3);
  printf("\n\n4-Jumps BENCHMARKS(Real life usage):\n"
         "16                  64                  256                 1024                8192               \n"
         "------------------- ------------------- ------------------- ------------------- -------------------\n"
         "%19.2f %19.2f %19.2f %19.2f %19.2f\n\n", Average16H4, Average64H4, Average256H4, Average1024H4, Average8192H4);
  return 0;
}
