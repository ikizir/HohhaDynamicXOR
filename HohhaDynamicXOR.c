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

/* -*- c++ -*- */
/*
 * Copyright 2005,2011 Free Software Foundation, Inc.
 * 
 * This file is part of GNU Radio
 * 
 * GNU Radio is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
 * any later version.
 * 
 * GNU Radio is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with GNU Radio; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street,
 * Boston, MA 02110-1301, USA.
 */

/*
 * See also ISO 3309 [ISO-3309] or ITU-T V.42 [ITU-V42] for a formal specification.
 */

// Automatically generated CRC function
// polynomial: 0x104C11DB7
unsigned int
digital_update_crc32(unsigned int crc, const unsigned char *data, size_t len)
{
    static const unsigned int table[256] = {
    0x00000000U,0x04C11DB7U,0x09823B6EU,0x0D4326D9U,
    0x130476DCU,0x17C56B6BU,0x1A864DB2U,0x1E475005U,
    0x2608EDB8U,0x22C9F00FU,0x2F8AD6D6U,0x2B4BCB61U,
    0x350C9B64U,0x31CD86D3U,0x3C8EA00AU,0x384FBDBDU,
    0x4C11DB70U,0x48D0C6C7U,0x4593E01EU,0x4152FDA9U,
    0x5F15ADACU,0x5BD4B01BU,0x569796C2U,0x52568B75U,
    0x6A1936C8U,0x6ED82B7FU,0x639B0DA6U,0x675A1011U,
    0x791D4014U,0x7DDC5DA3U,0x709F7B7AU,0x745E66CDU,
    0x9823B6E0U,0x9CE2AB57U,0x91A18D8EU,0x95609039U,
    0x8B27C03CU,0x8FE6DD8BU,0x82A5FB52U,0x8664E6E5U,
    0xBE2B5B58U,0xBAEA46EFU,0xB7A96036U,0xB3687D81U,
    0xAD2F2D84U,0xA9EE3033U,0xA4AD16EAU,0xA06C0B5DU,
    0xD4326D90U,0xD0F37027U,0xDDB056FEU,0xD9714B49U,
    0xC7361B4CU,0xC3F706FBU,0xCEB42022U,0xCA753D95U,
    0xF23A8028U,0xF6FB9D9FU,0xFBB8BB46U,0xFF79A6F1U,
    0xE13EF6F4U,0xE5FFEB43U,0xE8BCCD9AU,0xEC7DD02DU,
    0x34867077U,0x30476DC0U,0x3D044B19U,0x39C556AEU,
    0x278206ABU,0x23431B1CU,0x2E003DC5U,0x2AC12072U,
    0x128E9DCFU,0x164F8078U,0x1B0CA6A1U,0x1FCDBB16U,
    0x018AEB13U,0x054BF6A4U,0x0808D07DU,0x0CC9CDCAU,
    0x7897AB07U,0x7C56B6B0U,0x71159069U,0x75D48DDEU,
    0x6B93DDDBU,0x6F52C06CU,0x6211E6B5U,0x66D0FB02U,
    0x5E9F46BFU,0x5A5E5B08U,0x571D7DD1U,0x53DC6066U,
    0x4D9B3063U,0x495A2DD4U,0x44190B0DU,0x40D816BAU,
    0xACA5C697U,0xA864DB20U,0xA527FDF9U,0xA1E6E04EU,
    0xBFA1B04BU,0xBB60ADFCU,0xB6238B25U,0xB2E29692U,
    0x8AAD2B2FU,0x8E6C3698U,0x832F1041U,0x87EE0DF6U,
    0x99A95DF3U,0x9D684044U,0x902B669DU,0x94EA7B2AU,
    0xE0B41DE7U,0xE4750050U,0xE9362689U,0xEDF73B3EU,
    0xF3B06B3BU,0xF771768CU,0xFA325055U,0xFEF34DE2U,
    0xC6BCF05FU,0xC27DEDE8U,0xCF3ECB31U,0xCBFFD686U,
    0xD5B88683U,0xD1799B34U,0xDC3ABDEDU,0xD8FBA05AU,
    0x690CE0EEU,0x6DCDFD59U,0x608EDB80U,0x644FC637U,
    0x7A089632U,0x7EC98B85U,0x738AAD5CU,0x774BB0EBU,
    0x4F040D56U,0x4BC510E1U,0x46863638U,0x42472B8FU,
    0x5C007B8AU,0x58C1663DU,0x558240E4U,0x51435D53U,
    0x251D3B9EU,0x21DC2629U,0x2C9F00F0U,0x285E1D47U,
    0x36194D42U,0x32D850F5U,0x3F9B762CU,0x3B5A6B9BU,
    0x0315D626U,0x07D4CB91U,0x0A97ED48U,0x0E56F0FFU,
    0x1011A0FAU,0x14D0BD4DU,0x19939B94U,0x1D528623U,
    0xF12F560EU,0xF5EE4BB9U,0xF8AD6D60U,0xFC6C70D7U,
    0xE22B20D2U,0xE6EA3D65U,0xEBA91BBCU,0xEF68060BU,
    0xD727BBB6U,0xD3E6A601U,0xDEA580D8U,0xDA649D6FU,
    0xC423CD6AU,0xC0E2D0DDU,0xCDA1F604U,0xC960EBB3U,
    0xBD3E8D7EU,0xB9FF90C9U,0xB4BCB610U,0xB07DABA7U,
    0xAE3AFBA2U,0xAAFBE615U,0xA7B8C0CCU,0xA379DD7BU,
    0x9B3660C6U,0x9FF77D71U,0x92B45BA8U,0x9675461FU,
    0x8832161AU,0x8CF30BADU,0x81B02D74U,0x857130C3U,
    0x5D8A9099U,0x594B8D2EU,0x5408ABF7U,0x50C9B640U,
    0x4E8EE645U,0x4A4FFBF2U,0x470CDD2BU,0x43CDC09CU,
    0x7B827D21U,0x7F436096U,0x7200464FU,0x76C15BF8U,
    0x68860BFDU,0x6C47164AU,0x61043093U,0x65C52D24U,
    0x119B4BE9U,0x155A565EU,0x18197087U,0x1CD86D30U,
    0x029F3D35U,0x065E2082U,0x0B1D065BU,0x0FDC1BECU,
    0x3793A651U,0x3352BBE6U,0x3E119D3FU,0x3AD08088U,
    0x2497D08DU,0x2056CD3AU,0x2D15EBE3U,0x29D4F654U,
    0xC5A92679U,0xC1683BCEU,0xCC2B1D17U,0xC8EA00A0U,
    0xD6AD50A5U,0xD26C4D12U,0xDF2F6BCBU,0xDBEE767CU,
    0xE3A1CBC1U,0xE760D676U,0xEA23F0AFU,0xEEE2ED18U,
    0xF0A5BD1DU,0xF464A0AAU,0xF9278673U,0xFDE69BC4U,
    0x89B8FD09U,0x8D79E0BEU,0x803AC667U,0x84FBDBD0U,
    0x9ABC8BD5U,0x9E7D9662U,0x933EB0BBU,0x97FFAD0CU,
    0xAFB010B1U,0xAB710D06U,0xA6322BDFU,0xA2F33668U,
    0xBCB4666DU,0xB8757BDAU,0xB5365D03U,0xB1F740B4U,
    };
  
    while (len > 0)
    {
      crc = table[*data ^ ((crc >> 24) & 0xff)] ^ (crc << 8);
      data++;
      len--;
    }
    return crc;
}

unsigned int digital_crc32(uint8_t *buf, size_t len)
{
  return digital_update_crc32(0xffffffff, buf, len) ^ 0xffffffff;
}

/* ------------------------- END CRC UTILITY FUNCTIONS ----------------- */


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

/* ------------------------- END UTILITY FUNCTIONS ----------------- */

#define SALT_SIZE 8 // 
#define MAX_NUM_JUMPS 64
#define FALSE (0U)
#define TRUE (!(FALSE))
#define VERBOSE

/* Function used to determine if V is unique among the first Pos elements
 * Used by the xorGetKey function to check particle length uniqueness
 */
#define MAX_BODY_SIZE 256 // DO NOT SET THIS LIMIT TO MORE THAN 256 BYTES! Or you must also change encryption&decryption code for key coverage

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
  assert(NumJumps > 1 && BodyLen > 7 && BodyLen<=MAX_BODY_SIZE & NumJumps<MAX_NUM_JUMPS && ((BodyLen-1)&BodyLen) == 0);
  
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
 * KeyCheckSum is 32 bit CRC checksum: Used to prevent "Related key attacks". If some bits of the key changes, entire cyphertext changes
 * InOutDataLen is the length of the data to be encrypted or decrypted
 * InOutBuf is the pointer to the data to be encrypted or decrypted
 * Salt(or nonce) is a 4 bytes random number array.
 * This logic ensures us this: An original key is created with an original salt value, for example for an online communication
 * for each distinct packet, in the packet header, we can transmit a specific salt value for that packet and we can encrypt it with original key and salt
 * when the receiver receives the packet, decrypts the new salt value with the original salt value of the key and passes that salt value to function,
 * and decrypts packet body with that salt value. This method prevents "known plaintext" attacks amongst others.
 */

#define xorComputeKeyCheckSum(K) digital_crc32(K, SP_BODY + GetBodyLen(K))

uint64_t xorEncrypt(uint8_t *K, uint8_t *Salt, uint32_t KeyCheckSum, size_t InOutDataLen, uint8_t *InOutBuf)
{ // Encrypts message and returns checksum of the InOutBuf BEFORE encyption
  // SaltData is a 8 bytes uint8 array! IT IS NOT READ ONLY! IT WILL BE MANIPULATED BY THE FUNCTION!
  register uint32_t tt, M;
  register size_t t;
  register uint8_t XORVal, LastPlainTextVal = 0, LastCipherTextVal = 0; // Last PLAINTEXT byte processed. It will be an input parameter for the next encryption
  register uint64_t Checksum=0;
  register uint32_t BodyMask = GetBodyLen(K); // +1 because we will use this "Mersenne number" for & operation instead of modulus operation
  uint8_t Body[MAX_BODY_SIZE];
  
  memcpy(Body,K+SP_BODY,BodyMask);
  BodyMask--;
  
  // We compute our start values as much randomly as possible upon salt(or nonce or iv) value which is transmitted with every data to be encrypted or decrypted
  LastCipherTextVal = Salt[0];
  LastCipherTextVal &= Salt[1]; 
  LastCipherTextVal ^= Salt[2]; 
  LastCipherTextVal &= Salt[3]; 
  LastCipherTextVal ^= Salt[4]; 
  LastCipherTextVal &= Salt[5]; 
  LastCipherTextVal ^= Salt[6]; 
  LastCipherTextVal &= Salt[7]; 
  
  // Our initial jump position in the key body depends on a random value
  M = (BodyMask & Salt[LastCipherTextVal&(SALT_SIZE-1)]);
  
  for (t=0; t<InOutDataLen; t++)
  {  
    // On first jump, we take previous encrypted byte and we jump to another position depending on its value
    XORVal = (Checksum&8) ^ Body[M]; 
    M = (M ^ LastCipherTextVal) & BodyMask; 
    
    XORVal ^= Body[M]; 
    XORVal ^= (1 << (KeyCheckSum&31)); 
    KeyCheckSum = ROL32_1(KeyCheckSum);
    M = (M ^ (*(Salt + (LastPlainTextVal&(SALT_SIZE-1))))) & BodyMask; 
    
    for (tt=2; tt < GetNumJumps(K); tt++)
    {
      // All following jumps are based on body values
      XORVal ^= Body[M]; 
      M = (M ^ Body[M]) & BodyMask; 
    }
    Checksum += InOutBuf[t]; 
    LastCipherTextVal = InOutBuf[t]; 
    
    XORVal ^= (1 << (M&7)); 
    InOutBuf[t] ^= ((uint8_t)(XORVal));
    LastPlainTextVal = LastCipherTextVal; 
    LastCipherTextVal = InOutBuf[t];
    
    Body[M] ^= LastCipherTextVal;
  }
  return Checksum;
} 
uint64_t xorDecrypt(uint8_t *K, uint8_t *Salt, uint32_t KeyCheckSum, size_t InOutDataLen, uint8_t *InOutBuf)
{ // Encrypts message and returns checksum of the InOutBuf BEFORE encyption
  // SaltData is a 8 bytes uint8 array! IT IS NOT READ ONLY! IT WILL BE MANIPULATED BY THE FUNCTION!
  register uint32_t tt, M;
  register size_t t;
  register uint8_t XORVal, LastPlainTextVal = 0, LastCipherTextVal = 0; // Last PLAINTEXT byte processed. It will be an input parameter for the next encryption
  register uint64_t Checksum=0;
  register uint32_t BodyMask = GetBodyLen(K); // +1 because we will use this "Mersenne number" for & operation instead of modulus operation
  uint8_t Body[MAX_BODY_SIZE];
  
  memcpy(Body,K+SP_BODY,BodyMask);
  BodyMask--;
  
  // We compute our start values as much randomly as possible upon salt(or nonce or iv) value which is transmitted with every data to be encrypted or decrypted
  LastCipherTextVal = Salt[0];
  LastCipherTextVal &= Salt[1]; 
  LastCipherTextVal ^= Salt[2]; 
  LastCipherTextVal &= Salt[3]; 
  LastCipherTextVal ^= Salt[4]; 
  LastCipherTextVal &= Salt[5]; 
  LastCipherTextVal ^= Salt[6]; 
  LastCipherTextVal &= Salt[7]; 
  
  // Our initial jump position in the key body depends on a random value
  M = (BodyMask & Salt[LastCipherTextVal&(SALT_SIZE-1)]);
  
  for (t=0; t<InOutDataLen; t++)
  {
    // In first two jumps, we take high 3 bits of each key body element
    XORVal = (Checksum&8) ^ Body[M]; 
    M = (M ^ LastCipherTextVal) & BodyMask; 
    
    XORVal ^= Body[M]; 
    XORVal ^= (1 << (KeyCheckSum&31)); 
    KeyCheckSum = ROL32_1(KeyCheckSum);
    M = (M ^ (*(Salt + (LastPlainTextVal&(SALT_SIZE-1))))) & BodyMask; 
    
    for (tt=2; tt < GetNumJumps(K); tt++)
    {
      // All following jumps are based on body values
      XORVal ^= Body[M]; 
      M = (M ^ Body[M]) & BodyMask; 
    }
    XORVal ^= (1 << (M&7)); 
    
    LastCipherTextVal = InOutBuf[t];
    InOutBuf[t] ^= ((uint8_t)(XORVal));
    LastPlainTextVal = InOutBuf[t]; 
    Checksum += LastPlainTextVal; 
    
    Body[M] ^= LastCipherTextVal;
  }
  return Checksum;
} 

uint64_t xorEncryptHOP2(uint8_t *K, uint8_t *Salt, uint32_t KeyCheckSum, size_t InOutDataLen, uint8_t *InOutBuf)
{ // Encrypts message and returns checksum of the InOutBuf BEFORE encyption
  // SaltData is a 8 bytes uint8 array! IT IS NOT READ ONLY! IT WILL BE MANIPULATED BY THE FUNCTION!
  register uint32_t M;
  register size_t t;
  register uint8_t XORVal, LastPlainTextVal = 0, LastCipherTextVal = 0; // Last PLAINTEXT byte processed. It will be an input parameter for the next encryption
  register uint64_t Checksum=0;
  register uint32_t BodyMask = GetBodyLen(K); // +1 because we will use this "Mersenne number" for & operation instead of modulus operation
  uint8_t Body[MAX_BODY_SIZE];
  
  memcpy(Body,K+SP_BODY,BodyMask);
  BodyMask--;
  
  // We compute our start values as much randomly as possible upon salt(or nonce or iv) value which is transmitted with every data to be encrypted or decrypted
  LastCipherTextVal = Salt[0];
  LastCipherTextVal &= Salt[1]; 
  LastCipherTextVal ^= Salt[2]; 
  LastCipherTextVal &= Salt[3]; 
  LastCipherTextVal ^= Salt[4]; 
  LastCipherTextVal &= Salt[5]; 
  LastCipherTextVal ^= Salt[6]; 
  LastCipherTextVal &= Salt[7]; 
  
  // Our initial jump position in the key body depends on a random value
  M = (BodyMask & Salt[LastCipherTextVal&(SALT_SIZE-1)]);
  
  for (t=0; t<InOutDataLen; t++)
  {  
    // On first jump, we take previous encrypted byte and we jump to another position depending on its value
    XORVal = (Checksum&8) ^ Body[M]; 
    M = (M ^ LastCipherTextVal) & BodyMask; 
    
    XORVal ^= Body[M]; 
    XORVal ^= (1 << (KeyCheckSum&31)); 
    KeyCheckSum = ROL32_1(KeyCheckSum);
    M = (M ^ (*(Salt + (LastPlainTextVal&(SALT_SIZE-1))))) & BodyMask; 
    
    Checksum += InOutBuf[t]; 
    LastCipherTextVal = InOutBuf[t]; 
    
    XORVal ^= (1 << (M&7)); 
    InOutBuf[t] ^= ((uint8_t)(XORVal));
    LastPlainTextVal = LastCipherTextVal; 
    LastCipherTextVal = InOutBuf[t];
    
    Body[M] ^= LastCipherTextVal;
  }
  return Checksum;
} 
uint64_t xorDecryptHOP2(uint8_t *K, uint8_t *Salt, uint32_t KeyCheckSum, size_t InOutDataLen, uint8_t *InOutBuf)
{ // Encrypts message and returns checksum of the InOutBuf BEFORE encyption
  // SaltData is a 8 bytes uint8 array! IT IS NOT READ ONLY! IT WILL BE MANIPULATED BY THE FUNCTION!
  register uint32_t M;
  register size_t t;
  register uint8_t XORVal, LastPlainTextVal = 0, LastCipherTextVal = 0; // Last PLAINTEXT byte processed. It will be an input parameter for the next encryption
  register uint64_t Checksum=0;
  register uint32_t BodyMask = GetBodyLen(K); // +1 because we will use this "Mersenne number" for & operation instead of modulus operation
  uint8_t Body[MAX_BODY_SIZE];
  
  memcpy(Body,K+SP_BODY,BodyMask);
  BodyMask--;
  
  // We compute our start values as much randomly as possible upon salt(or nonce or iv) value which is transmitted with every data to be encrypted or decrypted
  LastCipherTextVal = Salt[0];
  LastCipherTextVal &= Salt[1]; 
  LastCipherTextVal ^= Salt[2]; 
  LastCipherTextVal &= Salt[3]; 
  LastCipherTextVal ^= Salt[4]; 
  LastCipherTextVal &= Salt[5]; 
  LastCipherTextVal ^= Salt[6]; 
  LastCipherTextVal &= Salt[7]; 
  
  // Our initial jump position in the key body depends on a random value
  M = (BodyMask & Salt[LastCipherTextVal&(SALT_SIZE-1)]);
  
  for (t=0; t<InOutDataLen; t++)
  {
    // In first two jumps, we take high 3 bits of each key body element
    XORVal = (Checksum&8) ^ Body[M]; 
    M = (M ^ LastCipherTextVal) & BodyMask; 
    
    XORVal ^= Body[M]; 
    XORVal ^= (1 << (KeyCheckSum&31)); 
    KeyCheckSum = ROL32_1(KeyCheckSum);
    M = (M ^ (*(Salt + (LastPlainTextVal&(SALT_SIZE-1))))) & BodyMask; 
    
    XORVal ^= (1 << (M&7)); 
    
    LastCipherTextVal = InOutBuf[t];
    InOutBuf[t] ^= ((uint8_t)(XORVal));
    LastPlainTextVal = InOutBuf[t]; 
    Checksum += LastPlainTextVal; 
    
    Body[M] ^= LastCipherTextVal;
  }
  return Checksum;
} 

uint64_t xorEncryptHOP3(uint8_t *K, uint8_t *Salt, uint32_t KeyCheckSum, size_t InOutDataLen, uint8_t *InOutBuf)
{ // Encrypts message and returns checksum of the InOutBuf BEFORE encyption
  // SaltData is a 8 bytes uint8 array! IT IS NOT READ ONLY! IT WILL BE MANIPULATED BY THE FUNCTION!
  register uint32_t M;
  register size_t t;
  register uint8_t XORVal, LastPlainTextVal = 0, LastCipherTextVal = 0; // Last PLAINTEXT byte processed. It will be an input parameter for the next encryption
  register uint64_t Checksum=0;
  register uint32_t BodyMask = GetBodyLen(K); // +1 because we will use this "Mersenne number" for & operation instead of modulus operation
  uint8_t Body[MAX_BODY_SIZE];
  
  memcpy(Body,K+SP_BODY,BodyMask);
  BodyMask--;
  
  // We compute our start values as much randomly as possible upon salt(or nonce or iv) value which is transmitted with every data to be encrypted or decrypted
  LastCipherTextVal = Salt[0];
  LastCipherTextVal &= Salt[1]; 
  LastCipherTextVal ^= Salt[2]; 
  LastCipherTextVal &= Salt[3]; 
  LastCipherTextVal ^= Salt[4]; 
  LastCipherTextVal &= Salt[5]; 
  LastCipherTextVal ^= Salt[6]; 
  LastCipherTextVal &= Salt[7]; 
  
  // Our initial jump position in the key body depends on a random value
  M = (BodyMask & Salt[LastCipherTextVal&(SALT_SIZE-1)]);
  
  for (t=0; t<InOutDataLen; t++)
  {  
    // On first jump, we take previous encrypted byte and we jump to another position depending on its value
    XORVal = (Checksum&8) ^ Body[M]; 
    M = (M ^ LastCipherTextVal) & BodyMask; 
    
    XORVal ^= Body[M]; 
    XORVal ^= (1 << (KeyCheckSum&31)); 
    KeyCheckSum = ROL32_1(KeyCheckSum);
    M = (M ^ (*(Salt + (LastPlainTextVal&(SALT_SIZE-1))))) & BodyMask; 
    
    // All following jumps are based on body values
    XORVal ^= Body[M]; 
    M = (M ^ Body[M]) & BodyMask; 

    Checksum += InOutBuf[t]; 
    LastCipherTextVal = InOutBuf[t]; 
    
    XORVal ^= (1 << (M&7)); 
    InOutBuf[t] ^= ((uint8_t)(XORVal));
    LastPlainTextVal = LastCipherTextVal; 
    LastCipherTextVal = InOutBuf[t];
    
    Body[M] ^= LastCipherTextVal;
  }
  return Checksum;
} 
uint64_t xorDecryptHOP3(uint8_t *K, uint8_t *Salt, uint32_t KeyCheckSum, size_t InOutDataLen, uint8_t *InOutBuf)
{ // Encrypts message and returns checksum of the InOutBuf BEFORE encyption
  // SaltData is a 8 bytes uint8 array! IT IS NOT READ ONLY! IT WILL BE MANIPULATED BY THE FUNCTION!
  register uint32_t M;
  register size_t t;
  register uint8_t XORVal, LastPlainTextVal = 0, LastCipherTextVal = 0; // Last PLAINTEXT byte processed. It will be an input parameter for the next encryption
  register uint64_t Checksum=0;
  register uint32_t BodyMask = GetBodyLen(K); // +1 because we will use this "Mersenne number" for & operation instead of modulus operation
  uint8_t Body[MAX_BODY_SIZE];
  
  memcpy(Body,K+SP_BODY,BodyMask);
  BodyMask--;
  
  // We compute our start values as much randomly as possible upon salt(or nonce or iv) value which is transmitted with every data to be encrypted or decrypted
  LastCipherTextVal = Salt[0];
  LastCipherTextVal &= Salt[1]; 
  LastCipherTextVal ^= Salt[2]; 
  LastCipherTextVal &= Salt[3]; 
  LastCipherTextVal ^= Salt[4]; 
  LastCipherTextVal &= Salt[5]; 
  LastCipherTextVal ^= Salt[6]; 
  LastCipherTextVal &= Salt[7]; 
  
  // Our initial jump position in the key body depends on a random value
  M = (BodyMask & Salt[LastCipherTextVal&(SALT_SIZE-1)]);
  
  for (t=0; t<InOutDataLen; t++)
  {
    // In first two jumps, we take high 3 bits of each key body element
    XORVal = (Checksum&8) ^ Body[M]; 
    M = (M ^ LastCipherTextVal) & BodyMask; 
    
    XORVal ^= Body[M]; 
    XORVal ^= (1 << (KeyCheckSum&31)); 
    KeyCheckSum = ROL32_1(KeyCheckSum);
    M = (M ^ (*(Salt + (LastPlainTextVal&(SALT_SIZE-1))))) & BodyMask; 
    
    // All following jumps are based on body values
    XORVal ^= Body[M]; 
    M = (M ^ Body[M]) & BodyMask; 

    XORVal ^= (1 << (M&7)); 
    
    LastCipherTextVal = InOutBuf[t];
    InOutBuf[t] ^= ((uint8_t)(XORVal));
    LastPlainTextVal = InOutBuf[t]; 
    Checksum += LastPlainTextVal; 
    
    Body[M] ^= LastCipherTextVal;
  }
  return Checksum;
} 


uint64_t xorEncryptHOP4(uint8_t *K, uint8_t *Salt, uint32_t KeyCheckSum, size_t InOutDataLen, uint8_t *InOutBuf)
{ // Encrypts message and returns checksum of the InOutBuf BEFORE encyption
  // SaltData is a 8 bytes uint8 array! IT IS NOT READ ONLY! IT WILL BE MANIPULATED BY THE FUNCTION!
  register uint32_t M;
  register size_t t;
  register uint8_t XORVal, LastPlainTextVal = 0, LastCipherTextVal = 0; // Last PLAINTEXT byte processed. It will be an input parameter for the next encryption
  register uint64_t Checksum=0;
  register uint32_t BodyMask = GetBodyLen(K); // +1 because we will use this "Mersenne number" for & operation instead of modulus operation
  uint8_t Body[MAX_BODY_SIZE];
  
  memcpy(Body,K+SP_BODY,BodyMask);
  BodyMask--;
  
  // We compute our start values as much randomly as possible upon salt(or nonce or iv) value which is transmitted with every data to be encrypted or decrypted
  LastCipherTextVal = Salt[0];
  LastCipherTextVal &= Salt[1]; 
  LastCipherTextVal ^= Salt[2]; 
  LastCipherTextVal &= Salt[3]; 
  LastCipherTextVal ^= Salt[4]; 
  LastCipherTextVal &= Salt[5]; 
  LastCipherTextVal ^= Salt[6]; 
  LastCipherTextVal &= Salt[7]; 
  
  // Our initial jump position in the key body depends on a random value
  M = (BodyMask & Salt[LastCipherTextVal&(SALT_SIZE-1)]);
  
  for (t=0; t<InOutDataLen; t++)
  {  
    // On first jump, we take previous encrypted byte and we jump to another position depending on its value
    XORVal = (Checksum&8) ^ Body[M]; 
    M = (M ^ LastCipherTextVal) & BodyMask; 
    
    XORVal ^= Body[M]; 
    XORVal ^= (1 << (KeyCheckSum&31)); 
    KeyCheckSum = ROL32_1(KeyCheckSum);
    M = (M ^ (*(Salt + (LastPlainTextVal&(SALT_SIZE-1))))) & BodyMask; 
    
    // All following jumps are based on body values
    XORVal ^= Body[M]; 
    M = (M ^ Body[M]) & BodyMask; 
    XORVal ^= Body[M]; 
    M = (M ^ Body[M]) & BodyMask; 
    
    Checksum += InOutBuf[t]; 
    LastCipherTextVal = InOutBuf[t]; 
    
    XORVal ^= (1 << (M&7)); 
    InOutBuf[t] ^= ((uint8_t)(XORVal));
    LastPlainTextVal = LastCipherTextVal; 
    LastCipherTextVal = InOutBuf[t];
    
    Body[M] ^= LastCipherTextVal;
  }
  return Checksum;
} 
uint64_t xorDecryptHOP4(uint8_t *K, uint8_t *Salt, uint32_t KeyCheckSum, size_t InOutDataLen, uint8_t *InOutBuf)
{ // Encrypts message and returns checksum of the InOutBuf BEFORE encyption
  // SaltData is a 8 bytes uint8 array! IT IS NOT READ ONLY! IT WILL BE MANIPULATED BY THE FUNCTION!
  register uint32_t M;
  register size_t t;
  register uint8_t XORVal, LastPlainTextVal = 0, LastCipherTextVal = 0; // Last PLAINTEXT byte processed. It will be an input parameter for the next encryption
  register uint64_t Checksum=0;
  register uint32_t BodyMask = GetBodyLen(K); // +1 because we will use this "Mersenne number" for & operation instead of modulus operation
  uint8_t Body[MAX_BODY_SIZE];
  
  memcpy(Body,K+SP_BODY,BodyMask);
  BodyMask--;
  
  // We compute our start values as much randomly as possible upon salt(or nonce or iv) value which is transmitted with every data to be encrypted or decrypted
  LastCipherTextVal = Salt[0];
  LastCipherTextVal &= Salt[1]; 
  LastCipherTextVal ^= Salt[2]; 
  LastCipherTextVal &= Salt[3]; 
  LastCipherTextVal ^= Salt[4]; 
  LastCipherTextVal &= Salt[5]; 
  LastCipherTextVal ^= Salt[6]; 
  LastCipherTextVal &= Salt[7]; 
  
  // Our initial jump position in the key body depends on a random value
  M = (BodyMask & Salt[LastCipherTextVal&(SALT_SIZE-1)]);
  
  for (t=0; t<InOutDataLen; t++)
  {
    // In first two jumps, we take high 3 bits of each key body element
    XORVal = (Checksum&8) ^ Body[M]; 
    M = (M ^ LastCipherTextVal) & BodyMask; 
    
    XORVal ^= Body[M]; 
    XORVal ^= (1 << (KeyCheckSum&31)); 
    KeyCheckSum = ROL32_1(KeyCheckSum);
    M = (M ^ (*(Salt + (LastPlainTextVal&(SALT_SIZE-1))))) & BodyMask; 
    
    // All following jumps are based on body values
    XORVal ^= Body[M]; 
    M = (M ^ Body[M]) & BodyMask; 
    XORVal ^= Body[M]; 
    M = (M ^ Body[M]) & BodyMask; 
    
    XORVal ^= (1 << (M&7)); 
    
    LastCipherTextVal = InOutBuf[t];
    InOutBuf[t] ^= ((uint8_t)(XORVal));
    LastPlainTextVal = InOutBuf[t]; 
    Checksum += LastPlainTextVal; 
    
    Body[M] ^= LastCipherTextVal;
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
double MemCpyBenchmark1(uint32_t TestSampleLength, uint32_t NumIterations)
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
  double Average = PrintElapsedTime(&StartTime,TotalProcessedBytes);
  free(Data);
  free(DestBuf);
  return Average;
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
  uint32_t KeyCheckSum;
  
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
  uint32_t KeyCheckSum;
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
  uint32_t KeyCheckSum;
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
  uint32_t KeyCheckSum;
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
      printf("String: %s ... optimized version test result: FAILED!!!!\n----------------------------------------\n", Data);
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
  uint32_t KeyCheckSum;
  uint64_t OriginalSaltData, SaltData;
  
  
  GetRandomNumbers(SALT_SIZE, (uint8_t *)&OriginalSaltData); // Fill salt data with random numbers
  SaltData = OriginalSaltData;
  
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

int64_t EncryptFile(const char *InFileName, const char *OutFileName, uint8_t *KeyBuf, uint32_t KeyCheckSum)
{
  int32_t FDesc;   
  int64_t Len, RLen;
  uint8_t *Data;
  uint64_t CheckSum=0, SaltData;
  
  if ((FDesc = open(InFileName, O_RDONLY)) == -1)
  {
    printf("Error in opening file!\n");
    return -1;
  }
  Len = lseek(FDesc, 0, SEEK_END);
  lseek(FDesc, 0, SEEK_SET);
  Data = (uint8_t *)malloc(Len);
  RLen = read(FDesc, Data, Len);
  if (RLen != Len)
  {
    printf("Error in reading file!\n");
    return -1;
  }
  close(FDesc);
  
  //GetRandomNumbers(8, (uint8_t *)(&SaltData));
  // Copy key's original salt value to salt buffer
  memcpy(&SaltData, KeyBuf+SP_SALT_DATA, SALT_SIZE);
  if (GetNumJumps(KeyBuf) == 2)
    CheckSum = xorEncryptHOP2(KeyBuf, (uint8_t *)(&SaltData), KeyCheckSum, Len, Data); 
  else if (GetNumJumps(KeyBuf) == 3)
    CheckSum = xorEncryptHOP3(KeyBuf, (uint8_t *)(&SaltData), KeyCheckSum, Len, Data); 
  else if (GetNumJumps(KeyBuf) == 4)
    CheckSum = xorEncryptHOP4(KeyBuf, (uint8_t *)(&SaltData), KeyCheckSum, Len, Data); 
  
  if ((FDesc = creat(OutFileName, 700)) == -1)
  {
    printf("Error in creating output file!\n");
    return -1;
  }
  write(FDesc,Data,Len);
  free(Data);
  close(FDesc);
  return CheckSum;
}
int64_t EncryptBMPFile(const char *InFileName, const char *OutFileName, uint8_t *KeyBuf, uint32_t KeyCheckSum)
{ // Encrypts a bmp file for visual attack
  int32_t FDesc;   
  int64_t Len, RLen;
  uint8_t *Data;
  uint8_t OriginalHeader[255];
  uint64_t CheckSum=0, SaltData;
  
  if ((FDesc = open(InFileName, O_RDONLY)) == -1)
  {
    printf("Error in opening file!\n");
    return -1;
  }
  Len = lseek(FDesc, 0, SEEK_END);
  if (lseek(FDesc, 0, SEEK_SET) != 0)
  {
    printf("Error seeking to beginning of file!\n");
    return -1;
  }  
  Data = (uint8_t *)malloc(Len);
  RLen = read(FDesc, Data, Len);
  if (RLen != Len)
  {
    printf("Error in reading file!\n");
    return -1;
  }
  // Copy original header to a buffer
  memcpy(OriginalHeader, Data, 54);
  close(FDesc);
  
  //GetRandomNumbers(8, (uint8_t *)(&SaltData));
  // Copy key's original salt value to salt buffer
  memcpy(&SaltData, KeyBuf+SP_SALT_DATA, SALT_SIZE);
/*  if (GetNumJumps(KeyBuf) == 2)
    CheckSum = xorEncryptHOP2(KeyBuf, (uint8_t *)(&SaltData), KeyCheckSum, Len, Data); 
  else if (GetNumJumps(KeyBuf) == 3)
    CheckSum = xorEncryptHOP3(KeyBuf, (uint8_t *)(&SaltData), KeyCheckSum, Len, Data); 
  else if (GetNumJumps(KeyBuf) == 4)
    CheckSum = xorEncryptHOP4(KeyBuf, (uint8_t *)(&SaltData), KeyCheckSum, Len, Data); 
  else {
    printf("Invalid number of jumps!\n");
    exit(-1);
  }*/
  CheckSum = xorEncrypt(KeyBuf, (uint8_t *)(&SaltData), KeyCheckSum, Len, Data); 
  if ((FDesc = creat(OutFileName, 777)) == -1)
  {
    printf("Error in creating output file!\n");
    return -1;
  }
  // Copy original header to encrypted file in order to see it on a browser
  memcpy(Data, OriginalHeader, 54);
  if (write(FDesc,Data,Len) != Len)
  {
    printf("Error writing file!\n");
    return -1;
  }  
  free(Data);
  close(FDesc);
  return CheckSum;
}

#define SAMPLE_FILE_PATH "/home/ikizir/Downloads/panda.bmp"
  #define SAMPLE_OUT_FILE_PATH "/home/ikizir/Downloads/panda_enc.bmp"
void TestEncryptFile(unsigned NumJumps, unsigned BodyLen)
{
  unsigned long long int ChkSum;
  unsigned RawKeyLen = xorComputeKeyBufLen(BodyLen);
  uint8_t *KeyBuf = (uint8_t *)malloc(RawKeyLen);
  uint32_t KeyCheckSum;
  char *Base64EncodedKeyStr;
  
  printf("----------- FILE ENC TEST(%u Jumps) --------------\n",NumJumps);
  xorGetKey(NumJumps, BodyLen, KeyBuf);
  KeyCheckSum = xorComputeKeyCheckSum(KeyBuf);
  Base64EncodedKeyStr = Base64Encode((const char *)KeyBuf, RawKeyLen);
  printf("Base64 encoded key: %s\n", Base64EncodedKeyStr);
  xorAnalyzeKey(KeyBuf);
  ChkSum = EncryptFile(SAMPLE_FILE_PATH, SAMPLE_OUT_FILE_PATH, KeyBuf, KeyCheckSum);
  printf("Result: %llu\n", ChkSum);
}

void TestEncryptBMPFile(const char *InFileName, const char *OutFileName, unsigned NumJumps, unsigned BodyLen)
{
  unsigned long long int ChkSum;
  unsigned RawKeyLen = xorComputeKeyBufLen(BodyLen);
  uint8_t *KeyBuf = (uint8_t *)malloc(RawKeyLen);
  uint32_t KeyCheckSum;
  char *Base64EncodedKeyStr;
  
  printf("----------- FILE ENC TEST(%u Jumps) --------------\n",NumJumps);
  xorGetKey(NumJumps, BodyLen, KeyBuf);
  KeyCheckSum = xorComputeKeyCheckSum(KeyBuf);
  Base64EncodedKeyStr = Base64Encode((const char *)KeyBuf, RawKeyLen);
  printf("Base64 encoded key: %s\n", Base64EncodedKeyStr);
  xorAnalyzeKey(KeyBuf);
  ChkSum = EncryptBMPFile(InFileName, OutFileName, KeyBuf, KeyCheckSum);
  printf("Result: %llu\n", ChkSum);
}

void CreateVisualProofs()
{
  TestEncryptBMPFile("/home/ikizir/Downloads/panda.bmp", "/home/ikizir/Downloads/panda_enc_2J_64.bmp", 2, 64);
  TestEncryptBMPFile("/home/ikizir/Downloads/panda.bmp", "/home/ikizir/Downloads/panda_enc_3J_64.bmp", 3, 64);
  
  TestEncryptBMPFile("/home/ikizir/Downloads/panda.bmp", "/home/ikizir/Downloads/panda_enc_2J_128.bmp", 2, 128);
  TestEncryptBMPFile("/home/ikizir/Downloads/panda.bmp", "/home/ikizir/Downloads/panda_enc_3J_128.bmp", 3, 128);
  
  TestEncryptBMPFile("/home/ikizir/Downloads/panda.bmp", "/home/ikizir/Downloads/panda_enc_2J_256.bmp", 2, 256);
  TestEncryptBMPFile("/home/ikizir/Downloads/panda.bmp", "/home/ikizir/Downloads/panda_enc_3J_256.bmp", 3, 256);
  
  TestEncryptBMPFile("/home/ikizir/Downloads/Bitmap1.bmp", "/home/ikizir/Downloads/Bitmap1_enc_2J_64.bmp", 2, 64);
  TestEncryptBMPFile("/home/ikizir/Downloads/Bitmap1.bmp", "/home/ikizir/Downloads/Bitmap1_enc_3J_64.bmp", 3, 64);
  
  TestEncryptBMPFile("/home/ikizir/Downloads/Bitmap1.bmp", "/home/ikizir/Downloads/Bitmap1_enc_2J_128.bmp", 2, 128);
  TestEncryptBMPFile("/home/ikizir/Downloads/Bitmap1.bmp", "/home/ikizir/Downloads/Bitmap1_enc_3J_128.bmp", 3, 128);
  
  TestEncryptBMPFile("/home/ikizir/Downloads/Bitmap1.bmp", "/home/ikizir/Downloads/Bitmap1_enc_2J_256.bmp", 2, 256);
  TestEncryptBMPFile("/home/ikizir/Downloads/Bitmap1.bmp", "/home/ikizir/Downloads/Bitmap1_enc_3J_256.bmp", 3, 256);
  
  TestEncryptBMPFile("/home/ikizir/Downloads/Viking.bmp", "/home/ikizir/Downloads/Viking_enc_2J_64.bmp", 2, 64);
  TestEncryptBMPFile("/home/ikizir/Downloads/Viking.bmp", "/home/ikizir/Downloads/Viking_enc_3J_64.bmp", 3, 64);
  
  TestEncryptBMPFile("/home/ikizir/Downloads/Viking.bmp", "/home/ikizir/Downloads/Viking_enc_2J_128.bmp", 2, 128);
  TestEncryptBMPFile("/home/ikizir/Downloads/Viking.bmp", "/home/ikizir/Downloads/Viking_enc_3J_128.bmp", 3, 128);
  
  TestEncryptBMPFile("/home/ikizir/Downloads/Viking.bmp", "/home/ikizir/Downloads/Viking_enc_2J_256.bmp", 2, 256);
  TestEncryptBMPFile("/home/ikizir/Downloads/Viking.bmp", "/home/ikizir/Downloads/Viking_enc_3J_256.bmp", 3, 256);
  
  TestEncryptBMPFile("/home/ikizir/Downloads/B.bmp", "/home/ikizir/Downloads/B_enc_2J_64.bmp", 2, 64);
  TestEncryptBMPFile("/home/ikizir/Downloads/B.bmp", "/home/ikizir/Downloads/B_enc_3J_64.bmp", 3, 64);
  
  TestEncryptBMPFile("/home/ikizir/Downloads/B.bmp", "/home/ikizir/Downloads/B_enc_2J_128.bmp", 2, 128);
  TestEncryptBMPFile("/home/ikizir/Downloads/B.bmp", "/home/ikizir/Downloads/B_enc_3J_128.bmp", 3, 128);
  
  TestEncryptBMPFile("/home/ikizir/Downloads/B.bmp", "/home/ikizir/Downloads/B_enc_2J_256.bmp", 2, 256);
  TestEncryptBMPFile("/home/ikizir/Downloads/B.bmp", "/home/ikizir/Downloads/B_enc_3J_256.bmp", 3, 256);
  
  
  
  
  TestEncryptBMPFile("/home/ikizir/Downloads/penguen.bmp", "/home/ikizir/Downloads/penguen_enc_2J_64.bmp", 2, 64);
  TestEncryptBMPFile("/home/ikizir/Downloads/penguen.bmp", "/home/ikizir/Downloads/penguen_enc_3J_64.bmp", 3, 64);
  
  TestEncryptBMPFile("/home/ikizir/Downloads/penguen.bmp", "/home/ikizir/Downloads/penguen_enc_2J_128.bmp", 2, 128);
  TestEncryptBMPFile("/home/ikizir/Downloads/penguen.bmp", "/home/ikizir/Downloads/penguen_enc_3J_128.bmp", 3, 128);
  
  TestEncryptBMPFile("/home/ikizir/Downloads/penguen.bmp", "/home/ikizir/Downloads/penguen_enc_2J_256.bmp", 2, 256);
  TestEncryptBMPFile("/home/ikizir/Downloads/penguen.bmp", "/home/ikizir/Downloads/penguen_enc_3J_256.bmp", 3, 256);
  
}


int main()
{
  uint32_t BodyLen = 128, NumJumps=2;

  //printf("CRC: %u\n", digital_crc32((uint8_t *)"Ismail", 7));
  //printf("CRC: %u\n", digital_crc32((uint8_t *)"Hasan", 5));
  //printf("CRC: %u\n", digital_crc32((uint8_t *)"Ismail", 7));
  
  Test1(2, BodyLen);
  //CreateVisualProofs();
//  exit(-1);
  
  //CircularShiftTest();
  //uint32_t TestSampleLength = 8192;
  uint32_t NumIterations = 1000000;
  //D1();
  Test1(2, BodyLen);
  Test1(3, BodyLen);
  Test1(4, BodyLen);
  //Test1(4, BodyLen);
  //Test1(5, BodyLen);
  
    //exit(-1);
  
  CheckOptimizedVersion(2, BodyLen);
  CheckOptimizedVersion(3, BodyLen);
  CheckOptimizedVersion(4, BodyLen);
  //CheckOptimizedVersion(5, BodyLen);
  
  double Average16M,Average64M,Average256M,Average1024M,Average8192M;
  double Average16H2,Average64H2,Average256H2,Average1024H2,Average8192H2;
  double Average16H3,Average64H3,Average256H3,Average1024H3,Average8192H3;
  double Average16H4,Average64H4,Average256H4,Average1024H4,Average8192H4;
  
  
  Average16M = MemCpyBenchmark1(16, NumIterations);
  Average64M = MemCpyBenchmark1(64, NumIterations);
  Average256M = MemCpyBenchmark1(256, NumIterations);
  Average1024M = MemCpyBenchmark1(1024, NumIterations);
  Average8192M = MemCpyBenchmark1(8192, NumIterations);
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
  
  printf("\n\nMemcpy BENCHMARKS(Real life usage):\n"
         "16                  64                  256                 1024                8192               \n"
         "------------------- ------------------- ------------------- ------------------- -------------------\n"
         "%19.2f %19.2f %19.2f %19.2f %19.2f\n\n", Average16M, Average64M, Average256M, Average1024M, Average8192M);
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
