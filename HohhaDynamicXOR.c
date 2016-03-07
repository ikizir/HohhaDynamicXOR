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

// Portable endian macros by Mathias Panzenböck
#if (defined(_WIN16) || defined(_WIN32) || defined(_WIN64)) && !defined(__WINDOWS__)

#	define __WINDOWS__

#endif

#if defined(__linux__) || defined(__CYGWIN__)

#	include <endian.h>

#elif defined(__APPLE__)

#	include <libkern/OSByteOrder.h>

#	define htobe16(x) OSSwapHostToBigInt16(x)
#	define htole16(x) OSSwapHostToLittleInt16(x)
#	define be16toh(x) OSSwapBigToHostInt16(x)
#	define le16toh(x) OSSwapLittleToHostInt16(x)
 
#	define htobe32(x) OSSwapHostToBigInt32(x)
#	define htole32(x) OSSwapHostToLittleInt32(x)
#	define be32toh(x) OSSwapBigToHostInt32(x)
#	define le32toh(x) OSSwapLittleToHostInt32(x)
 
#	define htobe64(x) OSSwapHostToBigInt64(x)
#	define htole64(x) OSSwapHostToLittleInt64(x)
#	define be64toh(x) OSSwapBigToHostInt64(x)
#	define le64toh(x) OSSwapLittleToHostInt64(x)

#	define __BYTE_ORDER    BYTE_ORDER
#	define __BIG_ENDIAN    BIG_ENDIAN
#	define __LITTLE_ENDIAN LITTLE_ENDIAN
#	define __PDP_ENDIAN    PDP_ENDIAN

#elif defined(__OpenBSD__)

#	include <sys/endian.h>

#elif defined(__NetBSD__) || defined(__FreeBSD__) || defined(__DragonFly__)

#	include <sys/endian.h>

#	define be16toh(x) betoh16(x)
#	define le16toh(x) letoh16(x)

#	define be32toh(x) betoh32(x)
#	define le32toh(x) letoh32(x)

#	define be64toh(x) betoh64(x)
#	define le64toh(x) letoh64(x)

#elif defined(__WINDOWS__)

#	include <winsock2.h>
#	include <sys/param.h>

#	if BYTE_ORDER == LITTLE_ENDIAN

#		define htobe16(x) htons(x)
#		define htole16(x) (x)
#		define be16toh(x) ntohs(x)
#		define le16toh(x) (x)
 
#		define htobe32(x) htonl(x)
#		define htole32(x) (x)
#		define be32toh(x) ntohl(x)
#		define le32toh(x) (x)
 
#		define htobe64(x) htonll(x)
#		define htole64(x) (x)
#		define be64toh(x) ntohll(x)
#		define le64toh(x) (x)

#	elif BYTE_ORDER == BIG_ENDIAN

		/* that would be xbox 360 */
#		define htobe16(x) (x)
#		define htole16(x) __builtin_bswap16(x)
#		define be16toh(x) (x)
#		define le16toh(x) __builtin_bswap16(x)
 
#		define htobe32(x) (x)
#		define htole32(x) __builtin_bswap32(x)
#		define be32toh(x) (x)
#		define le32toh(x) __builtin_bswap32(x)
 
#		define htobe64(x) (x)
#		define htole64(x) __builtin_bswap64(x)
#		define be64toh(x) (x)
#		define le64toh(x) __builtin_bswap64(x)

#	else

#		error byte order not supported

#	endif

#	define __BYTE_ORDER    BYTE_ORDER
#	define __BIG_ENDIAN    BIG_ENDIAN
#	define __LITTLE_ENDIAN LITTLE_ENDIAN
#	define __PDP_ENDIAN    PDP_ENDIAN

#else

#	error platform not supported

#endif

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
  uint8_t *B;
  B = (uint8_t *)calloc(1, Size);
  if (B == NULL)
  {
    printf("Out of memory!");
    exit(-1);
  }
  return B;
}

static const unsigned int CRC32Table[256] = {
  0x00000000, 0xf26b8303, 0xe13b70f7, 0x1350f3f4,
  0xc79a971f, 0x35f1141c, 0x26a1e7e8, 0xd4ca64eb,
  0x8ad958cf, 0x78b2dbcc, 0x6be22838, 0x9989ab3b,
  0x4d43cfd0, 0xbf284cd3, 0xac78bf27, 0x5e133c24,
  0x105ec76f, 0xe235446c, 0xf165b798, 0x030e349b,
  0xd7c45070, 0x25afd373, 0x36ff2087, 0xc494a384,
  0x9a879fa0, 0x68ec1ca3, 0x7bbcef57, 0x89d76c54,
  0x5d1d08bf, 0xaf768bbc, 0xbc267848, 0x4e4dfb4b,
  0x20bd8ede, 0xd2d60ddd, 0xc186fe29, 0x33ed7d2a,
  0xe72719c1, 0x154c9ac2, 0x061c6936, 0xf477ea35,
  0xaa64d611, 0x580f5512, 0x4b5fa6e6, 0xb93425e5,
  0x6dfe410e, 0x9f95c20d, 0x8cc531f9, 0x7eaeb2fa,
  0x30e349b1, 0xc288cab2, 0xd1d83946, 0x23b3ba45,
  0xf779deae, 0x05125dad, 0x1642ae59, 0xe4292d5a,
  0xba3a117e, 0x4851927d, 0x5b016189, 0xa96ae28a,
  0x7da08661, 0x8fcb0562, 0x9c9bf696, 0x6ef07595,
  0x417b1dbc, 0xb3109ebf, 0xa0406d4b, 0x522bee48,
  0x86e18aa3, 0x748a09a0, 0x67dafa54, 0x95b17957,
  0xcba24573, 0x39c9c670, 0x2a993584, 0xd8f2b687,
  0x0c38d26c, 0xfe53516f, 0xed03a29b, 0x1f682198,
  0x5125dad3, 0xa34e59d0, 0xb01eaa24, 0x42752927,
  0x96bf4dcc, 0x64d4cecf, 0x77843d3b, 0x85efbe38,
  0xdbfc821c, 0x2997011f, 0x3ac7f2eb, 0xc8ac71e8,
  0x1c661503, 0xee0d9600, 0xfd5d65f4, 0x0f36e6f7,
  0x61c69362, 0x93ad1061, 0x80fde395, 0x72966096,
  0xa65c047d, 0x5437877e, 0x4767748a, 0xb50cf789,
  0xeb1fcbad, 0x197448ae, 0x0a24bb5a, 0xf84f3859,
  0x2c855cb2, 0xdeeedfb1, 0xcdbe2c45, 0x3fd5af46,
  0x7198540d, 0x83f3d70e, 0x90a324fa, 0x62c8a7f9,
  0xb602c312, 0x44694011, 0x5739b3e5, 0xa55230e6,
  0xfb410cc2, 0x092a8fc1, 0x1a7a7c35, 0xe811ff36,
  0x3cdb9bdd, 0xceb018de, 0xdde0eb2a, 0x2f8b6829,
  0x82f63b78, 0x709db87b, 0x63cd4b8f, 0x91a6c88c,
  0x456cac67, 0xb7072f64, 0xa457dc90, 0x563c5f93,
  0x082f63b7, 0xfa44e0b4, 0xe9141340, 0x1b7f9043,
  0xcfb5f4a8, 0x3dde77ab, 0x2e8e845f, 0xdce5075c,
  0x92a8fc17, 0x60c37f14, 0x73938ce0, 0x81f80fe3,
  0x55326b08, 0xa759e80b, 0xb4091bff, 0x466298fc,
  0x1871a4d8, 0xea1a27db, 0xf94ad42f, 0x0b21572c,
  0xdfeb33c7, 0x2d80b0c4, 0x3ed04330, 0xccbbc033,
  0xa24bb5a6, 0x502036a5, 0x4370c551, 0xb11b4652,
  0x65d122b9, 0x97baa1ba, 0x84ea524e, 0x7681d14d,
  0x2892ed69, 0xdaf96e6a, 0xc9a99d9e, 0x3bc21e9d,
  0xef087a76, 0x1d63f975, 0x0e330a81, 0xfc588982,
  0xb21572c9, 0x407ef1ca, 0x532e023e, 0xa145813d,
  0x758fe5d6, 0x87e466d5, 0x94b49521, 0x66df1622,
  0x38cc2a06, 0xcaa7a905, 0xd9f75af1, 0x2b9cd9f2,
  0xff56bd19, 0x0d3d3e1a, 0x1e6dcdee, 0xec064eed,
  0xc38d26c4, 0x31e6a5c7, 0x22b65633, 0xd0ddd530,
  0x0417b1db, 0xf67c32d8, 0xe52cc12c, 0x1747422f,
  0x49547e0b, 0xbb3ffd08, 0xa86f0efc, 0x5a048dff,
  0x8ecee914, 0x7ca56a17, 0x6ff599e3, 0x9d9e1ae0,
  0xd3d3e1ab, 0x21b862a8, 0x32e8915c, 0xc083125f,
  0x144976b4, 0xe622f5b7, 0xf5720643, 0x07198540,
  0x590ab964, 0xab613a67, 0xb831c993, 0x4a5a4a90,
  0x9e902e7b, 0x6cfbad78, 0x7fab5e8c, 0x8dc0dd8f,
  0xe330a81a, 0x115b2b19, 0x020bd8ed, 0xf0605bee,
  0x24aa3f05, 0xd6c1bc06, 0xc5914ff2, 0x37faccf1,
  0x69e9f0d5, 0x9b8273d6, 0x88d28022, 0x7ab90321,
  0xae7367ca, 0x5c18e4c9, 0x4f48173d, 0xbd23943e,
  0xf36e6f75, 0x0105ec76, 0x12551f82, 0xe03e9c81,
  0x34f4f86a, 0xc69f7b69, 0xd5cf889d, 0x27a40b9e,
  0x79b737ba, 0x8bdcb4b9, 0x988c474d, 0x6ae7c44e,
  0xbe2da0a5, 0x4c4623a6, 0x5f16d052, 0xad7d5351
  };
unsigned int digital_update_crc32(unsigned int crc, const unsigned char *data, size_t len)
{
  while (len--)
  {
    crc = CRC32Table[*data ^ ((crc >> 24) & 0xff)] ^ (crc << 8);
    data++;
  }
  return crc;
}

unsigned int digital_crc32(uint8_t *buf, size_t len)
{
  return digital_update_crc32(0xffffffff, buf, len) ^ 0xffffffff;
}

/* ------------------------- END CRC UTILITY FUNCTIONS ----------------- */

// Note that reading from /dev/urandom is a slow operation
// For real life application, we recommend to use /dev/urandom for only key generation and another, faster, cryptographically secure random generator for random padding data
// If you increase RANDOM_BUF_SIZE, you will see dramatic speed gains on Packet benchmarks
#define RANDOM_BUF_SIZE 65536
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
  //memcpy(Buffer, RandomBuf + RandomBufStartPos, ByteCount);
  unsigned int t;
  uint8_t *dp = Buffer, *sp = RandomBuf + RandomBufStartPos;
  for (t=0; t<ByteCount; t++)
  {
    *dp = *sp;
    ++dp;
    ++sp;
  }
  RandomBufStartPos += ByteCount;
}
uint8_t GetRandomUInt8(void)
{
  if (RandomBufStartPos >= RANDOM_BUF_SIZE)
    RandomizeBuffer();
  return RandomBuf[RandomBufStartPos++];
}
uint32_t GetRandomUInt32(void)
{
  if (RandomBufStartPos+sizeof(uint32_t) > RANDOM_BUF_SIZE)
    RandomizeBuffer();
  RandomBufStartPos += sizeof(uint32_t);
  return *((uint32_t *)(RandomBuf + RandomBufStartPos-sizeof(uint32_t)));
}
uint64_t GetRandomUInt64(void)
{
  if (RandomBufStartPos+sizeof(uint64_t) > RANDOM_BUF_SIZE)
    RandomizeBuffer();
  RandomBufStartPos += sizeof(uint64_t);
  return *((uint64_t *)(RandomBuf + RandomBufStartPos-sizeof(uint64_t)));
}
void GetRandomNumbersForPadding(uint32_t ByteCount, uint8_t *Buffer)
{ // You can use another faster random generator here
  // For IOS, we can simply use arc4random_buf(void *buf, size_t nbytes); function
  GetRandomNumbers(ByteCount, Buffer);
}

// Standart C has not ROL or ROR function, but most modern cpus has instructions for circular shift operations
// This is a quick and dirty code for standart C versions and Intel Family cpu assembler optimized versions

#define GCC_INTEL_OPTIMIZED 
#if defined(GCC_INTEL_OPTIMIZED)
#define ROL32_1(v) asm ("rol %0;" :"=r"(v) /* output */ :"0"(v) /* input */ );
#define ROR32_1(v) asm ("ror %0;" :"=r"(v) /* output */ :"0"(v) /* input */ );
#else
#define ROL32_1(v) v=(((v) << 1) | ((v) >> 31))
#define ROR32_1(v) v=(((v) >> 1) | ((v) << 31))
#endif

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

/* ------------------------- END UTILITY FUNCTIONS ----------------- */

#define SALT_SIZE 8 // LEAVE AS IT IS
#define MAX_NUM_JUMPS 127 
#define FALSE (0U)
#define TRUE (!(FALSE))
#define VERBOSE

#define MIN_BODY_SIZE 64
#define MAX_BODY_SIZE 256 // DO NOT SET THIS LIMIT TO MORE THAN 256 BYTES! Or you must also change encryption&decryption code for key coverage

#define SP_NUM_JUMPS 0
#define SP_BODY_LEN 1
#define SP_SALT_DATA 3
#define SP_BODY (SP_SALT_DATA+SALT_SIZE)
#define GetBodyLen(K) (K[SP_BODY_LEN] + 256 * K[SP_BODY_LEN+1])
#define GetBodyPtr(K) (K + SP_BODY)
#define GetNumJumps(K) (K[SP_NUM_JUMPS])
#define xorComputeKeyBufLen(BodyLen) (SP_BODY+BodyLen)

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
  if (BodyLen < MIN_BODY_SIZE)
    return -4;
  if (BodyLen > MAX_BODY_SIZE)
    return -5;
  
#ifdef VERBOSE
  printf("Generating key ... BodyLen: %u NumJumps: %u\n",BodyLen,NumJumps);
#endif
  KeyBuf[SP_NUM_JUMPS] = (uint8_t)(NumJumps&255);
  KeyBuf[SP_BODY_LEN] = (uint8_t)((BodyLen % 256) & 0xff);
  KeyBuf[SP_BODY_LEN+1] = (uint8_t)((BodyLen / 256) & 0xff);
  GetRandomNumbers(SALT_SIZE + BodyLen, KeyBuf + SP_SALT_DATA); // Fill 4 bytes salt data with random numbers
  return 0;
}
#define xorComputeKeyCheckSum(K) digital_crc32(GetBodyPtr(K), GetBodyLen(K))
inline unsigned int CheckKeyIntegrity(uint8_t *K, size_t TotalKeyBufLen)
{
  unsigned int BodyLen = GetBodyLen(K);
  return ( 
    ((SP_BODY + BodyLen) == TotalKeyBufLen) &&
    (((BodyLen-1) & BodyLen) == 0) && // Key body must be a multiple of two
    (BodyLen >= MIN_BODY_SIZE && BodyLen <= MAX_BODY_SIZE) &&
    (GetNumJumps(K) >= 2 && GetNumJumps(K) <= MAX_NUM_JUMPS)
  );
}

void xorAnalyzeKey(uint8_t *K)
{
  uint32_t t;
    
  printf("-------------------------- Shifting xor key analyze ----------------------------\nNumJumps: %u\nBodyLen: %u\nKeycrc: %u\nSalt: ", 
         K[0], GetBodyLen(K), xorComputeKeyCheckSum(K));
  for (t=0; t < SALT_SIZE; t++)
  {
    printf(" %u", K[SP_SALT_DATA+t]);
  }
  printf("\n");
}

#if SALT_SIZE != 8
#error SALT_SIZE is not supported
#endif
/* UNOPTIMIZED VERSION for BETTER UNDERSTANDING OF THE FUNCTIONING OF THE ALGORITHM. IT IS NOT USED IN REAL LIFE. USE OPTIMIZED VERSIONS!
 * Encrypts or decrypts InOutBuf 
 * KeyBuf is the raw key buffer
 * KeyCheckSum is 32 bit CRC checksum: Used to prevent "Related key attacks". If some bits of the key changes, entire cyphertext changes
 * InOutDataLen is the length of the data to be encrypted or decrypted
 * InOutBuf is the pointer to the data to be encrypted or decrypted
 * Salt(or nonce) is a 8 bytes random number array.
 * This logic ensures us this: An original key is created with an original salt value, for example for an online communication
 * for each distinct packet, in the packet header, we can transmit a specific salt value for that packet and we can encrypt it with original key and salt
 * when the receiver receives the packet, decrypts the new salt value with the original salt value of the key and passes that salt value to function,
 * and decrypts packet body with that salt value. This method prevents "known plaintext" attacks amongst others.
 */
#define DISABLE_HAND_OPTIMIZED_FNCS
uint32_t xorEncrypt(uint8_t *K, uint8_t *Salt, uint32_t KeyCheckSum, size_t InOutDataLen, uint8_t *InOutBuf)
{ // Encrypts message and returns CRC32 of the PLAINTEXT!
  // SaltData is a SALT_SIZE bytes uint8 array! 
  // Our aim is to create maximum random output from "any" input. It may an all 0 file or all random distribution. It doesn't matter
  // In order to do this, we have : 
  //   Salt: 8 bytes of random salt data
  //   KeyChecksum: 32 bit CRC key checksum
  //   Body: KeyBody bytes of key body
  //   Checksum: Plaintext crc checksum
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
  //     We use a third dynamic variable initially set to Key CRC and dynamically updated according to plaintext checksum
  //     We update key body elements according to Salt values
  //     We update salt data according to key body elements
  //     Our jump start point and steps are hidden
  //     We use the previous XOR values obtained to XOR with the next XOR values(chaining)
  register uint32_t Salt1,Salt2;
  register size_t t = InOutDataLen;
  register uint8_t tt;
  register uint32_t M; // This is our moving pointer on key body bytes
  register uint32_t Checksum=0xffffffff, V = KeyCheckSum;
  register uint32_t BodyMask = GetBodyLen(K)-1; // +1 because we will use this "Mersenne number" for & operation instead of modulus operation
  register uint8_t *p;
  uint8_t Body[MAX_BODY_SIZE];
  
  memcpy(Body,K+SP_BODY, BodyMask+1);
  p = InOutBuf;
  // We compute our start values as much randomly as possible upon salt(or nonce or iv) value which is transmitted with every data to be encrypted or decrypted
  Salt1 = ((uint32_t)(Salt[0]) | ((uint32_t)(Salt[1]) << 8) | ((uint32_t)(Salt[2]) << 16) | ((uint32_t)(Salt[3]) << 24));
  Salt2 = ((uint32_t)(Salt[4]) | ((uint32_t)(Salt[5]) << 8) | ((uint32_t)(Salt[6]) << 16) | ((uint32_t)(Salt[7]) << 24));
  // Our initial jump position in the key body depends on a random value
  M = ((((uint32_t)Salt[3]) * ((uint32_t)Salt[7]))) & BodyMask;
  
  while (t--)
  { 
    // First jump point
    Salt1 ^= (uint32_t)(Body[M]);
    Body[M] = (uint8_t)(Salt2); 
    M = (M^Salt2) & BodyMask; 
    ROL32_1(Salt2);
    
    // Second jump point
    Salt2 ^= (uint32_t)(Body[M]);
    Body[M] = (uint8_t)(Salt1); 
    M = (M^V) & BodyMask; 
    ROR32_1(Salt1);
    
    // Following jumps
    for (tt=2; tt<GetNumJumps(K); tt++)
    {
      if (tt&1)
      {
        Salt2 ^= (uint32_t)(Body[M]);
        Body[M] = (uint8_t)(Salt1); 
        M = (M^Salt1) & BodyMask; 
        ROR32_1(Salt1);
      }
      else {
        Salt1 ^= (uint32_t)(Body[M]);
        Body[M] = (uint8_t)(Salt2); 
        M = (M^V) & BodyMask; 
        ROL32_1(Salt2);
      }
    }
    Checksum = CRC32Table[*p ^ ((Checksum >> 24) & 0xff)] ^ (Checksum << 8); 
    *p ^= ((uint8_t)(Salt1^Salt2^V));
    V ^= Checksum;
    ROL32_1(V);
    p++;
  }
  return Checksum ^ 0xffffffff;
} 

uint32_t xorDecrypt(uint8_t *K, uint8_t *Salt, uint32_t KeyCheckSum, size_t InOutDataLen, uint8_t *InOutBuf)
{ // Decrypts message and returns CRC32 of the PLAINTEXT
  // SaltData is a 8 bytes uint8 array! 
  register uint32_t Salt1,Salt2;
  register size_t t = InOutDataLen;
  register uint8_t tt;
  register uint32_t M; // This is our moving pointer on key body bytes
  register uint32_t Checksum=0xffffffff, V = KeyCheckSum;
  register uint32_t BodyMask = GetBodyLen(K)-1; // +1 because we will use this "Mersenne number" for & operation instead of modulus operation
  register uint8_t *p;
  uint8_t Body[MAX_BODY_SIZE];
  
  memcpy(Body,K+SP_BODY, BodyMask+1);
  p = InOutBuf;
  // We compute our start values as much randomly as possible upon salt(or nonce or iv) value which is transmitted with every data to be encrypted or decrypted
  Salt1 = (uint32_t)(Salt[0]) | ((uint32_t)(Salt[1]) << 8) | ((uint32_t)(Salt[2]) << 16) | ((uint32_t)(Salt[3]) << 24);
  Salt2 = (uint32_t)(Salt[4]) | ((uint32_t)(Salt[5]) << 8) | ((uint32_t)(Salt[6]) << 16) | ((uint32_t)(Salt[7]) << 24);
  // Our initial jump position in the key body depends on a random value
  M = ((((uint32_t)Salt[3]) * ((uint32_t)Salt[7]))) & BodyMask;
  //printf("Salt1: %u Salt2: %u M: %u\n ",Salt1,Salt2,M);
  while (t--)
  { 
    //V ^= ((uint32_t)1 << (uint32_t)(M&(uint32_t)31));
    // First jump point
    Salt1 ^= (uint32_t)(Body[M]);
    Body[M] = (uint8_t)(Salt2); 
    M = (M^Salt2) & BodyMask; 
    ROL32_1(Salt2);
    
    // Second jump point
    Salt2 ^= (uint32_t)(Body[M]);
    Body[M] = (uint8_t)(Salt1); 
    M = (M^V) & BodyMask; 
    ROR32_1(Salt1);
    
    // Following jumps
    for (tt=2; tt<GetNumJumps(K); tt++)
    {
      if (tt&1)
      {
        Salt2 ^= (uint32_t)(Body[M]);
        Body[M] = (uint8_t)(Salt1); 
        M = (M^Salt1) & BodyMask; 
        ROR32_1(Salt1);
      }
      else {
        Salt1 ^= (uint32_t)(Body[M]);
        Body[M] = (uint8_t)(Salt2); 
        M = (M^V) & BodyMask; 
        ROL32_1(Salt2);
      }
    }
    *p ^= ((uint8_t)(Salt1^Salt2^V));
    Checksum = CRC32Table[*p ^ ((Checksum >> 24) & 0xff)] ^ (Checksum << 8); 
    V ^= Checksum;
    ROL32_1(V);
    p++;
  }
  return Checksum ^ 0xffffffff;
} 

typedef uint32_t (*THOPEncryptorFnc)(uint8_t *Key, uint8_t *Salt, uint32_t KeyCheckSum, size_t InOutDataLen, uint8_t *InOutBuf);
typedef uint32_t (*THOPDecryptorFnc)(uint8_t *Key, uint8_t *Salt, uint32_t KeyCheckSum, size_t InOutDataLen, uint8_t *InOutBuf);

#ifdef DISABLE_HAND_OPTIMIZED_FNCS
static inline THOPEncryptorFnc xorGetProperHOPEncryptorFnc(uint8_t *Key)
{
  return &xorEncrypt;
}
static inline THOPDecryptorFnc xorGetProperHOPDecryptorFnc(uint8_t *Key)
{
  return &xorDecrypt;
}
#else
uint32_t xorEncryptHOP2(uint8_t *K, uint8_t *Salt, uint32_t KeyCheckSum, size_t InOutDataLen, uint8_t *InOutBuf)
{
  register uint32_t Salt1,Salt2;
  register size_t t = InOutDataLen;
  register uint32_t M; // This is our moving pointer on key body bytes
  register uint32_t Checksum=0xffffffff, V = KeyCheckSum;
  register uint32_t BodyMask = GetBodyLen(K)-1; // +1 because we will use this "Mersenne number" for & operation instead of modulus operation
  register uint8_t *p;
  uint8_t Body[MAX_BODY_SIZE];
  
  memcpy(Body,K+SP_BODY, BodyMask+1);
  p = InOutBuf;
  // We compute our start values as much randomly as possible upon salt(or nonce or iv) value which is transmitted with every data to be encrypted or decrypted
  Salt1 = ((uint32_t)(Salt[0]) | ((uint32_t)(Salt[1]) << 8) | ((uint32_t)(Salt[2]) << 16) | ((uint32_t)(Salt[3]) << 24));
  Salt2 = ((uint32_t)(Salt[4]) | ((uint32_t)(Salt[5]) << 8) | ((uint32_t)(Salt[6]) << 16) | ((uint32_t)(Salt[7]) << 24));
  // Our initial jump position in the key body depends on a random value
  M = ((((uint32_t)Salt[3]) * ((uint32_t)Salt[7]))) & BodyMask;
  
  while (t--)
  { 
    // First jump point
    Salt1 ^= (uint32_t)(Body[M]);
    Body[M] = (uint8_t)(Salt2); 
    M = (M^Salt2) & BodyMask; 
    ROL32_1(Salt2);
    
    // Second jump point
    Salt2 ^= (uint32_t)(Body[M]);
    Body[M] = (uint8_t)(Salt1); 
    M = (M^V) & BodyMask; 
    ROR32_1(Salt1);
    
    Checksum = CRC32Table[*p ^ ((Checksum >> 24) & 0xff)] ^ (Checksum << 8); 
    *p ^= ((uint8_t)(Salt1^Salt2^V));
    V ^= Checksum;
    ROL32_1(V);
    p++;
  }
  return Checksum ^ 0xffffffff;
} 

uint32_t xorDecryptHOP2(uint8_t *K, uint8_t *Salt, uint32_t KeyCheckSum, size_t InOutDataLen, uint8_t *InOutBuf)
{
  register uint32_t Salt1,Salt2;
  register size_t t = InOutDataLen;
  register uint32_t M; // This is our moving pointer on key body bytes
  register uint32_t Checksum=0xffffffff, V = KeyCheckSum;
  register uint32_t BodyMask = GetBodyLen(K)-1; // +1 because we will use this "Mersenne number" for & operation instead of modulus operation
  register uint8_t *p;
  uint8_t Body[MAX_BODY_SIZE];
  
  memcpy(Body,K+SP_BODY, BodyMask+1);
  p = InOutBuf;
  // We compute our start values as much randomly as possible upon salt(or nonce or iv) value which is transmitted with every data to be encrypted or decrypted
  Salt1 = ((uint32_t)(Salt[0]) | ((uint32_t)(Salt[1]) << 8) | ((uint32_t)(Salt[2]) << 16) | ((uint32_t)(Salt[3]) << 24));
  Salt2 = ((uint32_t)(Salt[4]) | ((uint32_t)(Salt[5]) << 8) | ((uint32_t)(Salt[6]) << 16) | ((uint32_t)(Salt[7]) << 24));
  // Our initial jump position in the key body depends on a random value
  M = ((((uint32_t)Salt[3]) * ((uint32_t)Salt[7]))) & BodyMask;
  //printf("Salt1: %u Salt2: %u M: %u\n ",Salt1,Salt2,M);
  while (t--)
  { 
    // First jump point
    Salt1 ^= (uint32_t)(Body[M]);
    Body[M] = (uint8_t)(Salt2); 
    M = (M^Salt2) & BodyMask; 
    ROL32_1(Salt2);
    
    // Second jump point
    Salt2 ^= (uint32_t)(Body[M]);
    Body[M] = (uint8_t)(Salt1); 
    M = (M^V) & BodyMask; 
    ROR32_1(Salt1);
    
    *p ^= ((uint8_t)(Salt1^Salt2^V));
    Checksum = CRC32Table[*p ^ ((Checksum >> 24) & 0xff)] ^ (Checksum << 8); 
    V ^= Checksum;
    ROL32_1(V);
    p++;
  }
  return Checksum ^ 0xffffffff;
} 

uint32_t xorEncryptHOP3(uint8_t *K, uint8_t *Salt, uint32_t KeyCheckSum, size_t InOutDataLen, uint8_t *InOutBuf)
{
  register uint32_t Salt1,Salt2;
  register size_t t = InOutDataLen;
  register uint32_t M; // This is our moving pointer on key body bytes
  register uint32_t Checksum=0xffffffff, V = KeyCheckSum;
  register uint32_t BodyMask = GetBodyLen(K)-1; // +1 because we will use this "Mersenne number" for & operation instead of modulus operation
  register uint8_t *p;
  uint8_t Body[MAX_BODY_SIZE];
  
  memcpy(Body,K+SP_BODY, BodyMask+1);
  p = InOutBuf;
  // We compute our start values as much randomly as possible upon salt(or nonce or iv) value which is transmitted with every data to be encrypted or decrypted
  Salt1 = ((uint32_t)(Salt[0]) | ((uint32_t)(Salt[1]) << 8) | ((uint32_t)(Salt[2]) << 16) | ((uint32_t)(Salt[3]) << 24));
  Salt2 = ((uint32_t)(Salt[4]) | ((uint32_t)(Salt[5]) << 8) | ((uint32_t)(Salt[6]) << 16) | ((uint32_t)(Salt[7]) << 24));
  // Our initial jump position in the key body depends on a random value
  M = ((((uint32_t)Salt[3]) * ((uint32_t)Salt[7]))) & BodyMask;
  
  while (t--)
  { 
    // First jump point
    Salt1 ^= (uint32_t)(Body[M]);
    Body[M] = (uint8_t)(Salt2); 
    M = (M^Salt2) & BodyMask; 
    ROL32_1(Salt2);
    
    // Second jump point
    Salt2 ^= (uint32_t)(Body[M]);
    Body[M] = (uint8_t)(Salt1); 
    M = (M^V) & BodyMask; 
    ROR32_1(Salt1);
    
    Salt1 ^= (uint32_t)(Body[M]);
    Body[M] = (uint8_t)(Salt2); 
    M = (M^V) & BodyMask; 
    ROL32_1(Salt2);
    
    Checksum = CRC32Table[*p ^ ((Checksum >> 24) & 0xff)] ^ (Checksum << 8); 
    *p ^= ((uint8_t)(Salt1^Salt2^V));
    V ^= Checksum;
    ROL32_1(V);
    p++;
  }
  return Checksum ^ 0xffffffff;
} 

uint32_t xorDecryptHOP3(uint8_t *K, uint8_t *Salt, uint32_t KeyCheckSum, size_t InOutDataLen, uint8_t *InOutBuf)
{
  register uint32_t Salt1,Salt2;
  register size_t t = InOutDataLen;
  register uint32_t M; // This is our moving pointer on key body bytes
  register uint32_t Checksum=0xffffffff, V = KeyCheckSum;
  register uint32_t BodyMask = GetBodyLen(K)-1; // +1 because we will use this "Mersenne number" for & operation instead of modulus operation
  register uint8_t *p;
  uint8_t Body[MAX_BODY_SIZE];
  
  memcpy(Body,K+SP_BODY, BodyMask+1);
  p = InOutBuf;
  // We compute our start values as much randomly as possible upon salt(or nonce or iv) value which is transmitted with every data to be encrypted or decrypted
  Salt1 = ((uint32_t)(Salt[0]) | ((uint32_t)(Salt[1]) << 8) | ((uint32_t)(Salt[2]) << 16) | ((uint32_t)(Salt[3]) << 24));
  Salt2 = ((uint32_t)(Salt[4]) | ((uint32_t)(Salt[5]) << 8) | ((uint32_t)(Salt[6]) << 16) | ((uint32_t)(Salt[7]) << 24));
  // Our initial jump position in the key body depends on a random value
  M = ((((uint32_t)Salt[3]) * ((uint32_t)Salt[7]))) & BodyMask;
  
  while (t--)
  { 
    // First jump point
    Salt1 ^= (uint32_t)(Body[M]);
    Body[M] = (uint8_t)(Salt2); 
    M = (M^Salt2) & BodyMask; 
    ROL32_1(Salt2);
    
    // Second jump point
    Salt2 ^= (uint32_t)(Body[M]);
    Body[M] = (uint8_t)(Salt1); 
    M = (M^V) & BodyMask; 
    ROR32_1(Salt1);
    
    Salt1 ^= (uint32_t)(Body[M]);
    Body[M] = (uint8_t)(Salt2); 
    M = (M^V) & BodyMask; 
    ROL32_1(Salt2);
    
    *p ^= ((uint8_t)(Salt1^Salt2^V));
    Checksum = CRC32Table[*p ^ ((Checksum >> 24) & 0xff)] ^ (Checksum << 8); 
    V ^= Checksum;
    ROL32_1(V);
    p++;
  }
  return Checksum ^ 0xffffffff;
} 

uint32_t xorEncryptHOP4(uint8_t *K, uint8_t *Salt, uint32_t KeyCheckSum, size_t InOutDataLen, uint8_t *InOutBuf)
{
  register uint32_t Salt1,Salt2;
  register size_t t = InOutDataLen;
  register uint32_t M; // This is our moving pointer on key body bytes
  register uint32_t Checksum=0xffffffff, V = KeyCheckSum;
  register uint32_t BodyMask = GetBodyLen(K)-1; // +1 because we will use this "Mersenne number" for & operation instead of modulus operation
  register uint8_t *p;
  uint8_t Body[MAX_BODY_SIZE];
  
  memcpy(Body,K+SP_BODY, BodyMask+1);
  p = InOutBuf;
  // We compute our start values as much randomly as possible upon salt(or nonce or iv) value which is transmitted with every data to be encrypted or decrypted
  Salt1 = ((uint32_t)(Salt[0]) | ((uint32_t)(Salt[1]) << 8) | ((uint32_t)(Salt[2]) << 16) | ((uint32_t)(Salt[3]) << 24));
  Salt2 = ((uint32_t)(Salt[4]) | ((uint32_t)(Salt[5]) << 8) | ((uint32_t)(Salt[6]) << 16) | ((uint32_t)(Salt[7]) << 24));
  // Our initial jump position in the key body depends on a random value
  M = ((((uint32_t)Salt[3]) * ((uint32_t)Salt[7]))) & BodyMask;
  
  while (t--)
  { 
    // First jump point
    Salt1 ^= (uint32_t)(Body[M]);
    Body[M] = (uint8_t)(Salt2); 
    M = (M^Salt2) & BodyMask; 
    ROL32_1(Salt2);
    
    // Second jump point
    Salt2 ^= (uint32_t)(Body[M]);
    Body[M] = (uint8_t)(Salt1); 
    M = (M^V) & BodyMask; 
    ROR32_1(Salt1);
    
    // Following jumps
    Salt1 ^= (uint32_t)(Body[M]);
    Body[M] = (uint8_t)(Salt2); 
    M = (M^V) & BodyMask; 
    ROL32_1(Salt2);
    
    Salt2 ^= (uint32_t)(Body[M]);
    Body[M] = (uint8_t)(Salt1); 
    M = (M^Salt1) & BodyMask; 
    ROR32_1(Salt1);
    
    Checksum = CRC32Table[*p ^ ((Checksum >> 24) & 0xff)] ^ (Checksum << 8); 
    *p ^= ((uint8_t)(Salt1^Salt2^V));
    V ^= Checksum;
    ROL32_1(V);
    p++;
  }
  return Checksum ^ 0xffffffff;
} 

uint32_t xorDecryptHOP4(uint8_t *K, uint8_t *Salt, uint32_t KeyCheckSum, size_t InOutDataLen, uint8_t *InOutBuf)
{
  register uint32_t Salt1,Salt2;
  register size_t t = InOutDataLen;
  register uint32_t M; // This is our moving pointer on key body bytes
  register uint32_t Checksum=0xffffffff, V = KeyCheckSum;
  register uint32_t BodyMask = GetBodyLen(K)-1; // +1 because we will use this "Mersenne number" for & operation instead of modulus operation
  register uint8_t *p;
  uint8_t Body[MAX_BODY_SIZE];
  
  memcpy(Body,K+SP_BODY, BodyMask+1);
  p = InOutBuf;
  // We compute our start values as much randomly as possible upon salt(or nonce or iv) value which is transmitted with every data to be encrypted or decrypted
  Salt1 = ((uint32_t)(Salt[0]) | ((uint32_t)(Salt[1]) << 8) | ((uint32_t)(Salt[2]) << 16) | ((uint32_t)(Salt[3]) << 24));
  Salt2 = ((uint32_t)(Salt[4]) | ((uint32_t)(Salt[5]) << 8) | ((uint32_t)(Salt[6]) << 16) | ((uint32_t)(Salt[7]) << 24));
  // Our initial jump position in the key body depends on a random value
  M = ((((uint32_t)Salt[3]) * ((uint32_t)Salt[7]))) & BodyMask;
  
  while (t--)
  { 
    // First jump point
    Salt1 ^= (uint32_t)(Body[M]);
    Body[M] = (uint8_t)(Salt2); 
    M = (M^Salt2) & BodyMask; 
    ROL32_1(Salt2);
    
    // Second jump point
    Salt2 ^= (uint32_t)(Body[M]);
    Body[M] = (uint8_t)(Salt1); 
    M = (M^V) & BodyMask; 
    ROR32_1(Salt1);
    
    // Following jumps
    Salt1 ^= (uint32_t)(Body[M]);
    Body[M] = (uint8_t)(Salt2); 
    M = (M^V) & BodyMask; 
    ROL32_1(Salt2);
    
    Salt2 ^= (uint32_t)(Body[M]);
    Body[M] = (uint8_t)(Salt1); 
    M = (M^Salt1) & BodyMask; 
    ROR32_1(Salt1);
    
    *p ^= ((uint8_t)(Salt1^Salt2^V));
    Checksum = CRC32Table[*p ^ ((Checksum >> 24) & 0xff)] ^ (Checksum << 8); 
    V ^= Checksum;
    ROL32_1(V);
    p++;
  }
  return Checksum ^ 0xffffffff;
} 

static inline THOPEncryptorFnc xorGetProperHOPEncryptorFnc(uint8_t *Key)
{
  if (GetNumJumps(Key) == 2)
    return &xorEncryptHOP2;
  if (GetNumJumps(Key) == 3)
    return &xorEncryptHOP3;
  if (GetNumJumps(Key) == 4)
    return &xorEncryptHOP4;
  return &xorEncrypt;
}
static inline THOPDecryptorFnc xorGetProperHOPDecryptorFnc(uint8_t *Key)
{
  if (GetNumJumps(Key) == 2)
    return &xorDecryptHOP2;
  if (GetNumJumps(Key) == 3)
    return &xorDecryptHOP3;
  if (GetNumJumps(Key) == 4)
    return &xorDecryptHOP4;
  return &xorDecrypt;
}
#endif
/* --------------------- HOHHA PROTOCOL SPECIFIC FUNCTIONS --------------- */
// The number of random padding bytes before the salt value in header. We use those random numbers in order to better hide our packet salt value. 
// The minimum value is 1, maximum is 8. We use 4 as default in Hohha Messenger. 
#define HEADER_SALT_PADDING_SIZE 1
// Hohha communication header structure:
// 1 byte AlignedLenSize which describes the size of the variable which describes the length of the plaintext body, in bytes
// SALT_PADDING_SIZE byte dummy random byte(against known plaintext attacks)
// 8 bytes packet salt value for encryption
// 4 bytes -> Plaintext checksum
// 1 byte Left padding(number of random characters) before the real plaintext or ciphertext
// AlignedLenSize bytes for packet plaintext length(low byte first)
#define ALIGN_TO(v,n) ((uint32_t)((v)+(n)-1) & (uint32_t)(0xffffffff - (n - 1)))
typedef struct __attribute__((__packed__)) {
  // AlignedLenSize; 
  //   Highest 1 bit(&128) : 1->Packet is encrypted 0->Packet is NOT encrypted
  //   Next highest 2 bits(&64 &32) : RESERVED FOR COMPRESSION TYPE! NOT IMPLEMENTED YET!
  //   Low 3 bits(&7) : 1 --> Aligned length is between 0..255; 2-> 255..65535 3->0..2^24-1 4-> 65536..2^32-1 THIS VALUE IS NEVER ENCRYPTED
  uint8_t AlignedLenSize; 
  uint8_t SaltProtectionPadding[HEADER_SALT_PADDING_SIZE]; // Random data to better protect random salt data
  uint8_t Salt[SALT_SIZE]; // Salt value unique for packet
  uint32_t PlaintextCRC; // Plaintext CRC value to check integrity of the packet LITTLE ENDIAN
  uint8_t Padding; // LeftPad + RightPad 
  uint8_t AlignedLen[8]; // Plaintext or ciphertext aligned length. May be 1,2,3,4 or 8 bytes!!! 8 BYTES IS NOT IMPLEMENTED!
} THohhaPacketHeader;
//#define HHLEN sizeof(THohhaPacketHeader)
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
#define HOHHA_TOTAL_COMM_PACKET_SIZE(DataSize,DataAlignment) ((ALIGN_TO((DataSize)+1,DataAlignment)) + GetCommHeaderLenByAlignedLen((ALIGN_TO((DataSize)+1,DataAlignment))))
#define HOHHA_TOTAL_COMM_PACKET_SIZE_WITHOUT_ENCRYPTION(DataSize) ((DataSize) + GetCommHeaderLenByAlignedLen(DataSize))
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

void CreateHohhaCommunicationPacket2(uint8_t *K, uint32_t KeyCheckSum, size_t InDataLen, uint8_t *InBuf, uint32_t DataAlignment, uint8_t *OutBuf)
{ // This function encrypts InBuf and creates a communication packet with a proper header
  // OutBuf must be already allocated and must be enough large to store (InDataLen-1 + HOHHA_PACKET_ALIGNMENT + HHLEN) bytes
  if (!OutBuf || !(DataAlignment == 8 || DataAlignment == 16 || DataAlignment == 32 || DataAlignment == 64))
  {
    //printf("INVALID DATAALIGNMENT: %d\n", DataAlignment);
    return;
  }
  
  uint8_t *OriginalSalt = K + SP_SALT_DATA;
  size_t AlignedDataLen = ALIGN_TO(InDataLen+1,DataAlignment);
  THOPEncryptorFnc EncryptorFnc = xorGetProperHOPEncryptorFnc(K);
  uint8_t AlignedLenSize = GetAlignedLenSize(AlignedDataLen);
  size_t HHLEN = GetCommHeaderLenByAlignedLenSize(AlignedLenSize);
  uint8_t RPad;
  ssize_t LPad;
  
  THohhaPacketHeader *PacketHeader = (THohhaPacketHeader *)OutBuf;
  uint8_t *OBufStart = OutBuf + HHLEN;
  SetHeaderAlignedLenValue((THohhaPacketHeader *)OutBuf, AlignedDataLen);
  PacketHeader->Padding = (uint8_t)(AlignedDataLen-InDataLen);
  RPad = PacketHeader->Padding >> 1;
  LPad = PacketHeader->Padding - RPad;
  
  // First, let's create a new salt value and its padding data, unique for this transmission and copy original salt data to a buffer
  GetRandomNumbers(SALT_SIZE+HEADER_SALT_PADDING_SIZE, (uint8_t *)&(PacketHeader->SaltProtectionPadding));
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
  PacketHeader->PlaintextCRC = htole32(EncryptorFnc(K, PacketHeader->Salt, KeyCheckSum, AlignedDataLen, OBufStart));
  //printf("PacketHeader->PlaintextCRC: %u\n",PacketHeader->PlaintextCRC);
  // We encrypted our packet. Now, let's encrypt packet header with original salt and key. But we don't encrypt header's first byte(AlignedLenSize)
  EncryptorFnc(K, OriginalSalt, KeyCheckSum, HHLEN-(1+AlignedLenSize), OutBuf+1);
  // Set encrypted flag to TRUE
  *OutBuf |= 128;
}

uint8_t *CreateHohhaCommunicationPacket(uint8_t *K, uint32_t KeyCheckSum, size_t InDataLen, uint8_t *InBuf, uint32_t DataAlignment)
{ // This function encrypts InBuf and creates a communication packet with a proper header
  // Allocates and returns encrypted packet data with size equal to HOHHA_TOTAL_COMM_PACKET_SIZE(DataSize)
  // If DoNotEncrypt is true, data will not be encrypted and copied into the packet as plaintext
  if (!(DataAlignment == 8 || DataAlignment == 16 || DataAlignment == 32 || DataAlignment == 64))
  {
    //printf("INVALID DATAALIGNMENT: %d\n", DataAlignment);
    return NULL;
  }
  
  uint8_t *OutBuf = malloc(HOHHA_TOTAL_COMM_PACKET_SIZE(InDataLen, DataAlignment));
  
  if (OutBuf)
    CreateHohhaCommunicationPacket2(K, KeyCheckSum, InDataLen, InBuf, DataAlignment, OutBuf);
  return OutBuf;
}

uint8_t *CreateHohhaCommunicationPacketPlaintext(size_t InDataLen, uint8_t *InBuf)
{ // This function encrypts InBuf and creates a communication packet with a proper header but without encryption and data alignment
  uint8_t AlignedLenSize = GetAlignedLenSize(InDataLen);
  size_t HHLEN = GetCommHeaderLenByAlignedLenSize(AlignedLenSize);
  uint8_t *OutBuf = malloc(InDataLen + HHLEN);
  
  if (!OutBuf)
    return OutBuf;
  THohhaPacketHeader *PacketHeader = (THohhaPacketHeader *)OutBuf;
  SetHeaderAlignedLenValue((THohhaPacketHeader *)OutBuf, InDataLen);
  PacketHeader->Padding = 0;
  
  // Now, let's copy our plaintext to new packet
  memcpy(OutBuf + HHLEN, InBuf, InDataLen);
  PacketHeader->PlaintextCRC = digital_crc32(InBuf, InDataLen);
  return OutBuf;
}

void CreateHohhaCommunicationPacket2Plaintext(size_t InDataLen, uint8_t *InBuf, uint8_t *OutBuf)
{ // This function encrypts InBuf and creates a communication packet with a proper header but without encryption and data alignment
  // OutBuf must be already allocated and must be enough large to store (InDataLen + 4 + HHLEN) bytes
  uint8_t AlignedLenSize = GetAlignedLenSize(InDataLen);
  size_t HHLEN = GetCommHeaderLenByAlignedLenSize(AlignedLenSize);
  
  THohhaPacketHeader *PacketHeader = (THohhaPacketHeader *)OutBuf;
  SetHeaderAlignedLenValue((THohhaPacketHeader *)OutBuf, InDataLen);
  PacketHeader->Padding = 0;
  
  // Now, let's copy our plaintext to new packet
  memcpy(OutBuf + HHLEN, InBuf, InDataLen);
  PacketHeader->PlaintextCRC = digital_crc32(InBuf, InDataLen);
}

uint8_t *DecryptCommPacket(uint8_t *K, uint32_t KeyCheckSum, size_t TotalPacketLen, uint8_t *InOutBuf, ssize_t *PlainTextLen)
{ // Decrypts the packet and returns a pointer to decrypted data(NULL on error)
  // On return, PlainTextLen will contain length of the plaintext on success or negative on error
  size_t ALenSize = (*InOutBuf & 7);
  uint32_t PlaintextCRC;
  THohhaPacketHeader *PacketHeader = (THohhaPacketHeader *)InOutBuf;
  size_t HHLEN = GetCommHeaderLenByHeader(PacketHeader);
  *PlainTextLen = GetHeaderAlignedLenValue(PacketHeader);
  
  if (!ALenSize || ALenSize > 4 || *PlainTextLen < 0)
  {
    *PlainTextLen = -1;
    return NULL; // Body len size must be 1,2,3 or 4!!!
  }
  //printf("PacketHeader->AlignedLenSize: %u\n", PacketHeader->AlignedLenSize);
  if  (!(PacketHeader->AlignedLenSize & 128))
  { // Message is not encrypted.
    PlaintextCRC = digital_crc32(InOutBuf + HHLEN, *PlainTextLen);
    if (PacketHeader->PlaintextCRC != PlaintextCRC)
    {
      *PlainTextLen = -2; // CRC mismatch
      return NULL; 
    }
    return InOutBuf+HHLEN;
  }
  
  uint8_t *OriginalSalt = K + SP_SALT_DATA;
  THOPDecryptorFnc DecryptorFnc = xorGetProperHOPDecryptorFnc(K);
  
  // First, we must decrypt the header with key and original salt value
  DecryptorFnc(K, OriginalSalt, KeyCheckSum, HHLEN-(ALenSize + 1), InOutBuf+1);
  
  if (TotalPacketLen-HHLEN < *PlainTextLen)
  {
    *PlainTextLen = -3; // Invalid plaintext length. Corrupted packet
    return NULL; 
  }
  // Then, we must decrypt the packet with salt value obtained from header
  PlaintextCRC = htole32(DecryptorFnc(K, PacketHeader->Salt, KeyCheckSum, *PlainTextLen, InOutBuf + HHLEN));
  // Now, let's compute exact plaintext size. Because *PlainTextLen still contains aligned data length
  size_t LeftPad = PacketHeader->Padding - (PacketHeader->Padding >> 1);
  //size_t RightPad = PacketHeader->Padding - LeftPad;
  *PlainTextLen -= PacketHeader->Padding;
  //printf("Real data size: %lld Pad: %u Decrypted data from encrypted packet:::  %s\n",(long long int)(*PlainTextLen), PacketHeader->Padding, InOutBuf+HHLEN+((THohhaPacketHeader *)InOutBuf)->LeftPadding);
  // Let's make integrity checks:
  if (PacketHeader->PlaintextCRC != PlaintextCRC)
  {
    *PlainTextLen = -2; // CRC mismatch
    return NULL; 
  }
  return InOutBuf+HHLEN+LeftPad;
}
/* --------------------- HOHHA PROTOCOL SPECIFIC FUNCTIONS ENDS HERE --------------- */

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
  uint8_t *KeyBuf = (uint8_t *)malloc(xorComputeKeyBufLen(BodyLen)); assert (KeyBuf);
  uint8_t *Data = CreateDataBuf(TestSampleLength);
  unsigned long long int TotalProcessedBytes = 0;
  uint32_t t; 
  uint8_t Salt[SALT_SIZE];
  uint32_t KeyCheckSum;
  int Err;
  
  printf("Benchmark1\n\tNumJumps: %u\n\tBodyLen: %u\n\tTestSampleLength: %u\n\tNumIterations: %u ... ",NumJumps,BodyLen,TestSampleLength,NumIterations);  
  
  GetRandomNumbers(TestSampleLength, Data);
  Err = xorGetKey(NumJumps, BodyLen, KeyBuf);
  if (Err != 0)
  {
    printf("Couldn't create the key. Error: %d\n",Err);
    exit(-1);
  }
  KeyCheckSum = xorComputeKeyCheckSum(KeyBuf);
  xorAnalyzeKey(KeyBuf);
  struct timeval StartTime;
  gettimeofday (&StartTime, NULL); 
  
  for (t=0; t<NumIterations; t++)
  {
    IncByOne(Data, TestSampleLength);
    GetRandomNumbers(SALT_SIZE, Salt);
    xorEncrypt(KeyBuf, (uint8_t *)(&Salt), KeyCheckSum, TestSampleLength, Data);
    TotalProcessedBytes += TestSampleLength;
  }
  double Average = PrintElapsedTime(&StartTime,TotalProcessedBytes);
  free(Data);
  free(KeyBuf);
  return Average;
}
static inline uint32_t BufCheckSum(uint8_t *Buf, uint64_t BufLen)
{
  return digital_crc32(Buf, BufLen);
}
double BenchmarkHOP(uint8_t NumJumps, uint32_t BodyLen, uint32_t TestSampleLength, uint32_t NumIterations)
{
  uint8_t *KeyBuf = (uint8_t *)malloc(xorComputeKeyBufLen(BodyLen)); assert (KeyBuf);
  uint8_t *Data = CreateDataBuf(TestSampleLength);
  unsigned long long int TotalProcessedBytes = 0;
  uint32_t t;
  uint32_t KeyCheckSum;
  uint8_t SaltData[SALT_SIZE]; 
  
  
  assert(KeyBuf);
  printf("BenchmarkHop\n\tNumJumps: %u\n\tBodyLen: %u\n\tTestSampleLength: %u\n\tNumIterations: %u ... ",NumJumps,BodyLen,TestSampleLength,NumIterations);  
  
  GetRandomNumbers(SALT_SIZE, SaltData);
  GetRandomNumbers(TestSampleLength, Data);
  int Err = xorGetKey(NumJumps, BodyLen, KeyBuf);
  if (Err != 0)
  {
    printf("Couldn't create the key. Error: %d\n",Err);
    exit(-1);
  }
  KeyCheckSum = xorComputeKeyCheckSum(KeyBuf);
  xorAnalyzeKey(KeyBuf);
  struct timeval StartTime;
  gettimeofday (&StartTime, NULL); 
  
  BufCheckSum(Data, TestSampleLength);  
  THOPEncryptorFnc EncryptorFnc = xorGetProperHOPEncryptorFnc(KeyBuf);
  for (t=0; t<NumIterations; t++)
  {
    IncByOne(Data, TestSampleLength);
    EncryptorFnc(KeyBuf, (uint8_t *)(&SaltData), KeyCheckSum, TestSampleLength, Data);
    TotalProcessedBytes += TestSampleLength;
  }
  double Average = PrintElapsedTime(&StartTime,TotalProcessedBytes);
  free(Data);
  free(KeyBuf);
  return Average;
}

double BenchmarkPack(uint8_t NumJumps, uint32_t BodyLen, uint32_t TestSampleLength, uint32_t NumIterations)
{
  uint8_t *KeyBuf = (uint8_t *)malloc(xorComputeKeyBufLen(BodyLen)); assert (KeyBuf);
  uint8_t *Data = CreateDataBuf(TestSampleLength);
  unsigned long long int TotalProcessedBytes = 0;
  uint32_t t;
  uint32_t KeyCheckSum;
  uint8_t SaltData[SALT_SIZE]; 
  
  
  assert(KeyBuf);
  printf("BenchmarkHop\n\tNumJumps: %u\n\tBodyLen: %u\n\tTestSampleLength: %u\n\tNumIterations: %u ... ",NumJumps,BodyLen,TestSampleLength,NumIterations);  
  
  GetRandomNumbers(SALT_SIZE, SaltData);
  GetRandomNumbers(TestSampleLength, Data);
  int Err = xorGetKey(NumJumps, BodyLen, KeyBuf);
  if (Err != 0)
  {
    printf("Couldn't create the key. Error: %d\n",Err);
    exit(-1);
  }
  KeyCheckSum = xorComputeKeyCheckSum(KeyBuf);
  xorAnalyzeKey(KeyBuf);
  struct timeval StartTime;
  gettimeofday (&StartTime, NULL); 
  
  
  #define PACK_ALIGNMENT_BENCHMARK 16
  
  uint8_t *Packet;
  
  for (t=0; t<NumIterations; t++)
  {
    IncByOne(Data, TestSampleLength);
    Packet = CreateHohhaCommunicationPacket(KeyBuf, KeyCheckSum, TestSampleLength, Data, PACK_ALIGNMENT_BENCHMARK);
    TotalProcessedBytes += TestSampleLength;
    free(Packet);
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
  uint8_t *KeyBuf = (uint8_t *)malloc(RawKeyLen); assert (KeyBuf);
  uint8_t PlainTextBuf[132000], Data[132000];
  unsigned long long int KeyCheckSum;
  uint8_t SaltData[SALT_SIZE]; 
  
  GetRandomNumbers(SALT_SIZE, SaltData);  
  printf("-------------------- TESTING OPTIMIZED VERSION FOR %u PARTICLES -------------------------\n",NumJumps);
  int Err = xorGetKey(NumJumps, BodyLen, KeyBuf);
  if (Err != 0)
  {
    printf("Couldn't create the key. Error: %d\n",Err);
    exit(-1);
  }
  KeyCheckSum = xorComputeKeyCheckSum(KeyBuf);
  DLen = TESTSTR1_LEN; 
  memcpy(Data, TESTSTR1, DLen);
  memcpy(PlainTextBuf, TESTSTR1, DLen);
  
  for (DLen = 0; DLen < TESTSTR1_LEN; DLen++)
  {
    PlainTextBuf[DLen] = (uint8_t)(DLen & 255);
    Data[DLen] = PlainTextBuf[DLen];
    OriginalPlainTextCheckSum = BufCheckSum(Data, DLen+1);
    CheckSumReturnedFromEncryptor = xorEncrypt(KeyBuf, (uint8_t *)(&SaltData), KeyCheckSum, DLen+1, Data); // We encrypt with non-optimized version
    if (OriginalPlainTextCheckSum != CheckSumReturnedFromEncryptor)
    {
      printf("Original Checksum %llu returned from BufChecksum fnc <> Checksum %llu returned from xorEncryptDecrypt\n",OriginalPlainTextCheckSum,CheckSumReturnedFromEncryptor);
      exit(-1);
    }
    THOPDecryptorFnc DecryptorFnc = xorGetProperHOPDecryptorFnc(KeyBuf);
    CheckSumReturnedFromDecryptor = DecryptorFnc(KeyBuf, (uint8_t *)(&SaltData), KeyCheckSum, DLen+1, Data);
    
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
  uint8_t *KeyBuf = (uint8_t *)malloc(RawKeyLen); assert (KeyBuf);
  uint8_t Data[2048],Data2[2048];
  char *Base64EncodedKeyStr, *Base64CipherText;
  uint32_t KeyCheckSum;
  //uint8_t SaltData[SALT_SIZE];
  
  //GetRandomNumbers(SALT_SIZE, SaltData);  
  uint8_t *SaltData = KeyBuf + SP_SALT_DATA;
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
  CheckSumReturnedFromEncryptor = xorEncrypt(KeyBuf, SaltData, KeyCheckSum, DLen, Data); // We encrypt with non-optimized version
  if (OriginalPlainTextCheckSum != CheckSumReturnedFromEncryptor)
  {
    printf("Original Checksum %llu returned from BufChecksum fnc <> Checksum %llu returned from non-optimized encryptor\n",OriginalPlainTextCheckSum,CheckSumReturnedFromEncryptor);
    exit(-1);
  } else printf("OriginalPlainTextCheckSum %llu = CheckSumReturnedFromEncryptor %llu :: SUCCESS!\n",OriginalPlainTextCheckSum,CheckSumReturnedFromEncryptor);
  // Now let's encrypt with the optimized encryptor
  
  THOPEncryptorFnc EncryptorFnc = xorGetProperHOPEncryptorFnc(KeyBuf);
  THOPDecryptorFnc DecryptorFnc = xorGetProperHOPDecryptorFnc(KeyBuf);
    
  CheckSumReturnedFromEncryptor = EncryptorFnc(KeyBuf, SaltData, KeyCheckSum, DLen, Data2); 
  
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
  uint8_t *K = (uint8_t *)Base64Decode(Base64EncodedKeyStr);
  
  if (memcmp((char *)KeyBuf, (char *)K, RawKeyLen) != 0)
  {
    printf("Original key and base64 encoded and decoded keys are different!!!!!\n");
    exit(-1);
  }
  //CheckSumReturnedFromDecryptor = xorDecrypt(K, (uint8_t *)(&SaltData), KeyCheckSum, DLen, Data);
  
  CheckSumReturnedFromDecryptor = DecryptorFnc(K, SaltData, KeyCheckSum, DLen, Data);
  
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
}
void CommPacketTest(unsigned NumJumps, unsigned BodyLen)
{
  unsigned long long int DLen;
  unsigned RawKeyLen = xorComputeKeyBufLen(BodyLen);
  uint8_t *KeyBuf = (uint8_t *)malloc(RawKeyLen); assert (KeyBuf);
  uint8_t Data[2048],Data2[2048];
  char *Base64EncodedKeyStr;
  uint32_t KeyCheckSum;
  uint8_t SaltData[SALT_SIZE];
  
  GetRandomNumbers(SALT_SIZE, SaltData);  
  printf("----------- COMM PACKETS TEST(%u Jumps) --------------\n",NumJumps);
  int Err = xorGetKey(NumJumps, BodyLen, KeyBuf);
  if (Err != 0)
  {
    printf("Couldn't create the key. Error: %d\n",Err);
    exit(-1);
  }
  KeyCheckSum = xorComputeKeyCheckSum(KeyBuf);
  Base64EncodedKeyStr = Base64Encode((const char *)KeyBuf, RawKeyLen);
  printf("Base64 encoded key: %s\n", Base64EncodedKeyStr);

  memset(&Data, 0, sizeof(Data));
  memset(&Data2, 0, sizeof(Data2));
  DLen = TESTSTR1_LEN; 
  memcpy(Data, TESTSTR1, DLen);
  
  
  #define PACK_ALIGNMENT 16
  uint32_t CommPacketTotalSize = HOHHA_TOTAL_COMM_PACKET_SIZE(DLen,PACK_ALIGNMENT);
  uint8_t *CommPacket = malloc(CommPacketTotalSize);
  CreateHohhaCommunicationPacket2(KeyBuf, KeyCheckSum, DLen, Data, PACK_ALIGNMENT, CommPacket);
  
  char *Base64EncodedCommPacket = Base64Encode((const char *)CommPacket, CommPacketTotalSize);
  printf("Encrypted communication packet: %s\n", Base64EncodedCommPacket);
  free(Base64EncodedCommPacket);
  
  // Now, let's decrypt it
  ssize_t DpRes;
  uint8_t *PPText = DecryptCommPacket(KeyBuf, KeyCheckSum, CommPacketTotalSize, CommPacket, &DpRes);
  if (DpRes < 0 || DpRes != DLen)
  {
    printf("DecryptCommPacket error: %lld. DLen: %lld\n", (long long int)DpRes, (long long int)DLen);
    exit(-1);
  }
//  THohhaPacketHeader *PacketHeader = (THohhaPacketHeader *)CommPacket;
  if (memcmp((char *)PPText, TESTSTR1, DLen) == 0)
  {
    printf("String: %.*s ... Hohha Comm Packet Test result: SUCCESSFUL!!!!\n----------------------------------------\n", (int)(DpRes), PPText);
  }
  else {
    printf("String: %.*s ... Hohha Comm Packet Test result: FAILED!!!!\n----------------------------------------\n", (int)(DpRes), PPText);
    exit(-1);
  }
  free(CommPacket);
  
  CommPacketTotalSize = HOHHA_TOTAL_COMM_PACKET_SIZE_WITHOUT_ENCRYPTION(DLen);
  CommPacket = calloc(1, CommPacketTotalSize);
  CreateHohhaCommunicationPacket2Plaintext(DLen, Data, CommPacket);
  
  Base64EncodedCommPacket = Base64Encode((const char *)CommPacket, CommPacketTotalSize);
  printf("Plaintext communication packet in base64: %s\n", Base64EncodedCommPacket);
  free(Base64EncodedCommPacket);
  
  // Now, let's decrypt it
  PPText = DecryptCommPacket(KeyBuf, KeyCheckSum, CommPacketTotalSize, CommPacket, &DpRes);
  if (DpRes < 0 || DpRes != DLen)
  {
    printf("DecryptCommPacket error: %lld. DLen: %lld\n", (long long int)DpRes, (long long int)DLen);
    exit(-1);
  }
  //PacketHeader = (THohhaPacketHeader *)CommPacket;
  if (memcmp((char *)PPText, TESTSTR1, DLen) == 0)
  {
    printf("String: %.*s ... Hohha plaintext Comm Packet Test result: SUCCESSFUL!!!!\n----------------------------------------\n", (int)(DpRes), PPText);
  }
  else {
    printf("String: %.*s ... Hohha plaintext Comm Packet Test result: FAILED!!!!\n----------------------------------------\n", (int)(DpRes), PPText);
    exit(-1);
  }
  free(CommPacket);
  
  // Variable length packets test
  
  uint8_t *EncPack;
  DLen = 0;
  while (DLen < 2048)
  {
    Data[DLen] = (uint8_t)(DLen & 255);
    DLen++;
    EncPack = CreateHohhaCommunicationPacket(KeyBuf, KeyCheckSum, DLen, Data, 16);
    if (!EncPack)
    {
      printf("CreateHohhaCommunicationPacket FAILED!");
      exit(-1);
    }
    PPText = DecryptCommPacket(KeyBuf, KeyCheckSum, HOHHA_TOTAL_COMM_PACKET_SIZE(DLen,16), EncPack, &DpRes);
    if (!PPText || DpRes < 0)
    {
      printf("DecryptCommPacket error: %lld. DLen: %lld\n", (long long int)DpRes, (long long int)DLen);
      exit(-1);
    }
    if (memcmp((char *)PPText, Data, DLen) != 0)
    {
      printf("DecryptCommPacket error: ORIGINAL DATA AND DECRYPTED DATA ARE NOT SAME! DLen: %lld\n", (long long int)DLen);
    }
    free(EncPack);
  }
  //exit(-1);
}

void CircularShiftTest()
{
  uint32_t t, Nn = (uint32_t)(0b10000000000000000000000000000010U);
  char Buf[256];
  printf("Circular shift left:\n");
  for (t=0; t<5; t++)
  {
    printf("%s\n", GetBinStr(Nn,Buf));  
    ROL32_1(Nn);
  }
  printf("Circular shift right:\n");
  for (t=0; t<6; t++)
  {
    printf("%s\n", GetBinStr(Nn,Buf));  
    ROR32_1(Nn);
  }
}

ssize_t EncryptFile(const char *InFileName, const char *OutFileName, uint8_t *KeyBuf, uint32_t KeyCheckSum)
{
  int32_t FDesc;   
  int64_t Len, RLen;
  uint8_t *Data;
  uint8_t SaltData[SALT_SIZE]; 
  ssize_t CheckSum=0;
  
  if ((FDesc = open(InFileName, O_RDONLY)) == -1)
  {
    printf("Error in opening file!\n");
    return -1;
  }
  Len = lseek(FDesc, 0, SEEK_END);
  lseek(FDesc, 0, SEEK_SET);
  Data = (uint8_t *)malloc(Len);
  if (Data == NULL)
  {
    printf("OUT OF MEMORY!\n");
    close(FDesc);
    return -1;
  }
  RLen = read(FDesc, Data, Len);
  if (RLen != Len)
  {
    printf("Error in reading file!\n");
    free(Data);
    close(FDesc);
    return -1;
  }
  close(FDesc);
  
  //GetRandomNumbers(8, (uint8_t *)(&SaltData));
  // Copy key's original salt value to salt buffer
  memcpy(&SaltData, KeyBuf+SP_SALT_DATA, SALT_SIZE);
  
  THOPEncryptorFnc EncryptorFnc = xorGetProperHOPEncryptorFnc(KeyBuf);
  
  CheckSum = (ssize_t)EncryptorFnc(KeyBuf, (uint8_t *)(&SaltData), KeyCheckSum, Len, Data); 
  
  if ((FDesc = creat(OutFileName, 700)) == -1)
  {
    printf("Error in creating output file!\n");
    free(Data);
    return -1;
  }
  write(FDesc,Data,Len);
  free(Data);
  close(FDesc);
  return CheckSum;
}
#define BMP_FILE_HEADER_LEN 54
ssize_t EncryptBMPFile(const char *InFileName, const char *OutFileName, uint8_t *KeyBuf, uint32_t KeyCheckSum)
{ // Encrypts a bmp file for visual attack and returns -1 on error. 
  int32_t FDesc;   
  int64_t Len, RLen;
  uint8_t *Data;
  uint8_t SaltData[SALT_SIZE]; 
  ssize_t CheckSum=0;
  
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
  if (Data == NULL)
  {
    printf("OUT OF MEMORY!\n");
    close(FDesc);
    free(Data);
    return -1;
  }
  RLen = read(FDesc, Data, Len);
  if (RLen != Len || RLen <= BMP_FILE_HEADER_LEN)
  {
    printf("Error in reading file!\n");
    close(FDesc);
    free(Data);
    return -1;
  }
  close(FDesc);
  
  //GetRandomNumbers(8, (uint8_t *)(&SaltData));
  // Copy key's original salt value to salt buffer
  memcpy(&SaltData, KeyBuf+SP_SALT_DATA, SALT_SIZE);

  THOPEncryptorFnc EncryptorFnc = xorGetProperHOPEncryptorFnc(KeyBuf);
  CheckSum = (ssize_t)EncryptorFnc(KeyBuf, (uint8_t *)(&SaltData), KeyCheckSum, Len-BMP_FILE_HEADER_LEN, Data + BMP_FILE_HEADER_LEN); 
  if ((FDesc = creat(OutFileName, 777)) == -1)
  {
    printf("Error in creating output file!\n");
    free(Data);
    return -1;
  }
  
  if (write(FDesc,Data,Len) != Len)
  {
    printf("Error writing file!\n");
    free(Data);
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
  ChkSum = EncryptBMPFile(InFileName, OutFileName, KeyBuf, KeyCheckSum);
  printf("Result: %llu\n", ChkSum);
}

void CreateVisualProofs()
{
  TestEncryptBMPFile("/home/ikizir/Downloads/allzero.bmp", "/home/ikizir/Downloads/allzero_enc_2J_64.bmp", 2, 64);
  TestEncryptBMPFile("/home/ikizir/Downloads/allzero.bmp", "/home/ikizir/Downloads/allzero_enc_3J_64.bmp", 3, 64);
  TestEncryptBMPFile("/home/ikizir/Downloads/allzero.bmp", "/home/ikizir/Downloads/allzero_enc_4J_64.bmp", 4, 64);
  
  TestEncryptBMPFile("/home/ikizir/Downloads/allzero.bmp", "/home/ikizir/Downloads/allzero_enc_2J_128.bmp", 2, 128);
  TestEncryptBMPFile("/home/ikizir/Downloads/allzero.bmp", "/home/ikizir/Downloads/allzero_enc_3J_128.bmp", 3, 128);
  TestEncryptBMPFile("/home/ikizir/Downloads/allzero.bmp", "/home/ikizir/Downloads/allzero_enc_4J_128.bmp", 4, 128);
  
  TestEncryptBMPFile("/home/ikizir/Downloads/allzero.bmp", "/home/ikizir/Downloads/allzero_enc_2J_256.bmp", 2, 256);
  TestEncryptBMPFile("/home/ikizir/Downloads/allzero.bmp", "/home/ikizir/Downloads/allzero_enc_3J_256.bmp", 3, 256);
  TestEncryptBMPFile("/home/ikizir/Downloads/allzero.bmp", "/home/ikizir/Downloads/allzero_enc_4J_256.bmp", 4, 256);
  
  TestEncryptBMPFile("/home/ikizir/Downloads/panda.bmp", "/home/ikizir/Downloads/panda_enc_2J_64.bmp", 2, 64);
  TestEncryptBMPFile("/home/ikizir/Downloads/panda.bmp", "/home/ikizir/Downloads/panda_enc_3J_64.bmp", 3, 64);
  TestEncryptBMPFile("/home/ikizir/Downloads/panda.bmp", "/home/ikizir/Downloads/panda_enc_4J_64.bmp", 4, 64);
  
  TestEncryptBMPFile("/home/ikizir/Downloads/panda.bmp", "/home/ikizir/Downloads/panda_enc_2J_128.bmp", 2, 128);
  TestEncryptBMPFile("/home/ikizir/Downloads/panda.bmp", "/home/ikizir/Downloads/panda_enc_3J_128.bmp", 3, 128);
  TestEncryptBMPFile("/home/ikizir/Downloads/panda.bmp", "/home/ikizir/Downloads/panda_enc_4J_128.bmp", 4, 128);
  
  TestEncryptBMPFile("/home/ikizir/Downloads/panda.bmp", "/home/ikizir/Downloads/panda_enc_2J_256.bmp", 2, 256);
  TestEncryptBMPFile("/home/ikizir/Downloads/panda.bmp", "/home/ikizir/Downloads/panda_enc_3J_256.bmp", 3, 256);
  TestEncryptBMPFile("/home/ikizir/Downloads/panda.bmp", "/home/ikizir/Downloads/panda_enc_4J_256.bmp", 4, 256);
  
  TestEncryptBMPFile("/home/ikizir/Downloads/Bitmap1.bmp", "/home/ikizir/Downloads/Bitmap1_enc_2J_64.bmp", 2, 64);
  TestEncryptBMPFile("/home/ikizir/Downloads/Bitmap1.bmp", "/home/ikizir/Downloads/Bitmap1_enc_3J_64.bmp", 3, 64);
  TestEncryptBMPFile("/home/ikizir/Downloads/Bitmap1.bmp", "/home/ikizir/Downloads/Bitmap1_enc_4J_64.bmp", 4, 64);
  
  TestEncryptBMPFile("/home/ikizir/Downloads/Bitmap1.bmp", "/home/ikizir/Downloads/Bitmap1_enc_2J_128.bmp", 2, 128);
  TestEncryptBMPFile("/home/ikizir/Downloads/Bitmap1.bmp", "/home/ikizir/Downloads/Bitmap1_enc_3J_128.bmp", 3, 128);
  TestEncryptBMPFile("/home/ikizir/Downloads/Bitmap1.bmp", "/home/ikizir/Downloads/Bitmap1_enc_4J_128.bmp", 4, 128);
  
  TestEncryptBMPFile("/home/ikizir/Downloads/Bitmap1.bmp", "/home/ikizir/Downloads/Bitmap1_enc_2J_256.bmp", 2, 256);
  TestEncryptBMPFile("/home/ikizir/Downloads/Bitmap1.bmp", "/home/ikizir/Downloads/Bitmap1_enc_3J_256.bmp", 3, 256);
  TestEncryptBMPFile("/home/ikizir/Downloads/Bitmap1.bmp", "/home/ikizir/Downloads/Bitmap1_enc_4J_256.bmp", 4, 256);
  
  TestEncryptBMPFile("/home/ikizir/Downloads/Viking.bmp", "/home/ikizir/Downloads/Viking_enc_2J_64.bmp", 2, 64);
  TestEncryptBMPFile("/home/ikizir/Downloads/Viking.bmp", "/home/ikizir/Downloads/Viking_enc_3J_64.bmp", 3, 64);
  TestEncryptBMPFile("/home/ikizir/Downloads/Viking.bmp", "/home/ikizir/Downloads/Viking_enc_4J_64.bmp", 4, 64);
  
  TestEncryptBMPFile("/home/ikizir/Downloads/Viking.bmp", "/home/ikizir/Downloads/Viking_enc_2J_128.bmp", 2, 128);
  TestEncryptBMPFile("/home/ikizir/Downloads/Viking.bmp", "/home/ikizir/Downloads/Viking_enc_3J_128.bmp", 3, 128);
  TestEncryptBMPFile("/home/ikizir/Downloads/Viking.bmp", "/home/ikizir/Downloads/Viking_enc_4J_128.bmp", 4, 128);
  
  TestEncryptBMPFile("/home/ikizir/Downloads/Viking.bmp", "/home/ikizir/Downloads/Viking_enc_2J_256.bmp", 2, 256);
  TestEncryptBMPFile("/home/ikizir/Downloads/Viking.bmp", "/home/ikizir/Downloads/Viking_enc_3J_256.bmp", 3, 256);
  TestEncryptBMPFile("/home/ikizir/Downloads/Viking.bmp", "/home/ikizir/Downloads/Viking_enc_4J_256.bmp", 4, 256);
  
  TestEncryptBMPFile("/home/ikizir/Downloads/B.bmp", "/home/ikizir/Downloads/B_enc_2J_64.bmp", 2, 64);
  TestEncryptBMPFile("/home/ikizir/Downloads/B.bmp", "/home/ikizir/Downloads/B_enc_3J_64.bmp", 3, 64);
  TestEncryptBMPFile("/home/ikizir/Downloads/B.bmp", "/home/ikizir/Downloads/B_enc_4J_64.bmp", 4, 64);
  
  TestEncryptBMPFile("/home/ikizir/Downloads/B.bmp", "/home/ikizir/Downloads/B_enc_2J_128.bmp", 2, 128);
  TestEncryptBMPFile("/home/ikizir/Downloads/B.bmp", "/home/ikizir/Downloads/B_enc_3J_128.bmp", 3, 128);
  TestEncryptBMPFile("/home/ikizir/Downloads/B.bmp", "/home/ikizir/Downloads/B_enc_4J_128.bmp", 4, 128);
  
  TestEncryptBMPFile("/home/ikizir/Downloads/B.bmp", "/home/ikizir/Downloads/B_enc_2J_256.bmp", 2, 256);
  TestEncryptBMPFile("/home/ikizir/Downloads/B.bmp", "/home/ikizir/Downloads/B_enc_3J_256.bmp", 3, 256);
  TestEncryptBMPFile("/home/ikizir/Downloads/B.bmp", "/home/ikizir/Downloads/B_enc_4J_256.bmp", 4, 256);
  
  TestEncryptBMPFile("/home/ikizir/Downloads/penguen.bmp", "/home/ikizir/Downloads/penguen_enc_2J_64.bmp", 2, 64);
  TestEncryptBMPFile("/home/ikizir/Downloads/penguen.bmp", "/home/ikizir/Downloads/penguen_enc_3J_64.bmp", 3, 64);
  TestEncryptBMPFile("/home/ikizir/Downloads/penguen.bmp", "/home/ikizir/Downloads/penguen_enc_4J_64.bmp", 4, 64);
  
  TestEncryptBMPFile("/home/ikizir/Downloads/penguen.bmp", "/home/ikizir/Downloads/penguen_enc_2J_128.bmp", 2, 128);
  TestEncryptBMPFile("/home/ikizir/Downloads/penguen.bmp", "/home/ikizir/Downloads/penguen_enc_3J_128.bmp", 3, 128);
  TestEncryptBMPFile("/home/ikizir/Downloads/penguen.bmp", "/home/ikizir/Downloads/penguen_enc_4J_128.bmp", 4, 128);
  
  TestEncryptBMPFile("/home/ikizir/Downloads/penguen.bmp", "/home/ikizir/Downloads/penguen_enc_2J_256.bmp", 2, 256);
  TestEncryptBMPFile("/home/ikizir/Downloads/penguen.bmp", "/home/ikizir/Downloads/penguen_enc_3J_256.bmp", 3, 256);
  TestEncryptBMPFile("/home/ikizir/Downloads/penguen.bmp", "/home/ikizir/Downloads/penguen_enc_4J_256.bmp", 4, 256);
}


int main()
{
  uint32_t BodyLen = 256;

  //printf("CRC: %u\n", digital_crc32((uint8_t *)"A", 1));
  //printf("CRC: %u\n", digital_crc32((uint8_t *)"Ismail", 6));
  Test1(2, BodyLen);
  CommPacketTest(3, 128);
  //exit(-1);
  
  
  CreateVisualProofs();
//  exit(-1);
  
  //CircularShiftTest();
  //uint32_t TestSampleLength = 8192;
  uint32_t NumIterations = 1000000;
  //D1();
  Test1(2, BodyLen);
  Test1(3, BodyLen);
  Test1(11, BodyLen);
  //Test1(4, BodyLen);
  //Test1(5, BodyLen);
  
    //exit(-1);
  
  CheckOptimizedVersion(2, BodyLen);
  CheckOptimizedVersion(3, BodyLen);
  CheckOptimizedVersion(4, BodyLen);
  //CheckOptimizedVersion(5, BodyLen);
  //exit(-1);
  
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
  
  Average16H2 = BenchmarkPack(2, BodyLen, 16, NumIterations);
  Average64H2 = BenchmarkPack(2, BodyLen, 64, NumIterations);
  Average256H2 = BenchmarkPack(2, BodyLen, 256, NumIterations);
  Average1024H2 = BenchmarkPack(2, BodyLen, 1024, NumIterations);
  Average8192H2 = BenchmarkPack(2, BodyLen, 8192, NumIterations);
  
  Average16H3 = BenchmarkPack(3, BodyLen, 16, NumIterations);
  Average64H3 = BenchmarkPack(3, BodyLen, 64, NumIterations);
  Average256H3 = BenchmarkPack(3, BodyLen, 256, NumIterations);
  Average1024H3 = BenchmarkPack(3, BodyLen, 1024, NumIterations);
  Average8192H3 = BenchmarkPack(3, BodyLen, 8192, NumIterations);
  
  Average16H4 = BenchmarkPack(4, BodyLen, 16, NumIterations);
  Average64H4 = BenchmarkPack(4, BodyLen, 64, NumIterations);
  Average256H4 = BenchmarkPack(4, BodyLen, 256, NumIterations);
  Average1024H4 = BenchmarkPack(4, BodyLen, 1024, NumIterations);
  Average8192H4 = BenchmarkPack(4, BodyLen, 8192, NumIterations);
  
  printf("\n\nPacket construction BENCHMARKS(Real life usage):\n"
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
  
  
  
  Average16H2 = BenchmarkHOP(2, BodyLen, 16, NumIterations);
  Average64H2 = BenchmarkHOP(2, BodyLen, 64, NumIterations);
  Average256H2 = BenchmarkHOP(2, BodyLen, 256, NumIterations);
  Average1024H2 = BenchmarkHOP(2, BodyLen, 1024, NumIterations);
  Average8192H2 = BenchmarkHOP(2, BodyLen, 8192, NumIterations);
  
  Average16H3 = BenchmarkHOP(3, BodyLen, 16, NumIterations);
  Average64H3 = BenchmarkHOP(3, BodyLen, 64, NumIterations);
  Average256H3 = BenchmarkHOP(3, BodyLen, 256, NumIterations);
  Average1024H3 = BenchmarkHOP(3, BodyLen, 1024, NumIterations);
  Average8192H3 = BenchmarkHOP(3, BodyLen, 8192, NumIterations);
  
  Average16H4 = BenchmarkHOP(4, BodyLen, 16, NumIterations);
  Average64H4 = BenchmarkHOP(4, BodyLen, 64, NumIterations);
  Average256H4 = BenchmarkHOP(4, BodyLen, 256, NumIterations);
  Average1024H4 = BenchmarkHOP(4, BodyLen, 1024, NumIterations);
  Average8192H4 = BenchmarkHOP(4, BodyLen, 8192, NumIterations);
  
  printf("\n\nRaw encryption benchmarks:\n"
         "16                  64                  256                 1024                8192               \n"
         "------------------- ------------------- ------------------- ------------------- -------------------\n"
         "%19.2f %19.2f %19.2f %19.2f %19.2f\n\n", Average16M, Average64M, Average256M, Average1024M, Average8192M);
  printf("\n\n2-Jumps BENCHMARKS:\n"
         "16                  64                  256                 1024                8192               \n"
         "------------------- ------------------- ------------------- ------------------- -------------------\n"
         "%19.2f %19.2f %19.2f %19.2f %19.2f\n\n", Average16H2, Average64H2, Average256H2, Average1024H2, Average8192H2);
  printf("\n\n3-Jumps BENCHMARKS:\n"
         "16                  64                  256                 1024                8192               \n"
         "------------------- ------------------- ------------------- ------------------- -------------------\n"
         "%19.2f %19.2f %19.2f %19.2f %19.2f\n\n", Average16H3, Average64H3, Average256H3, Average1024H3, Average8192H3);
  printf("\n\n4-Jumps BENCHMARKS:\n"
         "16                  64                  256                 1024                8192               \n"
         "------------------- ------------------- ------------------- ------------------- -------------------\n"
         "%19.2f %19.2f %19.2f %19.2f %19.2f\n\n", Average16H4, Average64H4, Average256H4, Average1024H4, Average8192H4);
  return 0;
}
