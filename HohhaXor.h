// B.
// Hohha Xor Encryption functions

#if !defined(HOHHA_XOR_H)
#define HOHHA_XOR_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

void init_rand(uint32_t x);
void GetRandomNumbers(uint32_t ByteCount, void *Buffer);

// Portable endian macros by Mathias Panzenböck
#if (defined(_WIN16) || defined(_WIN32) || defined(_WIN64)) && !defined(__WINDOWS__)

#	define __WINDOWS__

#endif

#if defined(__linux__) || defined(__CYGWIN__) || defined(__EMSCRIPTEN__)

#	include <endian.h>

#elif defined(__APPLE__)

#	include <libkern/OSByteOrder.h>

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


#define ALIGN_TO_ROUND_DOWN32(v,n) ((uint32_t)(v) & ~((uint32_t)(n)-1))
#define ALIGN_TO_ROUND_UP32(v,n) (((uint32_t)(v) + (uint32_t)(n) - 1) & ~((uint32_t)(n)-1))

#define ALIGN_TO_ROUND_DOWN64(v,n) ((uint64_t)(v) & ~((uint64_t)(n)-1))
#define ALIGN_TO_ROUND_UP64(v,n) (((uint64_t)(v) + (uint64_t)(n) - 1) & ~((uint64_t)(n)-1))

// Returns base64 encoded length of binary data
#define BASE64_ENCODED_LEN(l) ALIGN_TO_ROUND_UP64((4*(l))/3, 4)
// Returns the maximum amount of space required to store a a base64 encoded binary data
#define BASE64_DECODED_BINBUF_REQUIREMENT(l) (((3*(l))/4)+3)


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

static inline uint32_t ROL32_N(uint32_t v, unsigned NumShifts) { return (((v) << NumShifts) | ((v) >> (32-NumShifts))); }
static inline uint32_t ROR32_N(uint32_t v, unsigned NumShifts) { return (((v) >> NumShifts) | ((v) << (32-NumShifts))); }

#define MAX_HOHHA_ENCRYPTION_DATA_LEN 0xfffffffffffULL
#define MAX_NUM_JUMPS 127 
#if !defined(TRUE)
#define FALSE (0U)
#define TRUE (!(FALSE))
#endif

#define HOHHA_ERROR_INVALID_HEADER -1
#define HOHHA_ERROR_CRC_MISMATCH_CORRUPTED_PACKET -2
#define HOHHA_ERROR_INVALID_PLAINTEXT_LEN_CORRUPTED_PACKET -3
#define HOHHA_ERROR_KEY_BODY_LEN_MUST_BE_POWER_OF_TWO -4
#define HOHHA_ERROR_KEY_JUMPS_MUST_BE_GREATER_THAN_ONE -5
#define HOHHA_ERROR_KEY_MAX_NUM_JUMPS_LIMIT_EXCEEDED -6
#define HOHHA_ERROR_KEY_BODY_SIZE_TOO_SHORT -7
#define HOHHA_ERROR_KEY_BODY_SIZE_TOO_LONG -8

#define SALT_SIZE 8 // LEAVE AS IT IS
#define MIN_BODY_SIZE 16
#define MAX_BODY_SIZE 256 // DO NOT SET THIS LIMIT TO MORE THAN 256 BYTES! Or you must also change encryption&decryption code for key coverage

#define SP_NUM_JUMPS 0
#define SP_BODY_LEN 1
#define SP_SALT_DATA 3
#define SP_BODY (SP_SALT_DATA+SALT_SIZE)
#define xorGetKeyBodyLen(K) (K[SP_BODY_LEN] + 256 * K[SP_BODY_LEN+1])
#define xorGetKeyBodyPtr(K) (K + SP_BODY)
#define xorGetKeyNumJumps(K) (K[SP_NUM_JUMPS])
#define xorComputeKeyBufLen(BodyLen) (SP_BODY+BodyLen)

// THohhaAuthCode is the return value of hohha encryption and decryption functions
// This is a 16 byte authentication code of the plaintext
// It is represented by 4 different unsigned integer stored consecutively, each in Little Endian Format
typedef struct {
  uint32_t S1;
  uint32_t S2;
  uint32_t X;
  uint32_t Y;
} THohhaAuthCode;

// Hohha packet header size is ALWAYS 36 Bytes!
// The number of random padding bytes before the salt value in header. We use those random numbers in order to better hide our packet salt value. 
#define HEADER_SALT_PADDING_SIZE 4
// Hohha communication header structure:
typedef struct __attribute__((__packed__)) {
  uint8_t SaltProtectionPadding[HEADER_SALT_PADDING_SIZE]; // Random data to better protect random salt data
  uint8_t Salt[SALT_SIZE]; // Salt value unique for packet
  THohhaAuthCode AuthCode; // Plaintext authentication code
  uint8_t AlignedLen [7]; // Plaintext or ciphertext aligned length. Encoded as VarUInt
  uint8_t Padding; // LeftPad + RightPad 
} THohhaPacketHeader;
#define HOHHA_PACKET_HEADER_LEN sizeof(THohhaPacketHeader) // IT MUST BE ALWAYS EQUAL TO 36!

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
int xorGetKey(uint8_t NumJumps, uint32_t BodyLen, uint8_t *KeyBuf);

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
int xorGetKey2(uint8_t NumJumps, uint32_t BodyLen, uint8_t *Body, uint8_t *Salt, uint8_t *KeyBuf);

void xorAnalyzeKey(const uint8_t *K);

typedef THohhaAuthCode (*THOPEncryptorFnc)(uint8_t *Key, uint8_t *Salt, size_t InOutDataLen, uint8_t *InOutBuf);
typedef THohhaAuthCode (*THOPDecryptorFnc)(uint8_t *Key, uint8_t *Salt, size_t InOutDataLen, uint8_t *InOutBuf);

THOPEncryptorFnc xorGetProperHOPEncryptorFnc(uint8_t *Key);
THOPDecryptorFnc xorGetProperHOPDecryptorFnc(uint8_t *Key);

THohhaAuthCode xorEncrypt(uint8_t *K, uint8_t *Salt, size_t InOutDataLen, uint8_t *InOutBuf);
THohhaAuthCode xorDecrypt(uint8_t *K, uint8_t *Salt, size_t InOutDataLen, uint8_t *InOutBuf);

// Checks key integrity and returns 0 for erronous keys
unsigned int xorCheckKeyIntegrity(const uint8_t *K, size_t TotalKeyBufLen);

// Checks key integrity and returns 0 for erronous keys
unsigned int CheckKeyIntegrity(uint8_t *K, size_t TotalKeyBufLen);


/**
 * GetHohhaExactEncryptedPacketSize returns the exact size of of an encrypted hohha packet
 * You can use this function 
 * @param PlainTextDataSize Length of the input
 * @param DataAlignment is the alignment of data for better security
 *        The encrypted data is aligned to that size and there will be pads both in left and right
 *        It may be 4, 8, 16 or 32 bytes.
 * @return Exact size of the packet, including header, to be obtained after encrypted packet creation
 */
static inline size_t GetHohhaExactEncryptedPacketSize(size_t InputDataSize, size_t DataAlignment)
{
  return ALIGN_TO_ROUND_UP64((InputDataSize)+1,DataAlignment) + HOHHA_PACKET_HEADER_LEN;
}

/**
 * xorEncryptAndSign2 encrypts InBuf and creates a communication packet with a proper header
 * A communcation packet contains an padded data ciphertext and padded header ciphertext
 * Header is also encrypted (with original salt(or iv) on the key).
 * Header contains:
 *   4 bytes random padding data for better protection
 *   16 bytes Message Authentication code (first MAC then encyrpt method. But it's well protected by a second encryption)
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
void xorEncryptAndSign2(uint8_t *K, size_t InDataLen, const uint8_t *InBuf, uint32_t DataAlignment, uint8_t *OutBuf);
uint8_t *xorEncryptAndSign(uint8_t *K, size_t InDataLen, uint8_t *InBuf, uint32_t DataAlignment);

uint8_t *xorDecryptAndVerify(uint8_t *K, size_t TotalPacketLen, uint8_t *InOutBuf, ssize_t *PlainTextLen);

static inline unsigned AuthCodesMatch(THohhaAuthCode *C1, THohhaAuthCode *C2)
{
  return (C1->S1 == C2->S1) && (C1->S2 == C2->S2) && (C1->X == C2->X) && (C1->Y == C2->Y);
}


#ifdef __cplusplus
}
#endif

#endif
