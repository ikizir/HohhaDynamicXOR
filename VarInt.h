// Variable integer encdoing decoding fncs
// (C) 2016 Ismail Kizir 
#if !defined(VARINT_H)
#define VARINT_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * EncodeVarUInt64 encodes a uint64_t value in a portable variable length buffer
 * The method of encoding is MOST SIGNIFICANT BIT encoding
 * Don't confuse this with most significant byte encoding.
 * Simply, we use only 7 bit of every byte. 
 * We set the most significant bit to indicate there is more data in the buffer
 * @param V Value to be Encoded
 * @param DestBuf A char pointer max. 9 bytes can be safely written to
 * @return The length of resulting buffer
 */
unsigned EncodeVarUInt64(const uint64_t V, uint8_t *DestBuf);

/**
 * EncodedVarUInt64Len returns the buffer requirement to encode a 64 bit unsigned integer
 * Returned length DOES NOT contain any zero pad character at the end
 * @param V uint64_t
 * @return Length of the encoded value
 */
unsigned EncodedVarUInt64Len(uint64_t V);

/**
 * DecodeVarUInt64 decodes a previously encoded 64 bit unsigned integer to a native uint64_t
 * @param uint8_t **Buf Pointer to input buffer pointer containing variable length encoded unsigned integer. 
 *        When this function returns, *Buf will point to next character following consumed varint data
 * @param MaxCharsToRead Maximum number of characters we can read from the buffer
 * @return Native uint64_t 
 */
uint64_t DecodeVarUInt64(uint8_t **Buf, unsigned MaxCharsToRead);

/**
 * EncodeVarInt32 encodes a int32_t value in a portable variable length buffer
 * We are using Google Protobuf's technique for signed numbers
 * See https://developers.google.com/protocol-buffers/docs/encoding#signed-integers for details
 * The method of encoding is MOST SIGNIFICANT BIT encoding
 * Don't confuse this with most significant byte encoding.
 * Simply, we use only 7 bit of every byte. 
 * We set the most significant bit to indicate there is more data in the buffer
 * @param V Value to be Encoded
 * @param DestBuf A char pointer max. 9 bytes can be safely written to
 * @return The length of resulting buffer
 */
unsigned EncodeVarInt32(int32_t V, uint8_t *DestBuf);

/**
 * DecodeVarInt32 decodes a previously encoded 32 bit signed integer to a native int32_t
 * @param uint8_t **Buf Pointer to input buffer pointer containing variable length encoded unsigned integer. 
 *        When this function returns, *Buf will point to next character following consumed varint data
 * @param MaxCharsToRead Maximum number of characters we can read from the buffer
 * @return Native uint32_t 
 */
int32_t DecodeVarInt32(uint8_t **Buf, unsigned MaxCharsToRead) ;

/**
 * EncodeVarInt64 encodes a int64_t value in a portable variable length buffer
 * It first write one byte sign data: 1 if V is negative or 0 if V >= 0
 * And it encodes abs(V) as uint64 varint
 * @param V Value to be Encoded
 * @param DestBuf A char pointer max. 9 bytes can be safely written to
 * @return The length of resulting buffer
 */
unsigned EncodeVarInt64(int64_t V, uint8_t *DestBuf);

  
#ifdef __cplusplus
}
#endif

#endif
