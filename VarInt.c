// (C) 2016 Ismail Kizir 
#include "VarInt.h"

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
unsigned EncodeVarUInt64(const uint64_t Val, uint8_t *DestBuf)
{
  uint8_t *dp = DestBuf;
  uint64_t V = Val;
  
  while (V > 127) 
  {
    // By OR'in with 128, we indicate there is more bytes to read
    *dp = ((uint8_t)(V & 127)) | (uint8_t)128;
    dp++;
    V >>= 7;
  }
  *dp = (uint8_t)V;
  return (unsigned)(dp - DestBuf) + 1;
}

/**
 * EncodedVarUInt64Len returns the buffer requirement to encode a 64 bit unsigned integer
 * Returned length DOES NOT contain any zero pad character at the end
 * @param V uint64_t
 * @return Length of the encoded value
 */
unsigned EncodedVarUInt64Len(uint64_t V)
{
  unsigned R = 1;
  while (V > 127) 
  {
    R++;
    V >>= 7;
  }
  return R;
}


/**
 * DecodeVarUInt64 decodes a previously encoded 64 bit unsigned integer to a native uint64_t
 * @param uint8_t **Buf Pointer to input buffer pointer containing variable length encoded unsigned integer. 
 *        When this function returns, *Buf will point to next character following consumed varint data
 * @param MaxCharsToRead Maximum number of characters we can read from the buffer
 * @return Native uint64_t 
 */
uint64_t DecodeVarUInt64(uint8_t **Buf, unsigned MaxCharsToRead) 
{
  uint64_t R = 0;
  unsigned ShiftCount = 0;
  uint8_t *Sp = (void *)(*Buf);
  
  while ((*Sp & 128) && ((Sp - *Buf) < MaxCharsToRead))
  {
    R |= ((*Sp) & 127) << ShiftCount;
    ShiftCount += 7;
    ++Sp;
  }
  R |= ((*Sp) & 127) << ShiftCount;
  *Buf = Sp+1;
  return R;
}

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
unsigned EncodeVarInt32(int32_t V, uint8_t *DestBuf)
{
  uint32_t N = (V << 1) ^ (V >> 31);
  //printf("EncodeVarInt32: %d will be encoded as %u\n",(int)V,(unsigned)N);
  return EncodeVarUInt64(N, DestBuf);
}

/**
 * DecodeVarInt32 decodes a previously encoded 32 bit signed integer to a native int32_t
 * @param uint8_t **Buf Pointer to input buffer pointer containing variable length encoded unsigned integer. 
 *        When this function returns, *Buf will point to next character following consumed varint data
 * @param MaxCharsToRead Maximum number of characters we can read from the buffer
 * @return Native uint32_t 
 */
int32_t DecodeVarInt32(uint8_t **Buf, unsigned MaxCharsToRead) 
{
  uint32_t N = DecodeVarUInt64(Buf, MaxCharsToRead);
  return (N & 1) ? (N >> 1) ^ 4294967295 : (N >> 1); // 4294967295: unsigned representation of -1 or 11111111111111111111111111111111 binary
}

/**
 * EncodeVarInt64 encodes a int64_t value in a portable variable length buffer
 * It first write one byte sign data: 1 if V is negative or 0 if V >= 0
 * And it encodes abs(V) as uint64 varint
 * @param V Value to be Encoded
 * @param DestBuf A char pointer max. 9 bytes can be safely written to
 * @return The length of resulting buffer
 */
unsigned EncodeVarInt64(int64_t V, uint8_t *DestBuf)
{
  
  if (V < 0)
  {
    *DestBuf = 1;
    return EncodeVarUInt64(V * -1, DestBuf + 1) + 1;
  }
  *DestBuf = 0;
  return EncodeVarUInt64(V, DestBuf + 1) + 1;
}

/**
 * DecodeVarInt64 decodes a previously encoded 32 bit signed integer to a native int32_t
 * @param uint8_t **Buf Pointer to input buffer pointer containing variable length encoded unsigned integer. 
 *        When this function returns, *Buf will point to next character following consumed varint data
 * @param MaxCharsToRead Maximum number of characters we can read from the buffer
 * @return Native uint32_t 
 */
int64_t DecodeVarInt64(uint8_t **Buf, unsigned MaxCharsToRead) 
{
  uint32_t N = DecodeVarUInt64(Buf, MaxCharsToRead);
  return (N & 1) ? (N >> 1) ^ 4294967295 : (N >> 1); // 4294967295: unsigned representation of -1 or 11111111111111111111111111111111 binary
}
