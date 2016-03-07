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
  register uint8_t tt, LastPlainTextByte=0;
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
        //Body[M] = (uint8_t)(Salt1); 
        M = (M^Salt1) & BodyMask; 
        ROR32_1(Salt1);
      }
      else {
        Salt1 ^= (uint32_t)(Body[M]);
        //Body[M] = (uint8_t)(Salt2); 
        M = (M^V) & BodyMask; 
        ROL32_1(Salt2);
      }
    }
    Checksum = CRC32Table[*p ^ ((Checksum >> 24) & 0xff)] ^ (Checksum << 8); 
    LastPlainTextByte = (!*p) ^ Body[t&BodyMask];
    *p ^= (uint8_t)(Salt1 ^ Salt2 ^ V);
    Salt1 ^= ((uint32_t)(LastPlainTextByte) << 24);
    ROR32_1(Salt1);
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
  register uint8_t tt, LastPlainTextByte=0;
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
        //Body[M] = (uint8_t)(Salt1); 
        M = (M^Salt1) & BodyMask; 
        ROR32_1(Salt1);
      }
      else {
        Salt1 ^= (uint32_t)(Body[M]);
        //Body[M] = (uint8_t)(Salt2); 
        M = (M^V) & BodyMask; 
        ROL32_1(Salt2);
      }
    }
    *p ^= (uint8_t)(Salt1 ^ Salt2 ^ V);
    Salt1 ^= ((uint32_t)((!*p) ^ Body[t&BodyMask]) << 24);
    ROR32_1(Salt1);
    Checksum = CRC32Table[*p ^ ((Checksum >> 24) & 0xff)] ^ (Checksum << 8); 
    V ^= Checksum;
    ROL32_1(V);
    p++;
  }
  return Checksum ^ 0xffffffff;
} 
