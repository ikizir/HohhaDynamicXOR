// B.
#include "HohhaXor.h"
#include "MyRandom.h"
#include <sys/time.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <assert.h>
#include "libbase64.h"
#include <unistd.h>
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
  printf("Total data processed: %6.2f MBytes Elapsed Time: %u ms. Average: %10.4f MBytes/secs \n",TotalMBytes, EInMs, Average);
  return Average;
}

void IncByOne(uint8_t *Buf, uint32_t BufLen)
{
  unsigned t;
  for (t=0; t<BufLen; t++)
    Buf[t]++;
}
uint8_t *CreateDataBuf(size_t Size)
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
  printf("MemCpyBenchmark1 SampleLen: %u Iterations: %u ... ",TestSampleLength,NumIterations);  
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
  uint32_t t; 
  uint8_t Salt[SALT_SIZE];
  int Err;
  
  printf("Benchmark1 NumJumps: %u BodyLen: %u SampleLen: %u Iterations: %u ... ",NumJumps,BodyLen,TestSampleLength,NumIterations);  
  
  GetRandomNumbers(TestSampleLength, Data);
  Err = xorGetKey(NumJumps, BodyLen, KeyBuf);
  if (Err != 0)
  {
    printf("Couldn't create the key. Error: %d\n",Err);
    exit(-1);
  }
  xorAnalyzeKey(KeyBuf);
  struct timeval StartTime;
  gettimeofday (&StartTime, NULL); 
  
  for (t=0; t<NumIterations; t++)
  {
    IncByOne(Data, TestSampleLength);
    GetRandomNumbers(SALT_SIZE, Salt);
    xorEncrypt(KeyBuf, (uint8_t *)(&Salt), TestSampleLength, Data);
    TotalProcessedBytes += TestSampleLength;
  }
  double Average = PrintElapsedTime(&StartTime,TotalProcessedBytes);
  free(Data);
  free(KeyBuf);
  return Average;
}
double BenchmarkHOP(uint8_t NumJumps, uint32_t BodyLen, uint32_t TestSampleLength, uint32_t NumIterations)
{
  uint8_t *KeyBuf = (uint8_t *)malloc(xorComputeKeyBufLen(BodyLen)); assert (KeyBuf);
  uint8_t *Data = CreateDataBuf(TestSampleLength);
  unsigned long long int TotalProcessedBytes = 0;
  uint32_t t;
  uint8_t SaltData[SALT_SIZE]; 
  
  assert(KeyBuf);
  printf("BenchmarkHop NumJumps: %u BodyLen: %u SampleLen: %u Iterations: %u ... ",NumJumps,BodyLen,TestSampleLength,NumIterations);  
  GetRandomNumbers(SALT_SIZE, SaltData);
  GetRandomNumbers(TestSampleLength, Data);
  int Err = xorGetKey(NumJumps, BodyLen, KeyBuf);
  if (Err != 0)
  {
    printf("Couldn't create the key. Error: %d\n",Err);
    exit(-1);
  }
  xorAnalyzeKey(KeyBuf);
  struct timeval StartTime;
  gettimeofday (&StartTime, NULL); 
  
  THOPEncryptorFnc EncryptorFnc = xorGetProperHOPEncryptorFnc(KeyBuf);
  for (t=0; t<NumIterations; t++)
  {
    IncByOne(Data, TestSampleLength);
    EncryptorFnc(KeyBuf, (uint8_t *)(&SaltData), TestSampleLength, Data);
    TotalProcessedBytes += TestSampleLength;
  }
  double Average = PrintElapsedTime(&StartTime,TotalProcessedBytes);
  free(Data);
  free(KeyBuf);
  return Average;
}

double BenchmarkPack(uint8_t NumJumps, uint32_t BodyLen, uint32_t TestSampleLength, uint32_t NumIterations)
{
  uint8_t KeyBuf[xorComputeKeyBufLen(BodyLen)];
  uint8_t *Data = CreateDataBuf(TestSampleLength);
  unsigned long long int TotalProcessedBytes = 0;
  uint32_t t;
  uint8_t SaltData[SALT_SIZE]; 
  
  printf("SampleLen: %4u :: ",TestSampleLength);  
  
  GetRandomNumbers(SALT_SIZE, SaltData);
  GetRandomNumbers(TestSampleLength, Data);
  int Err = xorGetKey(NumJumps, BodyLen, KeyBuf);
  if (Err != 0)
  {
    printf("Couldn't create the key. Error: %d\n",Err);
    exit(-1);
  }
  //xorAnalyzeKey(KeyBuf);
  struct timeval StartTime;
  gettimeofday (&StartTime, NULL); 
  
  
  #define PACK_ALIGNMENT_BENCHMARK 16
  
  uint8_t Packet[GetHohhaExactEncryptedPacketSize(TestSampleLength, PACK_ALIGNMENT_BENCHMARK)];
  
  for (t=0; t<NumIterations; t++)
  {
    IncByOne(Data, TestSampleLength);  
    xorEncryptAndSign2(KeyBuf, TestSampleLength, Data, PACK_ALIGNMENT_BENCHMARK, (uint8_t *)&Packet);
    TotalProcessedBytes += TestSampleLength;
  }
  double Average = PrintElapsedTime(&StartTime,TotalProcessedBytes);
  free(Data);
  return Average;
}
#define TESTSTR2 "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
#define TESTSTR2_LEN strlen(TESTSTR2)

#define TESTSTR1 "TÜRKÇE karakter kullanınız DENEME. TÜRKÇE karakter kullanınız DENEME. uzuuuuuuun. TÜRKÇE karakter kullanınız DENEME. Çok uzun çok!222TÜRKÇE karakter kullanınız DENEME. TÜRKÇE karakter kullanınız DENEME. uzuuuuuuun. TÜRKÇE karakter kullanınız DENEME. Çok uzun çok!frfrTÜRKÇE karakter kullanınız DENEME. TÜRKÇE karakter kullanınız DENEME. uzuuuuuuun. TÜRKÇE karakter kullanınız DENEME. Çok uzun çok!"
#define TESTSTR1_LEN strlen(TESTSTR1)
void CheckOptimizedVersion(unsigned NumJumps, unsigned BodyLen)
{
  unsigned long long int DLen;
  
  THohhaAuthCode CheckSumReturnedFromEncryptor, CheckSumReturnedFromDecryptor;
  unsigned RawKeyLen = xorComputeKeyBufLen(BodyLen);
  uint8_t *KeyBuf = (uint8_t *)malloc(RawKeyLen); assert (KeyBuf);
  uint8_t PlainTextBuf[132000], Data[132000];
  uint8_t SaltData[SALT_SIZE]; 
  
  GetRandomNumbers(SALT_SIZE, SaltData);  
  printf("-------------------- TESTING OPTIMIZED VERSION FOR %u JUMPS -------------------------\n",NumJumps);
  int Err = xorGetKey(NumJumps, BodyLen, KeyBuf);
  if (Err != 0)
  {
    printf("Couldn't create the key. Error: %d\n",Err);
    exit(-1);
  }
  DLen = TESTSTR1_LEN; 
  memcpy(Data, TESTSTR1, DLen);
  memcpy(PlainTextBuf, TESTSTR1, DLen);
  
  for (DLen = 0; DLen < TESTSTR1_LEN; DLen++)
  {
    PlainTextBuf[DLen] = (uint8_t)(DLen & 255);
    Data[DLen] = PlainTextBuf[DLen];
    
    CheckSumReturnedFromEncryptor = xorEncrypt(KeyBuf, (uint8_t *)(&SaltData), ALIGN_TO_ROUND_UP64(DLen+1, sizeof(uint32_t)), Data); // We encrypt with non-optimized version
    THOPDecryptorFnc DecryptorFnc = xorGetProperHOPDecryptorFnc(KeyBuf);
    CheckSumReturnedFromDecryptor = DecryptorFnc(KeyBuf, (uint8_t *)(&SaltData), ALIGN_TO_ROUND_UP64(DLen+1, sizeof(uint32_t)), Data);
    
    if (!AuthCodesMatch(&CheckSumReturnedFromEncryptor, &CheckSumReturnedFromDecryptor))
    {
      printf("Original Checksum returned from encryptor fnc <> Checksum returned from HOP decyptor\n"
        "Encryptor returned: S1:%u S2:%u X:%u Y:%u\nDecryptor: S1:%u S2:%u X:%u Y:%u\n", 
        (unsigned)CheckSumReturnedFromEncryptor.S1, CheckSumReturnedFromEncryptor.S2,(unsigned)CheckSumReturnedFromEncryptor.X, (unsigned)CheckSumReturnedFromEncryptor.Y,
        (unsigned)CheckSumReturnedFromDecryptor.S1, CheckSumReturnedFromDecryptor.S2,(unsigned)CheckSumReturnedFromDecryptor.X, (unsigned)CheckSumReturnedFromDecryptor.Y);
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
  unsigned long long int DLen;
  THohhaAuthCode  CheckSumReturnedFromEncryptor, CheckSumReturnedFromDecryptor;
  unsigned RawKeyLen = xorComputeKeyBufLen(BodyLen);
  uint8_t KeyBuf [RawKeyLen];
  uint8_t Data[2048],Data2[2048];
  char Base64EncodedKeyStr[BASE64_ENCODED_LEN(RawKeyLen)+1];
  size_t l;
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
  base64_encode((const char *)KeyBuf, RawKeyLen, Base64EncodedKeyStr, &l, 0);
  Base64EncodedKeyStr[l]='\0';
  printf("Base64 encoded key: %s\n", Base64EncodedKeyStr);

  xorAnalyzeKey(KeyBuf);
  memset(&Data, 0, sizeof(Data));
  memset(&Data2, 0, sizeof(Data2));
  DLen = ALIGN_TO_ROUND_UP64(TESTSTR1_LEN+1, sizeof(uint32_t)); 
  memcpy(Data, TESTSTR1, TESTSTR1_LEN);
  memcpy(Data2, TESTSTR1, TESTSTR1_LEN);
  
  CheckSumReturnedFromEncryptor = xorEncrypt(KeyBuf, SaltData, DLen, Data); // We encrypt with non-optimized version
  
  // Now let's encrypt with the optimized encryptor
  
  THOPEncryptorFnc EncryptorFnc = xorGetProperHOPEncryptorFnc(KeyBuf);
  THOPDecryptorFnc DecryptorFnc = xorGetProperHOPDecryptorFnc(KeyBuf);
    
  CheckSumReturnedFromEncryptor = EncryptorFnc(KeyBuf, SaltData, DLen, Data2); 
  
  if (memcmp((char *)Data, Data2, DLen) != 0)
  {
    printf("Non-optimized and optimized encryptor functions outputs are different! FAILED! FAILED!\n");
    exit(-1);
  } else printf("Non-optimized and optimized encryptor test PASS!\n");
  char Base64CipherText[BASE64_ENCODED_LEN(DLen) + 7];
  
  base64_encode((const char *)Data, DLen, Base64CipherText, &l, 0);
  Base64CipherText[l] = '\0';
  printf("Base64CipherText: %s\n", Base64CipherText);
  printf("\n\nDecryption process:\n\n");
  uint8_t K[RawKeyLen];
  base64_decode(Base64EncodedKeyStr, l, (char *)K, &l, 0 );
  
  if (memcmp((char *)KeyBuf, (char *)K, RawKeyLen) != 0)
  {
    printf("Original key and base64 encoded and decoded keys are different!!!!!\n");
    exit(-1);
  }
  //CheckSumReturnedFromDecryptor = xorDecrypt(K, (uint8_t *)(&SaltData), DLen, Data);
  
  CheckSumReturnedFromDecryptor = DecryptorFnc(K, SaltData, DLen, Data);
  
  if (!AuthCodesMatch(&CheckSumReturnedFromEncryptor, &CheckSumReturnedFromDecryptor))
  {
    printf("Original Checksum returned from encryptor fnc <> Checksum returned from HOP decyptor\n"
        "Encryptor returned: S1:%u S2:%u X:%u Y:%u\nDecryptor: S1:%u S2:%u X:%u Y:%u\n", 
        (unsigned)CheckSumReturnedFromEncryptor.S1, CheckSumReturnedFromEncryptor.S2,(unsigned)CheckSumReturnedFromEncryptor.X, (unsigned)CheckSumReturnedFromEncryptor.Y,
        (unsigned)CheckSumReturnedFromDecryptor.S1, CheckSumReturnedFromDecryptor.S2,(unsigned)CheckSumReturnedFromDecryptor.X, (unsigned)CheckSumReturnedFromDecryptor.Y);
    exit(-1);
  }
  if (memcmp((char *)Data, TESTSTR1, TESTSTR1_LEN) == 0)
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
  uint8_t KeyBuf[RawKeyLen];
  uint8_t Data[2048],Data2[2048];
  char Base64EncodedKeyStr[BASE64_ENCODED_LEN(RawKeyLen)+1];
  uint8_t SaltData[SALT_SIZE];
  size_t l;
  
  GetRandomNumbers(SALT_SIZE, SaltData);  
  printf("----------- COMM PACKETS TEST(%u Jumps) --------------\n",NumJumps);
  int Err = xorGetKey(NumJumps, BodyLen, KeyBuf);
  if (Err != 0)
  {
    printf("Couldn't create the key. Error: %d\n",Err);
    exit(-1);
  }
  base64_encode((const char *)KeyBuf, RawKeyLen, Base64EncodedKeyStr, &l, 0);
  Base64EncodedKeyStr[l]='\0';
  printf("Base64 encoded key: %s\n", Base64EncodedKeyStr);
  
  memset(&Data, 0, sizeof(Data));
  memset(&Data2, 0, sizeof(Data2));
  DLen = TESTSTR1_LEN; 
  memcpy(Data, TESTSTR1, DLen);
  
  
  #define PACK_ALIGNMENT 16
  uint32_t CommPacketTotalSize = GetHohhaExactEncryptedPacketSize(DLen,PACK_ALIGNMENT);
  uint8_t *CommPacket = malloc(CommPacketTotalSize);
  xorEncryptAndSign2(KeyBuf, DLen, Data, PACK_ALIGNMENT, CommPacket);
  
  char Base64EncodedCommPacket[BASE64_ENCODED_LEN(CommPacketTotalSize)+1];
  base64_encode((const char *)CommPacket, CommPacketTotalSize, Base64EncodedCommPacket, &l, 0);
  Base64EncodedCommPacket[l] = '\0';
  printf("Encrypted communication packet: %s\n", Base64EncodedCommPacket);
  
  // Now, let's decrypt it
  ssize_t DpRes;
  uint8_t *PPText = xorDecryptAndVerify(KeyBuf, CommPacketTotalSize, CommPacket, &DpRes);
  if (DpRes < 0 || DpRes != DLen)
  {
    printf("xorDecryptAndVerify error: %lld. DLen: %lld\n", (long long int)DpRes, (long long int)DLen);
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
  
  /*CommPacketTotalSize = HOHHA_TOTAL_COMM_PACKET_SIZE_WITHOUT_ENCRYPTION(DLen);
  CommPacket = calloc(1, CommPacketTotalSize);
  xorEncryptAndSign2Plaintext(DLen, Data, CommPacket);
  
  Base64EncodedCommPacket = Base64Encode((const char *)CommPacket, CommPacketTotalSize);
  printf("Plaintext communication packet in base64: %s\n", Base64EncodedCommPacket);
  free(Base64EncodedCommPacket);
  
  // Now, let's decrypt it
  PPText = xorDecryptAndVerify(KeyBuf, CommPacketTotalSize, CommPacket, &DpRes);
  if (DpRes < 0 || DpRes != DLen)
  {
    printf("xorDecryptAndVerify error: %lld. DLen: %lld\n", (long long int)DpRes, (long long int)DLen);
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
  free(CommPacket);*/
  
  // Variable length packets test
  
  uint8_t *EncPack;
  DLen = 0;
  while (DLen < 2048)
  {
    Data[DLen] = (uint8_t)(DLen & 255);
    DLen++;
    EncPack = xorEncryptAndSign(KeyBuf,  DLen, Data, 16);
    if (!EncPack)
    {
      printf("xorEncryptAndSign FAILED!");
      exit(-1);
    }
    PPText = xorDecryptAndVerify(KeyBuf, GetHohhaExactEncryptedPacketSize(DLen,16), EncPack, &DpRes);
    if (!PPText || DpRes < 0)
    {
      printf("xorDecryptAndVerify error: %lld. DLen: %lld\n", (long long int)DpRes, (long long int)DLen);
      exit(-1);
    }
    if (memcmp((char *)PPText, Data, DLen) != 0)
    {
      printf("xorDecryptAndVerify error: ORIGINAL DATA AND DECRYPTED DATA ARE NOT SAME! DLen: %lld\n", (long long int)DLen);
    }
    free(EncPack);
  }
  //exit(-1);
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
    ROL32_1(Nn);
  }
  printf("Circular shift right:\n");
  for (t=0; t<6; t++)
  {
    printf("%s\n", GetBinStr(Nn,Buf));  
    ROR32_1(Nn);
  }
}

#define BMP_FILE_HEADER_LEN 52
ssize_t EncryptBMPFile(const char *InFileName, const char *OutFileName, uint8_t *KeyBuf)
{ // Encrypts a bmp file for visual attack and returns -1 on error. 
  int32_t FDesc;   
  int64_t Len, RLen;
  uint8_t *Data;
  uint8_t SaltData[SALT_SIZE]; 
  
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
  (void)EncryptorFnc(KeyBuf, (uint8_t *)(&SaltData), ALIGN_TO_ROUND_DOWN64(Len-BMP_FILE_HEADER_LEN-4, 4), Data + BMP_FILE_HEADER_LEN); 
  FDesc = open(OutFileName, O_CREAT | O_TRUNC | O_WRONLY, 777);
  if (FDesc == -1) // FDesc = creat(OutFileName, 777)
  {
    printf("Error in creating output file: %s!\n", OutFileName);
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
  return 1;
}

#define SAMPLE_FILE_PATH "/Users/ikizir//Desktop/bmpsamples"
#define SAMPLE_OUT_FILE_PATH "/Users/ikizir/Desktop/bmpsamples/output"
static char FNameStaticBuf[256];
const char *GetFP(const char *FName)
{
  sprintf(FNameStaticBuf, SAMPLE_FILE_PATH"/%s", FName);
  return FNameStaticBuf;
}
static char FNameStaticBuf2[256];
const char *GetFP2(const char *FName)
{
  sprintf(FNameStaticBuf2, SAMPLE_OUT_FILE_PATH"/%s", FName);
  return FNameStaticBuf2;
}

void TestEncryptBMPFile(const char *InFileName, const char *OutFileName, unsigned NumJumps, unsigned BodyLen)
{
  unsigned RawKeyLen = xorComputeKeyBufLen(BodyLen);
  uint8_t *KeyBuf = (uint8_t *)malloc(RawKeyLen);
  char Base64EncodedKeyStr[BASE64_ENCODED_LEN(RawKeyLen)+1];
  size_t l;
  
  printf("----------- BMPFILE ENC TEST(%u Jumps) --------------\n",NumJumps);
  int Err = xorGetKey(NumJumps, BodyLen, KeyBuf);
  if (Err != 0)
  {
    printf("\nTestEncryptBMPFile: Couldn't create the key. Error: %d\n\n",Err); fflush(stdout);
    exit(-1);
  }
  base64_encode((const char *)KeyBuf, RawKeyLen, Base64EncodedKeyStr, &l, 0);
  Base64EncodedKeyStr[l] = '\0';
  printf("TestEncryptBMPFile: Base64 encoded key: %s\n", Base64EncodedKeyStr);
  xorAnalyzeKey(KeyBuf);
  EncryptBMPFile(InFileName, OutFileName, KeyBuf);
}

void CreateVisualProofs(void)
{
  TestEncryptBMPFile(GetFP("allzero.bmp"), GetFP2("allzero_enc_2J_16.bmp"), 2, 16);
  TestEncryptBMPFile(GetFP("allzero.bmp"), GetFP2("allzero_enc_3J_16.bmp"), 3, 16);
  TestEncryptBMPFile(GetFP("allzero.bmp"), GetFP2("allzero_enc_4J_16.bmp"), 4, 16);
  
  TestEncryptBMPFile(GetFP("allzero.bmp"), GetFP2("allzero_enc_2J_32.bmp"), 2, 32);
  TestEncryptBMPFile(GetFP("allzero.bmp"), GetFP2("allzero_enc_3J_32.bmp"), 3, 32);
  TestEncryptBMPFile(GetFP("allzero.bmp"), GetFP2("allzero_enc_4J_32.bmp"), 4, 32);
  
  TestEncryptBMPFile(GetFP("allzero.bmp"), GetFP2("allzero_enc_2J_64.bmp"), 2, 64);
  TestEncryptBMPFile(GetFP("allzero.bmp"), GetFP2("allzero_enc_3J_64.bmp"), 3, 64);
  TestEncryptBMPFile(GetFP("allzero.bmp"), GetFP2("allzero_enc_4J_64.bmp"), 4, 64);
  
  TestEncryptBMPFile(GetFP("allzero.bmp"), GetFP2("allzero_enc_2J_128.bmp"), 2, 128);
  TestEncryptBMPFile(GetFP("allzero.bmp"), GetFP2("allzero_enc_3J_128.bmp"), 3, 128);
  TestEncryptBMPFile(GetFP("allzero.bmp"), GetFP2("allzero_enc_4J_128.bmp"), 4, 128);
  
  TestEncryptBMPFile(GetFP("allzero.bmp"), GetFP2("allzero_enc_2J_256.bmp"), 2, 256);
  TestEncryptBMPFile(GetFP("allzero.bmp"), GetFP2("allzero_enc_3J_256.bmp"), 3, 256);
  TestEncryptBMPFile(GetFP("allzero.bmp"), GetFP2("allzero_enc_4J_256.bmp"), 4, 256);
  
  TestEncryptBMPFile(GetFP("panda.bmp"), GetFP2("panda_enc_2J_16.bmp"), 2, 16);
  TestEncryptBMPFile(GetFP("panda.bmp"), GetFP2("panda_enc_3J_16.bmp"), 3, 16);
  TestEncryptBMPFile(GetFP("panda.bmp"), GetFP2("panda_enc_4J_16.bmp"), 4, 16);
  
  TestEncryptBMPFile(GetFP("panda.bmp"), GetFP2("panda_enc_2J_32.bmp"), 2, 32);
  TestEncryptBMPFile(GetFP("panda.bmp"), GetFP2("panda_enc_3J_32.bmp"), 3, 32);
  TestEncryptBMPFile(GetFP("panda.bmp"), GetFP2("panda_enc_4J_32.bmp"), 4, 32);
  
  TestEncryptBMPFile(GetFP("panda.bmp"), GetFP2("panda_enc_2J_64.bmp"), 2, 64);
  TestEncryptBMPFile(GetFP("panda.bmp"), GetFP2("panda_enc_3J_64.bmp"), 3, 64);
  TestEncryptBMPFile(GetFP("panda.bmp"), GetFP2("panda_enc_4J_64.bmp"), 4, 64);
  
  TestEncryptBMPFile(GetFP("panda.bmp"), GetFP2("panda_enc_2J_128.bmp"), 2, 128);
  TestEncryptBMPFile(GetFP("panda.bmp"), GetFP2("panda_enc_3J_128.bmp"), 3, 128);
  TestEncryptBMPFile(GetFP("panda.bmp"), GetFP2("panda_enc_4J_128.bmp"), 4, 128);
  
  TestEncryptBMPFile(GetFP("panda.bmp"), GetFP2("panda_enc_2J_256.bmp"), 2, 256);
  TestEncryptBMPFile(GetFP("panda.bmp"), GetFP2("panda_enc_3J_256.bmp"), 3, 256);
  TestEncryptBMPFile(GetFP("panda.bmp"), GetFP2("panda_enc_4J_256.bmp"), 4, 256);
  
  TestEncryptBMPFile(GetFP("Bitmap1.bmp"), GetFP2("Bitmap1_enc_2J_16.bmp"), 2, 16);
  TestEncryptBMPFile(GetFP("Bitmap1.bmp"), GetFP2("Bitmap1_enc_3J_16.bmp"), 3, 16);
  TestEncryptBMPFile(GetFP("Bitmap1.bmp"), GetFP2("Bitmap1_enc_4J_16.bmp"), 4, 16);
  
  TestEncryptBMPFile(GetFP("Bitmap1.bmp"), GetFP2("Bitmap1_enc_2J_32.bmp"), 2, 32);
  TestEncryptBMPFile(GetFP("Bitmap1.bmp"), GetFP2("Bitmap1_enc_3J_32.bmp"), 3, 32);
  TestEncryptBMPFile(GetFP("Bitmap1.bmp"), GetFP2("Bitmap1_enc_4J_32.bmp"), 4, 32);
  
  TestEncryptBMPFile(GetFP("Bitmap1.bmp"), GetFP2("Bitmap1_enc_2J_64.bmp"), 2, 64);
  TestEncryptBMPFile(GetFP("Bitmap1.bmp"), GetFP2("Bitmap1_enc_3J_64.bmp"), 3, 64);
  TestEncryptBMPFile(GetFP("Bitmap1.bmp"), GetFP2("Bitmap1_enc_4J_64.bmp"), 4, 64);
  
  TestEncryptBMPFile(GetFP("Bitmap1.bmp"), GetFP2("Bitmap1_enc_2J_128.bmp"), 2, 128);
  TestEncryptBMPFile(GetFP("Bitmap1.bmp"), GetFP2("Bitmap1_enc_3J_128.bmp"), 3, 128);
  TestEncryptBMPFile(GetFP("Bitmap1.bmp"), GetFP2("Bitmap1_enc_4J_128.bmp"), 4, 128);
  
  TestEncryptBMPFile(GetFP("Bitmap1.bmp"), GetFP2("Bitmap1_enc_2J_256.bmp"), 2, 256);
  TestEncryptBMPFile(GetFP("Bitmap1.bmp"), GetFP2("Bitmap1_enc_3J_256.bmp"), 3, 256);
  TestEncryptBMPFile(GetFP("Bitmap1.bmp"), GetFP2("Bitmap1_enc_4J_256.bmp"), 4, 256);
  
  TestEncryptBMPFile(GetFP("Viking.bmp"), GetFP2("Viking_enc_2J_16.bmp"), 2, 16);
  TestEncryptBMPFile(GetFP("Viking.bmp"), GetFP2("Viking_enc_3J_16.bmp"), 3, 16);
  TestEncryptBMPFile(GetFP("Viking.bmp"), GetFP2("Viking_enc_4J_16.bmp"), 4, 16);
  
  TestEncryptBMPFile(GetFP("Viking.bmp"), GetFP2("Viking_enc_2J_32.bmp"), 2, 32);
  TestEncryptBMPFile(GetFP("Viking.bmp"), GetFP2("Viking_enc_3J_32.bmp"), 3, 32);
  TestEncryptBMPFile(GetFP("Viking.bmp"), GetFP2("Viking_enc_4J_32.bmp"), 4, 32);
  
  TestEncryptBMPFile(GetFP("Viking.bmp"), GetFP2("Viking_enc_2J_64.bmp"), 2, 64);
  TestEncryptBMPFile(GetFP("Viking.bmp"), GetFP2("Viking_enc_3J_64.bmp"), 3, 64);
  TestEncryptBMPFile(GetFP("Viking.bmp"), GetFP2("Viking_enc_4J_64.bmp"), 4, 64);
  
  TestEncryptBMPFile(GetFP("Viking.bmp"), GetFP2("Viking_enc_2J_128.bmp"), 2, 128);
  TestEncryptBMPFile(GetFP("Viking.bmp"), GetFP2("Viking_enc_3J_128.bmp"), 3, 128);
  TestEncryptBMPFile(GetFP("Viking.bmp"), GetFP2("Viking_enc_4J_128.bmp"), 4, 128);
  
  TestEncryptBMPFile(GetFP("Viking.bmp"), GetFP2("Viking_enc_2J_256.bmp"), 2, 256);
  TestEncryptBMPFile(GetFP("Viking.bmp"), GetFP2("Viking_enc_3J_256.bmp"), 3, 256);
  TestEncryptBMPFile(GetFP("Viking.bmp"), GetFP2("Viking_enc_4J_256.bmp"), 4, 256);
  
  TestEncryptBMPFile(GetFP("B.bmp"), GetFP2("B_enc_2J_16.bmp"), 2, 16);
  TestEncryptBMPFile(GetFP("B.bmp"), GetFP2("B_enc_3J_16.bmp"), 3, 16);
  TestEncryptBMPFile(GetFP("B.bmp"), GetFP2("B_enc_4J_16.bmp"), 4, 16);
  
  TestEncryptBMPFile(GetFP("B.bmp"), GetFP2("B_enc_2J_32.bmp"), 2, 32);
  TestEncryptBMPFile(GetFP("B.bmp"), GetFP2("B_enc_3J_32.bmp"), 3, 32);
  TestEncryptBMPFile(GetFP("B.bmp"), GetFP2("B_enc_4J_32.bmp"), 4, 32);
  
  TestEncryptBMPFile(GetFP("B.bmp"), GetFP2("B_enc_2J_64.bmp"), 2, 64);
  TestEncryptBMPFile(GetFP("B.bmp"), GetFP2("B_enc_3J_64.bmp"), 3, 64);
  TestEncryptBMPFile(GetFP("B.bmp"), GetFP2("B_enc_4J_64.bmp"), 4, 64);
  
  TestEncryptBMPFile(GetFP("B.bmp"), GetFP2("B_enc_2J_128.bmp"), 2, 128);
  TestEncryptBMPFile(GetFP("B.bmp"), GetFP2("B_enc_3J_128.bmp"), 3, 128);
  TestEncryptBMPFile(GetFP("B.bmp"), GetFP2("B_enc_4J_128.bmp"), 4, 128);
  
  TestEncryptBMPFile(GetFP("B.bmp"), GetFP2("B_enc_2J_256.bmp"), 2, 256);
  TestEncryptBMPFile(GetFP("B.bmp"), GetFP2("B_enc_3J_256.bmp"), 3, 256);
  TestEncryptBMPFile(GetFP("B.bmp"), GetFP2("B_enc_4J_256.bmp"), 4, 256);
  
  TestEncryptBMPFile(GetFP("penguen.bmp"), GetFP2("penguen_enc_2J_16.bmp"), 2, 16);
  TestEncryptBMPFile(GetFP("penguen.bmp"), GetFP2("penguen_enc_3J_16.bmp"), 3, 16);
  TestEncryptBMPFile(GetFP("penguen.bmp"), GetFP2("penguen_enc_4J_16.bmp"), 4, 16);
  
  TestEncryptBMPFile(GetFP("penguen.bmp"), GetFP2("penguen_enc_2J_32.bmp"), 2, 32);
  TestEncryptBMPFile(GetFP("penguen.bmp"), GetFP2("penguen_enc_3J_32.bmp"), 3, 32);
  TestEncryptBMPFile(GetFP("penguen.bmp"), GetFP2("penguen_enc_4J_32.bmp"), 4, 32);
  
  TestEncryptBMPFile(GetFP("penguen.bmp"), GetFP2("penguen_enc_2J_64.bmp"), 2, 64);
  TestEncryptBMPFile(GetFP("penguen.bmp"), GetFP2("penguen_enc_3J_64.bmp"), 3, 64);
  TestEncryptBMPFile(GetFP("penguen.bmp"), GetFP2("penguen_enc_4J_64.bmp"), 4, 64);
  
  TestEncryptBMPFile(GetFP("penguen.bmp"), GetFP2("penguen_enc_2J_128.bmp"), 2, 128);
  TestEncryptBMPFile(GetFP("penguen.bmp"), GetFP2("penguen_enc_3J_128.bmp"), 3, 128);
  TestEncryptBMPFile(GetFP("penguen.bmp"), GetFP2("penguen_enc_4J_128.bmp"), 4, 128);
  
  TestEncryptBMPFile(GetFP("penguen.bmp"), GetFP2("penguen_enc_2J_256.bmp"), 2, 256);
  TestEncryptBMPFile(GetFP("penguen.bmp"), GetFP2("penguen_enc_3J_256.bmp"), 3, 256);
  TestEncryptBMPFile(GetFP("penguen.bmp"), GetFP2("penguen_enc_4J_256.bmp"), 4, 256);
}

static void CreateKey(unsigned KBLen, unsigned NumJumps, uint8_t *KeyBuf)
{
    unsigned RawKeyLen = xorComputeKeyBufLen(KBLen);
    char Base64EncodedKeyStr[BASE64_ENCODED_LEN(RawKeyLen)+1];
    size_t l;

    int Err = xorGetKey(NumJumps, KBLen, KeyBuf);
    if (Err != 0)
    {
      printf("\nCouldn't create the key. Error: %d\n",Err);
      exit(-1);
    }
    base64_encode((const char *)KeyBuf, RawKeyLen, Base64EncodedKeyStr, &l, 0);
    Base64EncodedKeyStr[l]='\0';
    printf("Base64 encoded key: %s\n", Base64EncodedKeyStr);
    xorAnalyzeKey(KeyBuf);
    //exit(-1);
}

void EncAndSign(uint8_t *KeyBuf, uint8_t *Data, size_t DLen, unsigned PacketAlignment)
{
  size_t l;

  uint32_t CommPacketTotalSize = GetHohhaExactEncryptedPacketSize(DLen, PacketAlignment);
  uint8_t *CommPacket = malloc(CommPacketTotalSize);
  xorEncryptAndSign2(KeyBuf, DLen, Data, PacketAlignment, CommPacket);

  char Base64EncodedCommPacket[BASE64_ENCODED_LEN(CommPacketTotalSize)+1];
  base64_encode((const char *)CommPacket, CommPacketTotalSize, Base64EncodedCommPacket, &l, 0);
  Base64EncodedCommPacket[l] = '\0';
  printf("\n--Encrypted and signed packet: %s\n", Base64EncodedCommPacket);
  free(CommPacket);
}

static void DecAndVerify(uint8_t *KeyBuf, const char *Base64EncodedCipherText)
{
  size_t l, Base64EncodedCipherTextLen = strlen(Base64EncodedCipherText);
  uint8_t Data2[BASE64_DECODED_BINBUF_REQUIREMENT(Base64EncodedCipherTextLen)];


  base64_decode(Base64EncodedCipherText, Base64EncodedCipherTextLen, (char *)Data2, &l, 0);
  // Now, let's decrypt it
  ssize_t DpRes;
  uint8_t *PPText = xorDecryptAndVerify(KeyBuf, l, Data2, &DpRes);
  if (DpRes < 0)
  {
    printf("xorDecryptAndVerify error: %lld. DLen: %lld PPText: %s\n", (long long int)DpRes, (long long int)l, PPText);
    exit(-1);
  }

  printf("Successfully decrypted string [%.*s]\n", (int)(DpRes), (char *)PPText);
}
static void RunBench(int NumIterations)
{
  uint32_t BodyLen = 16;
  
  Test1(2, BodyLen);
  CommPacketTest(2, 64);
  
  
  //CreateVisualProofs();
  //exit(-1);
  
  //CircularShiftTest();
  //uint32_t TestSampleLength = 8192;
  //D1();
  //Test1(2, BodyLen);
  //Test1(3, BodyLen);
  //Test1(11, BodyLen);
  //Test1(4, BodyLen);
  //Test1(5, BodyLen);
  
    //exit(-1);

  //CheckOptimizedVersion(2, BodyLen);
  //CheckOptimizedVersion(3, BodyLen);
  //CheckOptimizedVersion(4, BodyLen);
  //CheckOptimizedVersion(5, BodyLen);
  //exit(-1);
  
  double Average16M,Average64M,Average256M,Average1024M,Average8192M;

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
  
#define DO_RAW_ENCRYPTION_BENCH
#if defined(DO_RAW_ENCRYPTION_BENCH)
  double Average16H2,Average64H2,Average256H2,Average1024H2,Average8192H2;
  double Average16H3,Average64H3,Average256H3,Average1024H3,Average8192H3;
  double Average16H4,Average64H4,Average256H4,Average1024H4,Average8192H4;

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
         "\n\n2-Jumps BENCHMARKS:\n"
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
#endif

#define DO_PACKET_BENCH
#if defined(DO_PACKET_BENCH)
  unsigned J;
  for (BodyLen = 16; BodyLen<256; BodyLen <<= 1)
  {
    for (J=2; J<5; J++)
    {
      printf("----------------- PACKET CONSTRUCTION. BodyLen: %u NumJumps: %u Iterations: %u ----------------------\n",BodyLen,J,NumIterations);
      BenchmarkPack(J, BodyLen, 16, NumIterations);
      BenchmarkPack(J, BodyLen, 64, NumIterations);
      BenchmarkPack(J, BodyLen, 256, NumIterations);
      BenchmarkPack(J, BodyLen, 1024, NumIterations);
      BenchmarkPack(J, BodyLen, 8192, NumIterations);
    }
  }
#endif
}
int32_t main(int32_t argc, char *argv[], char *envp[]) {
  int c, KBLen=0, NumJumps=0;
  uint8_t KeyBuf[512];
  //unsigned CVP = 0;
  size_t l;
  unsigned PacketAlignment=16;
  init_rand(time(NULL));
  puts("\n");

  /*base64_decode("AhAAb+nQZRF410edsZ+exzgMGyW/MO3hxJAH", strlen("AhAAb+nQZRF410edsZ+exzgMGyW/MO3hxJAH"), (char *)KeyBuf, &l, 0 );
  xorAnalyzeKey(KeyBuf);
  DecAndVerify(KeyBuf, "hsB8eglB8Og9ZHFtWNBjM5VwGB7MdnRjSBhCIP9rV+N3FEr8JO9/+gqQv0QuRxoHUc/kuA==");
  exit(-1);*/
  while ((c = getopt(argc, argv, "k:j:b:i:e:a:d:r:")) != EOF)
  {
    switch (c)
    {
      case 'a': // Packet alignment
        PacketAlignment = atoi(optarg);
        break;
      case 'j': // Number of jumps for the key to be created
        NumJumps = atoi(optarg);
        if (NumJumps && KBLen)
          CreateKey(KBLen, NumJumps, KeyBuf);
        break;
      case 'b': // Body len of the key to be created
        KBLen = atoi(optarg);
        if (NumJumps && KBLen)
          CreateKey(KBLen, NumJumps, KeyBuf);
        break;
      case 'k': // User gives us an existing key in base64 format
        base64_decode((const char *)optarg, strlen((const char *)optarg), (char *)KeyBuf, &l, 0 );
        xorAnalyzeKey(KeyBuf);
        break;
      case 'e': // User wants to encrypt and sign utf8 string
        EncAndSign(KeyBuf, (uint8_t *)optarg, strlen((const char *)optarg), PacketAlignment);
        break;
      case 'd': // User wants to decrypt and verify ciphertext encoded as base64
        DecAndVerify(KeyBuf, (const char *)optarg);
        break;
      default :
        RunBench(atoi(optarg));
        break;
    }
  }
  return 0;
}
