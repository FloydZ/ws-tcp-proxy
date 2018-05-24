#include "sha1.h"
//#define SHA1ASM

#ifdef SHA1ASM

/* sha1-x86.c - Intel SHA extensions using C intrinsics    */
/*   Written and place in public domain by Jeffrey Walton  */
/*   Based on code from Intel, and by Sean Gulley for      */
/*   the miTLS project.                                    */

/* Include the GCC super header */
# include <stdint.h>
# include <x86intrin.h>


/* Process multiple blocks. The caller is resonsible for setting the initial */
/*  state, and the caller is responsible for padding the final block.        */
void sha1_process_x86(uint32_t state[5], const uint8_t data[], uint32_t length)
{
    __m128i ABCD, ABCD_SAVE, E0, E0_SAVE, E1;
    __m128i MASK, MSG0, MSG1, MSG2, MSG3;

    /* Load initial values */
    ABCD = _mm_loadu_si128((const __m128i*) state);
    E0 = _mm_set_epi32(state[4], 0, 0, 0);
    ABCD = _mm_shuffle_epi32(ABCD, 0x1B);
    MASK = _mm_set_epi64x(0x0001020304050607ULL, 0x08090a0b0c0d0e0fULL);

    while (length >= 64)
    {
        /* Save current state  */
        ABCD_SAVE = ABCD;
        E0_SAVE = E0;

        /* Rounds 0-3 */
        MSG0 = _mm_loadu_si128((const __m128i*)(data + 0));
        MSG0 = _mm_shuffle_epi8(MSG0, MASK);
        E0 = _mm_add_epi32(E0, MSG0);
        E1 = ABCD;
        ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 0);

        /* Rounds 4-7 */
        MSG1 = _mm_loadu_si128((const __m128i*)(data + 16));
        MSG1 = _mm_shuffle_epi8(MSG1, MASK);
        E1 = _mm_sha1nexte_epu32(E1, MSG1);
        E0 = ABCD;
        ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 0);
        MSG0 = _mm_sha1msg1_epu32(MSG0, MSG1);

        /* Rounds 8-11 */
        MSG2 = _mm_loadu_si128((const __m128i*)(data + 32));
        MSG2 = _mm_shuffle_epi8(MSG2, MASK);
        E0 = _mm_sha1nexte_epu32(E0, MSG2);
        E1 = ABCD;
        ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 0);
        MSG1 = _mm_sha1msg1_epu32(MSG1, MSG2);
        MSG0 = _mm_xor_si128(MSG0, MSG2);

        /* Rounds 12-15 */
        MSG3 = _mm_loadu_si128((const __m128i*)(data + 48));
        MSG3 = _mm_shuffle_epi8(MSG3, MASK);
        E1 = _mm_sha1nexte_epu32(E1, MSG3);
        E0 = ABCD;
        MSG0 = _mm_sha1msg2_epu32(MSG0, MSG3);
        ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 0);
        MSG2 = _mm_sha1msg1_epu32(MSG2, MSG3);
        MSG1 = _mm_xor_si128(MSG1, MSG3);

        /* Rounds 16-19 */
        E0 = _mm_sha1nexte_epu32(E0, MSG0);
        E1 = ABCD;
        MSG1 = _mm_sha1msg2_epu32(MSG1, MSG0);
        ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 0);
        MSG3 = _mm_sha1msg1_epu32(MSG3, MSG0);
        MSG2 = _mm_xor_si128(MSG2, MSG0);

        /* Rounds 20-23 */
        E1 = _mm_sha1nexte_epu32(E1, MSG1);
        E0 = ABCD;
        MSG2 = _mm_sha1msg2_epu32(MSG2, MSG1);
        ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 1);
        MSG0 = _mm_sha1msg1_epu32(MSG0, MSG1);
        MSG3 = _mm_xor_si128(MSG3, MSG1);

        /* Rounds 24-27 */
        E0 = _mm_sha1nexte_epu32(E0, MSG2);
        E1 = ABCD;
        MSG3 = _mm_sha1msg2_epu32(MSG3, MSG2);
        ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 1);
        MSG1 = _mm_sha1msg1_epu32(MSG1, MSG2);
        MSG0 = _mm_xor_si128(MSG0, MSG2);

        /* Rounds 28-31 */
        E1 = _mm_sha1nexte_epu32(E1, MSG3);
        E0 = ABCD;
        MSG0 = _mm_sha1msg2_epu32(MSG0, MSG3);
        ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 1);
        MSG2 = _mm_sha1msg1_epu32(MSG2, MSG3);
        MSG1 = _mm_xor_si128(MSG1, MSG3);

        /* Rounds 32-35 */
        E0 = _mm_sha1nexte_epu32(E0, MSG0);
        E1 = ABCD;
        MSG1 = _mm_sha1msg2_epu32(MSG1, MSG0);
        ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 1);
        MSG3 = _mm_sha1msg1_epu32(MSG3, MSG0);
        MSG2 = _mm_xor_si128(MSG2, MSG0);

        /* Rounds 36-39 */
        E1 = _mm_sha1nexte_epu32(E1, MSG1);
        E0 = ABCD;
        MSG2 = _mm_sha1msg2_epu32(MSG2, MSG1);
        ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 1);
        MSG0 = _mm_sha1msg1_epu32(MSG0, MSG1);
        MSG3 = _mm_xor_si128(MSG3, MSG1);

        /* Rounds 40-43 */
        E0 = _mm_sha1nexte_epu32(E0, MSG2);
        E1 = ABCD;
        MSG3 = _mm_sha1msg2_epu32(MSG3, MSG2);
        ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 2);
        MSG1 = _mm_sha1msg1_epu32(MSG1, MSG2);
        MSG0 = _mm_xor_si128(MSG0, MSG2);

        /* Rounds 44-47 */
        E1 = _mm_sha1nexte_epu32(E1, MSG3);
        E0 = ABCD;
        MSG0 = _mm_sha1msg2_epu32(MSG0, MSG3);
        ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 2);
        MSG2 = _mm_sha1msg1_epu32(MSG2, MSG3);
        MSG1 = _mm_xor_si128(MSG1, MSG3);

        /* Rounds 48-51 */
        E0 = _mm_sha1nexte_epu32(E0, MSG0);
        E1 = ABCD;
        MSG1 = _mm_sha1msg2_epu32(MSG1, MSG0);
        ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 2);
        MSG3 = _mm_sha1msg1_epu32(MSG3, MSG0);
        MSG2 = _mm_xor_si128(MSG2, MSG0);

        /* Rounds 52-55 */
        E1 = _mm_sha1nexte_epu32(E1, MSG1);
        E0 = ABCD;
        MSG2 = _mm_sha1msg2_epu32(MSG2, MSG1);
        ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 2);
        MSG0 = _mm_sha1msg1_epu32(MSG0, MSG1);
        MSG3 = _mm_xor_si128(MSG3, MSG1);

        /* Rounds 56-59 */
        E0 = _mm_sha1nexte_epu32(E0, MSG2);
        E1 = ABCD;
        MSG3 = _mm_sha1msg2_epu32(MSG3, MSG2);
        ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 2);
        MSG1 = _mm_sha1msg1_epu32(MSG1, MSG2);
        MSG0 = _mm_xor_si128(MSG0, MSG2);

        /* Rounds 60-63 */
        E1 = _mm_sha1nexte_epu32(E1, MSG3);
        E0 = ABCD;
        MSG0 = _mm_sha1msg2_epu32(MSG0, MSG3);
        ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 3);
        MSG2 = _mm_sha1msg1_epu32(MSG2, MSG3);
        MSG1 = _mm_xor_si128(MSG1, MSG3);

        /* Rounds 64-67 */
        E0 = _mm_sha1nexte_epu32(E0, MSG0);
        E1 = ABCD;
        MSG1 = _mm_sha1msg2_epu32(MSG1, MSG0);
        ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 3);
        MSG3 = _mm_sha1msg1_epu32(MSG3, MSG0);
        MSG2 = _mm_xor_si128(MSG2, MSG0);

        /* Rounds 68-71 */
        E1 = _mm_sha1nexte_epu32(E1, MSG1);
        E0 = ABCD;
        MSG2 = _mm_sha1msg2_epu32(MSG2, MSG1);
        ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 3);
        MSG3 = _mm_xor_si128(MSG3, MSG1);

        /* Rounds 72-75 */
        E0 = _mm_sha1nexte_epu32(E0, MSG2);
        E1 = ABCD;
        MSG3 = _mm_sha1msg2_epu32(MSG3, MSG2);
        ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 3);

        /* Rounds 76-79 */
        E1 = _mm_sha1nexte_epu32(E1, MSG3);
        E0 = ABCD;
        ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 3);

        /* Combine state */
        E0 = _mm_sha1nexte_epu32(E0, E0_SAVE);
        ABCD = _mm_add_epi32(ABCD, ABCD_SAVE);

        data += 64;
        length -= 64;
    }
    
    /* Save state */
    ABCD = _mm_shuffle_epi32(ABCD, 0x1B);
    _mm_storeu_si128((__m128i*) state, ABCD);
    state[4] = _mm_extract_epi32(E0, 3);
}

static char encoding_table[] = {
  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
  'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
  'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
  'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
  'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
  'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
  'w', 'x', 'y', 'z', '0', '1', '2', '3',
  '4', '5', '6', '7', '8', '9', '+', '/'
};
static int mod_table[] = {0, 2, 1};


void shacalc(const char* src, char* dest)
{
    uint32_t input_length = sizeof(src);
    uint32_t state[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
    sha1_process_x86(state, (const unsigned char *)src, input_length);
    
    //TODO Perfomance des Todes
    char *dd = (char *)malloc(20);
    /*
    int k = 0;
    for (int i = 0; i < 5; i++) {
        for (int j = 24; j >= 0; j -= 8)
        {
            printf("%u, %u, %u\n", i, j ,k);
            sprintf(dd + k, "%02x", (state[i] >> j) & 0xFF);
            k++;
        }
    }
     */
  
        dd[0] = (state[0] >> 24) & 0xFF;
        dd[1] = (state[0] >> 16) & 0xFF;
        dd[2] = (state[0] >> 8) & 0xFF;
        dd[3] = (state[0] >> 0) & 0xFF;
     
        dd[4] = (state[1] >> 24) & 0xFF;
        dd[5] = (state[1] >> 16) & 0xFF;
        dd[6] = (state[1] >> 8) & 0xFF;
        dd[7] = (state[1] >> 0) & 0xFF;
        
        dd[8] = (state[2] >> 24) & 0xFF;
        dd[9] = (state[2] >> 16) & 0xFF;
        dd[10] = (state[2] >> 8) & 0xFF;
        dd[11] = (state[2] >> 0) & 0xFF;
        
        dd[12] = (state[3] >> 24) & 0xFF;
        dd[13] = (state[3] >> 16) & 0xFF;
        dd[14] = (state[3] >> 8) & 0xFF;
        dd[15] = (state[3] >> 0) & 0xFF;
        
        dd[16] = (state[4] >> 24) & 0xFF;
        dd[17] = (state[4] >> 16) & 0xFF;
        dd[18] = (state[4] >> 8) & 0xFF;
        dd[19] = (state[4] >> 0) & 0xFF;
        
        //dd[20] = "\n";
   
    //BASE64
    input_length = 20;
    int i = 0;
    int j = 0;
    for (i = 0, j = 0; i < input_length;) {
        uint32_t octet_a = i < input_length ? dd[i++] : 0;
        uint32_t octet_b = i < input_length ? dd[i++] : 0;
        uint32_t octet_c = i < input_length ? dd[i++] : 0;
        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;
        dest[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
        dest[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
        dest[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
        dest[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
    }
    
    for (i = 0; i < mod_table[20 % 3]; i++) {
        dest[28 - 1 - i] = '=';
    }
        printf("HASH: %s\n", dest);
}

#if defined(TEST_MAIN)

#include <stdio.h>
#include <string.h>
int main(int argc, char* argv[])
{
    /* empty message with padding */
    uint8_t message[64];
    memset(message, 0x00, sizeof(message));
    message[0] = 0x80;

    /* intial state */
    uint32_t state[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};

    sha1_process_x86(state, message, sizeof(message));

    /* DA39A3EE5E6B4B0D... */
    printf("SHA1 hash of empty message: ");
    printf("%02X%02X%02X%02X%02X%02X%02X%02X...\n",
        (state[0] >> 24) & 0xFF, (state[0] >> 16) & 0xFF, (state[0] >> 8) & 0xFF, (state[0] >> 0) & 0xFF,
        (state[1] >> 24) & 0xFF, (state[1] >> 16) & 0xFF, (state[1] >> 8) & 0xFF, (state[1] >> 0) & 0xFF);

    int success = (((state[0] >> 24) & 0xFF) == 0xDA) && (((state[0] >> 16) & 0xFF) == 0x39) &&
        (((state[0] >> 8) & 0xFF) == 0xA3) && (((state[0] >> 0) & 0xFF) == 0xEE);

    if (success)
        printf("Success!\n");
    else
        printf("Failure!\n");

    return (success != 0 ? 0 : 1);
}

#endif

#else
static char encoding_table[] = {
  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
  'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
  'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
  'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
  'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
  'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
  'w', 'x', 'y', 'z', '0', '1', '2', '3',
  '4', '5', '6', '7', '8', '9', '+', '/'
};
static int mod_table[] = {0, 2, 1};

const unsigned int rol(const unsigned int value, const unsigned int steps)
{
  return ((value << steps) | (value >> (32 - steps)));
}

void clearWBuffert(unsigned int* buffert)
{
  int pos = 0;
  for (pos = 16; --pos >= 0;)
  {
    buffert[pos] = 0;
  }
}

void innerHash(unsigned int* result, unsigned int* w)
{
  unsigned int a = result[0];
  unsigned int b = result[1];
  unsigned int c = result[2];
  unsigned int d = result[3];
  unsigned int e = result[4];
  int round = 0;
#define sha1macro(func,val) \
{ \
const unsigned int t = rol(a, 5) + (func) + e + val + w[round]; \
e = d; \
d = c; \
c = rol(b, 30); \
b = a; \
a = t; \
}
  while (round < 16)
  {
    sha1macro((b & c) | (~b & d), 0x5a827999)
    ++round;
  }
  while (round < 20)
  {
    w[round] = rol((w[round - 3] ^ w[round - 8] ^ w[round - 14] ^ w[round - 16]), 1);
    sha1macro((b & c) | (~b & d), 0x5a827999)
    ++round;
  }
  while (round < 40)
  {
    w[round] = rol((w[round - 3] ^ w[round - 8] ^ w[round - 14] ^ w[round - 16]), 1);
    sha1macro(b ^ c ^ d, 0x6ed9eba1)
    ++round;
  }
  while (round < 60)
  {
    w[round] = rol((w[round - 3] ^ w[round - 8] ^ w[round - 14] ^ w[round - 16]), 1);
    sha1macro((b & c) | (b & d) | (c & d), 0x8f1bbcdc)
    ++round;
  }
  while (round < 80)
  {
    w[round] = rol((w[round - 3] ^ w[round - 8] ^ w[round - 14] ^ w[round - 16]), 1);
    sha1macro(b ^ c ^ d, 0xca62c1d6)
    ++round;
  }
#undef sha1macro
  result[0] += a;
  result[1] += b;
  result[2] += c;
  result[3] += d;
  result[4] += e;
}

void shacalc(const char* src, char* dest)
{
  unsigned char hash[20];
  int bytelength = (int)strlen(src);
  unsigned int result[5] = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0 };
  const unsigned char* sarray = (const unsigned char*) src;
  unsigned int w[80];
  const int endOfFullBlocks = bytelength - 64;
  int endCurrentBlock;
  int currentBlock = 0;
  while (currentBlock <= endOfFullBlocks)
  {
    endCurrentBlock = currentBlock + 64;
    int roundPos = 0;
    for (roundPos = 0; currentBlock < endCurrentBlock; currentBlock += 4)
    {
      w[roundPos++] = (unsigned int) sarray[currentBlock + 3]
        | (((unsigned int) sarray[currentBlock + 2]) << 8)
        | (((unsigned int) sarray[currentBlock + 1]) << 16)
        | (((unsigned int) sarray[currentBlock]) << 24);
    }
    innerHash(result, w);
  }
  endCurrentBlock = bytelength - currentBlock;
  clearWBuffert(w);
  int lastBlockBytes = 0;
  for (;lastBlockBytes < endCurrentBlock; ++lastBlockBytes)
  {
    w[lastBlockBytes >> 2] |= (unsigned int) sarray[lastBlockBytes + currentBlock] << ((3 - (lastBlockBytes & 3)) << 3);
  }
  w[lastBlockBytes >> 2] |= 0x80 << ((3 - (lastBlockBytes & 3)) << 3);
  if (endCurrentBlock >= 56)
  {
    innerHash(result, w);
    clearWBuffert(w);
  }
  w[15] = bytelength << 3;
  innerHash(result, w);
  int hashByte = 0;
  for (hashByte = 20; --hashByte >= 0;)
  {
    hash[hashByte] = (result[hashByte >> 2] >> (((3 - hashByte) & 0x3) << 3)) & 0xff;
  }
  int i = 0;
  int j = 0;
  for (i = 0, j = 0; i < 20;) {
    uint32_t octet_a = i < 20 ? hash[i++] : 0;
    uint32_t octet_b = i < 20 ? hash[i++] : 0;
    uint32_t octet_c = i < 20 ? hash[i++] : 0;
    uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;
    dest[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
    dest[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
    dest[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
    dest[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
  }
  for (i = 0; i < mod_table[20 % 3]; i++) {
    dest[28 - 1 - i] = '=';
  }
}
#endif

unsigned char *base64_encode(const unsigned char *data, size_t input_length, size_t *output_length) {
  *output_length = (size_t) (4.0 * ceil((double) input_length / 3.0));
  unsigned char *encoded_data = malloc(*output_length);
  if (!encoded_data) return 0;
  int i = 0;
  int j = 0;
  for (i = 0, j = 0; i < input_length;) {
    uint32_t octet_a = i < input_length ? data[i++] : 0;
    uint32_t octet_b = i < input_length ? data[i++] : 0;
    uint32_t octet_c = i < input_length ? data[i++] : 0;
    uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;
    encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
    encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
    encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
    encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
  }
  for (i = 0; i < mod_table[input_length % 3]; i++) {
    encoded_data[*output_length - 1 - i] = '=';
  }
  return encoded_data;
}