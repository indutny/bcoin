#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

static const char *CHARSET =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

static const int TABLE[128] = {
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1,  0,  1,  2,  3,  4,  5,  6,  7,  8, -1, -1, -1, -1, -1, -1,
  -1,  9, 10, 11, 12, 13, 14, 15, 16, -1, 17, 18, 19, 20, 21, -1,
  22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, -1, -1, -1, -1, -1,
  -1, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, -1, 44, 45, 46,
  47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, -1, -1, -1, -1, -1
};

int
bcrypto_base58_encode(char **str, size_t *strlen,
                      const uint8_t *data, size_t datalen) {
  if (datalen > 1073741823ul) /* 2^30 - 1 */
    return 0;

  if (datalen == 0) {
    *str = NULL;
    *strlen = 0;
    return 1;
  }

  size_t zeroes = 0;
  size_t i;

  for (i = 0; i < datalen; i++) {
    if (data[i] != 0)
      break;

    zeroes += 1;
  }

  uint64_t b58size = (uint64_t)datalen * 138 / 100 + 1;
  size_t b58len = (size_t)b58size; /* 31 bit max */
  uint8_t *b58 = (uint8_t *)malloc(b58len);
  size_t length = 0;

  if (b58 == NULL)
    return 0;

  memset(b58, 0, b58len);

  for (; i < datalen; i++) {
    int carry = data[i];
    size_t j = 0;
    long k;

    for (k = (long)b58len - 1; k >= 0; k--, j++) {
      if (carry == 0 && j >= length)
        break;

      carry += 256 * b58[k];
      b58[k] = carry % 58;
      carry = carry / 58;
    }

    assert(carry == 0);

    length = j;
  }

  i = b58len - length;

  while (i < b58len && b58[i] == 0)
    i += 1;

  *str = (char *)malloc(zeroes + (b58len - i) + 1);

  if (*str == NULL) {
    free(b58);
    return 0;
  }

  size_t j;

  for (j = 0; j < zeroes; j++)
    (*str)[j] = '1';

  for (; i < b58len; i++)
    (*str)[j++] = CHARSET[b58[i]];

  (*str)[j] = '\0';
  *strlen = j;

  free(b58);

  return 1;
}

int
bcrypto_base58_decode(uint8_t **data, size_t *datalen,
                      const char *str, size_t strlen) {
  if (strlen > 1481763716ul) /* (2^30 - 1) * 138 / 100 + 1 */
    return 0;

  if (strlen == 0) {
    *data = NULL;
    *datalen = 0;
    return 1;
  }

  size_t zeroes = 0;
  size_t i;

  for (i = 0; i < strlen; i++) {
    if (str[i] != '1')
      break;

    zeroes += 1;
  }

  uint64_t b256size = (uint64_t)strlen * 733 / 1000 + 1;
  size_t b256len = (size_t)b256size;
  uint8_t *b256 = (uint8_t *)malloc(b256len);
  size_t length = 0;

  if (b256 == NULL)
    return 0;

  memset(b256, 0, b256len);

  for (; i < strlen; i++) {
    uint8_t ch = (uint8_t)str[i];
    int v = (ch & 0x80) ? -1 : TABLE[ch];

    if (v == -1) {
      free(b256);
      return 0;
    }

    int carry = v;
    size_t j = 0;
    long k;

    for (k = (long)b256len - 1; k >= 0; k--, j++) {
      if (carry == 0 && j >= length)
        break;

      carry += 58 * b256[k];
      b256[k] = carry % 256;
      carry = carry / 256;
    }

    assert(carry == 0);

    length = j;
  }

  i = 0;

  while (i < b256len && b256[i] == 0)
    i += 1;

  *data = (uint8_t *)malloc(zeroes + (b256len - i));

  if (*data == NULL) {
    free(b256);
    return 0;
  }

  size_t j;

  for (j = 0; j < zeroes; j++)
    (*data)[j] = 0;

  while (i < b256len)
    (*data)[j++] = b256[i++];

  *datalen = j;

  free(b256);

  return 1;
}

int
bcrypto_base58_test(const char *str, size_t strlen) {
  size_t i = 0;

  for (; i < strlen; i++) {
    uint8_t ch = (uint8_t)str[i];

    if (ch & 0x80)
      return 0;

    if (TABLE[ch] == -1)
      return 0;
  }

  return 1;
}
