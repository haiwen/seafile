#include "adler32.h"

#define CHAR_OFFSET 0

/*
 *   a simple 32 bit checksum that can be upadted from either end
 *   (inspired by Mark Adler's Adler-32 checksum)
 */
unsigned int adler32_checksum(char *buf, int len)
{
    int i;
    unsigned int s1, s2;

    s1 = s2 = 0;
    for (i = 0; i < (len - 4); i += 4) {
        s2 += 4 * (s1 + buf[i]) + 3 * buf[i+1] + 2 * buf[i+2] + buf[i+3] +
          10 * CHAR_OFFSET;
        s1 += (buf[i+0] + buf[i+1] + buf[i+2] + buf[i+3] + 4 * CHAR_OFFSET);
    }
    for (; i < len; i++) {
        s1 += (buf[i]+CHAR_OFFSET); 
        s2 += s1;
    }

    return (s1 & 0xffff) + (s2 << 16);
}

/*
 * adler32_checksum(X0, ..., Xn), X0, Xn+1 ----> adler32_checksum(X1, ..., Xn+1)
 * where csum is adler32_checksum(X0, ..., Xn), c1 is X0, c2 is Xn+1
 */
unsigned int adler32_rolling_checksum(unsigned int csum, int len, char c1, char c2)
{
    unsigned int s1, s2;

    s1 = csum & 0xffff;
    s2 = csum >> 16;
    s1 -= (c1 - c2);
    s2 -= (len * (c1 + CHAR_OFFSET) - s1);

    return (s1 & 0xffff) | (s2 << 16);
}
