#ifndef _ADLER32_H
#define _ADLER32_H

#ifdef __cplusplus
extern "C" {
#endif

unsigned int adler32_checksum(char *buf, int len);

unsigned int adler32_rolling_checksum(unsigned int csum, int len, char c1, char c2);

#ifdef __cplusplus
}
#endif

#endif
