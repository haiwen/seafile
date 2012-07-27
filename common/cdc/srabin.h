#ifndef _SRABIN_H
#define _SRABIN_H

#ifdef __cplusplus
extern "C" {
#endif

unsigned int srabin_checksum(char *buf, int len);

unsigned int srabin_rolling_checksum(unsigned int csum, int len, char c1, char c2);

#ifdef __cplusplus
}
#endif

#endif
