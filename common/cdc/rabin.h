#ifndef _RABIN_H
#define _RABIN_H

#ifdef __cplusplus
extern "C" {
#endif

unsigned int rabin_checksum(char *buf, int len);

unsigned int rabin_rolling_checksum(unsigned int csum, int len, char c1, char c2);

void rabin_init (int len);

#ifdef __cplusplus
}
#endif

#endif
