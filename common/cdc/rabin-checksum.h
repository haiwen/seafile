#ifndef _RABIN_CHECKSUM_H
#define _RABIN_CHECKSUM_H

unsigned int rabin_checksum(char *buf, int len);

unsigned int rabin_rolling_checksum(unsigned int csum, int len, char c1, char c2);

void rabin_init (int len);

#endif
