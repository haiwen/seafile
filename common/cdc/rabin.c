// $Id$

/*
 *
 * Copyright (C) 1998 David Mazieres (dm@uun.org)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2, or (at
 * your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA
 *
 */

#include <sys/types.h>
#include "rabin.h"
#include "msb.h"

#define INT64(n) n##LL
#define MSB64 INT64(0x8000000000000000)

static u_int64_t poly = 0xbfe6b8a5bf378d83LL;
static u_int64_t T[256];
static u_int64_t U[256];
static int shift;

u_int64_t polymod (u_int64_t nh, u_int64_t nl, u_int64_t d)
{
    int i = 0;
    int k = fls64 (d) - 1;

    d <<= 63 - k;

    if (nh) {
        if (nh & MSB64)
            nh ^= d;
        for (i = 62; i >= 0; i--)
            if (nh & ((u_int64_t) 1) << i) {
                nh ^= d >> (63 - i);
                nl ^= d << (i + 1);
            }
    }
    for (i = 63; i >= k; i--)
    {  
        if (nl & INT64 (1) << i)
            nl ^= d >> (63 - i);
    }
  
    return nl;
}

u_int64_t polygcd (u_int64_t x, u_int64_t y)
{
    for (;;) {
        if (!y)
            return x;
        x = polymod (0, x, y);
        if (!x)
            return y;
        y = polymod (0, y, x);
    }
}

void polymult (u_int64_t *php, u_int64_t *plp, u_int64_t x, u_int64_t y)
{
    int i;
    u_int64_t ph = 0, pl = 0;
    if (x & 1)
        pl = y;
    for (i = 1; i < 64; i++)
        if (x & (INT64 (1) << i)) {
            ph ^= y >> (64 - i);
            pl ^= y << i;
        }
    if (php)
        *php = ph;
    if (plp)
        *plp = pl;
}

u_int64_t polymmult (u_int64_t x, u_int64_t y, u_int64_t d)
{
    u_int64_t h, l;
    polymult (&h, &l, x, y);
    return polymod (h, l, d);
}

int polyirreducible(u_int64_t f)
{
    u_int64_t u = 2;
    int i;
    int m = (fls64 (f) - 1) >> 1;
    for (i = 0; i < m; i++) {
        u = polymmult (u, u, f);
        if (polygcd (f, u ^ 2) != 1)
            return 0;
    }
    return 1;
}

/*
 * rabin_checksum(X0, ..., Xn), X0, Xn+1 ----> rabin_checksum(X1, ..., Xn+1)
 * where csum is rabin_checksum(X0, ..., Xn), c1 is X0, c2 is Xn+1
 */
static u_int64_t append8 (u_int64_t p, u_char m)
{
    return ((p << 8) | m) ^ T[p >> shift];
}

static void calcT (u_int64_t poly)
{
    int j = 0;
//  assert (poly >= 0x100);
    int xshift = fls64 (poly) - 1;
    shift = xshift - 8;
    u_int64_t T1 = polymod (0, INT64 (1) << xshift, poly);
    for (j = 0; j < 256; j++) {
        T[j] = polymmult (j, T1, poly) | ((u_int64_t) j << xshift);
    }
}

static void calcU(int size)
{
    int i;
    u_int64_t sizeshift = 1;
    for (i = 1; i < size; i++)
        sizeshift = append8 (sizeshift, 0);
    for (i = 0; i < 256; i++)
        U[i] = polymmult (i, sizeshift, poly);
}

void rabin_init(int len)
{
    calcT(poly);
    calcU(len);
}

/*
 *   a simple 32 bit checksum that can be upadted from end
 */
unsigned int rabin_checksum(char *buf, int len)
{
    int i;
    unsigned int sum = 0;
    for (i = 0; i < len; ++i) {
        sum = rabin_rolling_checksum (sum, len, 0, buf[i]);
    }
    return sum;
}

unsigned int rabin_rolling_checksum(unsigned int csum, int len,
                                    char c1, char c2)
{
    return append8(csum ^ U[(unsigned char)c1], c2);
}
