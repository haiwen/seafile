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
#ifdef _LPCOX_DEBUG_
    printf ("polymod (nh %llu nl %llu d %llu)\n", nh, nl, d);
#endif
    int k = fls64 (d) - 1;
#ifdef _LPCOX_DEBUG_
    printf ("polymod : k = %d\n", k);
#endif
    d <<= 63 - k;
#ifdef _LPCOX_DEBUG_
    printf ("polymod : d = %llu\n", d);
    printf ("polymod : MSB64 = %llu\n", MSB64);
#endif

    if (nh) {
        if (nh & MSB64)
            nh ^= d;
#ifdef _LPCOX_DEBUG_
        printf ("polymod : nh = %llu\n", nh);
#endif
        for (i = 62; i >= 0; i--)
            if (nh & ((u_int64_t) 1) << i) {
                nh ^= d >> (63 - i);
                nl ^= d << (i + 1);
#ifdef _LPCOX_DEBUG_
                printf ("polymod : i = %d\n", i);
                printf ("polymod : shift1 = %llu\n", (d >> (63 - i)));
                printf ("polymod : shift2 = %llu\n", (d << (i + 1)));
                printf ("polymod : nh = %llu\n", nh);
                printf ("polymod : nl = %llu\n", nl);
#endif
            }
    }
    for (i = 63; i >= k; i--)
    {  
        if (nl & INT64 (1) << i)
            nl ^= d >> (63 - i);
#ifdef _LPCOX_DEBUG_
        printf ("polymod : nl = %llu\n", nl);
#endif
    }
  
#ifdef _LPCOX_DEBUG_
    printf ("polymod : returning %llu\n", nl);
#endif
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
#ifdef _LPCOX_DEBUG_
    printf ("polymult (x %llu y %llu)\n", x, y);
#endif
    u_int64_t ph = 0, pl = 0;
    if (x & 1)
        pl = y;
    for (i = 1; i < 64; i++)
        if (x & (INT64 (1) << i)) {
#ifdef _LPCOX_DEBUG_
            printf ("polymult : i = %d\n", i);
            printf ("polymult : ph = %llu\n", ph);
            printf ("polymult : pl = %llu\n", pl);
            printf ("polymult : y = %llu\n", y);
            printf ("polymult : ph ^ y >> (64-i) = %llu\n", (ph ^ y >> (64-i)));
            printf ("polymult : pl ^ y << i = %llu\n", (pl ^ y << i));
#endif
            ph ^= y >> (64 - i);
            pl ^= y << i;
#ifdef _LPCOX_DEBUG_
            printf ("polymult : ph %llu pl %llu\n", ph, pl);
#endif
        }
    if (php)
        *php = ph;
    if (plp)
        *plp = pl;
#ifdef _LPCOX_DEBUG_
    printf ("polymult : h %llu l %llu\n", ph, pl);
#endif
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
