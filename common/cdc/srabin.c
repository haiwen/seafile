#include "srabin.h"

#define BIG_NUMBER 0x3e6b8a5
#define T 2
#define MULT_T(a) ((a) << 1)
#define WINDOW_MAX_SIZE 48


static int T_MOD_P[WINDOW_MAX_SIZE] = { 1 };

static void __init()
{
    int i = 0;
    T_MOD_P[0] = T;
    for (i = 1; i < WINDOW_MAX_SIZE; ++i) {
        T_MOD_P[i] = MULT_T(T_MOD_P[i-1]) % BIG_NUMBER;
    }
}

/*
 *   a simple 32 bit checksum that can be upadted from end
 */
unsigned int srabin_checksum(char *buf, int len)
{
    int i;
    static int first = 0;
    if (first == 0) {
        first = 1;
        __init();
    }
    unsigned int sum = buf[0];
    for (i = 1; i < len; ++i) {
        sum = MULT_T(sum) + buf[i];
        if (sum > BIG_NUMBER)
            sum = sum % BIG_NUMBER;
    }
    return sum % BIG_NUMBER;
}

/*
 * rabin_checksum(X0, ..., Xn), X0, Xn+1 ----> rabin_checksum(X1, ..., Xn+1)
 * where csum is rabin_checksum(X0, ..., Xn), c1 is X0, c2 is Xn+1
 */
unsigned int srabin_rolling_checksum(unsigned int csum, int len, char c1, char c2)
{
    unsigned int sum = MULT_T(csum)  + c2 - (c1 * T_MOD_P[len - 1]);
    return sum % BIG_NUMBER;
}
