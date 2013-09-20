/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <limits.h>
#include <stdint.h>
#include <string.h>
#include <openssl/sha.h>
#include <assert.h>

#include "bloom-filter.h"

#define SETBIT(a, n) (a[n/CHAR_BIT] |= (1<<(n%CHAR_BIT)))
#define CLEARBIT(a, n) (a[n/CHAR_BIT] &= ~(1<<(n%CHAR_BIT)))
#define GETBIT(a, n) (a[n/CHAR_BIT] & (1<<(n%CHAR_BIT)))

Bloom* bloom_create(size_t size, int k, int counting)
{
    Bloom *bloom;
    size_t csize = 0;

    if (k <=0 || k > 4) return NULL;
    
    if ( !(bloom = malloc(sizeof(Bloom))) ) return NULL;
    if ( !(bloom->a = calloc((size+CHAR_BIT-1)/CHAR_BIT, sizeof(char))) )
    {
        free (bloom);
        return NULL;
    }
    if (counting) {
        csize = size*4;
        bloom->counters = calloc((csize+CHAR_BIT-1)/CHAR_BIT, sizeof(char));
        if (!bloom->counters) {
            free (bloom);
            return NULL;
        }
    }

    bloom->asize = size;
    bloom->csize = csize;
    bloom->k = k;
    bloom->counting = counting;

    return bloom;
}

int bloom_destroy(Bloom *bloom)
{
    free (bloom->a);
    if (bloom->counting) free (bloom->counters);
    free (bloom);

    return 0;
}

static void
incr_bit (Bloom *bf, unsigned int bit_idx)
{
    unsigned int char_idx, offset;
    unsigned char value;
    unsigned int high;
    unsigned int low;

    SETBIT (bf->a, bit_idx);

    if (!bf->counting) return;

    char_idx = bit_idx / 2;
    offset = bit_idx % 2;

    value = bf->counters[char_idx];
    low = value & 0xF;
    high = (value & 0xF0) >> 4;

    if (offset == 0) {
        if (low < 0xF)
            low++;
    } else {
        if (high < 0xF)
            high++;
    }
    value = ((high << 4) | low);

    bf->counters[char_idx] = value;
}

static void
decr_bit (Bloom *bf, unsigned int bit_idx)
{
    unsigned int char_idx, offset;
    unsigned char value;
    unsigned int high;
    unsigned int low;

    if (!bf->counting) {
        CLEARBIT (bf->a, bit_idx);
        return;
    }

    char_idx = bit_idx / 2;
    offset = bit_idx % 2;

    value = bf->counters[char_idx];
    low = value & 0xF;
    high = (value & 0xF0) >> 4;

    /* decrement, but once we have reached the max, never go back! */
    if (offset == 0) {
        if ((low > 0) && (low < 0xF))
            low--;
        if (low == 0) {
            CLEARBIT (bf->a, bit_idx);
        }
    } else {
        if ((high > 0) && (high < 0xF))
            high--;
        if (high == 0) {
            CLEARBIT (bf->a, bit_idx);
        }
    }
    value = ((high << 4) | low);

    bf->counters[char_idx] = value;
}

int bloom_add(Bloom *bloom, const char *s)
{
    int i;
    SHA256_CTX c;
    unsigned char sha256[SHA256_DIGEST_LENGTH];
    size_t *sha_int = (size_t *)&sha256;
    
    SHA256_Init(&c);
    SHA256_Update(&c, s, strlen(s));
    SHA256_Final (sha256, &c);
    
    for (i=0; i < bloom->k; ++i)
        incr_bit (bloom, sha_int[i] % bloom->asize);

    return 0;
}

int bloom_remove(Bloom *bloom, const char *s)
{
    int i;
    SHA256_CTX c;
    unsigned char sha256[SHA256_DIGEST_LENGTH];
    size_t *sha_int = (size_t *)&sha256;
    
    if (!bloom->counting)
        return -1;

    SHA256_Init(&c);
    SHA256_Update(&c, s, strlen(s));
    SHA256_Final (sha256, &c);
    
    for (i=0; i < bloom->k; ++i)
        decr_bit (bloom, sha_int[i] % bloom->asize);

    return 0;
}

int bloom_test(Bloom *bloom, const char *s)
{
    int i;
    SHA256_CTX c;
    unsigned char sha256[SHA256_DIGEST_LENGTH];
    size_t *sha_int = (size_t *)&sha256;
    
    SHA256_Init(&c);
    SHA256_Update(&c, s, strlen(s));
    SHA256_Final (sha256, &c);
    
    for (i=0; i < bloom->k; ++i)
        if(!(GETBIT(bloom->a, sha_int[i] % bloom->asize))) return 0;

    return 1;
}
