/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef __BLOOM_H__
#define __BLOOM_H__

#include <stdlib.h>

typedef struct {
    size_t          asize;
    unsigned char  *a;
    size_t          csize;
    unsigned char  *counters;
    int             k;
    char            counting:1;
} Bloom;

Bloom *bloom_create (size_t size, int k, int counting);
int bloom_destroy (Bloom *bloom);
int bloom_add (Bloom *bloom, const char *s);
int bloom_remove (Bloom *bloom, const char *s);
int bloom_test (Bloom *bloom, const char *s);

#endif
