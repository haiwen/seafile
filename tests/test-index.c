/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "index.h"

/* static void rawdata_to_hex (const unsigned char *rawdata,  */
/*                             char *hex_str, int n_bytes) */
/* { */
/*     static const char hex[] = "0123456789abcdef"; */
/*     int i; */

/*     for (i = 0; i < n_bytes; i++) { */
/*         unsigned int val = *rawdata++; */
/*         *hex_str++ = hex[val >> 4]; */
/*         *hex_str++ = hex[val & 0xf]; */
/*     } */
/*     *hex_str = '\0'; */
/* } */

int main (int argc, char *argv[])
{
    char *index_file;
    struct index_state istate;

    if (argc < 2) {
        fprintf (stderr, "%s index_file\n", argv[0]);
        exit (-1);
    }
    index_file = argv[1];

    memset (&istate, 0, sizeof(istate));
    if (read_index_from (&istate, index_file) < 0) {
        fprintf (stderr, "Corrupt index file %s\n", index_file);
        exit (-1);
    }

    int i;
    struct cache_entry *ce;
    char id[41];
    printf ("Totally %u entries in index.\n", istate.cache_nr);
    for (i = 0; i < istate.cache_nr; ++i) {
        ce = istate.cache[i];
        rawdata_to_hex (ce->sha1, id, 20);
        printf ("%s\t%d\t%s\n", ce->name, ce_stage(ce), id);
    }

    printf ("Index file format OK.\n");
    return 0;
}
