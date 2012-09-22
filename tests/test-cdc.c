/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <limits.h>

#include "cdc/cdc.h"

char *dest_dir = NULL;

static void rawdata_to_hex (const unsigned char *rawdata, 
                            char *hex_str, int n_bytes)
{
    static const char hex[] = "0123456789abcdef";
    int i;

    for (i = 0; i < n_bytes; i++) {
        unsigned int val = *rawdata++;
        *hex_str++ = hex[val >> 4];
        *hex_str++ = hex[val & 0xf];
    }
    *hex_str = '\0';
}

int test_chunks (CDCFileDescriptor *file_descriptor)
{
    struct stat sb;
    char chksum_str[CHECKSUM_LENGTH *2 + 1];
    char filename[NAME_MAX_SZ];
    uint8_t *ptr = file_descriptor->blk_sha1s;
    int i = 0;

    int max_sz = -1, min_sz = INT_MAX, total_sz = 0;

    printf ("%d chunks.\n", file_descriptor->block_nr);

    while (i < file_descriptor->block_nr) {
        rawdata_to_hex (ptr, chksum_str, CHECKSUM_LENGTH);
        snprintf (filename, NAME_MAX_SZ, "%s/%s", dest_dir, chksum_str);
        if (g_stat (filename, &sb) < 0) {
            perror ("stat");
            return -1;
        }

        if (sb.st_size < min_sz)
            min_sz = sb.st_size;
        if (sb.st_size > max_sz)
            max_sz = sb.st_size;
        total_sz += sb.st_size;

        if (sb.st_size > file_descriptor->block_max_sz) {
            fprintf (stderr, "chunk size too large: %s.\n", chksum_str);
            return -1;
        }
        if (sb.st_size < file_descriptor->block_min_sz &&
            i != file_descriptor->block_nr - 1) {
            fprintf (stderr, "chunk size too small: %s.\n", chksum_str);
            return -1;
        }

        ptr += CHECKSUM_LENGTH;
        ++i;
    }

    printf ("max size: %d\n", max_sz);
    printf ("min size: %d\n", min_sz);
    printf ("avg size: %d\n", total_sz/file_descriptor->block_nr);

    return 0;
}

int test_write_chunk (CDCDescriptor *chunk_descr,
                      struct SeafileCrypt *crypt,
                      uint8_t *checksum,
                      gboolean write_data)
{
    char filename[NAME_MAX_SZ];
    char chksum_str[CHECKSUM_LENGTH *2 + 1];
    int fd_chunk, ret;

    rawdata_to_hex (chunk_descr->checksum, chksum_str, CHECKSUM_LENGTH);
    snprintf (filename, NAME_MAX_SZ, "%s/%s", dest_dir, chksum_str);
    fd_chunk = g_open (filename, O_WRONLY | O_CREAT | O_BINARY, 0644);
    if (fd_chunk < 0)
        return -1;    
    
    ret = write (fd_chunk, chunk_descr->block_buf, chunk_descr->len);
    return ret;
}

int main (int argc, char *argv[])
{
    char *src_filename = NULL;
    int ret = 0, fd_src;
    CDCFileDescriptor file_descr;

    if (argc < 3) {
        fprintf(stderr, "%s SOURCE DEST \n", argv[0]);
        exit(0);
    } else {
        src_filename = argv[1];
        dest_dir = argv[2];
    }
    
    memset (&file_descr, 0, sizeof (file_descr));
    file_descr.write_block = test_write_chunk;
    ret = filename_chunk_cdc (src_filename, &file_descr, NULL, TRUE);
    if (ret == -1) {
        fprintf(stderr, "file chunk failed\n");
        exit(1);
    }

    ret = test_chunks (&file_descr);
    if (ret < 0) {
        fprintf (stderr, "chunk test failed.\n");
        exit(1);
    }

    printf ("test passed.\n");
    return 0;
}
