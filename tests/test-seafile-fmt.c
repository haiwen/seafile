/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <openssl/sha.h>

#include "utils.h"

/* SHA1 calculate */
void
sha1( uint8_t *    setme,
      const void * content,
      int          content_len)
{
    SHA_CTX sha;

    SHA1_Init (&sha);
    SHA1_Update (&sha, content, content_len);
    SHA1_Final (setme, &sha);
}

int main (int argc, char **argv)
{
    char *seafile_path, *file_path;
    uint64_t file_size, block_size;
    uint32_t n_blocks;
    int fd;
    FILE *fp;

    if (argc != 3) {
        printf ("seafile-fmt-test seafile original-file\n");
        exit (1);
    }

    seafile_path = argv[1];
    file_path = argv[2];

    fd = g_open (seafile_path, O_RDONLY | O_BINARY);
    if (fd < 0) {
        printf ("Failed to open seafile.\n");
        exit (1);
    }

    fp = fopen (file_path, "rb");
    if (!fp) {
        printf ("Failed to open original file.\n");
        exit (1);
    }

    if (readn (fd, &file_size, sizeof(file_size)) < 0) {
        printf ("Failed to read file size.\n");
        exit (1);
    }

    if (readn (fd, &block_size, sizeof(block_size)) < 0) {
        printf ("Failed to read block_size.\n");
        exit (1);
    }

    n_blocks = (uint32_t) ((file_size + block_size -1) / block_size);

    printf ("file size is %lld, block size is %lld, %d blocks.\n",
            (long long int)file_size, (long long int)block_size, n_blocks);

    uint8_t *blocks = (uint8_t *) malloc (n_blocks * 20);
    if (readn (fd, blocks, n_blocks * 20) < n_blocks * 20) {
        printf ("Failed to read blocks.\n");
        exit (1);
    }

    int i;
    char *block = valloc (block_size);
    uint8_t sha1_buf[20];
    for (i = 0; i < n_blocks; ++i) {
        int n = fread (block, 1, block_size, fp);
        if (n <= 0) {
            printf ("Failed to read original file\n");
            exit (1);
        }

        sha1 (sha1_buf, block, n);

        if (memcmp (sha1_buf, blocks, 20) != 0) {
            printf ("Error in blocks sha1\n");
            exit (1);
        }

        blocks += 20;
    }

    printf ("Check OK\n");
    return 0;
}
