/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <glib/gstdio.h>

#include "cdc.h"
#include "../seafile-crypt.h"

#ifdef HAVE_ADLER
#include "adler32.h"
#define finger adler32_checksum
#define rolling_finger adler32_rolling_checksum 

#else
#ifdef HAVE_SRABIN
#include "srabin.h"
#define finger srabin_checksum
#define rolling_finger srabin_rolling_checksum

#else
#include "rabin.h"
#define finger rabin_checksum
#define rolling_finger rabin_rolling_checksum

#endif
#endif //HAVE_ADLER

#define READ_SIZE 1024 * 4

#define BYTE_TO_HEX(b)  (((b)>=10)?('a'+b-10):('0'+b))

/* static void sha1 (const void *data, int len, uint8_t *sha1) */
/* { */
/*     SHA_CTX ctx; */

/*     SHA1_Init (&ctx); */
/*     SHA1_Update (&ctx, data, len); */
/*     SHA1_Final (sha1, &ctx); */
/* } */

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

/* Read "n" bytes from a descriptor. */
static ssize_t
readn(int fd, void *vptr, size_t n)
{
	size_t	nleft;
	ssize_t	nread;
	char	*ptr;

	ptr = vptr;
	nleft = n;
	while (nleft > 0) {
		if ( (nread = read(fd, ptr, nleft)) < 0) {
			if (errno == EINTR)
				nread = 0;		/* and call read() again */
			else
				return(-1);
		} else if (nread == 0)
			break;				/* EOF */

		nleft -= nread;
		ptr   += nread;
	}
	return(n - nleft);		/* return >= 0 */
}

/* Write "n" bytes to a descriptor. */
static ssize_t
writen(int fd, const void *vptr, size_t n)
{
	size_t		nleft;
	ssize_t		nwritten;
	const char	*ptr;

	ptr = vptr;
	nleft = n;
	while (nleft > 0) {
		if ( (nwritten = write(fd, ptr, nleft)) <= 0) {
			if (nwritten < 0 && errno == EINTR)
				nwritten = 0;		/* and call write() again */
			else
				return(-1);			/* error */
		}

		nleft -= nwritten;
		ptr   += nwritten;
	}
	return(n);
}

static int default_write_chunk (CDCDescriptor *chunk_descr)
{
    char filename[NAME_MAX_SZ];
    char chksum_str[CHECKSUM_LENGTH *2 + 1];
    int fd_chunk, ret;

    memset(chksum_str, 0, sizeof(chksum_str));
    rawdata_to_hex (chunk_descr->checksum, chksum_str, CHECKSUM_LENGTH);
    snprintf (filename, NAME_MAX_SZ, "./%s", chksum_str);
    fd_chunk = g_open (filename, O_RDWR | O_CREAT | O_BINARY, 0644);
    if (fd_chunk < 0)
        return -1;    
    
    ret = writen (fd_chunk, chunk_descr->block_buf, chunk_descr->len);
    close (fd_chunk);
    return ret;
}

static int init_cdc_file_descriptor (int fd, CDCFileDescriptor *file_descr)
{
    int max_block_nr = 0;
    int block_min_sz = 0;
    struct stat sb;

    file_descr->block_nr = 0;

    if (file_descr->block_min_sz <= 0)
        file_descr->block_min_sz = BLOCK_MIN_SZ;
    if (file_descr->block_max_sz <= 0)
        file_descr->block_max_sz = BLOCK_MAX_SZ;
    if (file_descr->block_sz <= 0)
        file_descr->block_sz = BLOCK_SZ;

    if (file_descr->write_block == NULL)
        file_descr->write_block = (WriteblockFunc)default_write_chunk;

    if (fstat (fd, &sb) < 0) {
        return -1;
    }

    block_min_sz = file_descr->block_min_sz;
    max_block_nr = ((sb.st_size + block_min_sz - 1) / block_min_sz);
    file_descr->blk_sha1s = (uint8_t *)calloc (sizeof(uint8_t),
                                               max_block_nr * CHECKSUM_LENGTH);

    return 0;
}

#define WRITE_CDC_BLOCK(block_sz, write_data)                \
do {                                                         \
    int _block_sz = (block_sz);                              \
    chunk_descr.len = _block_sz;                             \
    chunk_descr.offset = offset;                             \
    ret = file_descr->write_block (&chunk_descr,             \
            crypt, chunk_descr.checksum,                     \
                                   (write_data));            \
    if (ret < 0) {                                           \
        free (buf);                                          \
        return -1;                                           \
    }                                                        \
    memcpy (file_descr->blk_sha1s +                          \
            file_descr->block_nr * CHECKSUM_LENGTH,          \
            chunk_descr.checksum, CHECKSUM_LENGTH);          \
    SHA1_Update (&file_ctx, chunk_descr.checksum, 20);       \
    file_descr->block_nr++;                                  \
    offset += _block_sz;                                     \
                                                             \
    memmove (buf, buf + _block_sz, tail - _block_sz);        \
    tail = tail - _block_sz;                                 \
    cur = 0;                                                 \
}while(0);

/* content-defined chunking */
int file_chunk_cdc(int fd_src,
                   CDCFileDescriptor *file_descr,
                   SeafileCrypt *crypt,
                   gboolean write_data)
{
    char *buf;
    uint32_t buf_sz;
    SHA_CTX file_ctx;
    CDCDescriptor chunk_descr;
    SHA1_Init (&file_ctx);

    init_cdc_file_descriptor (fd_src, file_descr);
    uint32_t block_min_sz = file_descr->block_min_sz;
    uint32_t block_mask = file_descr->block_sz - 1;

    int fingerprint = 0;
    int offset = 0;
    int ret = 0;
    int tail, cur, rsize;

    buf_sz = file_descr->block_max_sz;
    buf = chunk_descr.block_buf = malloc (buf_sz);
    if (!buf)
        return -1;

    /* buf: a fix-sized buffer.
     * cur: data behind (inclusive) this offset has been scanned.
     *      cur + 1 is the bytes that has been scanned.
     * tail: length of data loaded into memory. buf[tail] is invalid.
     */
    tail = cur = 0;
    while (1) {
        if (cur < block_min_sz) {
            rsize = block_min_sz - cur + READ_SIZE;
        } else {
            rsize = (buf_sz - tail < READ_SIZE) ? (buf_sz - tail) : READ_SIZE;
        }
        ret = readn (fd_src, buf + tail, rsize);
        if (ret < 0) {
            free (buf);
            return -1;
        }
        tail += ret;

        /* We've read all the data in this file. Output the block immediately
         * in two cases:
         * 1. The data left in the file is less than block_min_sz;
         * 2. We cannot find the break value until the end of this file.
         */
        if (tail < block_min_sz || cur >= tail) {
            if (tail > 0)
                WRITE_CDC_BLOCK (tail, write_data);
            break;
        }

        /* 
         * A block is at least of size block_min_sz.
         */
        if (cur < block_min_sz - 1)
            cur = block_min_sz - 1;

        while (cur < tail) {
            fingerprint = (cur == block_min_sz - 1) ?
                finger(buf + cur - BLOCK_WIN_SZ + 1, BLOCK_WIN_SZ) :
                rolling_finger (fingerprint, BLOCK_WIN_SZ, 
                                *(buf+cur-BLOCK_WIN_SZ), *(buf + cur));

            /* get a chunk, write block info to chunk file */
            if (((fingerprint & block_mask) ==  ((BREAK_VALUE & block_mask)))
                || cur + 1 >= file_descr->block_max_sz) {
                WRITE_CDC_BLOCK (cur + 1, write_data);
                break;
            } else {
                cur ++;
            }
        }
    }

    SHA1_Final (file_descr->file_sum, &file_ctx);

    free (buf);

    return 0;
}

int filename_chunk_cdc(const char *filename,
                       CDCFileDescriptor *file_descr,
                       SeafileCrypt *crypt,
                       gboolean write_data)
{
    int fd_src = g_open (filename, O_RDONLY | O_BINARY, 0);
    if (fd_src < 0)
        return -1;

    int ret = file_chunk_cdc (fd_src, file_descr, crypt, write_data);
    close (fd_src);
    return ret;
}
