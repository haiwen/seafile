/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef CCNET_UTILS_H
#define CCNET_UTILS_H

#include <sys/time.h>
#include <stdint.h>
#include <unistd.h>
#include <stdarg.h>
#include <glib.h>
#include <glib-object.h>
#include <stdlib.h>
#include <evutil.h>
#include <sys/stat.h>

#ifdef __linux__
#include <endian.h>
#endif

#ifdef WIN32
#include <errno.h>
#include <glib/gstdio.h>

#ifndef WEXITSTATUS
#define WEXITSTATUS(status) (((status) & 0xff00) >> 8)
#endif

/* Borrowed from libevent */
#define ccnet_pipe_t intptr_t

int pgpipe (ccnet_pipe_t handles[2]);
#define ccnet_mkdir(a,b) g_mkdir((a),(b))
#define ccnet_pipe(a) pgpipe((a))
#define piperead(a,b,c) recv((a),(b),(c),0)
#define pipewrite(a,b,c) send((a),(b),(c),0)
#define pipeclose(a) closesocket((a))

static inline int ccnet_rename(const char *oldfile, const char *newfile)
{
    int ret = g_rename (oldfile, newfile);
    if (ret < 0) {
        if (errno != EEXIST) 
            return -1;
        
        ret = g_unlink(oldfile);
        
        if (ret < 0) {
            g_warning("ccnet_rename failed because g_unlink failed\n");
            return -1;
        }
        return g_rename(oldfile, newfile);
    }
    return 0;
}

#define SeafStat struct __stat64
#define seaf_fstat(fd,st) _fstat64(fd,st)

#else

#define ccnet_pipe_t int

#define ccnet_mkdir(a,b) g_mkdir((a),(b))
#define ccnet_pipe(a) pipe((a))
#define piperead(a,b,c) read((a),(b),(c))
#define pipewrite(a,b,c) write((a),(b),(c))
#define pipeclose(a) close((a))
#define ccnet_rename g_rename

#define SeafStat struct stat
#define seaf_fstat(fd,st) fstat(fd,st)

#endif

#define pipereadn(a,b,c) recvn((a),(b),(c))
#define pipewriten(a,b,c) sendn((a),(b),(c))

int seaf_stat (const char *path, SeafStat *st);

#ifndef O_BINARY
#define O_BINARY 0
#endif

/* for debug */
#ifndef ccnet_warning
#define ccnet_warning(fmt, ...) g_warning("%s(%d): " fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#endif

#ifndef ccnet_error
#define ccnet_error(fmt, ...)   g_error("%s(%d): " fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#endif

#ifndef ccnet_message
#define ccnet_message(fmt, ...) g_message("%s(%d): " fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#endif

#define CCNET_DOMAIN g_quark_from_string("ccnet")


struct timeval timeval_from_msec (uint64_t milliseconds);


size_t ccnet_strlcpy (char *dst, const char *src, size_t size);

void rawdata_to_hex (const unsigned char *rawdata, char *hex_str, int n_bytes);
int hex_to_rawdata (const char *hex_str, unsigned char *rawdata, int n_bytes);

#define sha1_to_hex(sha1, hex) rawdata_to_hex((sha1), (hex), 20)
#define hex_to_sha1(hex, sha1) hex_to_rawdata((hex), (sha1), 20)

int calculate_sha1 (unsigned char *sha1, const char *msg);
int ccnet_sha1_equal (const void *v1, const void *v2);
unsigned int ccnet_sha1_hash (const void *v);

char* gen_uuid ();
void gen_uuid_inplace (char *buf);
gboolean is_uuid_valid (const char *uuid_str);


/* dir operations */
int checkdir (const char *dir);
int checkdir_with_mkdir (const char *path);
char* ccnet_expand_path (const char *src);

/**
 * Make directory with 256 sub-directories from '00' to 'ff'.
 * `base` and subdir will be created if they are not existing. 
 */
int objstore_mkdir (const char *base);
void objstore_get_path (char *path, const char *base, const char *obj_id);


char** strsplit_by_space (char *string, int *length);

/* Read "n" bytes from a descriptor. */
ssize_t	readn(int fd, void *vptr, size_t n);
ssize_t writen(int fd, const void *vptr, size_t n);

/* Read "n" bytes from a socket. */
ssize_t	recvn(evutil_socket_t fd, void *vptr, size_t n);
ssize_t sendn(evutil_socket_t fd, const void *vptr, size_t n);

int copy_fd (int ifd, int ofd);
int copy_file (const char *dst, const char *src, int mode);


/* string utilities */

char** strsplit_by_char (char *string, int *length, char c);

char * strjoin_n (const char *seperator, int argc, char **argv);

int is_ipaddr_valid (const char *ip);

typedef void (*KeyValueFunc) (void *data, const char *key, char *value);
void parse_key_value_pairs (char *string, KeyValueFunc func, void *data);

typedef gboolean (*KeyValueFunc2) (void *data, const char *key,
                                   const char *value);
void parse_key_value_pairs2 (char *string, KeyValueFunc2 func, void *data);

gchar*  ccnet_key_file_get_string (GKeyFile *keyf,
                                   const char *category,
                                   const char *key);


GList *string_list_append (GList *str_list, const char *string);
GList *string_list_append_sorted (GList *str_list, const char *string);
GList *string_list_remove (GList *str_list, const char *string);
void string_list_free (GList *str_list);
gboolean string_list_is_exists (GList *str_list, const char *string);
void string_list_join (GList *str_list, GString *strbuf, const char *seperator);
GList *string_list_parse (const char *list_in_str, const char *seperator);
GList *string_list_parse_sorted (const char *list_in_str, const char *seperator);
gboolean string_list_sorted_is_equal (GList *list1, GList *list2);

char** ncopy_string_array (char **orig, int n);
void nfree_string_array (char **array, int n);


gchar *
key_value_list_to_json(const char *first, ...) G_GNUC_NULL_TERMINATED;

gchar *
key_value_list_to_json_v(const char *first, va_list args);

/* format char:
     i   integer (gint64)
     s   string (const char *) or NULL
 */
gchar *
json_printf(const char *format, ...);

gchar *
json_vprintf(const char *format, va_list args);


/* 64bit time */
gint64 get_current_time();

int
ccnet_encrypt (char **data_out,
               int *out_len,
               const char *data_in,
               const int in_len,
               const char *code,
               const int code_len);


int
ccnet_decrypt (char **data_out,
               int *out_len,
               const char *data_in,
               const int in_len,
               const char *code,
               const int code_len);


/*
 * Utility functions for converting data to/from network byte order.
 */

static inline uint64_t
bswap64 (uint64_t val)
{
    uint64_t ret;
    uint8_t *ptr = (uint8_t *)&ret;

    ptr[0]=((val)>>56)&0xFF;
    ptr[1]=((val)>>48)&0xFF;
    ptr[2]=((val)>>40)&0xFF;
    ptr[3]=((val)>>32)&0xFF;
    ptr[4]=((val)>>24)&0xFF;
    ptr[5]=((val)>>16)&0xFF;
    ptr[6]=((val)>>8)&0xFF;
    ptr[7]=(val)&0xFF;

    return ret;
}

static inline uint64_t
hton64(uint64_t val)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN || defined WIN32 || defined __APPLE__
    return bswap64 (val);
#else
    return val;
#endif
}

static inline uint64_t 
ntoh64(uint64_t val) 
{
#if __BYTE_ORDER == __LITTLE_ENDIAN || defined WIN32 || defined __APPLE__
    return bswap64 (val);
#else
    return val;
#endif
}

static inline void put64bit(uint8_t **ptr,uint64_t val)
{
    uint64_t val_n = hton64 (val);
    *((uint64_t *)(*ptr)) = val_n;
    (*ptr)+=8;
}

static inline void put32bit(uint8_t **ptr,uint32_t val)
{
    uint32_t val_n = htonl (val);
    *((uint32_t *)(*ptr)) = val_n;
    (*ptr)+=4;
}

static inline void put16bit(uint8_t **ptr,uint16_t val)
{
    uint16_t val_n = htons (val);
    *((uint16_t *)(*ptr)) = val_n;
    (*ptr)+=2;
}

static inline uint64_t get64bit(const uint8_t **ptr)
{
    uint64_t val_h = ntoh64 (*((uint64_t *)(*ptr)));
    (*ptr)+=8;
    return val_h;
}

static inline uint32_t get32bit(const uint8_t **ptr)
{
    uint32_t val_h = ntohl (*((uint32_t *)(*ptr)));
    (*ptr)+=4;
    return val_h;
}

static inline uint16_t get16bit(const uint8_t **ptr)
{
    uint16_t val_h = ntohs (*((uint16_t *)(*ptr)));
    (*ptr)+=2;
    return val_h;
}

/* Convert between local encoding and utf8. Returns the converted
 * string if success, otherwise return NULL
 */
char *ccnet_locale_from_utf8 (const gchar *src);
char *ccnet_locale_to_utf8 (const gchar *src);

/* Detect whether a process with the given name is running right now. */
gboolean process_is_running(const char *name);

/* count how much instance of a program is running  */
int count_process (const char *process_name_in);

#ifdef WIN32
int win32_kill_process (const char *process_name_in);
int win32_spawn_process (char *cmd, char *wd);
char *wchar_to_utf8 (const wchar_t *src);
wchar_t *wchar_from_utf8 (const char *src);
#endif

char* ccnet_object_type_from_id (const char *object_id);

gint64 ccnet_calc_directory_size (const char *path, GError **error);

#ifdef WIN32
char * strtok_r(char *s, const char *delim, char **save_ptr);
#endif


#endif
