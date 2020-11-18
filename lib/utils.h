/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef CCNET_UTILS_H
#define CCNET_UTILS_H

#ifdef WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x500
#endif
#include <winsock2.h>
#include <windows.h>
#endif

#ifndef WIN32
#include <sys/time.h>
#include <unistd.h>
#endif
#include <time.h>
#include <stdint.h>
#include <stdarg.h>
#include <glib.h>
#include <glib-object.h>
#include <stdlib.h>
#include <sys/stat.h>

#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#include <event2/util.h>
#else
#include <evutil.h>
#endif

#ifdef __linux__
#include <endian.h>
#endif

#ifdef __OpenBSD__
#include <machine/endian.h>
#endif

#ifdef WIN32
#include <errno.h>
#include <glib/gstdio.h>

#define mode_t int

#define ssize_t gssize

#ifndef WEXITSTATUS
#define WEXITSTATUS(status) (((status) & 0xff00) >> 8)
#endif

#define SeafStat struct __stat64

#else

#define SeafStat struct stat

#endif

int seaf_stat (const char *path, SeafStat *st);
int seaf_fstat (int fd, SeafStat *st);

#ifdef WIN32
void
seaf_stat_from_find_data (WIN32_FIND_DATAW *fdata, SeafStat *st);
#endif

int seaf_set_file_time (const char *path, guint64 mtime);

#ifdef WIN32
wchar_t *
win32_long_path (const char *path);

/* Convert a (possible) 8.3 format path to long path */
wchar_t *
win32_83_path_to_long_path (const char *worktree, const wchar_t *path, int path_len);

__time64_t
file_time_to_unix_time (FILETIME *ftime);
#endif

int
seaf_util_unlink (const char *path);

int
seaf_util_rmdir (const char *path);

int
seaf_util_mkdir (const char *path, mode_t mode);

int
seaf_util_open (const char *path, int flags);

int
seaf_util_create (const char *path, int flags, mode_t mode);

int
seaf_util_rename (const char *oldpath, const char *newpath);

gboolean
seaf_util_exists (const char *path);

gint64
seaf_util_lseek (int fd, gint64 offset, int whence);

#ifdef WIN32

typedef int (*DirentCallback) (wchar_t *parent,
                               WIN32_FIND_DATAW *fdata,
                               void *user_data,
                               gboolean *stop);

int
traverse_directory_win32 (wchar_t *path_w,
                          DirentCallback callback,
                          void *user_data);
#endif

#ifndef O_BINARY
#define O_BINARY 0
#endif

#ifdef WIN32
#define seaf_pipe_t intptr_t
#else
#define seaf_pipe_t int
#endif

int
seaf_pipe (seaf_pipe_t handles[2]);
int
seaf_pipe_read (seaf_pipe_t fd, char *buf, int len);
int
seaf_pipe_write (seaf_pipe_t fd, const char *buf, int len);
int
seaf_pipe_close (seaf_pipe_t fd);

ssize_t seaf_pipe_readn (seaf_pipe_t fd, void *vptr, size_t n);
ssize_t seaf_pipe_writen (seaf_pipe_t fd, const void *vptr, size_t n);

typedef enum IgnoreReason {
    IGNORE_REASON_END_SPACE_PERIOD = 0,
    IGNORE_REASON_INVALID_CHARACTER = 1,
} IgnoreReason;

gboolean
should_ignore_on_checkout (const char *file_path, IgnoreReason *ignore_reason);

/* for debug */
#ifndef ccnet_warning
#ifndef WIN32
#define ccnet_warning(fmt, ...) g_warning("%s(%d): " fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#else
#define ccnet_warning(...) g_warning (__VA_ARGS__)
#endif
#endif

#ifndef ccnet_error
#ifndef WIN32
#define ccnet_error(fmt, ...)   g_error("%s(%d): " fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#else
#define ccnet_error(...) g_error(__VA_ARGS__)
#endif
#endif

#ifndef ccnet_message
#ifndef WIN32
#define ccnet_message(fmt, ...) g_message("%s(%d): " fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#else
#define ccnet_message(...) g_message(__VA_ARGS__)
#endif
#endif

#define CCNET_DOMAIN g_quark_from_string("ccnet")


size_t ccnet_strlcpy (char *dst, const char *src, size_t size);

void rawdata_to_hex (const unsigned char *rawdata, char *hex_str, int n_bytes);
int hex_to_rawdata (const char *hex_str, unsigned char *rawdata, int n_bytes);

#define sha1_to_hex(sha1, hex) rawdata_to_hex((sha1), (hex), 20)
#define hex_to_sha1(hex, sha1) hex_to_rawdata((hex), (sha1), 20)

/* If msg is NULL-terminated, set len to -1 */
int calculate_sha1 (unsigned char *sha1, const char *msg, int len);
int ccnet_sha1_equal (const void *v1, const void *v2);
unsigned int ccnet_sha1_hash (const void *v);

char* gen_uuid ();
void gen_uuid_inplace (char *buf);
gboolean is_uuid_valid (const char *uuid_str);

gboolean
is_object_id_valid (const char *obj_id);

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

/* 64bit time */
gint64 get_current_time();

/*
 * Utility functions for converting data to/from network byte order.
 */

#if !defined(__NetBSD__)
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
#endif

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

#include <jansson.h>

const char *
json_object_get_string_member (json_t *object, const char *key);

gboolean
json_object_has_member (json_t *object, const char *key);

gint64
json_object_get_int_member (json_t *object, const char *key);

void
json_object_set_string_member (json_t *object, const char *key, const char *value);

void
json_object_set_int_member (json_t *object, const char *key, gint64 value);

/* Replace invalid UTF-8 bytes with '?' */
void
clean_utf8_data (char *data, int len);

char *
normalize_utf8_path (const char *path);

/* zlib related functions. */

int
seaf_compress (guint8 *input, int inlen, guint8 **output, int *outlen);

int
seaf_decompress (guint8 *input, int inlen, guint8 **output, int *outlen);

char*
format_dir_path (const char *path);

gboolean
is_empty_string (const char *str);

gboolean
is_permission_valid (const char *perm);

gboolean
is_eml_file (const char *path);

char *
canonical_server_url (const char *url_in);
#endif
