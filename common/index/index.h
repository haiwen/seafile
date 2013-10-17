#ifndef INDEX_H
#define INDEX_H

#include "common.h"

#include <unistd.h>
#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#ifndef __APPLE__
#include <limits.h>
#endif
#include <sys/param.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/time.h>
#include <time.h>

#include "utils.h"

#ifdef WIN32
#include <inttypes.h>
#include <winsock2.h>
#include <windows.h>   

#define DT_UNKNOWN 0
#define DT_DIR     1
#define DT_REG     2
#define DT_LNK     3
#define DTYPE(de)    DT_UNKNOWN

#define S_IFLNK    0120000 /* Symbolic link */
#define S_ISLNK(x) (((x) & S_IFMT) == S_IFLNK)
#define S_ISSOCK(x) 0

#ifndef PROT_READ
#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_PRIVATE 1
#endif

#ifndef MAP_FAILED
#define MAP_FAILED ((void *)-1)
#endif

#define mmap git_mmap
#define munmap git_munmap
extern void *git_mmap(void *start, size_t length, int prot, int flags, int fd, off_t offset);
extern int git_munmap(void *start, size_t length);

#else
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <sys/mman.h>

#define DTYPE(de)    ((de)->d_type)

#endif

#include "hash.h"

#ifndef O_BINARY
#define O_BINARY 0
#endif

/* unknown mode (impossible combination S_IFIFO|S_IFCHR) */
#define S_IFINVALID     0030000

/*
 * A "directory link" is a link to another git directory.
 *
 * The value 0160000 is not normally a valid mode, and
 * also just happens to be S_IFDIR + S_IFLNK
 *
 * NOTE! We *really* shouldn't depend on the S_IFxxx macros
 * always having the same values everywhere. We should use
 * our internal git values for these things, and then we can
 * translate that to the OS-specific value. It just so
 * happens that everybody shares the same bit representation
 * in the UNIX world (and apparently wider too..)
 */
#define S_IFGITLINK    0160000
#define S_ISGITLINK(m)    (((m) & S_IFMT) == S_IFGITLINK)

struct SeafileCrypt;

/*
 * Basic data structures for the directory cache
 */

#define CACHE_SIGNATURE 0x44495243    /* "DIRC" */
struct cache_header {
    unsigned int hdr_signature;
    unsigned int hdr_version;
    unsigned int hdr_entries;
};

/*
 * The "cache_time" is just the low 32 bits of the
 * time. It doesn't matter if it overflows - we only
 * check it for equality in the 32 bits we save.
 */
struct cache_time {
    unsigned int sec;
    unsigned int nsec;
};

/*
 * dev/ino/uid/gid/size are also just tracked to the low 32 bits
 * Again - this is just a (very strong in practice) heuristic that
 * the inode hasn't changed.
 *
 * We save the fields in big-endian order to allow using the
 * index file over NFS transparently.
 */
struct ondisk_cache_entry {
    struct cache_time ctime;
    struct cache_time mtime;
    unsigned int dev;
    unsigned int ino;
    unsigned int mode;
    unsigned int uid;
    unsigned int gid;
    uint64_t     size;
    unsigned char sha1[20];
    unsigned short flags;
    char name[0]; /* more */
} __attribute__ ((packed));

/*
 * This struct is used when CE_EXTENDED bit is 1
 * The struct must match ondisk_cache_entry exactly from
 * ctime till flags
 */
struct ondisk_cache_entry_extended {
    struct cache_time ctime;
    struct cache_time mtime;
    unsigned int dev;
    unsigned int ino;
    unsigned int mode;
    unsigned int uid;
    unsigned int gid;
    uint64_t     size;
    unsigned char sha1[20];
    unsigned short flags;
    unsigned short flags2;
    char name[0]; /* more */
} __attribute__ ((packed));

struct cache_entry {
    struct cache_time ce_ctime;
    struct cache_time ce_mtime;
    unsigned int ce_dev;
    unsigned int ce_ino;
    unsigned int ce_mode;
    unsigned int ce_uid;
    unsigned int ce_gid;
    uint64_t     ce_size;
    unsigned int ce_flags;
    unsigned char sha1[20];
    struct cache_entry *next;
    char name[0]; /* more */
};

#define CE_NAMEMASK  (0x0fff)
#define CE_STAGEMASK (0x3000)
#define CE_EXTENDED  (0x4000)
#define CE_VALID     (0x8000)
#define CE_STAGESHIFT 12

/*
 * Range 0xFFFF0000 in ce_flags is divided into
 * two parts: in-memory flags and on-disk ones.
 * Flags in CE_EXTENDED_FLAGS will get saved on-disk
 * if you want to save a new flag, add it in
 * CE_EXTENDED_FLAGS
 *
 * In-memory only flags
 */
#define CE_UPDATE            (1 << 16)
#define CE_REMOVE            (1 << 17)
#define CE_UPTODATE          (1 << 18)
#define CE_ADDED             (1 << 19)

#define CE_HASHED            (1 << 20)
#define CE_UNHASHED          (1 << 21)
#define CE_WT_REMOVE         (1 << 22) /* remove in work directory */
#define CE_CONFLICTED        (1 << 23)

#define CE_UNPACKED          (1 << 24)
#define CE_NEW_SKIP_WORKTREE (1 << 25)

/*
 * Extended on-disk flags
 */
#define CE_INTENT_TO_ADD     (1 << 29)
#define CE_SKIP_WORKTREE     (1 << 30)
/* CE_EXTENDED2 is for future extension */
#define CE_EXTENDED2         (1 << 31)

#define CE_EXTENDED_FLAGS (CE_INTENT_TO_ADD | CE_SKIP_WORKTREE)

/*
 * Safeguard to avoid saving wrong flags:
 *  - CE_EXTENDED2 won't get saved until its semantic is known
 *  - Bits in 0x0000FFFF have been saved in ce_flags already
 *  - Bits in 0x003F0000 are currently in-memory flags
 */
#if CE_EXTENDED_FLAGS & 0x803FFFFF
#error "CE_EXTENDED_FLAGS out of range"
#endif

/*
 * Copy the sha1 and stat state of a cache entry from one to
 * another. But we never change the name, or the hash state!
 */
#define CE_STATE_MASK (CE_HASHED | CE_UNHASHED)

static inline void copy_cache_entry(struct cache_entry *dst, struct cache_entry *src)
{
    unsigned int state = dst->ce_flags & CE_STATE_MASK;

    /* Don't copy hash chain and name */
    memcpy(dst, src, offsetof(struct cache_entry, next));

    /* Restore the hash state */
    dst->ce_flags = (dst->ce_flags & ~CE_STATE_MASK) | state;
}

static inline unsigned create_ce_flags(size_t len, unsigned stage)
{
    if (len >= CE_NAMEMASK)
        len = CE_NAMEMASK;
    return (len | (stage << CE_STAGESHIFT));
}

static inline size_t ce_namelen(const struct cache_entry *ce)
{
    size_t len = ce->ce_flags & CE_NAMEMASK;
    if (len < CE_NAMEMASK)
        return len;
    return strlen(ce->name + CE_NAMEMASK) + CE_NAMEMASK;
}

#define ce_size(ce) cache_entry_size(ce_namelen(ce))
#define ondisk_ce_size(ce) (((ce)->ce_flags & CE_EXTENDED) ? \
                ondisk_cache_entry_extended_size(ce_namelen(ce)) : \
                ondisk_cache_entry_size(ce_namelen(ce)))
#define ce_stage(ce) ((CE_STAGEMASK & (ce)->ce_flags) >> CE_STAGESHIFT)
#define ce_uptodate(ce) ((ce)->ce_flags & CE_UPTODATE)
#define ce_skip_worktree(ce) ((ce)->ce_flags & CE_SKIP_WORKTREE)
#define ce_mark_uptodate(ce) ((ce)->ce_flags |= CE_UPTODATE)

#define ce_permissions(mode) (((mode) & 0100) ? 0755 : 0644)
static inline unsigned int create_ce_mode(unsigned int mode)
{
    if (S_ISLNK(mode))
        return S_IFLNK;
    if (S_ISDIR(mode))
        return S_IFDIR;
    return S_IFREG | ce_permissions(mode);
}
static inline unsigned int ce_mode_from_stat(struct cache_entry *ce, unsigned int mode)
{
    return create_ce_mode(mode);
}
static inline int ce_to_dtype(const struct cache_entry *ce)
{
    unsigned ce_mode = ntohl(ce->ce_mode);
    if (S_ISREG(ce_mode))
        return DT_REG;
    else if (S_ISDIR(ce_mode) || S_ISGITLINK(ce_mode))
        return DT_DIR;
    else if (S_ISLNK(ce_mode))
        return DT_LNK;
    else
        return DT_UNKNOWN;
}
static inline unsigned int canon_mode(unsigned int mode)
{
    if (S_ISREG(mode))
        return S_IFREG | ce_permissions(mode);
    if (S_ISLNK(mode))
        return S_IFLNK;
    if (S_ISDIR(mode))
        return S_IFDIR;
    return S_IFGITLINK;
}

#define flexible_size(STRUCT,len) ((offsetof(struct STRUCT,name) + (len) + 8) & ~7)
#define cache_entry_size(len) flexible_size(cache_entry,len)
#define ondisk_cache_entry_size(len) flexible_size(ondisk_cache_entry,len)
#define ondisk_cache_entry_extended_size(len) flexible_size(ondisk_cache_entry_extended,len)

struct index_state {
    struct cache_entry **cache;
    unsigned int cache_nr, cache_alloc, cache_changed;
    /* struct cache_tree *cache_tree; */
    struct cache_time timestamp;
    void *alloc;
    unsigned name_hash_initialized : 1,
         initialized : 1;
    struct hash_table name_hash;
};

extern struct index_state the_index;

/* Name hashing */
extern void add_name_hash(struct index_state *istate, struct cache_entry *ce);
extern unsigned int hash_name(const char *name, int namelen);
/*
 * We don't actually *remove* it, we can just mark it invalid so that
 * we won't find it in lookups.
 *
 * Not only would we have to search the lists (simple enough), but
 * we'd also have to rehash other hash buckets in case this makes the
 * hash bucket empty (common). So it's much better to just mark
 * it.
 */
static inline void remove_name_hash(struct cache_entry *ce)
{
    ce->ce_flags |= CE_UNHASHED;
}

enum object_type {
    OBJ_BAD = -1,
    OBJ_NONE = 0,
    OBJ_COMMIT = 1,
    OBJ_TREE = 2,
    OBJ_BLOB = 3,
    OBJ_TAG = 4,
    /* 5 for future expansion */
    OBJ_OFS_DELTA = 6,
    OBJ_REF_DELTA = 7,
    OBJ_ANY,
    OBJ_MAX
};

static inline enum object_type object_type(unsigned int mode)
{
    return S_ISDIR(mode) ? OBJ_TREE :
        S_ISGITLINK(mode) ? OBJ_COMMIT :
        OBJ_BLOB;
}

#define alloc_nr(x) (((x)+16)*3/2)

/*
 * Realloc the buffer pointed at by variable 'x' so that it can hold
 * at least 'nr' entries; the number of entries currently allocated
 * is 'alloc', using the standard growing factor alloc_nr() macro.
 *
 * DO NOT USE any expression with side-effect for 'x', 'nr', or 'alloc'.
 */
#define ALLOC_GROW(x, nr, alloc) \
    do { \
        if ((nr) > alloc) { \
            if (alloc_nr(alloc) < (nr)) \
                alloc = (nr); \
            else \
                alloc = alloc_nr(alloc); \
            x = realloc((x), alloc * sizeof(*(x))); \
        } \
    } while (0)

/* Initialize and use the cache information */
extern int read_index(struct index_state *);
extern int read_index_preload(struct index_state *, const char **pathspec);
extern int read_index_from(struct index_state *, const char *path);
extern int is_index_unborn(struct index_state *);
extern int read_index_unmerged(struct index_state *);
extern int write_index(struct index_state *, int newfd);
extern int discard_index(struct index_state *);
extern int unmerged_index(const struct index_state *);
extern int verify_path(const char *path);
extern struct cache_entry *index_name_exists(struct index_state *istate, const char *name, int namelen, int igncase);
extern int index_name_pos(const struct index_state *, const char *name, int namelen);
#define ADD_CACHE_OK_TO_ADD 1        /* Ok to add */
#define ADD_CACHE_OK_TO_REPLACE 2    /* Ok to replace file/directory */
#define ADD_CACHE_SKIP_DFCHECK 4    /* Ok to skip DF conflict checks */
#define ADD_CACHE_JUST_APPEND 8        /* Append only; tree.c::read_tree() */
#define ADD_CACHE_NEW_ONLY 16        /* Do not replace existing ones */
extern int add_index_entry(struct index_state *, struct cache_entry *ce, int option);
extern void rename_index_entry_at(struct index_state *, int pos, const char *new_name);
extern int remove_index_entry_at(struct index_state *, int pos);
extern void remove_marked_cache_entries(struct index_state *istate);
extern int remove_file_from_index(struct index_state *, const char *path);

#define ADD_CACHE_VERBOSE 1
#define ADD_CACHE_PRETEND 2
#define ADD_CACHE_IGNORE_ERRORS    4
#define ADD_CACHE_IGNORE_REMOVAL 8
#define ADD_CACHE_INTENT 16

typedef int (*IndexCB) (const char *path,
                        unsigned char sha1[],
                        struct SeafileCrypt *crypt);

int add_to_index(struct index_state *istate,
                 const char *path,
                 const char *full_path,
                 SeafStat *st,
                 int flags,
                 struct SeafileCrypt *crypt,
                 IndexCB index_cb);

int
add_empty_dir_to_index (struct index_state *istate,
                        const char *path,
                        SeafStat *st);

extern int add_file_to_index(struct index_state *, const char *path, int flags);
extern struct cache_entry *make_cache_entry(unsigned int mode, const unsigned char *sha1, const char *path, const char *full_path, int stage, int refresh);
extern int ce_same_name(struct cache_entry *a, struct cache_entry *b);
extern int index_name_is_other(const struct index_state *, const char *, int);

/* do stat comparison even if CE_VALID is true */
#define CE_MATCH_IGNORE_VALID        01
/* do not check the contents but report dirty on racily-clean entries */
#define CE_MATCH_RACY_IS_DIRTY        02
/* do stat comparison even if CE_SKIP_WORKTREE is true */
#define CE_MATCH_IGNORE_SKIP_WORKTREE    04
extern int ie_match_stat(const struct index_state *, struct cache_entry *, SeafStat *, unsigned int);
extern int ie_modified(const struct index_state *, struct cache_entry *, SeafStat *, unsigned int);

extern int ce_path_match(const struct cache_entry *ce, const char **pathspec);
extern int index_fd(unsigned char *sha1, int fd, SeafStat *st, enum object_type type, const char *path);
extern int index_path(unsigned char *sha1, const char *path, SeafStat *st);
extern void fill_stat_cache_info(struct cache_entry *ce, SeafStat *st);
extern void mark_all_ce_unused(struct index_state *index);

#define MTIME_CHANGED    0x0001
#define CTIME_CHANGED    0x0002
#define OWNER_CHANGED    0x0004
#define MODE_CHANGED    0x0008
#define INODE_CHANGED   0x0010
#define DATA_CHANGED    0x0020
#define TYPE_CHANGED    0x0040

extern const unsigned char null_sha1[20];
static inline int is_null_sha1(const unsigned char *sha1)
{
    return !memcmp(sha1, null_sha1, 20);
}
static inline int hashcmp(const unsigned char *sha1, const unsigned char *sha2)
{
    return memcmp(sha1, sha2, 20);
}
static inline void hashcpy(unsigned char *sha_dst, const unsigned char *sha_src)
{
    memcpy(sha_dst, sha_src, 20);
}
static inline void hashclr(unsigned char *hash)
{
    memset(hash, 0, 20);
}

extern int cache_name_compare(const char *name1, int len1, const char *name2, int len2);
extern int df_name_compare(const char *name1, int len1, int mode1,
               const char *name2, int len2, int mode2);


#endif
