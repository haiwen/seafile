/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * GIT - The information manager from hell
 *
 * Copyright (C) Linus Torvalds, 2005
 */
#define NO_THE_INDEX_COMPATIBILITY_MACROS

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "common.h"

#include "index.h"
#include "../seafile-crypt.h"
/* #include "../vc-utils.h" */
/* #include "cache-tree.h" */

#include <glib.h>
#include <glib/gstdio.h>
#include <openssl/sha.h>

#ifdef WIN32

void vreportf(const char *prefix, const char *err, va_list params)
{
    char msg[4096];
    vsnprintf(msg, sizeof(msg), err, params);
    fprintf(stderr, "%s%s\n", prefix, msg);
}
static void usage_builtin(const char *err, va_list params)
{
    vreportf("usage: ", err, params);
    exit(129);
}

static void die_builtin(const char *err, va_list params)
{
    vreportf("fatal: ", err, params);
    exit(128);
}
static void error_builtin(const char *err, va_list params)
{
    vreportf("error: ", err, params);
}

static void warn_builtin(const char *warn, va_list params)
{
    vreportf("warning: ", warn, params);
}


/* If we are in a dlopen()ed .so write to a global variable would segfault
 * (ugh), so keep things static. */
static void (*usage_routine)(const char *err, va_list params) = usage_builtin;
static void (*die_routine)(const char *err, va_list params) = die_builtin;
static void (*error_routine)(const char *err, va_list params) = error_builtin;
static void (*warn_routine)(const char *err, va_list params) = warn_builtin;


void die(const char *err, ...)
{
    va_list params;

    va_start(params, err);
    die_routine(err, params);
    va_end(params);
}

void warning(const char *warn, ...)
{
    va_list params;

    va_start(params, warn);
    warn_routine(warn, params);
    va_end(params);
}

void *git_mmap(void *start, size_t length, int prot, int flags, int fd, off_t offset)
{
    HANDLE hmap;
    void *temp;
    off_t len;
    struct stat st;
    uint64_t o = offset;
    uint32_t l = o & 0xFFFFFFFF;
    uint32_t h = (o >> 32) & 0xFFFFFFFF;

    if (!fstat(fd, &st))
        len = st.st_size;
    else
        die("mmap: could not determine filesize");

    if ((length + offset) > len)
        length = xsize_t(len - offset);

    if (!(flags & MAP_PRIVATE))
        die("Invalid usage of mmap when built with USE_WIN32_MMAP");

    hmap = CreateFileMapping((HANDLE)_get_osfhandle(fd), 0, PAGE_WRITECOPY,
                             0, 0, 0);

    if (!hmap)
        return MAP_FAILED;

    temp = MapViewOfFileEx(hmap, FILE_MAP_COPY, h, l, length, start);

    if (!CloseHandle(hmap))
        warning("unable to close file mapping handle\n");

    return temp ? temp : MAP_FAILED;
}

int git_munmap(void *start, size_t length)
{
    return !UnmapViewOfFile(start);
}
#endif //for WIN32

static inline uint64_t
hton64(uint64_t val)
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
ntoh64(uint64_t val) 
{
    uint64_t t64;
    uint8_t *ptr = (uint8_t *)&val;

    t64=(ptr[3]+256*(ptr[2]+256*(ptr[1]+256*ptr[0])));
    t64<<=32;
    t64|=((ptr[7]+256*(ptr[6]+256*(ptr[5]+256*ptr[4]))))&0xffffffffU;

    return t64;
}

static void set_index_entry(struct index_state *istate, int nr, struct cache_entry *ce)
{
    istate->cache[nr] = ce;
    add_name_hash(istate, ce);
}

static void replace_index_entry(struct index_state *istate, int nr, struct cache_entry *ce)
{
    struct cache_entry *old = istate->cache[nr];

    remove_name_hash(old);
    set_index_entry(istate, nr, ce);
    istate->cache_changed = 1;
}

static int verify_hdr(struct cache_header *hdr, unsigned long size)
{
    SHA_CTX c;
    unsigned char sha1[20];

    if (hdr->hdr_signature != htonl(CACHE_SIGNATURE)) {
        g_critical("bad signature");
        return -1;
    }
    if (hdr->hdr_version != htonl(2) && hdr->hdr_version != htonl(3)) {
        g_critical("bad index version");
        return -1;
    }
    SHA1_Init(&c);
    SHA1_Update(&c, hdr, size - 20);
    SHA1_Final(sha1, &c);
    if (hashcmp(sha1, (unsigned char *)hdr + size - 20)) {
        g_critical("bad index file sha1 signature");
        return -1;
    }
    return 0;
}

static inline size_t estimate_cache_size(size_t ondisk_size, unsigned int entries)
{
    long per_entry;

    per_entry = sizeof(struct cache_entry) - sizeof(struct ondisk_cache_entry);

    /*
     * Alignment can cause differences. This should be "alignof", but
     * since that's a gcc'ism, just use the size of a pointer.
     */
    per_entry += sizeof(void *);
    return ondisk_size + entries*per_entry;
}

static int convert_from_disk(struct ondisk_cache_entry *ondisk, struct cache_entry **ce)
{
    size_t len;
    const char *name;
    unsigned int flags = 0;
    struct cache_entry *ret;

    flags = ntohs(ondisk->flags);

    len = flags & CE_NAMEMASK;

    if (flags & CE_EXTENDED) {
        struct ondisk_cache_entry_extended *ondisk2;
        int extended_flags;
        ondisk2 = (struct ondisk_cache_entry_extended *)ondisk;
        extended_flags = ntohs(ondisk2->flags2) << 16;
        /* We do not yet understand any bit out of CE_EXTENDED_FLAGS */
        if (extended_flags & ~CE_EXTENDED_FLAGS) {
            g_critical("Unknown index entry format %08x", extended_flags);
            return -1;
        }
        flags |= extended_flags;
        name = ondisk2->name;
    }
    else
        name = ondisk->name;

    if (len == CE_NAMEMASK)
        len = strlen(name);

    ret = calloc(1, cache_entry_size(len));

    ret->ce_ctime.sec = ntohl(ondisk->ctime.sec);
    ret->ce_mtime.sec = ntohl(ondisk->mtime.sec);
    ret->ce_ctime.nsec = ntohl(ondisk->ctime.nsec);
    ret->ce_mtime.nsec = ntohl(ondisk->mtime.nsec);
    ret->ce_dev   = ntohl(ondisk->dev);
    ret->ce_ino   = ntohl(ondisk->ino);
    ret->ce_mode  = ntohl(ondisk->mode);
    ret->ce_uid   = ntohl(ondisk->uid);
    ret->ce_gid   = ntohl(ondisk->gid);
    ret->ce_size  = ntoh64(ondisk->size);
    /* On-disk flags are just 16 bits */
    ret->ce_flags = flags;

    hashcpy(ret->sha1, ondisk->sha1);

    /*
     * NEEDSWORK: If the original index is crafted, this copy could
     * go unchecked.
     */
    memcpy(ret->name, name, len + 1);

    *ce = ret;

    return 0;
}

#if 0
static int read_index_extension(struct index_state *istate,
                                const char *ext, void *data, unsigned long sz)
{
    switch (CACHE_EXT(ext)) {
    case CACHE_EXT_TREE:
        istate->cache_tree = cache_tree_read(data, sz);
        break;
    case CACHE_EXT_RESOLVE_UNDO:
        /* istate->resolve_undo = resolve_undo_read(data, sz); */
        break;
    default:
        /* if (*ext < 'A' || 'Z' < *ext) */
        /*     return error("index uses %.4s extension, which we do not understand", */
        /*              ext); */
        /* fprintf(stderr, "ignoring %.4s extension\n", ext); */
        g_critical("unknown extension.");
        break;
    }
    return 0;
}
#endif

/* remember to discard_cache() before reading a different cache! */
int read_index_from(struct index_state *istate, const char *path)
{
    int fd, i;
    struct stat st;
    unsigned long src_offset, dst_offset;
    struct cache_header *hdr;
    void *mm;
    size_t mmap_size;

    if (istate->initialized)
        return istate->cache_nr;

    istate->timestamp.sec = 0;
    istate->timestamp.nsec = 0;
    fd = g_open (path, O_RDONLY | O_BINARY, 0);
    if (fd < 0) {
        if (errno == ENOENT)
            return 0;
        g_critical("index file open failed");
        return -1;
    }

    if (fstat(fd, &st)) {
        g_critical("cannot stat the open index");
        return -1;
    }

    mmap_size = (size_t)st.st_size;
    if (mmap_size < sizeof(struct cache_header) + 20) {
        g_critical("index file smaller than expected");
        return -1;
    }

    mm = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    close(fd);
    if (mm == MAP_FAILED) {
        g_critical("unable to map index file");
        return -1;
    }

    hdr = mm;
    if (verify_hdr(hdr, mmap_size) < 0)
        goto unmap;

    istate->cache_nr = ntohl(hdr->hdr_entries);
    istate->cache_alloc = alloc_nr(istate->cache_nr);
    istate->cache = calloc(istate->cache_alloc, sizeof(struct cache_entry *));

    /*
     * The disk format is actually larger than the in-memory format,
     * due to space for nsec etc, so even though the in-memory one
     * has room for a few  more flags, we can allocate using the same
     * index size
     */
    /* istate->alloc = malloc(estimate_cache_size(mmap_size, istate->cache_nr)); */
    istate->initialized = 1;

    src_offset = sizeof(*hdr);
    dst_offset = 0;
    for (i = 0; i < istate->cache_nr; i++) {
        struct ondisk_cache_entry *disk_ce;
        struct cache_entry *ce;

        disk_ce = (struct ondisk_cache_entry *)((char *)mm + src_offset);
        /* ce = (struct cache_entry *)((char *)istate->alloc + dst_offset); */

        /* allocate each ce separately so that we can free new
         * entries added by add_index_entry() later.
         */
        if (convert_from_disk(disk_ce, &ce) < 0)
            return -1;
        set_index_entry(istate, i, ce);

        src_offset += ondisk_ce_size(ce);
        dst_offset += ce_size(ce);
    }
    istate->timestamp.sec = st.st_mtime;
    istate->timestamp.nsec = 0;

#if 0
    while (src_offset <= mmap_size - 20 - 8) {
        /* After an array of active_nr index entries,
         * there can be arbitrary number of extended
         * sections, each of which is prefixed with
         * extension name (4-byte) and section length
         * in 4-byte network byte order.
         */
        uint32_t extsize;
        memcpy(&extsize, (char *)mm + src_offset + 4, 4);
        extsize = ntohl(extsize);
        if (read_index_extension(istate,
                                 (const char *) mm + src_offset,
                                 (char *) mm + src_offset + 8,
                                 extsize) < 0)
            goto unmap;
        src_offset += 8;
        src_offset += extsize;
    }
#endif
    munmap(mm, mmap_size);
    return istate->cache_nr;

unmap:
    munmap(mm, mmap_size);
    g_critical("index file corrupt");
    return -1;
}

int is_index_unborn(struct index_state *istate)
{
    return (!istate->cache_nr && !istate->alloc && !istate->timestamp.sec);
}

int unmerged_index(const struct index_state *istate)
{
    int i;
    for (i = 0; i < istate->cache_nr; i++) {
        if (ce_stage(istate->cache[i]))
            return 1;
    }
    return 0;
}

int cache_name_compare(const char *name1, int flags1, const char *name2, int flags2)
{
    int len1 = flags1 & CE_NAMEMASK;
    int len2 = flags2 & CE_NAMEMASK;
    int len = len1 < len2 ? len1 : len2;
    int cmp;

    cmp = memcmp(name1, name2, len);
    if (cmp)
        return cmp;
    if (len1 < len2)
        return -1;
    if (len1 > len2)
        return 1;

    /* Compare stages  */
    flags1 &= CE_STAGEMASK;
    flags2 &= CE_STAGEMASK;

    if (flags1 < flags2)
        return -1;
    if (flags1 > flags2)
        return 1;
    return 0;
}

/*
 * This only updates the "non-critical" parts of the directory
 * cache, ie the parts that aren't tracked by GIT, and only used
 * to validate the cache.
 */
void fill_stat_cache_info(struct cache_entry *ce, struct stat *st)
{
    ce->ce_ctime.sec = (unsigned int)st->st_ctime;
    ce->ce_mtime.sec = (unsigned int)st->st_mtime;
    ce->ce_ctime.nsec = 0;
    ce->ce_mtime.nsec = 0;
    ce->ce_dev = st->st_dev;
    ce->ce_ino = st->st_ino;
    ce->ce_uid = st->st_uid;
    ce->ce_gid = st->st_gid;
    ce->ce_size = st->st_size;

    /* if (assume_unchanged) */
    /*     ce->ce_flags |= CE_VALID; */

    if (S_ISREG(st->st_mode))
        ce_mark_uptodate(ce);
}

void mark_all_ce_unused(struct index_state *index)
{
    int i;
    for (i = 0; i < index->cache_nr; i++)
        index->cache[i]->ce_flags &= ~(CE_UNPACKED | CE_ADDED | CE_NEW_SKIP_WORKTREE);
}


static int is_empty_blob_sha1(const unsigned char *sha1)
{
    /* static const unsigned char empty_blob_sha1[20] = { */
    /*     0xe6,0x9d,0xe2,0x9b,0xb2,0xd1,0xd6,0x43,0x4b,0x8b, */
    /*     0x29,0xae,0x77,0x5a,0xd8,0xc2,0xe4,0x8c,0x53,0x91 */
    /* }; */

    static const unsigned char empty_blob_sha1[20] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };
    return !hashcmp(sha1, empty_blob_sha1);
}

static int ce_match_stat_basic(struct cache_entry *ce, struct stat *st)
{
    unsigned int changed = 0;

    if (ce->ce_flags & CE_REMOVE)
        return MODE_CHANGED | DATA_CHANGED | TYPE_CHANGED;

    switch (ce->ce_mode & S_IFMT) {
    case S_IFREG:
        changed |= !S_ISREG(st->st_mode) ? TYPE_CHANGED : 0;
        /* We consider only the owner x bit to be relevant for
         * "mode changes"
         */
#ifndef WIN32
        if ((0100 & (ce->ce_mode ^ st->st_mode)))
            changed |= MODE_CHANGED;
#endif
        break;
    case S_IFLNK:
        if (!S_ISLNK(st->st_mode))
            changed |= TYPE_CHANGED;
        break;
    case S_IFGITLINK:
        /* We ignore most of the st_xxx fields for gitlinks */
        if (!S_ISDIR(st->st_mode))
            changed |= TYPE_CHANGED;
        /* else if (ce_compare_gitlink(ce)) */
        /*     changed |= DATA_CHANGED; */
        return changed;
    default:
        g_warning("internal error: ce_mode is %o\n", ce->ce_mode);
        return -1;
    }
    if (ce->ce_mtime.sec != (unsigned int)st->st_mtime)
        changed |= MTIME_CHANGED;
    if (ce->ce_ctime.sec != (unsigned int)st->st_ctime)
        changed |= CTIME_CHANGED;

    if (ce->ce_uid != (unsigned int) st->st_uid ||
        ce->ce_gid != (unsigned int) st->st_gid)
        changed |= OWNER_CHANGED;
    if (ce->ce_ino != (unsigned int) st->st_ino)
        changed |= INODE_CHANGED;

    if (ce->ce_size != (unsigned int) st->st_size)
        changed |= DATA_CHANGED;

    /* Racily smudged entry? */
    if (!ce->ce_size) {
        if (!is_empty_blob_sha1(ce->sha1))
            changed |= DATA_CHANGED;
    }

    return changed;
}

static int is_racy_timestamp(const struct index_state *istate, struct cache_entry *ce)
{
    return (!S_ISGITLINK(ce->ce_mode) &&
            istate->timestamp.sec &&
#ifdef USE_NSEC
            /* nanosecond timestamped files can also be racy! */
            (istate->timestamp.sec < ce->ce_mtime.sec ||
             (istate->timestamp.sec == ce->ce_mtime.sec &&
              istate->timestamp.nsec <= ce->ce_mtime.nsec))
#else
            istate->timestamp.sec <= ce->ce_mtime.sec
#endif
        );
}

#if 0
static int ce_compare_data(struct cache_entry *ce, struct stat *st)
{
    int match = -1;
    int fd = g_open (ce->name, O_RDONLY | O_BINARY);

    if (fd >= 0) {
        unsigned char sha1[20];
        if (!index_fd(sha1, fd, st, OBJ_BLOB, ce->name))
            match = hashcmp(sha1, ce->sha1);
        /* index_fd() closed the file descriptor already */
    }
    return match;
}

static int ce_compare_link(struct cache_entry *ce, struct stat *st)
{
    int match = -1;
    unsigned char sha1[20];

    if (!index_path(sha1, ce->name, st))
        match = hashcmp(sha1, ce->sha1);

    return match;
}

static int ce_modified_check_fs(struct cache_entry *ce, struct stat *st)
{
    switch (st->st_mode & S_IFMT) {
    case S_IFREG:
        if (ce_compare_data(ce, st))
            return DATA_CHANGED;
        break;
    case S_IFLNK:
        if (ce_compare_link(ce, st))
            return DATA_CHANGED;
        break;
    default:
        return TYPE_CHANGED;
    }
    return 0;
}
#endif

int ie_match_stat(const struct index_state *istate,
                  struct cache_entry *ce, struct stat *st,
                  unsigned int options)
{
    unsigned int changed;
    int ignore_valid = options & CE_MATCH_IGNORE_VALID;
    int ignore_skip_worktree = options & CE_MATCH_IGNORE_SKIP_WORKTREE;
    /* int assume_racy_is_modified = options & CE_MATCH_RACY_IS_DIRTY; */

    /*
     * If it's marked as always valid in the index, it's
     * valid whatever the checked-out copy says.
     *
     * skip-worktree has the same effect with higher precedence
     */
    if (!ignore_skip_worktree && ce_skip_worktree(ce))
        return 0;
    if (!ignore_valid && (ce->ce_flags & CE_VALID))
        return 0;

    /*
     * Intent-to-add entries have not been added, so the index entry
     * by definition never matches what is in the work tree until it
     * actually gets added.
     */
    /* if (ce->ce_flags & CE_INTENT_TO_ADD) */
    /*     return DATA_CHANGED | TYPE_CHANGED | MODE_CHANGED; */

    changed = ce_match_stat_basic(ce, st);

    /*
     * Within 1 second of this sequence:
     *     echo xyzzy >file && git-update-index --add file
     * running this command:
     *     echo frotz >file
     * would give a falsely clean cache entry.  The mtime and
     * length match the cache, and other stat fields do not change.
     *
     * We could detect this at update-index time (the cache entry
     * being registered/updated records the same time as "now")
     * and delay the return from git-update-index, but that would
     * effectively mean we can make at most one commit per second,
     * which is not acceptable.  Instead, we check cache entries
     * whose mtime are the same as the index file timestamp more
     * carefully than others.
     */
#if 0
    if (!changed && is_racy_timestamp(istate, ce)) {
        /* if (assume_racy_is_modified) */
        /*     changed |= DATA_CHANGED; */
        /* else */
        /*     changed |= ce_modified_check_fs(ce, st); */
        changed = DATA_CHANGED;
    }
#endif

    return changed;
}

/*
 * df_name_compare() is identical to base_name_compare(), except it
 * compares conflicting directory/file entries as equal. Note that
 * while a directory name compares as equal to a regular file, they
 * then individually compare _differently_ to a filename that has
 * a dot after the basename (because '\0' < '.' < '/').
 *
 * This is used by routines that want to traverse the git namespace
 * but then handle conflicting entries together when possible.
 */
int df_name_compare(const char *name1, int len1, int mode1,
                    const char *name2, int len2, int mode2)
{
    int len = len1 < len2 ? len1 : len2, cmp;
    unsigned char c1, c2;

    cmp = memcmp(name1, name2, len);
    if (cmp)
        return cmp;
    /* Directories and files compare equal (same length, same name) */
    if (len1 == len2)
        return 0;
    c1 = name1[len];
    if (!c1 && S_ISDIR(mode1))
        c1 = '/';
    c2 = name2[len];
    if (!c2 && S_ISDIR(mode2))
        c2 = '/';
    if (c1 == '/' && !c2)
        return 0;
    if (c2 == '/' && !c1)
        return 0;
    return c1 - c2;
}

int index_name_pos(const struct index_state *istate, const char *name, int namelen)
{
    int first, last;

    first = 0;
    last = istate->cache_nr;
    while (last > first) {
        int next = (last + first) >> 1;
        struct cache_entry *ce = istate->cache[next];
        int cmp = cache_name_compare(name, namelen, ce->name, ce->ce_flags);
        if (!cmp)
            return next;
        if (cmp < 0) {
            last = next;
            continue;
        }
        first = next+1;
    }
    return -first-1;
}

/* Remove entry, return true if there are more entries to go.. */
int remove_index_entry_at(struct index_state *istate, int pos)
{
    struct cache_entry *ce = istate->cache[pos];

    /* record_resolve_undo(istate, ce); */
    remove_name_hash(ce);
    istate->cache_changed = 1;
    istate->cache_nr--;
    if (pos >= istate->cache_nr)
        return 0;
    memmove(istate->cache + pos,
            istate->cache + pos + 1,
            (istate->cache_nr - pos) * sizeof(struct cache_entry *));
    return 1;
}

/*
 * Remove all cache ententries marked for removal, that is where
 * CE_REMOVE is set in ce_flags.  This is much more effective than
 * calling remove_index_entry_at() for each entry to be removed.
 */
void remove_marked_cache_entries(struct index_state *istate)
{
    struct cache_entry **ce_array = istate->cache;
    unsigned int i, j;

    for (i = j = 0; i < istate->cache_nr; i++) {
        if (ce_array[i]->ce_flags & CE_REMOVE) {
            remove_name_hash(ce_array[i]);
            free (ce_array[i]);
        } else {
            ce_array[j++] = ce_array[i];
        }
    }
    istate->cache_changed = 1;
    istate->cache_nr = j;
}

int remove_file_from_index(struct index_state *istate, const char *path)
{
    int pos = index_name_pos(istate, path, strlen(path));
    if (pos < 0)
        pos = -pos-1;
    /* cache_tree_invalidate_path(istate->cache_tree, path); */
    while (pos < istate->cache_nr && !strcmp(istate->cache[pos]->name, path))
        remove_index_entry_at(istate, pos);
    return 0;
}

int ce_same_name(struct cache_entry *a, struct cache_entry *b)
{
    int len = ce_namelen(a);
    return ce_namelen(b) == len && !memcmp(a->name, b->name, len);
}

int ce_path_match(const struct cache_entry *ce, const char **pathspec)
{
    const char *match, *name;
    int len;

    if (!pathspec)
        return 1;

    len = ce_namelen(ce);
    name = ce->name;
    while ((match = *pathspec++) != NULL) {
        int matchlen = strlen(match);
        if (matchlen > len)
            continue;
        if (memcmp(name, match, matchlen))
            continue;
        if (matchlen && name[matchlen-1] == '/')
            return 1;
        if (name[matchlen] == '/' || !name[matchlen])
            return 1;
        if (!matchlen)
            return 1;
    }
    return 0;
}

/*
 * We fundamentally don't like some paths: we don't want
 * dot or dot-dot anywhere, and for obvious reasons don't
 * want to recurse into ".git" either.
 *
 * Also, we don't want double slashes or slashes at the
 * end that can make pathnames ambiguous.
 */
static int verify_dotfile(const char *rest)
{
    /*
     * The first character was '.', but that
     * has already been discarded, we now test
     * the rest.
     */
    switch (*rest) {
        /* "." is not allowed */
    case '\0': case '/':
        return 0;

        /*
         * ".git" followed by  NUL or slash is bad. This
         * shares the path end test with the ".." case.
         */
    case 'g':
        if (rest[1] != 'i')
            break;
        if (rest[2] != 't')
            break;
        rest += 2;
        /* fallthrough */
    case '.':
        if (rest[1] == '\0' || rest[1] == '/')
            return 0;
    }
    return 1;
}

int verify_path(const char *path)
{
    char c;

    goto inside;
    for (;;) {
        if (!c)
            return 1;
        if (c == '/') {
        inside:
            c = *path++;
            switch (c) {
            default:
                continue;
            case '/': case '\0':
                break;
            case '.':
                if (verify_dotfile(path))
                    continue;
            }
            return 0;
        }
        c = *path++;
    }
}

static int add_index_entry_with_check(struct index_state *istate, struct cache_entry *ce, int option)
{
    int pos;
    int ok_to_add = option & ADD_CACHE_OK_TO_ADD;
    /* int ok_to_replace = option & ADD_CACHE_OK_TO_REPLACE; */
    /* int skip_df_check = option & ADD_CACHE_SKIP_DFCHECK; */
    int new_only = option & ADD_CACHE_NEW_ONLY;

    pos = index_name_pos(istate, ce->name, ce->ce_flags);

    /* existing match? Just replace it. */
    if (pos >= 0) {
        if (!new_only)
            replace_index_entry(istate, pos, ce);
        return 0;
    }
    pos = -pos-1;

    /*
     * Inserting a merged entry ("stage 0") into the index
     * will always replace all non-merged entries..
     */
    if (pos < istate->cache_nr && ce_stage(ce) == 0) {
        while (ce_same_name(istate->cache[pos], ce)) {
            ok_to_add = 1;
            if (!remove_index_entry_at(istate, pos))
                break;
        }
    }

    if (!ok_to_add)
        return -1;
    /* if (!verify_path(ce->name)) { */
    /*     g_warning("Invalid path '%s'\n", ce->name); */
    /*     return -1; */
    /* } */

    /* if (!skip_df_check && */
    /*     check_file_directory_conflict(istate, ce, pos, ok_to_replace)) { */
    /*     if (!ok_to_replace) */
    /*         return error("'%s' appears as both a file and as a directory", */
    /*                  ce->name); */
    /*     pos = index_name_pos(istate, ce->name, ce->ce_flags); */
    /*     pos = -pos-1; */
    /* } */
    return pos + 1;
}

int add_index_entry(struct index_state *istate, struct cache_entry *ce, int option)
{
    int pos;

    if (option & ADD_CACHE_JUST_APPEND)
        pos = istate->cache_nr;
    else {
        int ret;
        ret = add_index_entry_with_check(istate, ce, option);
        if (ret <= 0)
            return ret;
        pos = ret - 1;
    }

    /* Make sure the array is big enough .. */
    if (istate->cache_nr == istate->cache_alloc) {
        istate->cache_alloc = alloc_nr(istate->cache_alloc);
        istate->cache = realloc(istate->cache,
                                istate->cache_alloc * sizeof(struct cache_entry *));
    }

    /* Add it in.. */
    istate->cache_nr++;
    if (istate->cache_nr > pos + 1)
        memmove(istate->cache + pos + 1,
                istate->cache + pos,
                (istate->cache_nr - pos - 1) * sizeof(ce));
    set_index_entry(istate, pos, ce);
    istate->cache_changed = 1;
    return 0;
}

int add_to_index(struct index_state *istate,
                 const char *path,
                 const char *full_path,
                 struct stat *st,
                 int flags,
                 SeafileCrypt *crypt,
                 IndexCB index_cb)
{
    int size, namelen, was_same;
    mode_t st_mode = st->st_mode;
    struct cache_entry *ce, *alias;
    unsigned char sha1[20];
    unsigned ce_option = CE_MATCH_IGNORE_VALID|CE_MATCH_IGNORE_SKIP_WORKTREE|CE_MATCH_RACY_IS_DIRTY;
    int add_option = (ADD_CACHE_OK_TO_ADD|ADD_CACHE_OK_TO_REPLACE);

    if (!S_ISREG(st_mode) && !S_ISLNK(st_mode) && !S_ISDIR(st_mode)) {
        g_warning("%s: can only add regular files, symbolic links or git-directories\n", path);
        return -1;
    }

    namelen = strlen(path);
    /* if (S_ISDIR(st_mode)) { */
    /*     while (namelen && path[namelen-1] == '/') */
    /*         namelen--; */
    /* } */
    size = cache_entry_size(namelen);
    ce = calloc(1, size);
    memcpy(ce->name, path, namelen);
    ce->ce_flags = namelen;
    fill_stat_cache_info(ce, st);

    ce->ce_mode = create_ce_mode(st_mode);

    alias = index_name_exists(istate, ce->name, ce_namelen(ce), 0);
    if (alias && !ce_stage(alias) && !ie_match_stat(istate, alias, st, ce_option)) {
        /* Nothing changed, really */
        free(ce);
        if (!S_ISGITLINK(alias->ce_mode))
            ce_mark_uptodate(alias);
        alias->ce_flags |= CE_ADDED;
        return 0;
    }
    if (index_cb (full_path, sha1, crypt) < 0)
        return -1;
    memcpy (ce->sha1, sha1, 20);

    ce->ce_flags |= CE_ADDED;

    /* It was suspected to be racily clean, but it turns out to be Ok */
    was_same = (alias &&
                !ce_stage(alias) &&
                !hashcmp(alias->sha1, ce->sha1) &&
                ce->ce_mode == alias->ce_mode);

    if (add_index_entry(istate, ce, add_option)) {
        g_warning("unable to add %s to index\n",path);
        return -1;
    }
    /* if (!was_same) */
    /*     g_debug("add '%s'\n", path); */
    return 0;
}

int
add_empty_dir_to_index (struct index_state *istate, const char *path)
{
    int namelen, size;
    struct cache_entry *ce;
    int add_option = (ADD_CACHE_OK_TO_ADD|ADD_CACHE_OK_TO_REPLACE);

    namelen = strlen(path);
    size = cache_entry_size(namelen);
    ce = calloc(1, size);
    memcpy(ce->name, path, namelen);
    ce->ce_flags = namelen;

    ce->ce_mode = S_IFDIR;
    /* sha1 is all-zero. */

    if (add_index_entry(istate, ce, add_option)) {
        g_warning("unable to add %s to index\n",path);
        return -1;
    }

    return 0;
}

static struct cache_entry *refresh_cache_entry(struct cache_entry *ce,
                                               const char *full_path)
{
    struct stat st;

    if (g_lstat (full_path, &st) < 0) {
        g_warning("Failed to stat %s.\n", full_path);
        return NULL;
    }
    fill_stat_cache_info(ce, &st);

    return ce;
}

struct cache_entry *make_cache_entry(unsigned int mode,
                                     const unsigned char *sha1, 
                                     const char *path, const char *full_path, 
                                     int stage, int refresh)
{
    int size, len;
    struct cache_entry *ce;

    /* if (!verify_path(path)) { */
    /*     g_warning("Invalid path '%s'", path); */
    /*     return NULL; */
    /* } */

    len = strlen(path);
    size = cache_entry_size(len);
    ce = calloc(1, size);

    hashcpy(ce->sha1, sha1);
    memcpy(ce->name, path, len);
    ce->ce_flags = create_ce_flags(len, stage);
    ce->ce_mode = create_ce_mode(mode);

    if (refresh)
        return refresh_cache_entry(ce, full_path);

    return ce;
}


#if 0
int add_file_to_index(struct index_state *istate, const char *path, int flags)
{
    struct stat st;
    if (g_lstat (path, &st)) {
        g_warning("unable to stat '%s'\n", path);
        return -1;
    }
    return add_to_index(istate, path, &st, flags);
}
#endif

static ssize_t
readn(int fd, void *vptr, size_t n)
{
    size_t    nleft;
    ssize_t    nread;
    char    *ptr;

    ptr = vptr;
    nleft = n;
    while (nleft > 0) {
        if ( (nread = read(fd, ptr, nleft)) < 0) {
            if (errno == EINTR)
                nread = 0;        /* and call read() again */
            else
                return(-1);
        } else if (nread == 0)
            break;                /* EOF */

        nleft -= nread;
        ptr   += nread;
    }
    return(n - nleft);        /* return >= 0 */
}

static ssize_t
writen(int fd, const void *vptr, size_t n)
{
    size_t        nleft;
    ssize_t        nwritten;
    const char    *ptr;

    ptr = vptr;
    nleft = n;
    while (nleft > 0) {
        if ( (nwritten = write(fd, ptr, nleft)) <= 0) {
            if (nwritten < 0 && errno == EINTR)
                nwritten = 0;        /* and call write() again */
            else
                return(-1);            /* error */
        }

        nleft -= nwritten;
        ptr   += nwritten;
    }
    return(n);
}

#define ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]))

static const char *object_type_strings[] = {
    NULL,        /* OBJ_NONE = 0 */
    "commit",    /* OBJ_COMMIT = 1 */
    "tree",        /* OBJ_TREE = 2 */
    "blob",        /* OBJ_BLOB = 3 */
    "tag",        /* OBJ_TAG = 4 */
};

static const char *typename(unsigned int type)
{
    if (type >= ARRAY_SIZE(object_type_strings))
        return NULL;
    return object_type_strings[type];
}

#if 0
static int type_from_string(const char *str)
{
    int i;

    for (i = 1; i < ARRAY_SIZE(object_type_strings); i++)
        if (!strcmp(str, object_type_strings[i]))
            return i;
    g_warning("invalid object type \"%s\"\n", str);
    return -1;
}
#endif

static void hash_sha1_file(const void *buf, unsigned long len,
                           const char *type, unsigned char *sha1)
{
    SHA_CTX c;

    /* Sha1.. */
    SHA1_Init(&c);
    SHA1_Update(&c, buf, len);
    SHA1_Final(sha1, &c);
}

static int index_mem(unsigned char *sha1, void *buf, uint64_t size,
                     enum object_type type, const char *path)
{
    if (!type)
        type = OBJ_BLOB;

    hash_sha1_file(buf, size, typename(type), sha1);
    return 0;
}

#define SMALL_FILE_SIZE (32*1024)

int index_fd(unsigned char *sha1, int fd, struct stat *st,
             enum object_type type, const char *path)
{
    int ret;
    uint64_t size = st->st_size;

    if (!size) {
        ret = index_mem(sha1, NULL, size, type, path);
    } else if (size <= SMALL_FILE_SIZE) {
        char *buf = malloc(size);
        if (size == readn(fd, buf, size)) {
            ret = index_mem(sha1, buf, size, type, path);
        } else {
            g_warning("short read %s\n", strerror(errno));
            ret = -1;
        }
        free(buf);
    } else {
        void *buf = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
        ret = index_mem(sha1, buf, size, type, path);
        munmap(buf, size);
    }
    close(fd);
    return ret;
}

int index_path(unsigned char *sha1, const char *path, struct stat *st)
{
    int fd;
    char buf[SEAF_PATH_MAX];
    int pathlen;

    switch (st->st_mode & S_IFMT) {
    case S_IFREG:
        fd = g_open (path, O_RDONLY | O_BINARY, 0);
        if (fd < 0) {
            g_warning("g_open (\"%s\"): %s\n", path, strerror(errno));
            return -1;
        }
        if (index_fd(sha1, fd, st, OBJ_BLOB, path) < 0) {
            return -1;
        }
        break;
#ifndef WIN32        
    case S_IFLNK:
        pathlen = readlink(path, buf, SEAF_PATH_MAX);
        if (pathlen != st->st_size) {
            char *errstr = strerror(errno);
            g_warning("readlink(\"%s\"): %s\n", path, errstr);
            return -1;
        }
        hash_sha1_file(buf, pathlen, typename(OBJ_BLOB), sha1);
        break;
#endif        
    default:
        g_warning("%s: unsupported file type\n", path);
        return -1;
    }
    return 0;
}

#if 0
static unsigned char write_buffer[WRITE_BUFFER_SIZE];
static unsigned long write_buffer_len;
#endif

#define WRITE_BUFFER_SIZE 8192

typedef struct {
    SHA_CTX context;
    unsigned char write_buffer[WRITE_BUFFER_SIZE];
    unsigned long write_buffer_len;
} WriteIndexInfo;

static int ce_write_flush(WriteIndexInfo *info, int fd)
{
    unsigned int buffered = info->write_buffer_len;
    if (buffered) {
        SHA1_Update(&info->context, info->write_buffer, buffered);
        if (writen(fd, info->write_buffer, buffered) != buffered)
            return -1;
        info->write_buffer_len = 0;
    }
    return 0;
}

static int ce_write(WriteIndexInfo *info, int fd, void *data, unsigned int len)
{
    while (len) {
        unsigned int buffered = info->write_buffer_len;
        unsigned int partial = WRITE_BUFFER_SIZE - buffered;
        if (partial > len)
            partial = len;
        memcpy(info->write_buffer + buffered, data, partial);
        buffered += partial;
        if (buffered == WRITE_BUFFER_SIZE) {
            info->write_buffer_len = buffered;
            if (ce_write_flush(info, fd))
                return -1;
            buffered = 0;
        }
        info->write_buffer_len = buffered;
        len -= partial;
        data = (char *) data + partial;
    }
    return 0;
}

#if 0
static int write_index_ext_header(SHA_CTX *context, int fd,
                                  unsigned int ext, unsigned int sz)
{
    ext = htonl(ext);
    sz = htonl(sz);
    return ((ce_write(context, fd, &ext, 4) < 0) ||
            (ce_write(context, fd, &sz, 4) < 0)) ? -1 : 0;
}
#endif

static int ce_flush(WriteIndexInfo *info, int fd)
{
    unsigned int left = info->write_buffer_len;

    if (left) {
        info->write_buffer_len = 0;
        SHA1_Update(&info->context, info->write_buffer, left);
    }

    /* Flush first if not enough space for SHA1 signature */
    if (left + 20 > WRITE_BUFFER_SIZE) {
        if (writen(fd, info->write_buffer, left) != left)
            return -1;
        left = 0;
    }

    /* Append the SHA1 signature at the end */
    SHA1_Final(info->write_buffer + left, &info->context);
    left += 20;
    return (writen(fd, info->write_buffer, left) != left) ? -1 : 0;
}

static void ce_smudge_racily_clean_entry(struct cache_entry *ce)
{
    /*
     * The only thing we care about in this function is to smudge the
     * falsely clean entry due to touch-update-touch race, so we leave
     * everything else as they are.  We are called for entries whose
     * ce_mtime match the index file mtime.
     *
     * Note that this actually does not do much for gitlinks, for
     * which ce_match_stat_basic() always goes to the actual
     * contents.  The caller checks with is_racy_timestamp() which
     * always says "no" for gitlinks, so we are not called for them ;-)
     */
    struct stat st;

    if (g_lstat (ce->name, &st) < 0)
        return;
    if (ce_match_stat_basic(ce, &st))
        return;

    /* This is "racily clean"; smudge it.  Note that this
     * is a tricky code.  At first glance, it may appear
     * that it can break with this sequence:
     *
     * $ echo xyzzy >frotz
     * $ git-update-index --add frotz
     * $ : >frotz
     * $ sleep 3
     * $ echo filfre >nitfol
     * $ git-update-index --add nitfol
     *
     * but it does not.  When the second update-index runs,
     * it notices that the entry "frotz" has the same timestamp
     * as index, and if we were to smudge it by resetting its
     * size to zero here, then the object name recorded
     * in index is the 6-byte file but the cached stat information
     * becomes zero --- which would then match what we would
     * obtain from the filesystem next time we stat("frotz").
     *
     * However, the second update-index, before calling
     * this function, notices that the cached size is 6
     * bytes and what is on the filesystem is an empty
     * file, and never calls us, so the cached size information
     * for "frotz" stays 6 which does not match the filesystem.
     */
    ce->ce_size = 0;
}

static int ce_write_entry(WriteIndexInfo *info, int fd, struct cache_entry *ce)
{
    int size = ondisk_ce_size(ce);
    struct ondisk_cache_entry *ondisk = calloc(1, size);
    char *name;
    int result;

    ondisk->ctime.sec = htonl(ce->ce_ctime.sec);
    ondisk->mtime.sec = htonl(ce->ce_mtime.sec);
    ondisk->ctime.nsec = htonl(ce->ce_ctime.nsec);
    ondisk->mtime.nsec = htonl(ce->ce_mtime.nsec);
    ondisk->dev  = htonl(ce->ce_dev);
    ondisk->ino  = htonl(ce->ce_ino);
    ondisk->mode = htonl(ce->ce_mode);
    ondisk->uid  = htonl(ce->ce_uid);
    ondisk->gid  = htonl(ce->ce_gid);
    ondisk->size = hton64(ce->ce_size);
    hashcpy(ondisk->sha1, ce->sha1);
    ondisk->flags = htons(ce->ce_flags);
    if (ce->ce_flags & CE_EXTENDED) {
        struct ondisk_cache_entry_extended *ondisk2;
        ondisk2 = (struct ondisk_cache_entry_extended *)ondisk;
        ondisk2->flags2 = htons((ce->ce_flags & CE_EXTENDED_FLAGS) >> 16);
        name = ondisk2->name;
    }
    else
        name = ondisk->name;
    memcpy(name, ce->name, ce_namelen(ce));

    result = ce_write(info, fd, ondisk, size);
    free(ondisk);
    return result;
}

int write_index(struct index_state *istate, int newfd)
{
    WriteIndexInfo info;
    struct cache_header hdr;
    int i, removed, extended;
    struct cache_entry **cache = istate->cache;
    int entries = istate->cache_nr;
    struct stat st;

    memset (&info, 0, sizeof(info));

    for (i = removed = extended = 0; i < entries; i++) {
        if (cache[i]->ce_flags & CE_REMOVE)
            removed++;

        /* reduce extended entries if possible */
        /* cache[i]->ce_flags &= ~CE_EXTENDED; */
        /* if (cache[i]->ce_flags & CE_EXTENDED_FLAGS) { */
        /*     extended++; */
        /*     cache[i]->ce_flags |= CE_EXTENDED; */
        /* } */
    }

    hdr.hdr_signature = htonl(CACHE_SIGNATURE);
    /* for extended format, increase version so older git won't try to read it */
    hdr.hdr_version = htonl(extended ? 3 : 2);
    hdr.hdr_entries = htonl(entries - removed);

    SHA1_Init(&info.context);
    if (ce_write(&info, newfd, &hdr, sizeof(hdr)) < 0)
        return -1;

    for (i = 0; i < entries; i++) {
        struct cache_entry *ce = cache[i];
        if (ce->ce_flags & CE_REMOVE)
            continue;
        /* if (!ce_uptodate(ce) && is_racy_timestamp(istate, ce)) */
        /*     ce_smudge_racily_clean_entry(ce); */
        if (ce_write_entry(&info, newfd, ce) < 0)
            return -1;
    }

#if 0
    /* Write extension data here */
    if (istate->cache_tree) {
        struct strbuf sb = STRBUF_INIT;

        cache_tree_write(&sb, istate->cache_tree);
        err = write_index_ext_header(&c, newfd, CACHE_EXT_TREE, sb.len) < 0
            || ce_write(&c, newfd, sb.buf, sb.len) < 0;
        strbuf_release(&sb);
        if (err)
            return -1;
    }
    if (istate->resolve_undo) {
        struct strbuf sb = STRBUF_INIT;

        resolve_undo_write(&sb, istate->resolve_undo);
        err = write_index_ext_header(&c, newfd, CACHE_EXT_RESOLVE_UNDO,
                                     sb.len) < 0
            || ce_write(&c, newfd, sb.buf, sb.len) < 0;
        strbuf_release(&sb);
        if (err)
            return -1;
    }
#endif

    if (ce_flush(&info, newfd) || fstat(newfd, &st))
        return -1;
    istate->timestamp.sec = (unsigned int)st.st_mtime;
    istate->timestamp.nsec = 0;
    return 0;
}

int discard_index(struct index_state *istate)
{
    int i;
    for (i = 0; i < istate->cache_nr; ++i)
        free (istate->cache[i]);

    istate->cache_nr = 0;
    istate->cache_changed = 0;
    istate->timestamp.sec = 0;
    istate->timestamp.nsec = 0;
    istate->name_hash_initialized = 0;
    free_hash(&istate->name_hash);
    /* cache_tree_free(&(istate->cache_tree)); */
    /* free(istate->alloc); */
    free(istate->cache);
    istate->alloc = NULL;
    istate->initialized = 0;

    /* no need to throw away allocated active_cache */
    return 0;
}
