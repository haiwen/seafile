#include "common.h"

#include <ccnet.h>

#include "index/index.h"
#include "unpack-trees.h"
#include "diff.h"
#include "status.h"

#include "seafile-session.h"
#include "repo-mgr.h"
#include "branch-mgr.h"
#include "commit-mgr.h"
#include "vc-utils.h"

#define DIFF_CHANGED 0x3
#define NUM_CANDIDATE_PER_DST 4

const unsigned char null_sha1[20];

static struct diff_filespec *alloc_filespec(const char *path);
static void fill_filespec(struct diff_filespec *spec, const unsigned char *sha1,
                   unsigned short mode);

struct diff_score {
    int src; /* index in rename_src */
    int dst; /* index in rename_dst */
    unsigned short score;
    short name_score;
};

/*
 * Idea here is very simple.
 *
 * Almost all data we are interested in are text, but sometimes we have
 * to deal with binary data.  So we cut them into chunks delimited by
 * LF byte, or 64-byte sequence, whichever comes first, and hash them.
 *
 * For those chunks, if the source buffer has more instances of it
 * than the destination buffer, that means the difference are the
 * number of bytes not copied from source to destination.  If the
 * counts are the same, everything was copied from source to
 * destination.  If the destination has more, everything was copied,
 * and destination added more.
 *
 * We are doing an approximation so we do not really have to waste
 * memory by actually storing the sequence.  We just hash them into
 * somewhere around 2^16 hashbuckets and count the occurrences.
 */

/* Wild guess at the initial hash size */
#define INITIAL_HASH_SIZE 9

/* We leave more room in smaller hash but do not let it
 * grow to have unused hole too much.
 */
#define INITIAL_FREE(sz_log2) ((1<<(sz_log2))*(sz_log2-3)/(sz_log2))

/* A prime rather carefully chosen between 2^16..2^17, so that
 * HASHBASE < INITIAL_FREE(17).  We want to keep the maximum hashtable
 * size under the current 2<<17 maximum, which can hold this many
 * different values before overflowing to hashtable of size 2<<18.
 */
#define HASHBASE 107927

struct spanhash {
    unsigned int hashval;
    unsigned int cnt;
};
struct spanhash_top {
    int alloc_log2;
    int free;
    struct spanhash data[0];
};

static struct spanhash_top *spanhash_rehash(struct spanhash_top *orig)
{
    struct spanhash_top *new;
    int i;
    int osz = 1 << orig->alloc_log2;
    int sz = osz << 1;

    new = malloc(sizeof(*orig) + sizeof(struct spanhash) * sz);
    new->alloc_log2 = orig->alloc_log2 + 1;
    new->free = INITIAL_FREE(new->alloc_log2);
    memset(new->data, 0, sizeof(struct spanhash) * sz);
    for (i = 0; i < osz; i++) {
        struct spanhash *o = &(orig->data[i]);
        int bucket;
        if (!o->cnt)
            continue;
        bucket = o->hashval & (sz - 1);
        while (1) {
            struct spanhash *h = &(new->data[bucket++]);
            if (!h->cnt) {
                h->hashval = o->hashval;
                h->cnt = o->cnt;
                new->free--;
                break;
            }
            if (sz <= bucket)
                bucket = 0;
        }
    }
    free(orig);
    return new;
}

static struct spanhash_top *add_spanhash(struct spanhash_top *top,
        unsigned int hashval, int cnt)
{
    int bucket, lim;
    struct spanhash *h;

    lim = (1 << top->alloc_log2);
    bucket = hashval & (lim - 1);
    while (1) {
        h = &(top->data[bucket++]);
        if (!h->cnt) {
            h->hashval = hashval;
            h->cnt = cnt;
            top->free--;
            if (top->free < 0)
                return spanhash_rehash(top);
            return top;
        }
        if (h->hashval == hashval) {
            h->cnt += cnt;
            return top;
        }
        if (lim <= bucket)
            bucket = 0;
    }
}

static int spanhash_cmp(const void *a_, const void *b_)
{
    const struct spanhash *a = a_;
    const struct spanhash *b = b_;

    /* A count of zero compares at the end.. */
    if (!a->cnt)
        return !b->cnt ? 0 : 1;
    if (!b->cnt)
        return -1;
    return a->hashval < b->hashval ? -1 :
        a->hashval > b->hashval ? 1 : 0;
}

static struct spanhash_top *hash_chars(struct diff_filespec *one)
{
    int i, n;
    unsigned int accum1, accum2, hashval;
    struct spanhash_top *hash;
    unsigned char *buf = one->data;
    unsigned int sz = one->size;
    int is_text = 1;/*!diff_filespec_is_binary(one);*/

    i = INITIAL_HASH_SIZE;
    hash = malloc(sizeof(*hash) + sizeof(struct spanhash) * (1<<i));
    hash->alloc_log2 = i;
    hash->free = INITIAL_FREE(i);
    memset(hash->data, 0, sizeof(struct spanhash) * (1<<i));

    n = 0;
    accum1 = accum2 = 0;
    while (sz) {
        unsigned int c = *buf++;
        unsigned int old_1 = accum1;
        sz--;

        /* Ignore CR in CRLF sequence if text */
        if (is_text && c == '\r' && sz && *buf == '\n')
            continue;

        accum1 = (accum1 << 7) ^ (accum2 >> 25);
        accum2 = (accum2 << 7) ^ (old_1 >> 25);
        accum1 += c;
        if (++n < 64 && c != '\n')
            continue;
        hashval = (accum1 + accum2 * 0x61) % HASHBASE;
        hash = add_spanhash(hash, hashval, n);
        n = 0;
        accum1 = accum2 = 0;
    }
    qsort(hash->data,
            1ul << hash->alloc_log2,
            sizeof(hash->data[0]),
            spanhash_cmp);
    return hash;
}

int diffcore_count_changes(struct diff_filespec *src,
        struct diff_filespec *dst,
        void **src_count_p,
        void **dst_count_p,
        unsigned long delta_limit,
        unsigned long *src_copied,
        unsigned long *literal_added)
{
    struct spanhash *s, *d;
    struct spanhash_top *src_count, *dst_count;
    unsigned long sc, la;

    src_count = dst_count = NULL;
    if (src_count_p)
        src_count = *src_count_p;
    if (!src_count) {
        src_count = hash_chars(src);
        if (src_count_p)
            *src_count_p = src_count;
    }
    if (dst_count_p)
        dst_count = *dst_count_p;
    if (!dst_count) {
        dst_count = hash_chars(dst);
        if (dst_count_p)
            *dst_count_p = dst_count;
    }
    sc = la = 0;

    s = src_count->data;
    d = dst_count->data;
    for (;;) {
        unsigned dst_cnt, src_cnt;
        if (!s->cnt)
            break; /* we checked all in src */
        while (d->cnt) {
            if (d->hashval >= s->hashval)
                break;
            la += d->cnt;
            d++;
        }
        src_cnt = s->cnt;
        dst_cnt = 0;
        if (d->cnt && d->hashval == s->hashval) {
            dst_cnt = d->cnt;
            d++;
        }
        if (src_cnt < dst_cnt) {
            la += dst_cnt - src_cnt;
            sc += src_cnt;
        }
        else
            sc += dst_cnt;
        s++;
    }
    while (d->cnt) {
        la += d->cnt;
        d++;
    }

    if (!src_count_p)
        free(src_count);
    if (!dst_count_p)
        free(dst_count);
    *src_copied = sc;
    *literal_added = la;
    return 0;
}

static int estimate_similarity(struct diff_filespec *src,
        struct diff_filespec *dst,
        int minimum_score)
{
    /* src points at a file that existed in the original tree (or
     * optionally a file in the destination tree) and dst points
     * at a newly created file.  They may be quite similar, in which
     * case we want to say src is renamed to dst or src is copied into
     * dst, and then some edit has been applied to dst.
     *
     * Compare them and return how similar they are, representing
     * the score as an integer between 0 and MAX_SCORE.
     *
     * When there is an exact match, it is considered a better
     * match than anything else; the destination does not even
     * call into this function in that case.
     */
    unsigned long max_size, delta_size, base_size, src_copied, literal_added;
    unsigned long delta_limit;
    int score;

    /* We deal only with regular files.  Symlink renames are handled
     * only when they are exact matches --- in other words, no edits
     * after renaming.
     */
    if (!S_ISREG(src->mode) || !S_ISREG(dst->mode))
        return 0;

    /*
     * Need to check that source and destination sizes are
     * filled in before comparing them.
     *
     * If we already have "cnt_data" filled in, we know it's
     * all good (avoid checking the size for zero, as that
     * is a possible size - we really should have a flag to
     * say whether the size is valid or not!)
     */
#if 0 
    if (!src->cnt_data && diff_populate_filespec(src, 1))
        return 0;
    if (!dst->cnt_data && diff_populate_filespec(dst, 1))
        return 0;
#endif

    max_size = ((src->size > dst->size) ? src->size : dst->size);
    base_size = ((src->size < dst->size) ? src->size : dst->size);
    delta_size = max_size - base_size;

    /* We would not consider edits that change the file size so
     * drastically.  delta_size must be smaller than
     * (MAX_SCORE-minimum_score)/MAX_SCORE * min(src->size, dst->size).
     *
     * Note that base_size == 0 case is handled here already
     * and the final score computation below would not have a
     * divide-by-zero issue.
     */
    if (max_size * (MAX_SCORE-minimum_score) < delta_size * MAX_SCORE)
        return 0;

#if 0 
    if (!src->cnt_data && diff_populate_filespec(src, 0))
        return 0;
    if (!dst->cnt_data && diff_populate_filespec(dst, 0))
        return 0;
#endif

    delta_limit = (unsigned long)
        (base_size * (MAX_SCORE-minimum_score) / MAX_SCORE);
    diffcore_count_changes(src, dst, &src->cnt_data, &dst->cnt_data,
            delta_limit, &src_copied, &literal_added);

    /* How similar are they?
     * what percentage of material in dst are from source?
     */
    if (!dst->size)
        score = 0; /* should not happen */
    else
        score = (int)(src_copied * MAX_SCORE / max_size);
    return score;
}

struct file_similarity {
    int src_dst, index;
    struct diff_filespec *filespec;
    struct file_similarity *next;
};

static void free_similarity_list(struct file_similarity *p)
{
    while (p) {
        struct file_similarity *entry = p;
        p = p->next;
        free(entry);
    }
}

static struct diff_rename_dst {
    struct diff_filespec *two;
    struct diff_filepair *pair;
} *rename_dst;
static int rename_dst_nr, rename_dst_alloc;

static struct diff_rename_dst *locate_rename_dst(struct diff_filespec *two,
        int insert_ok)
{
    int first, last;

    first = 0;
    last = rename_dst_nr;
    while (last > first) {
        int next = (last + first) >> 1;
        struct diff_rename_dst *dst = &(rename_dst[next]);
        int cmp = strcmp(two->path, dst->two->path);
        if (!cmp)
            return dst;
        if (cmp < 0) {
            last = next;
            continue;
        }
        first = next + 1;
    }
    /* not found */
    if (!insert_ok)
        return NULL;
    /* insert to make it at "first" */
    if (rename_dst_alloc <= rename_dst_nr) {
        rename_dst_alloc = alloc_nr(rename_dst_alloc);
        rename_dst = realloc(rename_dst,
                rename_dst_alloc * sizeof(*rename_dst));
    }
    rename_dst_nr++;
    if (first < rename_dst_nr)
        memmove(rename_dst + first + 1, rename_dst + first,
                (rename_dst_nr - first - 1) * sizeof(*rename_dst));
    rename_dst[first].two = alloc_filespec(two->path);
    fill_filespec(rename_dst[first].two, two->sha1, two->mode);
    rename_dst[first].pair = NULL;
    return &(rename_dst[first]);
}

static struct diff_rename_src {
    struct diff_filepair *p;
    unsigned short score; /* to remember the break score */
} *rename_src;
static int rename_src_nr, rename_src_alloc;

static struct diff_rename_src *register_rename_src(struct diff_filepair *p)
{
    int first, last;
    struct diff_filespec *one = p->one;
    unsigned short score = p->score;

    first = 0;
    last = rename_src_nr;
    while (last > first) {
        int next = (last + first) >> 1;
        struct diff_rename_src *src = &(rename_src[next]);
        int cmp = strcmp(one->path, src->p->one->path);
        if (!cmp)
            return src;
        if (cmp < 0) {
            last = next;
            continue;
        }
        first = next + 1;
    }

    /* insert to make it at "first" */
    if (rename_src_alloc <= rename_src_nr) {
        rename_src_alloc = alloc_nr(rename_src_alloc);
        rename_src = realloc(rename_src,
                rename_src_alloc * sizeof(*rename_src));
    }
    rename_src_nr++;
    if (first < rename_src_nr)
        memmove(rename_src + first + 1, rename_src + first,
                (rename_src_nr - first - 1) * sizeof(*rename_src));
    rename_src[first].p = p;
    rename_src[first].score = score;
    return &(rename_src[first]);
}

static unsigned int hash_filespec(struct diff_filespec *filespec)
{
    unsigned int hash;

    memcpy(&hash, filespec->sha1, sizeof(hash)); 
    return hash;
}

static void insert_file_table(struct hash_table *table, int src_dst, int index, struct diff_filespec *filespec)
{
    void **pos;
    unsigned int hash;
    struct file_similarity *entry = malloc(sizeof(*entry));

    entry->src_dst = src_dst;
    entry->index = index;
    entry->filespec = filespec;
    entry->next = NULL;

    hash = hash_filespec(filespec);
    pos = insert_hash(hash, entry, table);

    /* We already had an entry there? */
    if (pos) {
        entry->next = *pos;
        *pos = entry;
    }
}

static int basename_same(struct diff_filespec *src, struct diff_filespec *dst)
{
    int src_len = strlen(src->path), dst_len = strlen(dst->path);
    while (src_len && dst_len) {
        char c1 = src->path[--src_len];
        char c2 = dst->path[--dst_len];
        if (c1 != c2)
            return 0;
        if (c1 == '/')
            return 1;
    }
    return (!src_len || src->path[src_len - 1] == '/') &&
        (!dst_len || dst->path[dst_len - 1] == '/');
}

static void record_rename_pair(int dst_index, int src_index, int score)
{
    struct diff_filespec *src, *dst;
    struct diff_filepair *dp;

    if (rename_dst[dst_index].pair) {
        g_warning("dst already matched.");
        return;
    }

    src = rename_src[src_index].p->one;
    src->rename_used++;
    src->count++;

    dst = rename_dst[dst_index].two;
    dst->count++;

    /*dp = diff_queue(NULL, src, dst);*/
    dp = calloc(1, sizeof(*dp));
    dp->one = src;
    dp->two = dst;
    dp->renamed_pair = 1;
    if (!strcmp(src->path, dst->path))
        dp->score = rename_src[src_index].score;
    else
        dp->score = score;
    rename_dst[dst_index].pair = dp;
}

static int find_identical_files(struct file_similarity *src,
        struct file_similarity *dst,
        struct diff_options *options)
{
    int renames = 0;

    /*
     * Walk over all the destinations ...
     */
    do {
        struct diff_filespec *target = dst->filespec;
        struct file_similarity *p, *best;
        int i =100, best_score = -1;

        /*
         * .. to find the best source match
         */
        best = NULL;
        for (p = src; p; p = p->next) {
            int score;
            struct diff_filespec *source = p->filespec;

            /* False hash collision? */
            if (hashcmp(source->sha1, target->sha1))
                continue;
            /* Non-regular files? If so, the modes must match! */
            if (!S_ISREG(source->mode) || !S_ISREG(target->mode)) {
                if (source->mode != target->mode)
                    continue;
            }
            /* Give higher scores to sources that haven't been used already */
            score = !source->rename_used;
            if (source->rename_used /*&&options->detect_rename != DIFF_DETECT_COPY*/)
                continue;
            score += basename_same(source, target);
            if (score > best_score) {
                best = p;
                best_score = score;
                if (score == 2)
                    break;
            }

            /* Too many identical alternatives? Pick one */
            if (!--i)
                break;
        }
        if (best) {
            record_rename_pair(dst->index, best->index, MAX_SCORE);
            renames++;
        }
    } while ((dst = dst->next) != NULL);
    return renames;
}

static int find_same_files(void *ptr, void *data)
{
    int ret;
    struct file_similarity *p = ptr;
    struct file_similarity *src = NULL, *dst = NULL;
    struct diff_options *options = data;

    /* Split the hash list up into sources and destinations */
    do {
        struct file_similarity *entry = p;
        p = p->next;
        if (entry->src_dst < 0) {
            entry->next = src;
            src = entry;
        } else {
            entry->next = dst;
            dst = entry;
        }
    } while (p);

    /*
     * If we have both sources *and* destinations, see if
     * we can match them up
     */
    ret = (src && dst) ? find_identical_files(src, dst, options) : 0;

    /* Free the hashes and return the number of renames found */
    free_similarity_list(src);
    free_similarity_list(dst);
    return ret;
}

/*
 * Find exact renames first.
 *
 * The first round matches up the up-to-date entries,
 * and then during the second round we try to match
 * cache-dirty entries as well.
 */
static int find_exact_renames(struct diff_options *options)
{
    int i;
    struct hash_table file_table;

    init_hash(&file_table);
    for (i = 0; i < rename_src_nr; i++)
        insert_file_table(&file_table, -1, i, rename_src[i].p->one);

    for (i = 0; i < rename_dst_nr; i++)
        insert_file_table(&file_table, 1, i, rename_dst[i].two);

    /* Find the renames */
    i = for_each_hash(&file_table, find_same_files, options);

    /* .. and free the hash data structure */
    free_hash(&file_table);

    return i;
}

/*
 * We sort the rename similarity matrix with the score, in descending
 * order (the most similar first).
 */
static int score_compare(const void *a_, const void *b_)
{
    const struct diff_score *a = a_, *b = b_;

    /* sink the unused ones to the bottom */
    if (a->dst < 0)
        return (0 <= b->dst);
    else if (b->dst < 0)
        return -1;

    if (a->score == b->score)
        return b->name_score - a->name_score;

    return b->score - a->score;
}

static void record_if_better(struct diff_score m[], struct diff_score *o)
{
    int i, worst;

    /* find the worst one */
    worst = 0;
    for (i = 1; i < NUM_CANDIDATE_PER_DST; i++)
        if (score_compare(&m[i], &m[worst]) > 0)
            worst = i;

    /* is it better than the worst one? */
    if (score_compare(&m[worst], o) > 0)
        m[worst] = *o;
}

static int find_renames(struct diff_score *mx, int dst_cnt, int minimum_score, int copies)
{
    int count = 0, i;

    for (i = 0; i < dst_cnt * NUM_CANDIDATE_PER_DST; i++) {
        struct diff_rename_dst *dst;

        if ((mx[i].dst < 0) ||
                (mx[i].score < minimum_score))
            break; /* there is no more usable pair. */
        dst = &rename_dst[mx[i].dst];
        if (dst->pair)
            continue; /* already done, either exact or fuzzy. */
        if (!copies && rename_src[mx[i].src].p->one->rename_used)
            continue;
        record_rename_pair(mx[i].dst, mx[i].src, mx[i].score);
        count++;
    }
    return count;
}

int diff_unmodified_pair(struct diff_filepair *p)
{
    /* This function is written stricter than necessary to support
     * the currently implemented transformers, but the idea is to
     * let transformers to produce diff_filepairs any way they want,
     * and filter and clean them up here before producing the output.
     */
    struct diff_filespec *one = p->one, *two = p->two;

    if (DIFF_PAIR_UNMERGED(p))
        return 0; /* unmerged is interesting */

    /* deletion, addition, mode or type change
     * and rename are all interesting.
     */
    if (DIFF_FILE_VALID(one) != DIFF_FILE_VALID(two) ||
            DIFF_PAIR_MODE_CHANGED(p) ||
            strcmp(one->path, two->path))
        return 0;

    /* both are valid and point at the same path.  that is, we are
     * dealing with a change.
     */
    if (one->sha1_valid && two->sha1_valid &&
            !hashcmp(one->sha1, two->sha1) &&
            !one->dirty_submodule && !two->dirty_submodule)
        return 1; /* no change */
    if (!one->sha1_valid && !two->sha1_valid)
        return 1; /* both look at the same file on the filesystem. */
    return 0;
}

void diff_free_filespec_blob(struct diff_filespec *s)
{
    if (s->should_free)
        free(s->data);
    else if (s->should_munmap)
        munmap(s->data, s->size);

    if (s->should_free || s->should_munmap) {
        s->should_free = s->should_munmap = 0;
        s->data = NULL;
    }
}

void diff_free_filespec_data(struct diff_filespec *s)
{
    diff_free_filespec_blob(s);
    free(s->cnt_data);
    s->cnt_data = NULL;
}

void free_filespec(struct diff_filespec *spec)
{
    if (!--spec->count) {
        diff_free_filespec_data(spec);
        free(spec);
    }
}

void diff_free_filepair(struct diff_filepair *p)
{
    free_filespec(p->one);
    free_filespec(p->two);
    free(p);
}

void diff_rename(struct diff_options *options)
{
    int detect_rename = DIFF_DETECT_RENAME; /* we don't need to detect copy */
    int minimum_score = DEFAULT_RENAME_SCORE;
    int i, j, rename_count;
    int num_create, dst_cnt;
    struct diff_score *mx;
    GList *ptr, *outlist = NULL;

    for (ptr = options->df_list; ptr; ptr = ptr->next) {
        struct diff_filepair *p = (struct diff_filepair *)ptr->data;
        if (!DIFF_FILE_VALID(p->one)) {
            if (!DIFF_FILE_VALID(p->two))
                continue; /* unmerged */
            else
                locate_rename_dst(p->two, 1);
        } else if (!DIFF_PAIR_UNMERGED(p) && !DIFF_FILE_VALID(p->two)) {
            /*
             * If the source is a broken "delete", and
             * they did not really want to get broken,
             * that means the source actually stays.
             * So we increment the "rename_used" score
             * by one, to indicate ourselves as a user
             */
            if (p->broken_pair && !p->score)
                p->one->rename_used++;
            register_rename_src(p);
        } else if (detect_rename == DIFF_DETECT_COPY) {
            /*
             * Increment the "rename_used" score by
             * one, to indicate ourselves as a user.
             */
            p->one->rename_used++;
            register_rename_src(p);
        }
    }
    if (rename_dst_nr == 0 || rename_src_nr == 0)
        goto cleanup; /* nothing to do */

    /*
     * We really want to cull the candidates list early
     * with cheap tests in order to avoid doing deltas.
     */
    rename_count = find_exact_renames(options);

    /* Did we only want exact renames? */
    if (minimum_score == MAX_SCORE)
        goto cleanup;

    /*
     * Calculate how many renames are left (but all the source
     * files still remain as options for rename/copies!)
     */
    num_create = (rename_dst_nr - rename_count);

    /* All done? */
    if (!num_create)
        goto cleanup;

    mx = calloc(num_create * NUM_CANDIDATE_PER_DST, sizeof(*mx));
    for (dst_cnt = i = 0; i < rename_dst_nr; i++) {
        struct diff_filespec *two = rename_dst[i].two;
        struct diff_score *m;

        if (rename_dst[i].pair)
            continue; /* dealt with exact match already. */

        m = &mx[dst_cnt * NUM_CANDIDATE_PER_DST];
        for (j = 0; j < NUM_CANDIDATE_PER_DST; j++)
            m[j].dst = -1;

        for (j = 0; j < rename_src_nr; j++) {
            struct diff_filespec *one = rename_src[j].p->one;
            struct diff_score this_src;

#if 0 
            if (skip_unmodified &&
                    diff_unmodified_pair(rename_src[j].p))
                continue;
#endif

            this_src.score = estimate_similarity(one, two,
                    minimum_score);
            this_src.name_score = basename_same(one, two);
            this_src.dst = i;
            this_src.src = j;
            record_if_better(m, &this_src);
            /*
             * Once we run estimate_similarity,
             * We do not need the text anymore.
             */
            diff_free_filespec_blob(one);
            diff_free_filespec_blob(two);
        }
        dst_cnt++;
    }

    /* cost matrix sorted by most to least similar pair */
    qsort(mx, dst_cnt * NUM_CANDIDATE_PER_DST, sizeof(*mx), score_compare);

    rename_count += find_renames(mx, dst_cnt, minimum_score, 0);
#if 0	
    if (detect_rename == DIFF_DETECT_COPY)
        rename_count += find_renames(mx, dst_cnt, minimum_score, 1);
#endif
    free(mx);

cleanup:
    /* At this point, we have found some renames and copies and they
     * are recorded in rename_dst. The original list is still in *q.
     */
    for (ptr = options->df_list; ptr; ptr = ptr->next) {
        struct diff_filepair *p = ptr->data;
        struct diff_filepair *pair_to_free = NULL;

        if (DIFF_PAIR_UNMERGED(p)) {
            outlist = g_list_prepend(outlist, p);
        } else if (!DIFF_FILE_VALID(p->one) && DIFF_FILE_VALID(p->two)) {
            /*
             * Creation
             *
             * We could output this create record if it has
             * not been turned into a rename/copy already.
             */
            struct diff_rename_dst *dst =
                locate_rename_dst(p->two, 0);
            if (dst && dst->pair) {
                dst->pair->stage = p->stage;
                outlist = g_list_prepend(outlist, dst->pair);
            } else
                /* no matching rename/copy source, so
                 * record this as a creation.
                 */
                outlist = g_list_prepend(outlist, p);
        } else if (DIFF_FILE_VALID(p->one) && !DIFF_FILE_VALID(p->two)) {
            /*
             * Deletion
             *
             * We could output this delete record if:
             *
             * (1) this is a broken delete and the counterpart
             *     broken create remains in the output; or
             * (2) this is not a broken delete, and rename_dst
             *     does not have a rename/copy to move p->one->path
             *     out of existence.
             *
             * Otherwise, the counterpart broken create
             * has been turned into a rename-edit; or
             * delete did not have a matching create to
             * begin with.
             */
            if (DIFF_PAIR_BROKEN(p)) {
                /* broken delete */
                struct diff_rename_dst *dst =
                    locate_rename_dst(p->one, 0);
                if (dst && dst->pair)
                    /* counterpart is now rename/copy */
                    pair_to_free = p;
            } else {
                if (p->one->rename_used)
                    /* this path remains */
                    pair_to_free = p;
            }

            if (pair_to_free)
                ;
            else
                outlist = g_list_prepend(outlist, p);
        } else if (!diff_unmodified_pair(p))
            /* all the usual ones need to be kept */
            outlist = g_list_prepend(outlist, p);
        else
            /* no need to keep unmodified pairs */
            pair_to_free = p;

        if (pair_to_free)
            diff_free_filepair(pair_to_free);
    }

    options->df_list = outlist;

    for (i = 0; i < rename_dst_nr; i++)
        free_filespec(rename_dst[i].two);

    free(rename_dst);
    rename_dst = NULL;
    rename_dst_nr = rename_dst_alloc = 0;
    free(rename_src);
    rename_src = NULL;
    rename_src_nr = rename_src_alloc = 0;
    return;
}

void diff_resolve_rename_copy(struct diff_options *options)
{
    struct diff_filepair *p;
    GList *ptr;

    for (ptr = options->df_list; ptr; ptr = ptr->next) {
        p = (struct diff_filepair *)ptr->data;
        p->status = 0; /* undecided */
        if (DIFF_PAIR_UNMERGED(p))
            p->status = DIFF_STATUS_UNMERGED;
        else if (!DIFF_FILE_VALID(p->one))
            p->status = DIFF_STATUS_ADDED;
        else if (!DIFF_FILE_VALID(p->two))
            p->status = DIFF_STATUS_DELETED;
        else if (DIFF_PAIR_TYPE_CHANGED(p))
            p->status = DIFF_STATUS_TYPE_CHANGED;

        /* from this point on, we are dealing with a pair
         * whose both sides are valid and of the same type, i.e.
         * either in-place edit or rename/copy edit.
         */
        else if (DIFF_PAIR_RENAME(p)) {
            /*
             * A rename might have re-connected a broken
             * pair up, causing the pathnames to be the
             * same again. If so, that's not a rename at
             * all, just a modification..
             *
             * Otherwise, see if this source was used for
             * multiple renames, in which case we decrement
             * the count, and call it a copy.
             */
            if (!strcmp(p->one->path, p->two->path))
                p->status = DIFF_STATUS_MODIFIED;
            else if (--p->one->rename_used > 0)
                p->status = DIFF_STATUS_COPIED;
            else
                p->status = DIFF_STATUS_RENAMED;
        }
        else if (hashcmp(p->one->sha1, p->two->sha1) ||
                 p->one->mode != p->two->mode ||
                 p->one->dirty_submodule ||
                 p->two->dirty_submodule ||
                 is_null_sha1(p->one->sha1))
            p->status = DIFF_STATUS_MODIFIED;
        else {
            /* This is a "no-change" entry and should not
             * happen anymore, but prepare for broken callers.
             */
            g_warning("feeding unmodified %s to diffcore",
                      p->one->path);
            p->status = DIFF_STATUS_UNKNOWN;
        }
    }
}

static void fill_filespec(struct diff_filespec *spec, const unsigned char *sha1,
                   unsigned short mode)
{
    if (mode) {
        spec->mode = canon_mode(mode);
        hashcpy(spec->sha1, sha1);
        spec->sha1_valid = !is_null_sha1(sha1);
    }
}

struct diff_filepair *diff_queue(GList **queue,
                                 struct diff_filespec *one,
                                 struct diff_filespec *two)
{
    struct diff_filepair *dp = calloc(1, sizeof(*dp));
    dp->one = one;
    dp->two = two;
    *queue = g_list_prepend(*queue, dp);
    return dp;
}

struct diff_filespec *alloc_filespec(const char *path)
{
    int namelen = strlen(path);
    struct diff_filespec *spec = malloc(sizeof(*spec) + namelen + 1);

    memset(spec, 0, sizeof(*spec));
    spec->path = (char *)(spec + 1);
    memcpy(spec->path, path, namelen+1);
    spec->count = 1;
    spec->is_binary = -1;
    return spec;
}

struct diff_filepair *diff_unmerge(struct diff_options *options, const char *path)
{
    struct diff_filepair *pair;
    struct diff_filespec *one, *two;

    one = alloc_filespec(path);
    two = alloc_filespec(path);
    pair = diff_queue(&options->df_list, one, two);
    pair->is_unmerged = 1;
    return pair;
}

struct diff_filepair *diff_addremove(struct diff_options *options,
        int addremove, unsigned mode,
        const unsigned char *sha1,
        const char *concatpath, unsigned dirty_submodule)
{
    struct diff_filespec *one, *two;

    if (S_ISGITLINK(mode)/* && is_submodule_ignored(concatpath, options)*/)
        return NULL;

    one = alloc_filespec(concatpath);
    two = alloc_filespec(concatpath);

    if (addremove != '+')
        fill_filespec(one, sha1, mode);
    if (addremove != '-') {
        fill_filespec(two, sha1, mode);
        two->dirty_submodule = dirty_submodule;
    }

    return diff_queue(&options->df_list, one, two);
}

struct diff_filepair *diff_change(struct diff_options *options,
        unsigned old_mode, unsigned new_mode,
        const unsigned char *old_sha1,
        const unsigned char *new_sha1,
        const char *concatpath,
        unsigned old_dirty_submodule, unsigned new_dirty_submodule)
{
    struct diff_filespec *one, *two;

    if (S_ISGITLINK(old_mode) && S_ISGITLINK(new_mode)/* &&
        is_submodule_ignored(concatpath, options)*/)
        return NULL;

    one = alloc_filespec(concatpath);
    two = alloc_filespec(concatpath);
    fill_filespec(one, old_sha1, old_mode);
    fill_filespec(two, new_sha1, new_mode);
    one->dirty_submodule = old_dirty_submodule;
    two->dirty_submodule = new_dirty_submodule;

    return diff_queue(&options->df_list, one, two);
}

static void show_entry(struct diff_options *opt, const char *prefix,
                       struct name_entry *entry, const char *base);

/* A whole sub-tree went away or appeared */
static void show_tree(struct diff_options *opt, const char *prefix,
                      struct tree_desc *desc, const char *base)
{
    GList *ptr;
    struct name_entry entry;

    g_assert(desc);

    for (ptr = desc->tree->entries; ptr; ptr = ptr->next) {
        SeafDirent *dent = (SeafDirent *)ptr->data;

        memset(&entry, 0, sizeof(entry));
        hex_to_rawdata(dent->id, entry.sha1, 20);
        entry.path = dent->name;
        entry.pathlen = dent->name_len;
        entry.mode = dent->mode;

        show_entry(opt, prefix, &entry, base);
    }
}

/* A file entry went away or appeared */
static void show_entry(struct diff_options *opt, const char *prefix,
                       struct name_entry *entry, const char *base)
{
    unsigned mode;
    const char *path;
    const unsigned char *sha1;
    char *newbase;

    mode = entry->mode;
    path = entry->path;
    sha1 = entry->sha1;

    if (S_ISDIR(mode)) {
        struct tree_desc inner;
        char hex1[41];

        rawdata_to_hex(sha1, (char *)hex1, 20);
        fill_tree_descriptor(&inner, hex1);
        /* g_build_filename use the default path seperator of the current os
         * But in index, only "/" should be used, so we use g_build_path here
         * instead of g_build_filename and set the path seperator to be "/"
         */
        newbase = g_build_path(PATH_SEPERATOR, base, path, NULL);
        show_tree(opt, prefix, &inner, newbase);
        g_free(newbase);
    } else {
        newbase = g_build_path(PATH_SEPERATOR, base, path, NULL);
        diff_addremove(opt, prefix[0], mode, sha1, newbase, 0);
        g_free(newbase);
    }
}

static int diff_tree_sha1(const char *old, const char *new,
                          const char *base, struct diff_options *opt);
static int compare_tree_entry(struct name_entry *e1, struct name_entry *e2,
                              const char *base, struct diff_options *opt)
{
    unsigned mode1, mode2;
    const char *path1, *path2;
    const unsigned char *sha1, *sha2;
    int cmp, pathlen1, pathlen2;
    char *newbase;

    mode1 = e1->mode;
    path1 = e1->path;
    sha1 = e1->sha1;
    pathlen1 = e1->pathlen;

    mode2 = e2->mode;
    path2 = e2->path;
    sha2 = e2->sha1;
    pathlen2 = e2->pathlen;

    cmp = memcmp(path1, path2, pathlen1 < pathlen2 ? pathlen1 : pathlen2);
    if (cmp < 0) {
        show_entry(opt, "-", e1, base);
        return -1;
    }
    if (cmp > 0) {
        show_entry(opt, "+", e1, base);
        return 1;
    }
    if (!hashcmp(sha1, sha2) && mode1 == mode2)
        return 0;

    /*
     * If the filemode has changed to/from a directory from/to a regular
     * file, we need to consider it a remove and an add.
     */
    if (S_ISDIR(mode1) != S_ISDIR(mode2)) {
        newbase = g_build_path(PATH_SEPERATOR, base, path1, NULL);
        show_entry(opt, "-", e1, newbase);
        show_entry(opt, "+", e2, newbase);
        g_free(newbase);
        return 0;
    }

    if (S_ISDIR(mode1)) {
        char hex1[41], hex2[41];

        rawdata_to_hex(sha1, (char *)hex1, 20);
        rawdata_to_hex(sha2, (char *)hex2, 20);
        newbase = g_build_path(PATH_SEPERATOR, base, path1, NULL);
        diff_tree_sha1(hex1, hex2, newbase, opt);
        g_free(newbase);
    } else {
        newbase = g_build_path(PATH_SEPERATOR, base, path1, NULL);
        diff_change(opt, mode1, mode2, sha1, sha2, newbase, 0, 0);
        g_free(newbase);
    }
    return 0;
}

    static int
do_diff_tree(struct diff_options *opt, struct tree_desc *t, const char *base, int n)
{
    GList **ptrs = g_new0(GList *, n);
    SeafDirent *dent;
    struct name_entry *entries = g_new0(struct name_entry, n);
    char *first_name;
    gboolean done;
    unsigned long mask;
    int i, ret = 0;

    for (i = 0; i < n; i++) {
        if (t[i].tree)
            ptrs[i] = t[i].tree->entries;
        else
            ptrs[i] = NULL;
    }

    while (1) {
        first_name = NULL;
        mask = 0;
        memset(entries, 0, sizeof(entries[0]) * n);
        done = TRUE;

        /* Find the "largest" name, assuming dirents are sorted. */
        for (i = 0; i < n; i++) {
            if (ptrs[i] != NULL) {
                done = FALSE;
                dent = (SeafDirent *)ptrs[i]->data;
                if (!first_name)
                    first_name = dent->name;
                else if (strcmp(dent->name, first_name) > 0)
                    first_name = dent->name;
            }
        }

        if (done)
            break;

        /* Setup name entries for all names that equals first_name */
        for (i = 0; i < n; i++) {
            if (ptrs[i] != NULL) {
                dent = (SeafDirent *)ptrs[i]->data;
                if (strcmp(first_name, dent->name) == 0) {
                    mask |= 1 << i;

                    hex_to_rawdata(dent->id, entries[i].sha1, 20);
                    entries[i].path = dent->name;
                    entries[i].pathlen = dent->name_len;
                    entries[i].mode = dent->mode;
                }
            }
        }

        /* diff changed */
        if (mask == DIFF_CHANGED) {
            switch (compare_tree_entry(&entries[0], &entries[1], base, opt)) {
                case -1:
                    ptrs[0] = ptrs[0]->next;
                    continue;
                case 0:
                    ptrs[0] = ptrs[0]->next;
                case 1:
                    ptrs[1] = ptrs[1]->next;
                    continue;
            }
            g_warning("diff-tree: internal error\n");
            ret = -1;
            goto failed;
        }

        /* diff addremove */
        for (i = 0; i < n; i++) {
            unsigned int bit = 1u << i;

            if (!(mask & bit)) {
                /* if i == 0, then old tree don't have the entry */
                char *flag = i ? "-" : "+";

                show_entry(opt, flag, &entries[1-i], base);
                ptrs[1-i] = ptrs[1-i]->next;
            }
        }
    }

failed:
    g_free(ptrs);
    g_free(entries);

    return ret;
}

static int diffnamecmp(gconstpointer a_, gconstpointer b_)
{
    const struct diff_filepair *a = (const struct diff_filepair *)a_;
    const struct diff_filepair *b = (const struct diff_filepair *)b_;
    const char *name_a, *name_b;

    name_a = a->one ? a->one->path : a->two->path;
    name_b = b->one ? b->one->path : b->two->path;
    return strcmp(name_a, name_b);
}

static int
diff_tree_sha1(const char *old, const char *new,
               const char *base, struct diff_options *opt)
{
    struct tree_desc t[2];
    int ret = 0;

    fill_tree_descriptor(&t[0], old);
    fill_tree_descriptor(&t[1], new);

    if (do_diff_tree(opt, t, base, 2))
        /* diff failed */
        ret = -1;

    return ret;
}

    static char *
format_diff(GList *list)
{
    GString *res;
    GList *ptr;
    struct diff_filepair *p;
    unsigned char hex1[41], hex2[41];

    res = g_string_new("");

    for (ptr = list; ptr; ptr = ptr->next) {
        p = (struct diff_filepair *)ptr->data;
        rawdata_to_hex(p->one->sha1, (char *)hex1, 20);
        rawdata_to_hex(p->two->sha1, (char *)hex2, 20);
        /* g_debug(":%06o %06o %s %s %c %s\n", */
        /*         p->one->mode, p->two->mode, */
        /*         hex1, hex2, */
        /*         p->status, p->one->path); */
        if (p->status != DIFF_STATUS_RENAMED)
            g_string_append_printf(res, ":%06o %06o %s %s %c %ld %s\n",
                    p->one->mode, p->two->mode,
                    hex1, hex2,
                    p->status, strlen(p->one->path),
                    p->one->path);
        else
            g_string_append_printf(res, ":%06o %06o %s %s %c %ld %s %ld %s\n",
                    p->one->mode, p->two->mode,
                    hex1, hex2, p->status,
                    strlen(p->one->path), p->one->path,
                    strlen(p->two->path), p->two->path);
    }

    return g_string_free(res, FALSE);
}

    int
diff_tree(SeafRepo *repo, SeafCommit *c1, SeafCommit *c2, char **diff_result, char **error)
{
    struct diff_options opt;
    int ret = 0;

    g_assert(repo && c1 && c2);

    if (strcmp(c1->commit_id, c2->commit_id) == 0)
        /* c1 and c2 are the same */
        return 0;

    memset(&opt, 0, sizeof(opt));

    ret = diff_tree_sha1(c1->root_id, c2->root_id, "", &opt);
    if (ret < 0) {
        /* diff failed */
        *error = g_strdup("Internal error.\n");
        ret = -1;
        g_debug("Diff failed.\n");
    }

    diff_rename(&opt);
    diff_resolve_rename_copy(&opt);
    opt.df_list = g_list_sort(opt.df_list, diffnamecmp);
    *diff_result = format_diff(opt.df_list);

    return ret;
}

static int get_stat_data(struct cache_entry *ce,
        const unsigned char **sha1p,
        unsigned int *modep,
        int cached, int match_missing,
        unsigned *dirty_submodule, struct diff_options *diffopt)
{
    const unsigned char *sha1 = ce->sha1;
    unsigned int mode = ce->ce_mode;

    if (!cached && !ce_uptodate(ce)) {
        int changed;
        SeafStat st;
        changed = check_removed(ce, &st, diffopt->worktree);
        if (changed < 0)
            return -1;
        else if (changed) {
            if (match_missing) {
                *sha1p = sha1;
                *modep = mode;
                return 0;
            }
            return -1;
        }
        changed = ie_match_stat(diffopt->index, ce, &st, 0);
        if (changed) {
            mode = ce_mode_from_stat(ce, st.st_mode);
            sha1 = null_sha1;
        }
    }

    *sha1p = sha1;
    *modep = mode;
    return 0;
}

static int show_modified(struct diff_options *diffopt,
        struct cache_entry *old,
        struct cache_entry *new,
        int report_missing,
        int cached, int match_missing)
{
    struct diff_filepair *pair;
    unsigned int mode, oldmode;
    const unsigned char *sha1;
    unsigned dirty_submodule = 0;

    if (get_stat_data(new, &sha1, &mode, cached, match_missing,
                &dirty_submodule, diffopt) < 0) {
        if (report_missing)
            pair = diff_addremove(diffopt, '-', old->ce_mode,
                    old->sha1, old->name, 0);
        pair->stage = STAGE_COMMIT;
        return -1;
    }

    oldmode = old->ce_mode;
    if (mode == oldmode && !hashcmp(sha1, old->sha1) && !dirty_submodule/* &&
        !DIFF_OPT_TST(&revs->diffopt, FIND_COPIES_HARDER)*/)
        return 0;

    pair = diff_change(diffopt, oldmode, mode,
            old->sha1, sha1, old->name, 0, dirty_submodule);
    pair->stage = STAGE_COMMIT;
    return 0;
}

/*
 * This gets a mix of an existing index and a tree, one pathname entry
 * at a time. The index entry may be a single stage-0 one, but it could
 * also be multiple unmerged entries (in which case idx_pos/idx_nr will
 * give you the position and number of entries in the index).
 */
static void do_oneway_diff(struct unpack_trees_options *o,
        struct cache_entry *idx,
        struct cache_entry *tree)
{
    struct diff_options *diffopt = o->unpack_data;
    struct diff_filepair *pair;
    int match_missing, cached;

    /* if the entry is not checked out, don't examine work tree */
    cached = o->index_only ||
        (idx && ((idx->ce_flags & CE_VALID) || ce_skip_worktree(idx)));
    /*
     * Backward compatibility wart - "diff-index -m" does
     * not mean "do not ignore merges", but "match_missing".
     *
     * But with the revision flag parsing, that's found in
     * "!revs->ignore_merges".
     */
    match_missing = 0;

    if (cached && idx && ce_stage(idx)) {
        int mask = 0;
        mask |= 1 << ce_stage(idx);
        pair = diff_unmerge(diffopt, idx->name);
        pair->unmerged = diff_unmerged_stage(mask);
        pair->stage = STAGE_UNMERGED;
        if (tree)
            fill_filespec(pair->one, tree->sha1, tree->ce_mode);
        return;
    }

    /*
     * Something added to the tree?
     */
    if (!tree) {
        const unsigned char *sha1;
        unsigned int mode;
        unsigned dirty_submodule = 0;

        /*
         * New file in the index: it might actually be different in
         * the working tree.
         */
        if (get_stat_data(idx, &sha1, &mode, cached, match_missing,
                    &dirty_submodule, diffopt) < 0)
            return;

        pair = diff_addremove(diffopt, '+', mode,
                sha1, idx->name, dirty_submodule);
        pair->stage = STAGE_COMMIT;
        return;
    }

    /*
     * Something removed from the tree?
     */
    if (!idx) {
        pair = diff_addremove(diffopt, '-', tree->ce_mode,
                tree->sha1, tree->name, 0);
        pair->stage = STAGE_COMMIT;
        return;
    }

    /* Show difference between old and new */
    show_modified(diffopt, tree, idx, 1, cached, match_missing);
}

/*
 * The unpack_trees() interface is designed for merging, so
 * the different source entries are designed primarily for
 * the source trees, with the old index being really mainly
 * used for being replaced by the result.
 *
 * For diffing, the index is more important, and we only have a
 * single tree.
 *
 * We're supposed to advance o->pos to skip what we have already processed.
 *
 * This wrapper makes it all more readable, and takes care of all
 * the fairly complex unpack_trees() semantic requirements, including
 * the skipping, the path matching, the type conflict cases etc.
 */
static int oneway_diff(struct cache_entry **src, struct unpack_trees_options *o)
{
    struct cache_entry *idx = src[0];
    struct cache_entry *tree = src[1];

    /*
     * Unpack-trees generates a DF/conflict entry if
     * there was a directory in the index and a tree
     * in the tree. From a diff standpoint, that's a
     * delete of the tree and a create of the file.
     */
    if (tree == o->df_conflict_entry)
        tree = NULL;

    if (ce_path_match(idx ? idx : tree, NULL))
        do_oneway_diff(o, idx, tree);

    return 0;
}

int diff_cache(struct index_state *istate, struct diff_options *diffopt, SeafDir *root)
{
    struct tree_desc t;
    struct unpack_trees_options opts;

    memset(&opts, 0, sizeof(opts));
    opts.head_idx = 1;
    opts.index_only = 1;
    opts.merge = 1;
    opts.fn = oneway_diff;
    opts.unpack_data = diffopt;
    opts.src_index = istate;
    opts.dst_index = NULL;

    fill_tree_descriptor(&t, root->dir_id);
    return unpack_trees(1, &t, &opts);
}

int diff_unmerged_stage(int mask)
{
    mask >>= 1;
    switch (mask) {
        case 7:
            return STATUS_UNMERGED_BOTH_CHANGED;
        case 3:
            return STATUS_UNMERGED_OTHERS_REMOVED;
        case 5:
            return STATUS_UNMERGED_I_REMOVED;
        case 6:
            return STATUS_UNMERGED_BOTH_ADDED;
        case 2:
            return STATUS_UNMERGED_DFC_I_ADDED_FILE;
        case 4:
            return STATUS_UNMERGED_DFC_OTHERS_ADDED_FILE;
        default:
            g_warning ("Unexpected unmerged case\n");
    }
    return 0;
}
