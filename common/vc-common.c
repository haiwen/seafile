#include "common.h"

#include "seafile-session.h"
#include "vc-common.h"

static GList *
merge_bases_many (SeafCommit *one, int n, SeafCommit **twos);

static gint
compare_commit_by_time (gconstpointer a, gconstpointer b, gpointer unused)
{
    const SeafCommit *commit_a = a;
    const SeafCommit *commit_b = b;

    /* Latest commit comes first in the list. */
    return (commit_b->ctime - commit_a->ctime);
}

static gint
compare_commit (gconstpointer a, gconstpointer b)
{
    const SeafCommit *commit_a = a;
    const SeafCommit *commit_b = b;

    return strcmp (commit_a->commit_id, commit_b->commit_id);
}

static gboolean
add_to_commit_hash (SeafCommit *commit, void *vhash, gboolean *stop)
{
    GHashTable *hash = vhash;

    char *key = g_strdup (commit->commit_id);
    g_hash_table_insert (hash, key, key);

    return TRUE;
}

static GHashTable *
commit_tree_to_hash (SeafCommit *head)
{
    GHashTable *hash;
    gboolean res;

    hash = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);

    res = seaf_commit_manager_traverse_commit_tree (seaf->commit_mgr,
                                                    head->commit_id,
                                                    add_to_commit_hash,
                                                    hash);
    if (!res)
        goto fail;

    return hash;

fail:
    g_hash_table_destroy (hash);
    return NULL;
}

static GList *
get_independent_commits (GList *commits)
{
    SeafCommit **rslt;
    GList *list, *result;
    int cnt, i, j;
    SeafCommit *c;

    g_debug ("Get independent commits.\n");

    cnt = g_list_length (commits);

    rslt = calloc(cnt, sizeof(*rslt));
    for (list = commits, i = 0; list; list = list->next)
        rslt[i++] = list->data;
    g_list_free (commits);

    for (i = 0; i < cnt - 1; i++) {
        for (j = i+1; j < cnt; j++) {
            if (!rslt[i] || !rslt[j])
                continue;
            result = merge_bases_many(rslt[i], 1, &rslt[j]);
            for (list = result; list; list = list->next) {
                c = list->data;
                /* If two commits have fast-forward relationship,
                 * drop the older one.
                 */
                if (strcmp (rslt[i]->commit_id, c->commit_id) == 0) {
                    seaf_commit_unref (rslt[i]);
                    rslt[i] = NULL;
                }
                if (strcmp (rslt[j]->commit_id, c->commit_id) == 0) {
                    seaf_commit_unref (rslt[j]);
                    rslt[j] = NULL;
                }
                seaf_commit_unref (c);
            }
        }
    }

    /* Surviving ones in rslt[] are the independent results */
    result = NULL;
    for (i = 0; i < cnt; i++) {
        if (rslt[i])
            result = g_list_insert_sorted_with_data (result, rslt[i],
                                                     compare_commit_by_time,
                                                     NULL);
    }
    free(rslt);
    return result;
}

typedef struct {
    GList *result;
    GHashTable *commit_hash;
} MergeTraverseData;

static gboolean
get_merge_bases (SeafCommit *commit, void *vdata, gboolean *stop)
{
    MergeTraverseData *data = vdata;

    /* Found a common ancestor.
     * Dont traverse its parenets.
     */
    if (g_hash_table_lookup (data->commit_hash, commit->commit_id)) {
        if (!g_list_find_custom (data->result, commit, compare_commit)) {
            data->result = g_list_insert_sorted_with_data (data->result, commit,
                                                     compare_commit_by_time,
                                                     NULL);
            seaf_commit_ref (commit);
        }
        *stop = TRUE;
    }

    return TRUE;
}

/*
 * Merge "one" with commits in "twos".
 * The ancestors returned may not be ancestors for all the input commits.
 * They are common ancestors for one and some commits in twos array.
 */
static GList *
merge_bases_many (SeafCommit *one, int n, SeafCommit **twos)
{
    GHashTable *commit_hash;
    GList *result = NULL;
    SeafCommit *commit;
    int i;
    MergeTraverseData data;
    gboolean res;

    for (i = 0; i < n; i++) {
        if (one == twos[i])
            return g_list_append (result, one);
    }

    /* First construct a hash table of all commit ids rooted at one. */
    commit_hash = commit_tree_to_hash (one);
    if (!commit_hash) {
        g_warning ("Failed to load commit hash.\n");
        return NULL;
    }

    data.commit_hash = commit_hash;
    data.result = NULL;

    for (i = 0; i < n; i++) {
        res = seaf_commit_manager_traverse_commit_tree (seaf->commit_mgr,
                                                        twos[i]->commit_id,
                                                        get_merge_bases,
                                                        &data);
        if (!res)
            goto fail;
    }

    g_hash_table_destroy (commit_hash);
    result = data.result;

    if (!result || !result->next)
        return result;

    /* There are more than one. Try to find out independent ones. */
    result = get_independent_commits (result);

    return result;

fail:
    result = data.result;
    while (result) {
        commit = result->data;
        seaf_commit_unref (commit);
        result = g_list_delete_link (result, result);
    }
    g_hash_table_destroy (commit_hash);
    return NULL;
}

/*
 * Returns common ancesstor for two branches.
 * Any two commits should have a common ancestor.
 * So returning NULL indicates an error, for e.g. corupt commit.
 */
SeafCommit *
get_merge_base (SeafCommit *head, SeafCommit *remote)
{
    GList *result, *iter;
    SeafCommit *one, **twos;
    int n, i;
    SeafCommit *ret = NULL;

    one = head;
    twos = (SeafCommit **) calloc (1, sizeof(SeafCommit *));
    twos[0] = remote;
    n = 1;
    result = merge_bases_many (one, n, twos);
    free (twos);
    if (!result || !result->next)
        goto done;

    /*
     * More than one common ancestors.
     * Loop until the oldest common ancestor is found.
     */
    while (1) {
        n = g_list_length (result) - 1;
        g_assert (n > 0);
        one = result->data;
        twos = calloc (n, sizeof(SeafCommit *));
        for (iter = result->next, i = 0; i < n; iter = iter->next, i++) {
            twos[i] = iter->data;
        }
        g_list_free (result);

        result = merge_bases_many (one, n, twos);
        free (twos);
        if (!result || !result->next)
            break;
    }

done:
    if (result)
        ret = result->data;
    g_list_free (result);

    return ret;
}

/*
 * Returns true if src_head is ahead of dst_head.
 */
gboolean
is_fast_forward (const char *src_head, const char *dst_head)
{
    VCCompareResult res;

    res = vc_compare_commits (src_head, dst_head);

    return (res == VC_FAST_FORWARD);
}

gboolean
is_up_to_date (const char *src_head, const char *dst_head)
{
    VCCompareResult res;

    res = vc_compare_commits (src_head, dst_head);

    return (res == VC_UP_TO_DATE);
}

VCCompareResult
vc_compare_commits (const char *c1, const char *c2)
{
    SeafCommit *commit1, *commit2, *ca;
    VCCompareResult ret;

    /* Treat the same as up-to-date. */
    if (strcmp (c1, c2) == 0)
        return VC_UP_TO_DATE;

    commit1 = seaf_commit_manager_get_commit (seaf->commit_mgr, c1);
    if (!commit1)
        return VC_INDEPENDENT;

    commit2 = seaf_commit_manager_get_commit (seaf->commit_mgr, c2);
    if (!commit2) {
        seaf_commit_unref (commit1);
        return VC_INDEPENDENT;
    }

    ca = get_merge_base (commit1, commit2);

    if (!ca)
        ret = VC_INDEPENDENT;
    else if (strcmp(ca->commit_id, commit1->commit_id) == 0)
        ret = VC_UP_TO_DATE;
    else if (strcmp(ca->commit_id, commit2->commit_id) == 0)
        ret = VC_FAST_FORWARD;
    else
        ret = VC_INDEPENDENT;

    if (ca) seaf_commit_unref (ca);
    seaf_commit_unref (commit1);
    seaf_commit_unref (commit2);
    return ret;
}
