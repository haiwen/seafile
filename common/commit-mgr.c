/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include <json-glib/json-glib.h>
#include <openssl/sha.h>

#include "utils.h"
#include "db.h"
#include "searpc-utils.h"

#include "seafile-session.h"
#include "commit-mgr.h"
#include "seaf-utils.h"

#define MAX_TIME_SKEW 259200    /* 3 days */

struct _SeafCommitManagerPriv {
    /* GHashTable *commit_cache; */
    /* JsonGenerator   *gen; */
    /* JsonParser      *parser; */
    int dummy;
};

static SeafCommit *
load_commit (SeafCommitManager *mgr, const char *commit_id);
static int
save_commit (SeafCommitManager *manager, SeafCommit *commit);
static void
delete_commit (SeafCommitManager *mgr, const char *id);
static JsonNode *
commit_to_json_node (SeafCommit *commit);
static SeafCommit *
commit_from_json_node (const char *id, JsonNode *node);

static void compute_commit_id (SeafCommit* commit)
{
    SHA_CTX ctx;
    uint8_t sha1[20];    
    gint64 ctime_n;

    SHA1_Init (&ctx);
    SHA1_Update (&ctx, commit->root_id, 41);
    SHA1_Update (&ctx, commit->creator_id, 41);
    if (commit->creator_name)
        SHA1_Update (&ctx, commit->creator_name, strlen(commit->creator_name)+1);
    SHA1_Update (&ctx, commit->desc, strlen(commit->desc)+1);

    /* convert to network byte order */
    ctime_n = hton64 (commit->ctime);
    SHA1_Update (&ctx, &ctime_n, sizeof(ctime_n));
    SHA1_Final (sha1, &ctx);
    
    rawdata_to_hex (sha1, commit->commit_id, 20);
}

SeafCommit*
seaf_commit_new (const char *commit_id,
                 const char *repo_id,
                 const char *root_id,
                 const char *creator_name,
                 const char *creator_id,
                 const char *desc,
                 guint64 ctime)
{
    SeafCommit *commit;

    g_return_val_if_fail (repo_id != NULL, NULL);
    g_return_val_if_fail (root_id != NULL && creator_id != NULL, NULL);

    commit = g_new0 (SeafCommit, 1);

    memcpy (commit->repo_id, repo_id, 36);
    commit->repo_id[36] = '\0';
    
    memcpy (commit->root_id, root_id, 40);
    commit->root_id[40] = '\0';

    commit->creator_name = g_strdup (creator_name);

    memcpy (commit->creator_id, creator_id, 40);
    commit->creator_id[40] = '\0';

    commit->desc = g_strdup (desc);
    
    if (ctime == 0) {
        /* TODO: use more precise timer */
        commit->ctime = (gint64)time(NULL);
    } else
        commit->ctime = ctime;

    if (commit_id == NULL)
        compute_commit_id (commit);
    else {
        memcpy (commit->commit_id, commit_id, 40);
        commit->commit_id[40] = '\0';        
    }

    commit->ref = 1;
    return commit;
}

char *
seaf_commit_to_data (SeafCommit *commit, gsize *len)
{
    JsonGenerator *gen = json_generator_new ();
    JsonNode *root;
    char *json_data;

    root = commit_to_json_node (commit);

    json_generator_set_root (gen, root);

    json_data = json_generator_to_data (gen, len);
    json_node_free (root);
    g_object_unref (gen);

    return json_data;
}

SeafCommit *
seaf_commit_from_data (const char *id, const char *data, gsize len)
{
    JsonParser *parser = json_parser_new ();
    JsonNode *root;
    SeafCommit *commit;
    GError *error = NULL;

    if (!json_parser_load_from_data (parser, data, len, &error)) {
        g_warning ("Failed to parse commit data: %s.\n", error->message);
        g_object_unref (parser);
        return NULL;
    }

    root = json_parser_get_root (parser);

    commit = commit_from_json_node (id, root);

    g_object_unref (parser);

    return commit;
}

static void
seaf_commit_free (SeafCommit *commit)
{
    g_free (commit->desc);
    g_free (commit->creator_name);
    if (commit->parent_id) g_free (commit->parent_id);
    if (commit->second_parent_id) g_free (commit->second_parent_id);
    if (commit->repo_name) g_free (commit->repo_name);
    if (commit->repo_desc) g_free (commit->repo_desc);
    g_free (commit->magic);
    g_free (commit);
}

void
seaf_commit_ref (SeafCommit *commit)
{
    commit->ref++;
}

void
seaf_commit_unref (SeafCommit *commit)
{
    if (!commit)
        return;

    if (--commit->ref <= 0)
        seaf_commit_free (commit);
}

SeafCommitManager*
seaf_commit_manager_new (SeafileSession *seaf)
{
    SeafCommitManager *mgr = g_new0 (SeafCommitManager, 1);

    mgr->priv = g_new0 (SeafCommitManagerPriv, 1);
    mgr->seaf = seaf;
    mgr->obj_store = seaf_obj_store_new (mgr->seaf, "commits");

    return mgr;
}

int
seaf_commit_manager_init (SeafCommitManager *mgr)
{
#if defined SEAFILE_SERVER && defined FULL_FEATURE
    if (seaf_obj_store_init (mgr->obj_store, TRUE, seaf->ev_mgr) < 0) {
        g_warning ("[commit mgr] Failed to init commit object store.\n");
        return -1;
    }
#else
    if (seaf_obj_store_init (mgr->obj_store, FALSE, NULL) < 0) {
        g_warning ("[commit mgr] Failed to init commit object store.\n");
        return -1;
    }
#endif

    return 0;
}

#if 0
inline static void
add_commit_to_cache (SeafCommitManager *mgr, SeafCommit *commit)
{
    g_hash_table_insert (mgr->priv->commit_cache,
                         g_strdup(commit->commit_id),
                         commit);
    seaf_commit_ref (commit);
}

inline static void
remove_commit_from_cache (SeafCommitManager *mgr, SeafCommit *commit)
{
    g_hash_table_remove (mgr->priv->commit_cache, commit->commit_id);
    seaf_commit_unref (commit);
}
#endif

int
seaf_commit_manager_add_commit (SeafCommitManager *mgr, SeafCommit *commit)
{
    int ret;

    /* add_commit_to_cache (mgr, commit); */
    if ((ret = save_commit (mgr, commit)) < 0)
        return -1;
    
    return 0;
}

void
seaf_commit_manager_del_commit (SeafCommitManager *mgr, const char *id)
{
    g_return_if_fail (id != NULL);

#if 0
    commit = g_hash_table_lookup(mgr->priv->commit_cache, id);
    if (!commit)
        goto delete;

    /*
     * Catch ref count bug here. We have bug in commit ref, the
     * following assert can't pass. TODO: fix the commit ref bug
     */
    /* g_assert (commit->ref <= 1); */
    remove_commit_from_cache (mgr, commit);

delete:
#endif

    delete_commit (mgr, id);
}

SeafCommit* 
seaf_commit_manager_get_commit (SeafCommitManager *mgr, const char *id)
{
    SeafCommit *commit;

#if 0
    commit = g_hash_table_lookup (mgr->priv->commit_cache, id);
    if (commit != NULL) {
        seaf_commit_ref (commit);
        return commit;
    }
#endif

    commit = load_commit (mgr, id);
    if (!commit)
        return NULL;

    /* add_commit_to_cache (mgr, commit); */

    return commit;
}

static gint
compare_commit_by_time (gconstpointer a, gconstpointer b, gpointer unused)
{
    const SeafCommit *commit_a = a;
    const SeafCommit *commit_b = b;

    /* Latest commit comes first in the list. */
    return (commit_b->ctime - commit_a->ctime);
}

inline static int
insert_parent_commit (GList **list, GHashTable *hash, const char *parent_id)
{
    SeafCommit *p;
    char *key;

    if (g_hash_table_lookup (hash, parent_id) != NULL)
        return 0;

    p = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                        parent_id);
    if (!p) {
        g_warning ("Failed to find commit %s\n", parent_id);
        return -1;
    }

    *list = g_list_insert_sorted_with_data (*list, p,
                                           compare_commit_by_time,
                                           NULL);

    key = g_strdup (parent_id);
    g_hash_table_insert (hash, key, key);

    return 0;
}

gboolean
seaf_commit_manager_traverse_commit_tree_with_limit (SeafCommitManager *mgr,
                                                     const char *head,
                                                     CommitTraverseFunc func,
                                                     int limit,
                                                     void *data)
{
    SeafCommit *commit;
    GList *list = NULL;
    GHashTable *commit_hash;
    gboolean ret = TRUE;

    /* A hash table for recording id of traversed commits. */
    commit_hash = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);

    commit = seaf_commit_manager_get_commit (mgr, head);
    if (!commit) {
        g_warning ("Failed to find commit %s.\n", head);
        return FALSE;
    }

    list = g_list_insert_sorted_with_data (list, commit,
                                           compare_commit_by_time,
                                           NULL);

    char *key = g_strdup (commit->commit_id);
    g_hash_table_insert (commit_hash, key, key);

    int count = 0;
    while (list) {
        gboolean stop = FALSE;
        commit = list->data;
        list = g_list_delete_link (list, list);

        if (!func (commit, data, &stop)) {
            seaf_commit_unref (commit);
            ret = FALSE;
            goto out;
        }

        /* Stop when limit is reached. If limit < 0, there is no limit; */
        if (limit > 0 && ++count == limit) {
            seaf_commit_unref (commit);
            break;
        }
        
        if (stop) {
            seaf_commit_unref (commit);
            /* stop traverse down from this commit,
             * but not stop traversing the tree 
             */
            continue;
        }

        if (commit->parent_id) {
            if (insert_parent_commit (&list, commit_hash, commit->parent_id) < 0) {
                seaf_commit_unref (commit);
                ret = FALSE;
                goto out;
            }
        }
        if (commit->second_parent_id) {
            if (insert_parent_commit (&list, commit_hash, commit->second_parent_id) < 0) {
                seaf_commit_unref (commit);
                ret = FALSE;
                goto out;
            }
        }
        seaf_commit_unref (commit);
    }

out:
    g_hash_table_destroy (commit_hash);
    while (list) {
        commit = list->data;
        seaf_commit_unref (commit);
        list = g_list_delete_link (list, list);
    }
    return ret;
}

gboolean
seaf_commit_manager_traverse_commit_tree (SeafCommitManager *mgr,
                                          const char *head,
                                          CommitTraverseFunc func,
                                          void *data,
                                          gboolean skip_errors)
{
    SeafCommit *commit;
    GList *list = NULL;
    GHashTable *commit_hash;
    gboolean ret = TRUE;

    commit = seaf_commit_manager_get_commit (mgr, head);
    if (!commit) {
        g_warning ("Failed to find commit %s.\n", head);
        if (!skip_errors)
            return FALSE;
    }

    /* A hash table for recording id of traversed commits. */
    commit_hash = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);

    list = g_list_insert_sorted_with_data (list, commit,
                                           compare_commit_by_time,
                                           NULL);

    char *key = g_strdup (commit->commit_id);
    g_hash_table_insert (commit_hash, key, key);

    while (list) {
        gboolean stop = FALSE;
        commit = list->data;
        list = g_list_delete_link (list, list);

        if (!func (commit, data, &stop)) {
            g_warning("[comit-mgr] CommitTraverseFunc failed\n");

            /* If skip errors, continue to traverse parents. */
            if (!skip_errors) {
                seaf_commit_unref (commit);
                ret = FALSE;
                goto out;
            }
        }
        if (stop) {
            seaf_commit_unref (commit);
            /* stop traverse down from this commit,
             * but not stop traversing the tree 
             */
            continue;
        }

        if (commit->parent_id) {
            if (insert_parent_commit (&list, commit_hash, commit->parent_id) < 0) {
                g_warning("[comit-mgr] insert parent commit failed\n");

                /* If skip errors, try insert second parent. */
                if (!skip_errors) {
                    seaf_commit_unref (commit);
                    ret = FALSE;
                    goto out;
                }
            }
        }
        if (commit->second_parent_id) {
            if (insert_parent_commit (&list, commit_hash, commit->second_parent_id) < 0) {
                g_warning("[comit-mgr]insert second parent commit failed\n");

                if (!skip_errors) {
                    seaf_commit_unref (commit);
                    ret = FALSE;
                    goto out;
                }
            }
        }
        seaf_commit_unref (commit);
    }

out:
    g_hash_table_destroy (commit_hash);
    while (list) {
        commit = list->data;
        seaf_commit_unref (commit);
        list = g_list_delete_link (list, list);
    }
    return ret;
}

typedef struct FindingHelp {
    SeafCommit *to_find;
    gboolean result;
} FindingHelp;

static gboolean
find_commit(SeafCommit *commit, FindingHelp *f, gboolean *stop)
{
    if (f->result == TRUE) {
        *stop = TRUE;
        return TRUE;
    }

    if (strcmp(commit->commit_id, f->to_find->commit_id) == 0) {
        f->result = TRUE;
        *stop = TRUE;
    } else {
        if (commit->ctime < f->to_find->ctime - MAX_TIME_SKEW) {
            /* searched deep enough */
            f->result= FALSE;
            *stop = TRUE;
        } else
            *stop = FALSE;
    }

    return TRUE;
}

int
seaf_commit_manager_compare_commit (SeafCommitManager *mgr,
                                    const char *commit1,
                                    const char *commit2)
{
    SeafCommit *c1, *c2;
    int ret = 0;

    if (!commit1 || !commit2)
        return -2;

    if (strlen(commit1) != 40 || strlen(commit2) != 40) {
        g_warning ("Invalid commit\n");
        return -2;
    }

    if (strcmp(commit1, commit2) == 0)
        return 0;

    c1 = seaf_commit_manager_get_commit (mgr, commit1);
    if (!c1) {
        g_warning ("Failed to find commit %s.\n", commit1);
        return -2;
    }
    c2 = seaf_commit_manager_get_commit (mgr, commit2);
    if (!c2) {
        g_warning ("Failed to find commit %s.\n", commit2);
        return -2;
    }

    if (c1->ctime > c2->ctime) {
        FindingHelp f;
        f.to_find = c2;
        f.result = FALSE;
        if (!seaf_commit_manager_traverse_commit_tree (
                 mgr, c1->commit_id, (CommitTraverseFunc)find_commit, &f, FALSE))
            ret = -2;
        if (f.result == TRUE)
            ret = 1;
        else
            ret = 0;
    } else {
        FindingHelp f;
        f.to_find = c1;
        f.result = FALSE;
        if (!seaf_commit_manager_traverse_commit_tree (
                 mgr, c2->commit_id, (CommitTraverseFunc)find_commit, &f, FALSE))
            ret = -2;
        if (f.result == TRUE)
            ret = -1;
        else
            ret = 0;
    }

    seaf_commit_unref (c1);
    seaf_commit_unref (c2);
    return ret;
}

GList* 
seaf_commit_manager_get_repo_commits (SeafCommitManager *mgr, const char *repo_id)
{
    sqlite3 *db = mgr->db;
    
    int result;
    sqlite3_stmt *stmt;
    char sql[256];
    char *commit_id;
    GList *ret = NULL;
    SeafCommit *commit;

    snprintf (sql, 256, "SELECT commit_id FROM commits"
              " WHERE repo_id='%s' ORDER BY ctime DESC",
              repo_id);

    if ( !(stmt = sqlite_query_prepare(db, sql)) )
        return NULL;
    while (1) {
        result = sqlite3_step (stmt);
        if (result == SQLITE_ROW) {
            commit_id = (char *)sqlite3_column_text(stmt, 0);
            commit = seaf_commit_manager_get_commit (mgr, commit_id);
            if (commit)
                ret = g_list_prepend(ret, commit);
        }
        if (result == SQLITE_DONE)
            break;
        if (result == SQLITE_ERROR) {
            const gchar *str = sqlite3_errmsg (db);
            g_warning ("Couldn't prepare query, error: %d->'%s'\n", 
                       result, str ? str : "no error given");
            sqlite3_finalize (stmt);
            goto end;
        }
    }
    sqlite3_finalize (stmt);

end:
    return g_list_reverse(ret);
}

gboolean
seaf_commit_manager_commit_exists (SeafCommitManager *mgr, const char *id)
{
#if 0
    commit = g_hash_table_lookup (mgr->priv->commit_cache, id);
    if (commit != NULL)
        return TRUE;
#endif

    return seaf_obj_store_obj_exists (mgr->obj_store, id);
}

static JsonNode *
commit_to_json_node (SeafCommit *commit)
{
    JsonNode *root;
    JsonObject *object;
    
    root = json_node_new (JSON_NODE_OBJECT);
    object = json_object_new ();
 
    json_object_set_string_member (object, "commit_id", commit->commit_id);
    json_object_set_string_member (object, "root_id", commit->root_id);
    json_object_set_string_member (object, "repo_id", commit->repo_id);
    if (commit->creator_name)
        json_object_set_string_member (object, "creator_name", commit->creator_name);
    json_object_set_string_member (object, "creator", commit->creator_id);
    json_object_set_string_member (object, "description", commit->desc);
    json_object_set_int_member (object, "ctime", (gint64)commit->ctime);
    json_object_set_string_or_null_member (object, "parent_id", commit->parent_id);
    json_object_set_string_or_null_member (object, "second_parent_id",
                                           commit->second_parent_id);
    /*
     * also save repo's properties to commit file, for easy sharing of
     * repo info 
     */
    json_object_set_string_member (object, "repo_name", commit->repo_name);
    json_object_set_string_member (object, "repo_desc",
                                   commit->repo_desc);
    json_object_set_string_or_null_member (object, "repo_category",
                                           commit->repo_category);
    if (commit->encrypted)
        json_object_set_string_member (object, "encrypted", "true");

    if (commit->encrypted) {
        json_object_set_int_member (object, "enc_version", commit->enc_version);
        if (commit->enc_version >= 1)
            json_object_set_string_member (object, "magic", commit->magic);
    }
    if (commit->no_local_history)
        json_object_set_int_member (object, "no_local_history", 1);

    json_node_take_object (root, object);

    return root;
}

static SeafCommit *
commit_from_json_node (const char *commit_id, JsonNode *node)
{
    JsonObject *object;
    SeafCommit *commit = NULL;
    const char *root_id;
    const char *repo_id;
    const char *creator_name = NULL;
    const char *creator;
    const char *desc;
    gint64 ctime;
    const char *parent_id, *second_parent_id;
    const char *repo_name;
    const char *repo_desc;
    const char *repo_category;
    const char *encrypted = NULL;
    int enc_version = 0;
    const char *magic = NULL;
    int no_local_history = 0;

    object = json_node_get_object (node);
    if (!object) {
        g_warning ("Commit %.10s corrupted.\n", commit_id);
        return NULL;
    }

    root_id = json_object_get_string_member (object, "root_id");
    repo_id = json_object_get_string_member (object, "repo_id");
    if (json_object_has_member (object, "creator_name"))
        creator_name = json_object_get_string_or_null_member (object, "creator_name");
    creator = json_object_get_string_member (object, "creator");
    desc = json_object_get_string_member (object, "description");
    ctime = (guint64) json_object_get_int_member (object, "ctime");
    parent_id = json_object_get_string_or_null_member (object, "parent_id");
    second_parent_id = json_object_get_string_or_null_member (object, "second_parent_id");

    repo_name = json_object_get_string_member (object, "repo_name");
    repo_desc = json_object_get_string_member (object, "repo_desc");
    repo_category = json_object_get_string_or_null_member (object, "repo_category");
    if (json_object_has_member (object, "encrypted"))
        encrypted = json_object_get_string_or_null_member (object, "encrypted");

    if (encrypted && strcmp(encrypted, "true") == 0
        && json_object_has_member (object, "enc_version")) {
        enc_version = json_object_get_int_member (object, "enc_version");
        magic = json_object_get_string_member (object, "magic");
    }
    if (json_object_has_member (object, "no_local_history"))
        no_local_history = json_object_get_int_member (object, "no_local_history");

    /* sanity check for incoming values. */
    if (!repo_id || strlen(repo_id) != 36 ||
        !root_id || strlen(root_id) != 40 ||
        !creator || strlen(creator) != 40 ||
        (parent_id && strlen(parent_id) != 40) ||
        (second_parent_id && strlen(second_parent_id) != 40) ||
        (enc_version >= 1 && magic == NULL) ||
        (magic && strlen(magic) != 32))
        return commit;

    commit = seaf_commit_new (commit_id, repo_id, root_id,
                              creator_name, creator, desc, ctime);

    commit->parent_id = parent_id ? g_strdup(parent_id) : NULL;
    commit->second_parent_id = second_parent_id ? g_strdup(second_parent_id) : NULL;

    commit->repo_name = g_strdup(repo_name);
    commit->repo_desc = g_strdup(repo_desc);
    if (encrypted && strcmp(encrypted, "true") == 0)
        commit->encrypted = TRUE;
    else
        commit->encrypted = FALSE;
    if (repo_category)
        commit->repo_category = g_strdup(repo_category);

    if (commit->encrypted) {
        commit->enc_version = enc_version;
        if (enc_version >= 1)
            commit->magic = g_strdup(magic);
    }
    if (no_local_history)
        commit->no_local_history = TRUE;

    return commit;
}

static SeafCommit *
load_commit (SeafCommitManager *mgr, const char *commit_id)
{
    char *data;
    int len;
    SeafCommit *commit = NULL;
    JsonParser *parser;
    GError *error = NULL;

    if (!commit_id || strlen(commit_id) != 40)
        return NULL;

    if (seaf_obj_store_read_obj (mgr->obj_store, commit_id, (void **)&data, &len) < 0)
        return NULL;

    parser = json_parser_new ();
    json_parser_load_from_data (parser, data, len, &error);
    if (error) {
        g_warning ("Unable to parse commit %s: %s\n", commit_id,
                   error->message);
        g_error_free (error);
        goto out;
    }

    JsonNode *root;

    root = json_parser_get_root (parser);
    if (!root) {
        g_warning ("Commit %.10s corrupted.\n", commit_id);
        goto out;
    }

    commit = commit_from_json_node (commit_id, root);
    if (commit)
        commit->manager = mgr;

out:
    g_object_unref (parser);
    g_free (data);

    return commit;
}

static int
save_commit (SeafCommitManager *manager, SeafCommit *commit)
{
    JsonGenerator *gen = json_generator_new ();
    JsonNode *root;
    char *data;
    gsize len;

    root = commit_to_json_node (commit);

    json_generator_set_root (gen, root);

    data = json_generator_to_data (gen, &len);
    if (!data) {
        g_warning("Generate commit json failed.\n");
        json_node_free (root);
        g_object_unref (gen);
        return -1;
    }
    json_node_free (root);
    g_object_unref (gen);

    if (seaf_obj_store_write_obj (manager->obj_store, commit->commit_id,
                                  data, (int)len) < 0) {
        g_free (data);
        return -1;
    }
    g_free (data);

    return 0;
}

static void
delete_commit (SeafCommitManager *mgr, const char *id)
{
    seaf_obj_store_delete_obj (mgr->obj_store, id);
}
