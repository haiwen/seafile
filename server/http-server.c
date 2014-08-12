#include <pthread.h>
#include <string.h>
#include <jansson.h>

#include "common.h"
#include "utils.h"
#include "log.h"
#include "http-server.h"
#include "seafile-session.h"
#include "diff-simple.h"
#include "merge-new.h"

#define DEFAULT_BIND_HOST "0.0.0.0"
#define DEFAULT_BIND_PORT 8083
#define CLEANING_INTERVAL_MSEC 300	/* 5 minutes */
#define TOKEN_EXPIRE_TIME 7200	    /* 2 hour */

const char *GROUP_NAME = "httpserver";
const char *HOST = "host";
const char *PORT = "port";
const char *INIT_INFO = "If you see this page, Seafile HTTP syncing component works.";
const char *PROTO_VERSION = "{version: 1}";

const char *GET_PROTO_PATH = "/protocol_version/";
const char *OP_PERM_CHECK_REGEX = "^/repo/[\\da-z]{8}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{12}/permission-check/.*";
const char *GET_CHECK_QUOTA_REGEX = "^/repo/[\\da-z]{8}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{12}/quota-check/.*";
const char *HEAD_COMMIT_OPER_REGEX = "^/repo/[\\da-z]{8}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{12}/commit/HEAD";
const char *COMMIT_OPER_REGEX = "^/repo/[\\da-z]{8}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{12}/commit/[\\da-z]{40}";
const char *PUT_COMMIT_INFO_REGEX = "^/repo/[\\da-z]{8}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{12}/commit/[\\da-z]{40}";
const char *GET_FS_OBJ_ID_REGEX = "^/repo/[\\da-z]{8}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{12}/fs-id-list/.*";
const char *BLOCKT_OPER_REGEX = "^/repo/[\\da-z]{8}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{12}/block/[\\da-z]{40}";
const char *POST_CHECK_FS_REGEX = "^/repo/[\\da-z]{8}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{12}/check-fs";
const char *POST_CHECK_BLOCK_REGEX = "^/repo/[\\da-z]{8}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{12}/check-blocks";
const char *POST_RECV_FS_REGEX = "^/repo/[\\da-z]{8}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{12}/recv-fs";
const char *POST_PACK_FS_REGEX = "^/repo/[\\da-z]{8}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{12}/pack-fs";

static void
load_http_config (HttpServer *htp_server, SeafileSession *session)
{
    GError *error = NULL;
    char *host = NULL;
    int port = 0;

    host = g_key_file_get_string (session->config, GROUP_NAME, HOST, &error);
    if (!error) {
        htp_server->bind_addr = host;
    } else {
        if (error->code != G_KEY_FILE_ERROR_KEY_NOT_FOUND &&
            error->code != G_KEY_FILE_ERROR_GROUP_NOT_FOUND) {
            seaf_warning ("[conf] Error: failed to read the value of 'host'\n");
            exit (1);
        }

        htp_server->bind_addr = g_strdup (DEFAULT_BIND_HOST);
        g_clear_error (&error);
    }

    port = g_key_file_get_integer (session->config, GROUP_NAME, PORT, &error);
    if (!error) {
        htp_server->bind_port = port;
    } else {
        if (error->code != G_KEY_FILE_ERROR_KEY_NOT_FOUND &&
            error->code != G_KEY_FILE_ERROR_GROUP_NOT_FOUND) {
            seaf_warning ("[conf] Error: failed to read the value of 'port'\n");
            exit (1);
        }

        htp_server->bind_port = DEFAULT_BIND_PORT;
        g_clear_error (&error);
    }
}

static evhtp_res
validate_token_cb (evhtp_request_t * req, void * arg)
{
    const char *token = evhtp_kv_find (req->headers_in, "Seafile-Repo-Token");
    if (token == NULL) {
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
        return EVHTP_RES_BADREQ;
    }

    const char *repo_id = NULL;
    char *email = NULL;
    TokenInfo *token_info = NULL;

    char **parts = g_strsplit (req->uri->path->full + 1, "/", 0);
    repo_id = parts[1];
    HttpServer *htp_server = arg;

    pthread_mutex_lock (&htp_server->token_cache_lock);

    if (g_hash_table_lookup (htp_server->token_cache, token) == NULL) {
        email = seaf_repo_manager_get_email_by_token (htp_server->seaf_session->repo_mgr,
                                                      repo_id, token);
        if (email == NULL) {
            pthread_mutex_unlock (&htp_server->token_cache_lock);
            g_strfreev (parts);
            return EVHTP_RES_FORBIDDEN;
        }

        token_info = g_new0 (TokenInfo, 1);
        token_info->repo_id = g_strdup (repo_id);
        token_info->expire_time = (long)time(NULL) + TOKEN_EXPIRE_TIME;
        token_info->email = email;

        g_hash_table_insert (htp_server->token_cache, g_strdup (token), token_info);
    }

    pthread_mutex_unlock (&htp_server->token_cache_lock);

    g_strfreev (parts);

    return EVHTP_RES_OK;
}

static void
default_cb (evhtp_request_t *req, void *arg)
{
    evbuffer_add (req->buffer_out, INIT_INFO, strlen (INIT_INFO));
    evhtp_send_reply (req, EVHTP_RES_OK);
}

static void
get_check_permission_cb (evhtp_request_t *req, void *arg)
{
    const char *op = evhtp_kv_find (req->uri->query, "op");
    if (op == NULL || (strcmp (op, "upload") != 0 && strcmp (op, "download") != 0)) {
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
        return;
    }

    int token_status = validate_token_cb (req, arg);
    if (token_status != EVHTP_RES_OK) {
        evhtp_send_reply (req, token_status);
        return;
    }

    TokenInfo *token_info = NULL;
    char *email = NULL;
    char **parts = g_strsplit (req->uri->path->full + 1, "/", 0);
    char *repo_id = parts[1];
    HttpServer *htp_server = (HttpServer *)arg;
    const char *token = evhtp_kv_find (req->headers_in, "Seafile-Repo-Token");

    pthread_mutex_lock (&htp_server->token_cache_lock);

    token_info = g_hash_table_lookup (htp_server->token_cache, token);
    // recheck token from db, in case token expired
    if (!token_info) {
        email = seaf_repo_manager_get_email_by_token (htp_server->seaf_session->repo_mgr,
                                                      repo_id, token);
        if (email == NULL) {
            pthread_mutex_unlock (&htp_server->token_cache_lock);
            g_strfreev (parts);
            evhtp_send_reply (req, EVHTP_RES_FORBIDDEN);
            return;
        }

        token_info = g_new0 (TokenInfo, 1);
        token_info->repo_id = g_strdup (repo_id);
        token_info->expire_time = (long)time(NULL) + TOKEN_EXPIRE_TIME;
        token_info->email = email;

        g_hash_table_insert (htp_server->token_cache, g_strdup (token), token_info);
    } else {
        email = token_info->email;
    }

    pthread_mutex_unlock (&htp_server->token_cache_lock);

    char *perm = seaf_repo_manager_check_permission (htp_server->seaf_session->repo_mgr,
                                                     repo_id, email, NULL);
    if (!perm ||
        (strcmp (perm, "r") == 0 && strcmp (op, "upload") == 0)) {
        evhtp_send_reply (req, EVHTP_RES_FORBIDDEN);
        g_free (perm);
        goto out;
    }

    evhtp_send_reply (req, EVHTP_RES_OK);

out:
    g_strfreev (parts);
}

static void
get_protocol_cb (evhtp_request_t *req, void *arg)
{
    evbuffer_add (req->buffer_out, PROTO_VERSION, strlen (PROTO_VERSION));
    evhtp_send_reply (req, EVHTP_RES_OK);
}

static void
get_check_quoto_cb (evhtp_request_t *req, void *arg)
{
    const char *delta = evhtp_kv_find (req->uri->query, "delta");
    long int delta_num;
    if (delta == NULL ||
        (delta_num = strtol(delta, NULL, 10)) == 0) {
        char *error = "Invalid delta parameter.\n";
        seaf_warning ("%s", error);
        evbuffer_add (req->buffer_out, error, strlen (error));
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
        return;
    }

    int token_status = validate_token_cb (req, arg);
    if (token_status != EVHTP_RES_OK) {
        evhtp_send_reply (req, token_status);
        return;
    }

    SeafileSession *session = ((HttpServer *)arg)->seaf_session;
    char **parts = g_strsplit (req->uri->path->full + 1, "/", 0);
    char *repo_id = parts[1];

    if (seaf_quota_manager_check_quota (session->quota_mgr, repo_id) < 0) {
        evhtp_send_reply (req, EVHTP_RES_FORBIDDEN);
    } else {
        evhtp_send_reply (req, EVHTP_RES_OK);
    }

    g_strfreev (parts);
}

static void
get_head_commit_cb (evhtp_request_t *req, void *arg)
{
    int token_status = validate_token_cb (req, arg);
    if (token_status != EVHTP_RES_OK) {
        evhtp_send_reply (req, token_status);
        return;
    }

    SeafileSession *session = ((HttpServer *)arg)->seaf_session;
    char **parts = g_strsplit (req->uri->path->full + 1, "/", 0);
    char *repo_id = parts[1];

    SeafRepo *repo = seaf_repo_manager_get_repo (session->repo_mgr, repo_id);
    if (!repo) {
        seaf_warning ("Get head commit failed: Repo %s is missing or corrupted.\n", repo_id);
        evhtp_send_reply (req, EVHTP_RES_NOTFOUND);
        goto out;
    }

    evbuffer_add_printf (req->buffer_out,
                         "{\"is_corrupted\": %d, \"head_commit_id\": %s}",
                         repo->is_corrupted, repo->head->commit_id);
    evhtp_send_reply (req, EVHTP_RES_OK);
    seaf_repo_unref (repo);

out:
    g_strfreev (parts);
}

static char *
gen_merge_description (SeafRepo *repo,
                       const char *merged_root,
                       const char *p1_root,
                       const char *p2_root)
{
    GList *p;
    GList *results = NULL;
    char *desc;

    diff_merge_roots (repo->store_id, repo->version,
                      merged_root, p1_root, p2_root, &results, TRUE);

    desc = diff_results_to_description (results);

    for (p = results; p; p = p->next) {
        DiffEntry *de = p->data;
        diff_entry_free (de);
    }
    g_list_free (results);

    return desc;
}

static int
fast_forward_or_merge (const char *repo_id,
                       SeafCommit *base,
                       SeafCommit *new_commit)
{
#define MAX_RETRY_COUNT 3

    SeafRepo *repo = NULL;
    SeafCommit *current_head = NULL, *merged_commit = NULL;
    int retry_cnt = 0;
    int ret = 0;

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        seaf_warning ("Repo %s doesn't exist.\n", repo_id);
        ret = -1;
        goto out;
    }

retry:
    current_head = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                                   repo->id, repo->version,
                                                   repo->head->commit_id);
    if (!current_head) {
        seaf_warning ("Failed to find head commit of %s.\n", repo_id);
        ret = -1;
        goto out;
    }

    /* Merge if base and head are not the same. */
    if (strcmp (base->commit_id, current_head->commit_id) != 0) {
        MergeOptions opt;
        const char *roots[3];
        char *desc = NULL;

        memset (&opt, 0, sizeof(opt));
        opt.n_ways = 3;
        memcpy (opt.remote_repo_id, repo_id, 36);
        memcpy (opt.remote_head, new_commit->commit_id, 40);
        opt.do_merge = TRUE;

        roots[0] = base->root_id; /* base */
        roots[1] = current_head->root_id; /* head */
        roots[2] = new_commit->root_id;      /* remote */

        if (seaf_merge_trees (repo->store_id, repo->version, 3, roots, &opt) < 0) {
            seaf_warning ("Failed to merge.\n");
            ret = -1;
            goto out;
        }

        if (!opt.conflict)
            desc = g_strdup("Auto merge by system");
        else {
            desc = gen_merge_description (repo,
                                          opt.merged_tree_root,
                                          current_head->root_id,
                                          new_commit->root_id);
            if (!desc)
                desc = g_strdup("Auto merge by system");
        }

        merged_commit = seaf_commit_new(NULL, repo->id, opt.merged_tree_root,
                                        new_commit->creator_name, EMPTY_SHA1,
                                        desc,
                                        0);
        g_free (desc);

        merged_commit->parent_id = g_strdup (current_head->commit_id);
        merged_commit->second_parent_id = g_strdup (new_commit->commit_id);
        merged_commit->new_merge = TRUE;
        if (opt.conflict)
            merged_commit->conflict = TRUE;
        seaf_repo_to_commit (repo, merged_commit);

        if (seaf_commit_manager_add_commit (seaf->commit_mgr, merged_commit) < 0) {
            seaf_warning ("Failed to add commit.\n");
            ret = -1;
            goto out;
        }
    } else {
        seaf_commit_ref (new_commit);
        merged_commit = new_commit;
    }

    seaf_branch_set_commit(repo->head, merged_commit->commit_id);

    if (seaf_branch_manager_test_and_update_branch(seaf->branch_mgr,
                                                   repo->head,
                                                   current_head->commit_id) < 0)
    {
        seaf_repo_unref (repo);
        repo = NULL;
        seaf_commit_unref (current_head);
        current_head = NULL;
        seaf_commit_unref (merged_commit);
        merged_commit = NULL;

        repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
        if (!repo) {
            seaf_warning ("Repo %s doesn't exist.\n", repo_id);
            ret = -1;
            goto out;
        }

        if (++retry_cnt <= MAX_RETRY_COUNT) {
            seaf_message ("Concurrent branch update, retry.\n");
            /* Sleep random time between 100 and 1000 millisecs. */
            usleep (g_random_int_range(1, 11) * 100 * 1000);
            goto retry;
        } else {
            seaf_warning ("Stop retrying.\n");
            ret = -1;
            goto out;
        }
    }

out:
    seaf_commit_unref (current_head);
    seaf_commit_unref (merged_commit);
    seaf_repo_unref (repo);
    return ret;
}

static void
put_update_branch_cb (evhtp_request_t *req, void *arg)
{
    int token_status = validate_token_cb (req, arg);
    if (token_status != EVHTP_RES_OK) {
        evhtp_send_reply (req, token_status);
        return;
    }

    const char *new_commit_id = evhtp_kv_find (req->uri->query, "head");
    if (new_commit_id == NULL || strlen (new_commit_id) != 40) {
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
        return;
    }

    SeafileSession *seaf = ((HttpServer *)arg)->seaf_session;
    char **parts = g_strsplit (req->uri->path->full + 1, "/", 0);
    char *repo_id = parts[1];
    SeafRepo *repo = NULL;
    SeafCommit *new_commit = NULL, *base = NULL;

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        seaf_warning ("Repo %s is missing or corrupted.\n", repo_id);
        evhtp_send_reply (req, EVHTP_RES_NOTFOUND);
        goto out;
    }

    /* Since this is the last step of upload procedure, commit should exist. */
    new_commit = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                                 repo->id, repo->version,
                                                 new_commit_id);
    if (!new_commit) {
        seaf_warning ("Failed to get commit %s for repo %s.\n",
                      new_commit_id, repo->id);
        evhtp_send_reply (req, EVHTP_RES_NOTFOUND);
        goto out;
    }

    base = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                           repo->id, repo->version,
                                           new_commit->parent_id);
    if (!base) {
        seaf_warning ("Failed to get commit %s for repo %s.\n",
                      new_commit->parent_id, repo->id);
        evhtp_send_reply (req, EVHTP_RES_NOTFOUND);
        goto out;
    }

    if (seaf_quota_manager_check_quota (seaf->quota_mgr, repo_id) < 0) {
        seaf_warning ("Quota is full for repo %s.\n", repo->id);
        evhtp_send_reply (req, EVHTP_RES_FORBIDDEN);
        goto out;
    }

    if (fast_forward_or_merge (repo_id, base, new_commit) < 0) {
        seaf_warning ("Fast forward merge is failed.\n");
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
        goto out;
    }

    seaf_repo_manager_cleanup_virtual_repos (seaf->repo_mgr, repo_id);
    seaf_repo_manager_merge_virtual_repo (seaf->repo_mgr, repo_id, NULL);

    evhtp_send_reply (req, EVHTP_RES_OK);

out:
    seaf_repo_unref (repo);
    seaf_commit_unref (new_commit);
    seaf_commit_unref (base);
    g_strfreev (parts);
}

static void
head_commit_oper_cb (evhtp_request_t *req, void *arg)
{
   htp_method req_method = evhtp_request_get_method (req);

   if (req_method == htp_method_GET) {
       get_head_commit_cb (req, arg);
   } else if (req_method == htp_method_PUT) {
       put_update_branch_cb (req, arg);
   }
}

static void
get_commit_info_cb (evhtp_request_t *req, void *arg)
{
    int token_status = validate_token_cb (req, arg);
    if (token_status != EVHTP_RES_OK) {
        evhtp_send_reply (req, token_status);
        return;
    }

    SeafileSession *session = ((HttpServer *)arg)->seaf_session;
    char **parts = g_strsplit (req->uri->path->full + 1, "/", 0);
    char *repo_id = parts[1];
    char *commit_id = parts[3];
    char *data = NULL;
    int len;

    int ret = seaf_obj_store_read_obj (session->commit_mgr->obj_store, repo_id, 1,
                                       commit_id, (void **)&data, &len);
    if (ret < 0) {
        seaf_warning ("Get commit info failed: commit %s is missing.\n", commit_id);
        evhtp_send_reply (req, EVHTP_RES_NOTFOUND);
        goto out;
    }

    evbuffer_add (req->buffer_out, data, len);
    evhtp_send_reply (req, EVHTP_RES_OK);
    g_free (data);

out:
    g_strfreev (parts);
}

static void
put_commit_cb (evhtp_request_t *req, void *arg)
{
    int token_status = validate_token_cb (req, arg);
    if (token_status != EVHTP_RES_OK) {
        evhtp_send_reply (req, token_status);
        return;
    }

    int con_len = evbuffer_get_length (req->buffer_in);
    if(con_len == 0) {
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
        return;
    }

    void *data = g_new0 (char, con_len);
    if (!data) {
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
        return;
    }

    SeafileSession *session = ((HttpServer *)arg)->seaf_session;
    char **parts = g_strsplit (req->uri->path->full + 1, "/", 0);
    char *commit_id = parts[3];

    evbuffer_remove (req->buffer_in, data, con_len);
    SeafCommit *commit = seaf_commit_from_data (commit_id, (char *)data, con_len);
    if (!commit) {
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
        goto out;
    }

    if (seaf_commit_manager_add_commit (session->commit_mgr, commit) < 0) {
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
    } else {
        evhtp_send_reply (req, EVHTP_RES_OK);
    }
    seaf_commit_unref (commit);

out:
    g_free (data);
    g_strfreev (parts);
}

static void
commit_oper_cb (evhtp_request_t *req, void *arg)
{
    htp_method req_method = evhtp_request_get_method (req);

    if (req_method == htp_method_PUT) {
        put_commit_cb (req, arg);
    } else if (req_method == htp_method_GET) {
        get_commit_info_cb (req, arg);
    }
}

static gboolean
get_fs_obj_id (SeafCommit *commit, void *data, gboolean *stop)
{
    if (strlen (commit->root_id) != 40) {
        *stop = TRUE;
        return FALSE;
    }

    GList **list = (GList **)data;
    *list = g_list_prepend (*list, g_strdup (commit->root_id));
    return TRUE;
}

static void
get_fs_obj_id_cb (evhtp_request_t *req, void *arg)
{
    const char *commit_id = evhtp_kv_find (req->uri->query, "client-head");
    if (commit_id == NULL || strlen (commit_id) != 40) {
        char *error = "Invalid client-head parameter.\n";
        seaf_warning ("%s", error);
        evbuffer_add (req->buffer_out, error, strlen (error));
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
        return;
    }

    int token_status = validate_token_cb (req, arg);
    if (token_status != EVHTP_RES_OK) {
        evhtp_send_reply (req, token_status);
        return;
    }

    SeafileSession *session = ((HttpServer *)arg)->seaf_session;
    char **parts = g_strsplit (req->uri->path->full + 1, "/", 0);
    char *repo_id = parts[1];
    GList *list = NULL;

    int ret = seaf_commit_manager_traverse_commit_tree (session->commit_mgr, repo_id, 1,
                                                        commit_id, get_fs_obj_id,
                                                        &list, FALSE);
    g_strfreev (parts);

    if (ret < 0) {
        seaf_warning ("Get FS obj_id failed: commit %s is missing.\n", commit_id);
        evhtp_send_reply (req, EVHTP_RES_NOTFOUND);
        return;
    }

    GList *ptr = list;
    json_t *obj_array = json_array ();

    for (; ptr; ptr = ptr->next) {
        json_array_append_new (obj_array, json_string (ptr->data));
        g_free (ptr->data);
    }
    g_list_free (list);

    char *obj_list = json_dumps (obj_array, JSON_COMPACT);
    evbuffer_add (req->buffer_out, obj_list, strlen (obj_list));
    evhtp_send_reply (req, EVHTP_RES_OK);

    g_free (obj_list);
    json_decref (obj_array);
}

static void
get_block_cb (evhtp_request_t *req, void *arg)
{
    int token_status = validate_token_cb (req, arg);
    if (token_status != EVHTP_RES_OK) {
        evhtp_send_reply (req, token_status);
        return;
    }

    const char *repo_id = NULL;
    char *block_id = NULL;
    SeafileSession *session = ((HttpServer *)arg)->seaf_session;

    char **parts = g_strsplit (req->uri->path->full + 1, "/", 0);
    repo_id = parts[1];
    block_id = parts[3];

    if (!seaf_block_manager_block_exists (session->block_mgr, repo_id, 1, block_id)) {
        evhtp_send_reply (req, EVHTP_RES_NOTFOUND);
        goto out;
    }

    BlockHandle *blk_handle = NULL;
    blk_handle = seaf_block_manager_open_block(session->block_mgr,
                                               repo_id, 1, block_id, BLOCK_READ);
    if (!blk_handle) {
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
        goto out;
    }

    BlockMetadata *blk_meta = NULL;
    blk_meta = seaf_block_manager_stat_block (session->block_mgr,
                                              repo_id, 1, block_id);
    if (blk_meta == NULL) {
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
        goto free_handle;
    }

    void *block_con = g_new0 (char, blk_meta->size);
    if (!block_con) {
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
        goto free_handle;
    }

    int rsize = seaf_block_manager_read_block (session->block_mgr,
                                               blk_handle, block_con,
                                               blk_meta->size);
    if (rsize != blk_meta->size) {
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
    } else {
        evbuffer_add (req->buffer_out, block_con, blk_meta->size);
        evhtp_send_reply (req, EVHTP_RES_OK);
    }
    g_free (block_con);

free_handle:
    seaf_block_manager_close_block (session->block_mgr, blk_handle);
    seaf_block_manager_block_handle_free (session->block_mgr, blk_handle);

out:
    g_strfreev (parts);
}

static void
put_send_block_cb (evhtp_request_t *req, void *arg)
{
    int token_status = validate_token_cb (req, arg);
    if (token_status != EVHTP_RES_OK) {
        evhtp_send_reply (req, token_status);
        return;
    }

    const char *repo_id = NULL;
    char *block_id = NULL;
    SeafileSession *session = ((HttpServer *)arg)->seaf_session;

    char **parts = g_strsplit (req->uri->path->full + 1, "/", 0);
    repo_id = parts[1];
    block_id = parts[3];

    BlockHandle *blk_handle = NULL;
    blk_handle = seaf_block_manager_open_block (session->block_mgr,
                                                repo_id, 1, block_id, BLOCK_WRITE);
    g_strfreev (parts);

    if (blk_handle == NULL) {
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
        return;
    }

    int blk_len = evbuffer_get_length (req->buffer_in);
    if (blk_len == 0) {
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
        goto out;
    }

    void *blk_con = g_new0 (char, blk_len);
    if (!blk_con) {
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
        goto out;
    }

    evbuffer_remove (req->buffer_in, blk_con, blk_len);
    if (seaf_block_manager_write_block (session->block_mgr, blk_handle,
                                        blk_con, blk_len) != blk_len) {
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
        goto write_fail;
    }

    if (seaf_block_manager_commit_block (session->block_mgr,
                                         blk_handle) < 0) {
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
    } else {
        evhtp_send_reply (req, EVHTP_RES_OK);
    }

write_fail:
    g_free (blk_con);

out:
    seaf_block_manager_close_block (session->block_mgr, blk_handle);
    seaf_block_manager_block_handle_free (session->block_mgr, blk_handle);
}

static void
block_oper_cb (evhtp_request_t *req, void *arg)
{
    htp_method req_method = evhtp_request_get_method (req);

    if (req_method == htp_method_GET) {
        get_block_cb (req, arg);
    } else if (req_method == htp_method_PUT) {
        put_send_block_cb (req, arg);
    }
}

static void
post_check_exist_cb (evhtp_request_t *req, void *arg, CheckExistType type)
{
    int token_status = validate_token_cb (req, arg);
    if (token_status != EVHTP_RES_OK) {
        evhtp_send_reply (req, token_status);
        return;
    }

    size_t list_len = evbuffer_get_length (req->buffer_in);
    if (list_len == 0) {
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
        return;
    }

    char *obj_list_con = g_new0 (char, list_len);
    if (!obj_list_con) {
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
        return;
    }

    json_error_t jerror;
    evbuffer_remove (req->buffer_in, obj_list_con, list_len);
    json_t *obj_array = json_loadb (obj_list_con, list_len, 0, &jerror);

    if (!obj_array) {
        if (obj_list_con[list_len - 1] == 0)
            clean_utf8_data (obj_list_con, list_len - 1);
        else
            clean_utf8_data (obj_list_con, list_len);

        obj_array = json_loadb (obj_list_con, list_len, 0, &jerror);
    }
    g_free (obj_list_con);

    if (!obj_array) {
        seaf_warning ("dump obj_id to json failed, error: %s\n", jerror.text);
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
        return;
    }

    const char *repo_id = NULL;
    json_t *obj = NULL;
    gboolean ret = TRUE;
    const char *obj_id = NULL;
    int index = 0;

    SeafileSession *session = ((HttpServer *)arg)->seaf_session;
    char **parts = g_strsplit (req->uri->path->full + 1, "/", 0);
    repo_id = parts[1];
    int array_size = json_array_size (obj_array);
    json_t *needed_objs = json_array();

    for (; index < array_size; ++index) {
        obj = json_array_get (obj_array, index);
        obj_id = json_string_value (obj);
        if (strlen (obj_id) != 40)
            continue;

        if (type == CHECK_FS_EXIST) {
            ret = seaf_fs_manager_object_exists (session->fs_mgr, repo_id, 1,
                                                 obj_id);
        } else if (type == CHECK_BLOCK_EXIST) {
            ret = seaf_block_manager_block_exists (session->block_mgr, repo_id, 1,
                                                   obj_id);
        }

        if (!ret) {
            json_array_append (needed_objs, obj);
        }
    }

    char *ret_array = json_dumps (needed_objs, JSON_COMPACT);
    evbuffer_add (req->buffer_out, ret_array, strlen (ret_array));
    evhtp_send_reply (req, EVHTP_RES_OK);

    g_free (ret_array);
    json_decref (needed_objs);
    json_decref (obj_array);
    g_strfreev (parts);
}

static void
post_check_fs_cb (evhtp_request_t *req, void *arg)
{
   post_check_exist_cb (req, arg, CHECK_FS_EXIST);
}

static void
post_check_block_cb (evhtp_request_t *req, void *arg)
{
   post_check_exist_cb (req, arg, CHECK_BLOCK_EXIST);
}

static void
post_recv_fs_cb (evhtp_request_t *req, void *arg)
{
    int token_status = validate_token_cb (req, arg);
    if (token_status != EVHTP_RES_OK) {
        evhtp_send_reply (req, token_status);
        return;
    }

    int fs_con_len = evbuffer_get_length (req->buffer_in);
    if (fs_con_len == 0) {
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
        return;
    }

    char *obj_id = g_new0 (char, 44);
    if (!obj_id) {
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
    }

    void *obj_con = NULL;
    int con_len;
    SeafileSession *session = ((HttpServer *)arg)->seaf_session;
    char **parts = g_strsplit (req->uri->path->full + 1, "/", 0);
    const char *repo_id = parts[1];

    while (fs_con_len) {
        evbuffer_remove (req->buffer_in, obj_id, 44);
        memcpy (&con_len, obj_id + 40, 4);
        con_len = ntohl (con_len);
        obj_id[40] = '\0';

        obj_con = g_new0 (char, con_len);
        if (!obj_con) {
            evhtp_send_reply (req, EVHTP_RES_SERVERR);
            break;
        }
        evbuffer_remove (req->buffer_in, obj_con, con_len);

        if (seaf_obj_store_write_obj (session->fs_mgr->obj_store,
                                      repo_id, 1, obj_id, obj_con,
                                      con_len, FALSE) < 0) {
            seaf_warning ("Failed to write fs object %.8s to disk.\n",
                          obj_id);
            g_free (obj_con);
            evhtp_send_reply (req, EVHTP_RES_SERVERR);
            break;
        }

        fs_con_len -= con_len + 44;
        g_free (obj_con);
    }

    if (fs_con_len == 0) {
        evhtp_send_reply (req, EVHTP_RES_OK);
    }

    g_free (obj_id);
    g_strfreev (parts);
}

static void
post_pack_fs_cb (evhtp_request_t *req, void *arg)
{
    int token_status = validate_token_cb (req, arg);
    if (token_status != EVHTP_RES_OK) {
        evhtp_send_reply (req, token_status);
        return;
    }

    int fs_id_list_len = evbuffer_get_length (req->buffer_in);
    if (fs_id_list_len == 0) {
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
        return;
    }

    char *fs_id_list = g_new0 (char, fs_id_list_len);
    if (!fs_id_list) {
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
        return;
    }

    json_error_t jerror;
    evbuffer_remove (req->buffer_in, fs_id_list, fs_id_list_len);
    json_t *fs_id_array = json_loadb (fs_id_list, fs_id_list_len, 0, &jerror);

    if (!fs_id_array) {
        if (fs_id_list[fs_id_list_len - 1] == 0)
            clean_utf8_data (fs_id_list, fs_id_list_len - 1);
        else
            clean_utf8_data (fs_id_list, fs_id_list_len);

        fs_id_array = json_loadb (fs_id_list, fs_id_list_len, 0, &jerror);
    }
    g_free (fs_id_list);

    if (!fs_id_array) {
        seaf_warning ("dump fs obj_id from json failed, error: %s\n", jerror.text);
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
        return;
    }

    json_t *obj = NULL;
    const char *obj_id = NULL;
    int index = 0;
    void *fs_data = NULL;
    int data_len;
    int data_len_net;
    int valid_count = 0;

    int array_size = json_array_size (fs_id_array);
    SeafileSession *session = ((HttpServer *)arg)->seaf_session;
    char **parts = g_strsplit (req->uri->path->full + 1, "/", 0);
    const char *repo_id = parts[1];

    for (; index < array_size; ++index) {
        obj = json_array_get (fs_id_array, index);
        obj_id = json_string_value (obj);

        if (strlen (obj_id) != 40) {
            seaf_warning ("Invalid fs id %s.\n", obj_id);
            break;
        }
        if (seaf_obj_store_read_obj (session->fs_mgr->obj_store, repo_id, 1,
                                     obj_id, &fs_data, &data_len) < 0) {
            seaf_warning ("Failed to read seafile object %s.\n", obj_id);
            break;
        }

        evbuffer_add (req->buffer_out, obj_id, 40);
        data_len_net = htonl (data_len);
        evbuffer_add (req->buffer_out, &data_len_net, 4);
        evbuffer_add (req->buffer_out, fs_data, data_len);

        ++valid_count;
        g_free (fs_data);
    }

    if (valid_count == array_size) {
        evhtp_send_reply (req, EVHTP_RES_OK);
    } else {
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
    }

    json_decref (fs_id_array);
    g_strfreev (parts);
}

static void
http_request_init (HttpServer *htp_server)
{
    evhtp_set_cb (htp_server->evhtp,
                  GET_PROTO_PATH, get_protocol_cb,
                  NULL);

    evhtp_set_regex_cb (htp_server->evhtp,
                        GET_CHECK_QUOTA_REGEX, get_check_quoto_cb,
                        htp_server);

    evhtp_set_regex_cb (htp_server->evhtp,
                        OP_PERM_CHECK_REGEX, get_check_permission_cb,
                        htp_server);

    evhtp_set_regex_cb (htp_server->evhtp,
                        HEAD_COMMIT_OPER_REGEX, head_commit_oper_cb,
                        htp_server);

    evhtp_set_regex_cb (htp_server->evhtp,
                        COMMIT_OPER_REGEX, commit_oper_cb,
                        htp_server);

    evhtp_set_regex_cb (htp_server->evhtp,
                        GET_FS_OBJ_ID_REGEX, get_fs_obj_id_cb,
                        htp_server);

    evhtp_set_regex_cb (htp_server->evhtp,
                        BLOCKT_OPER_REGEX, block_oper_cb,
                        htp_server);

    evhtp_set_regex_cb (htp_server->evhtp,
                        POST_CHECK_FS_REGEX, post_check_fs_cb,
                        htp_server);

    evhtp_set_regex_cb (htp_server->evhtp,
                        POST_CHECK_BLOCK_REGEX, post_check_block_cb,
                        htp_server);

    evhtp_set_regex_cb (htp_server->evhtp,
                        POST_RECV_FS_REGEX, post_recv_fs_cb,
                        htp_server);

    evhtp_set_regex_cb (htp_server->evhtp,
                        POST_PACK_FS_REGEX, post_pack_fs_cb,
                        htp_server);
}

static void
token_cache_value_free (gpointer data)
{
    TokenInfo *token_info = (TokenInfo *)data;
    if (token_info != NULL) {
        g_free (token_info->repo_id);
        g_free (token_info->email);
        g_free (token_info);
    }
}

static gboolean
is_token_expire (gpointer key, gpointer value, gpointer arg)
{
    TokenInfo *token_info = (TokenInfo *)value;

    if(token_info && token_info->expire_time >= (long)time(NULL)) {
        return TRUE;
    }

    return FALSE;
}

static void
remove_expire_token_cb (evutil_socket_t sock, short type, void *data)
{
    HttpServer *htp_server = data;

    pthread_mutex_lock (&htp_server->token_cache_lock);
    g_hash_table_foreach_remove (htp_server->token_cache, is_token_expire, NULL);
    pthread_mutex_unlock (&htp_server->token_cache_lock);
}

static void *
http_server_run (void *arg)
{
    HttpServer *htp_server = arg;
    htp_server->evbase = event_base_new();
    htp_server->evhtp = evhtp_new(htp_server->evbase, NULL);

    if (evhtp_bind_socket(htp_server->evhtp,
                          htp_server->bind_addr,
                          htp_server->bind_port, 128) < 0) {
        seaf_warning ("Could not bind socket: %s\n", strerror (errno));
        exit(-1);
    }

    evhtp_set_gencb (htp_server->evhtp, default_cb, NULL);

    http_request_init (htp_server);

    evhtp_use_threads (htp_server->evhtp, NULL, 50, NULL);

    struct timeval tv;
    tv.tv_sec = CLEANING_INTERVAL_MSEC;
    tv.tv_usec = 0;
    htp_server->token_timer = evtimer_new (htp_server->evbase, remove_expire_token_cb,
                                           htp_server);
    evtimer_add (htp_server->token_timer, &tv);

    event_base_loop (htp_server->evbase, 0);
    seaf_http_server_release (htp_server);

    return NULL;
}

HttpServer *
seaf_http_server_new (struct _SeafileSession *session)
{
    HttpServer *http_server = g_new0 (HttpServer, 1);
    http_server->evbase = NULL;
    http_server->evhtp = NULL;
    http_server->thread_id = 0;

    load_http_config (http_server, session);

    session->http_server = http_server;
    http_server->seaf_session = session;
    http_server->token_cache = g_hash_table_new_full (g_str_hash, g_str_equal,
                                                      g_free, token_cache_value_free);
    pthread_mutexattr_t mutex_attr;
    pthread_mutexattr_init(&mutex_attr);
    pthread_mutexattr_settype(&mutex_attr, PTHREAD_MUTEX_RECURSIVE_NP);
    pthread_mutex_init (&http_server->token_cache_lock, &mutex_attr);

    return http_server;
}

void seaf_http_server_release (HttpServer *htp_server)
{
    if (htp_server) {
        if (htp_server->bind_addr) {
            g_free (htp_server->bind_addr);
        }
        if (htp_server->evhtp) {
            evhtp_unbind_socket (htp_server->evhtp);
            evhtp_free (htp_server->evhtp);
        }
        if (htp_server->evbase) {
            event_base_free (htp_server->evbase);
        }
        if (htp_server->token_cache) {
            g_hash_table_destroy (htp_server->token_cache);
        }
        if (htp_server->token_timer) {
            event_del (htp_server->token_timer);
        }
    }
}

int
seaf_http_server_start (HttpServer *htp_server)
{
   int ret = pthread_create (&htp_server->thread_id, NULL, http_server_run, htp_server);
   if (ret != 0)
       return -1;
   else
       return 0;
}

int
seaf_http_server_join (HttpServer *htp_server)
{
    if (htp_server->thread_id <= 0)
        return -1;
    return pthread_join (htp_server->thread_id, NULL);
}

int
seaf_http_server_detach (HttpServer *htp_server)
{
    if (htp_server->thread_id <= 0)
        return -1;
    return pthread_detach (htp_server->thread_id);
}

