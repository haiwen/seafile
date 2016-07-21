#include <pthread.h>
#include <jansson.h>

#include <ccnet.h>

#include "common.h"
#include "utils.h"
#include "log.h"
#include "seafile-error.h"
#include "seafile-session.h"
#include "pack-dir.h"
#include "web-accesstoken-mgr.h"
#include "zip-download-mgr.h"

#define MAX_ZIP_THREAD_NUM 5
#define SCAN_PROGRESS_INTERVAL 24 * 3600 // 1 day
#define PROGRESS_TTL 5 * 3600 // 5 hours

typedef struct ZipDownloadMgrPriv {
    pthread_mutex_t progress_lock;
    GHashTable *progress_store;
    GThreadPool *zip_tpool;
    // Abnormal behavior lead to no download request for the zip finished progress,
    // so related progress will not be removed,
    // this timer is used to scan progress and remove invalid progress.
    CcnetTimer *scan_progress_timer;
} ZipDownloadMgrPriv;

void
free_progress (Progress *progress)
{
    if (!progress)
        return;

    if (g_file_test (progress->zip_file_path, G_FILE_TEST_EXISTS)) {
        g_unlink (progress->zip_file_path);
    }
    g_free (progress->zip_file_path);
    g_free (progress);
}

typedef enum DownloadType {
    DOWNLOAD_DIR,
    DOWNLOAD_MULTI
} DownloadType;

typedef struct DownloadObj {
    char *token;
    DownloadType type;
    SeafRepo *repo;
    char *user;
    gboolean is_windows;
    // download-dir: top dir name; download-multi: ""
    char *dir_name;
    // download-dir: obj_id; download-multi: dirent list
    void *internal;
    Progress *progress;
} DownloadObj;

static void
free_download_obj (DownloadObj *obj)
{
    if (!obj)
        return;

    g_free (obj->token);
    seaf_repo_unref (obj->repo);
    g_free (obj->user);
    g_free (obj->dir_name);
    if (obj->type == DOWNLOAD_DIR) {
        g_free ((char *)obj->internal);
    } else {
        g_list_free_full ((GList *)obj->internal, (GDestroyNotify)seaf_dirent_free);
    }
    g_free (obj);
}

static void
start_zip_task (gpointer data, gpointer user_data);

static int
scan_progress (void *data);

ZipDownloadMgr *
zip_download_mgr_new ()
{
    GError *error = NULL;
    ZipDownloadMgr *mgr = g_new0 (ZipDownloadMgr, 1);
    ZipDownloadMgrPriv *priv = g_new0 (ZipDownloadMgrPriv, 1);

    priv->zip_tpool = g_thread_pool_new (start_zip_task, priv, MAX_ZIP_THREAD_NUM, FALSE, &error);
    if (!priv->zip_tpool) {
        if (error) {
            seaf_warning ("Failed to create zip task thread pool: %s.\n", error->message);
            g_clear_error (&error);
        } else {
            seaf_warning ("Failed to create zip task thread pool.\n");
        }
        g_free (priv);
        g_free (mgr);
        return NULL;
    }

    pthread_mutex_init (&priv->progress_lock, NULL);
    priv->progress_store = g_hash_table_new_full (g_str_hash, g_str_equal, g_free,
                                                  (GDestroyNotify)free_progress);
    priv->scan_progress_timer = ccnet_timer_new (scan_progress, priv,
                                                 SCAN_PROGRESS_INTERVAL * 1000);
    mgr->priv = priv;

    return mgr;
}

static void
remove_progress_by_token (ZipDownloadMgrPriv *priv, const char *token)
{
    pthread_mutex_lock (&priv->progress_lock);
    g_hash_table_remove (priv->progress_store, token);
    pthread_mutex_unlock (&priv->progress_lock);
}

static int
scan_progress (void *data)
{
    time_t now = time(NULL);
    ZipDownloadMgrPriv *priv = data;
    GHashTableIter iter;
    gpointer key, value;
    Progress *progress;

    pthread_mutex_lock (&priv->progress_lock);

    g_hash_table_iter_init (&iter, priv->progress_store);
    while (g_hash_table_iter_next (&iter, &key, &value)) {
        progress = value;
        if (now >= progress->expire_ts) {
            g_hash_table_iter_remove (&iter);
        }
    }

    pthread_mutex_unlock (&priv->progress_lock);

    return TRUE;
}

static SeafileCrypt *
get_seafile_crypt (SeafRepo *repo, const char *user)
{
    SeafileCryptKey *key = NULL;
    char *key_hex, *iv_hex;
    unsigned char enc_key[32], enc_iv[16];
    SeafileCrypt *crypt = NULL;

    key = seaf_passwd_manager_get_decrypt_key (seaf->passwd_mgr,
                                               repo->id, user);
    if (!key) {
        seaf_warning ("Failed to get derypt key for repo %.8s.\n", repo->id);
        return NULL;
    }

    g_object_get (key, "key", &key_hex, "iv", &iv_hex, NULL);
    if (repo->enc_version == 1)
        hex_to_rawdata (key_hex, enc_key, 16);
    else
        hex_to_rawdata (key_hex, enc_key, 32);
    hex_to_rawdata (iv_hex, enc_iv, 16);
    crypt = seafile_crypt_new (repo->enc_version, enc_key, enc_iv);
    g_free (key_hex);
    g_free (iv_hex);
    g_object_unref (key);

    return crypt;
}

static void
start_zip_task (gpointer data, gpointer user_data)
{
    DownloadObj *obj = data;
    ZipDownloadMgrPriv *priv = user_data;
    SeafRepo *repo = obj->repo;
    SeafileCrypt *crypt = NULL;
    int ret = 0;

    if (repo->encrypted) {
        crypt = get_seafile_crypt (repo, obj->user);
        if (!crypt) {
            ret = -1;
            goto out;
        }
    }

    ret = pack_files (repo->store_id, repo->version, obj->dir_name,
                      obj->internal, crypt, obj->is_windows, obj->progress);

out:
    if (crypt) {
        g_free (crypt);
    }
    if (ret == -1) {
        remove_progress_by_token (priv, obj->token);
    }
    free_download_obj (obj);
}

static int
parse_download_dir_data (DownloadObj *obj, const char *data)
{
    json_t *jobj;
    json_error_t jerror;
    const char *dir_name;
    const char *obj_id;

    jobj = json_loadb (data, strlen(data), 0, &jerror);
    if (!jobj) {
        seaf_warning ("Failed to parse download dir data: %s.\n", jerror.text);
        return -1;
    }

    obj->is_windows = json_object_get_int_member (jobj, "is_windows");

    dir_name = json_object_get_string_member (jobj, "dir_name");
    if (!dir_name || strcmp (dir_name, "") == 0) {
        seaf_warning ("Invalid download dir data: miss dir_name filed.\n");
        json_decref (jobj);
        return -1;
    }

    obj_id = json_object_get_string_member (jobj, "obj_id");
    if (!obj_id || strcmp (obj_id, "") == 0) {
        seaf_warning ("Invalid download dir data: miss obj_id filed.\n");
        json_decref (jobj);
        return -1;
    }

    obj->dir_name = g_strdup (dir_name);
    obj->internal = g_strdup (obj_id);

    json_decref (jobj);

    return 0;
}

static int
parse_download_multi_data (DownloadObj *obj, const char *data)
{
    json_t *jobj;
    SeafRepo *repo = obj->repo;
    const char *tmp_parent_dir;
    char *parent_dir;
    gboolean is_root_dir;
    json_t *name_array;
    json_error_t jerror;
    int i;
    int len;
    const char *file_name;
    char *file_path;
    SeafDirent *dirent;
    GList *dirent_list = NULL;
    GError *error = NULL;

    jobj = json_loadb (data, strlen(data), 0, &jerror);
    if (!jobj) {
        seaf_warning ("Failed to parse download multi data: %s.\n", jerror.text);
        return -1;
    }

    obj->is_windows = json_object_get_int_member (jobj, "is_windows");

    tmp_parent_dir = json_object_get_string_member (jobj, "parent_dir");
    if (!tmp_parent_dir || strcmp (tmp_parent_dir, "") == 0) {
        seaf_warning ("Invalid download multi data, miss parent_dir field.\n");
        json_decref (jobj);
        return -1;
    }
    name_array = json_object_get (jobj, "file_list");
    if (!name_array) {
        seaf_warning ("Invalid download multi data, miss file_list field.\n");
        json_decref (jobj);
        return -1;
    }
    len = json_array_size (name_array);
    if (len == 0) {
        seaf_warning ("Invalid download multi data, miss download file name.\n");
        json_decref (jobj);
        return -1;
    }
    parent_dir = format_dir_path (tmp_parent_dir);
    is_root_dir = strcmp (parent_dir, "/") == 0;

    for (i = 0; i < len; i++) {
        file_name = json_string_value (json_array_get (name_array, i));
        if (strcmp (file_name, "") == 0 || strchr (file_name, '/') != NULL) {
            seaf_warning ("Invalid download file name: %s.\n", file_name);
            if (dirent_list) {
                g_list_free_full (dirent_list, (GDestroyNotify)seaf_dirent_free);
                dirent_list = NULL;
            }
            break;
        }

        if (is_root_dir) {
            file_path = g_strconcat (parent_dir, file_name, NULL);
        } else {
            file_path = g_strconcat (parent_dir, "/", file_name, NULL);
        }

        dirent = seaf_fs_manager_get_dirent_by_path (seaf->fs_mgr, repo->store_id,
                                                     repo->version, repo->root_id,
                                                     file_path, &error);
        if (!dirent) {
            if (error) {
                seaf_warning ("Failed to get dirent for %s: %s.\n",
                              file_path, error->message);
                g_clear_error (&error);
            } else {
                seaf_warning ("Failed to get dirent for %s.\n",
                              file_path);
            }
            g_free (file_path);
            if (dirent_list) {
                g_list_free_full (dirent_list, (GDestroyNotify)seaf_dirent_free);
                dirent_list = NULL;
            }
            break;
        }

        g_free (file_path);
        dirent_list = g_list_prepend (dirent_list, dirent);
    }

    g_free (parent_dir);
    json_decref (jobj);

    if (!dirent_list) {
        return -1;
    }
    obj->dir_name = g_strdup ("");
    obj->internal = dirent_list;
    return 0;
}

static gint64
calcuate_download_multi_size (SeafRepo *repo, GList *dirent_list)
{
    GList *iter = dirent_list;
    SeafDirent *dirent;
    gint64 size;
    gint64 total_size = 0;

    for (; iter; iter = iter->next) {
        dirent = iter->data;
        if (S_ISREG(dirent->mode)) {
            if (repo->version > 0) {
                size = dirent->size;
            } else {
                size = seaf_fs_manager_get_file_size (seaf->fs_mgr, repo->store_id,
                                                      repo->version, dirent->id);
            }
            if (size < 0) {
                seaf_warning ("Failed to get file %s size.\n", dirent->name);
                return -1;
            }
            total_size += size;
        } else if (S_ISDIR(dirent->mode)) {
            size = seaf_fs_manager_get_fs_size (seaf->fs_mgr, repo->store_id,
                                                repo->version, dirent->id);
            if (size < 0) {
                seaf_warning ("Failed to get dir %s size.\n", dirent->name);
                return -1;
            }
            total_size += size;
        }
    }

    return total_size;
}

static int
calcuate_download_multi_file_count (SeafRepo *repo, GList *dirent_list)
{
    GList *iter = dirent_list;
    SeafDirent *dirent;
    int cur_count;
    int count = 0;

    for (; iter; iter = iter->next) {
        dirent = iter->data;
        if (S_ISREG(dirent->mode)) {
            count += 1;
        } else if (S_ISDIR(dirent->mode)) {
            cur_count = seaf_fs_manager_count_fs_files (seaf->fs_mgr, repo->store_id,
                                                        repo->version, dirent->id);
            if (cur_count < 0) {
                seaf_warning ("Failed to get dir %s file count.\n", dirent->name);
                return -1;
            }
            count += cur_count;
        }
    }

    return count;
}

static gboolean
validate_download_size (DownloadObj *obj, GError **error)
{
    SeafRepo *repo = obj->repo;
    gint64 download_size;

    if (obj->type == DOWNLOAD_DIR) {
        download_size = seaf_fs_manager_get_fs_size (seaf->fs_mgr,
                                                     repo->store_id, repo->version,
                                                     (char *)obj->internal);
    } else {
        download_size = calcuate_download_multi_size (repo, (GList *)obj->internal);
    }

    if (download_size < 0) {
        seaf_warning ("Failed to get download size.\n");
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to get download size.");
        return FALSE;
    } else if (download_size > seaf->http_server->max_download_dir_size) {
        seaf_warning ("Total download size %"G_GINT64_FORMAT
                      ", exceed max download dir size %"G_GINT64_FORMAT".\n",
                      download_size, seaf->http_server->max_download_dir_size);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Download size exceed max download dir size.");
        return FALSE;
    }

    return TRUE;
}

static int
get_download_file_count (DownloadObj *obj, GError **error)
{
    int file_count;
    SeafRepo *repo = obj->repo;

    if (obj->type == DOWNLOAD_DIR) {
        file_count = seaf_fs_manager_count_fs_files (seaf->fs_mgr, repo->store_id,
                                                     repo->version, (char *)obj->internal);
    } else {
        file_count = calcuate_download_multi_file_count (repo, (GList *)obj->internal);
    }

    if (file_count < 0) {
        seaf_warning ("Failed to get download file count.\n");
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to get download file count.");
        return -1;
    }

    return file_count;
}

int
zip_download_mgr_start_zip_task (ZipDownloadMgr *mgr,
                                 const char *token,
                                 SeafileWebAccess *info,
                                 GError **error)
{
    const char *repo_id;
    const char *data;
    const char *operation;
    SeafRepo *repo;
    void *internal;
    DownloadObj *obj;
    Progress *progress;
    int file_count;
    int ret = 0;
    ZipDownloadMgrPriv *priv = mgr->priv;

    repo_id = seafile_web_access_get_repo_id (info);
    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        seaf_warning ("Failed to get repo %.8s.\n", repo_id);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to get repo.");
        return -1;
    }
    data = seafile_web_access_get_obj_id (info);
    operation = seafile_web_access_get_op (info);

    obj = g_new0 (DownloadObj, 1);
    obj->token = g_strdup (token);
    obj->repo = repo;
    obj->user = g_strdup (seafile_web_access_get_username (info));

    if (strcmp (operation, "download-dir") == 0) {
        obj->type = DOWNLOAD_DIR;
        ret = parse_download_dir_data (obj, data);
        if (ret < 0) {
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                         "Failed to parse download dir data.");
            goto out;
        }
        if (!seaf_fs_manager_object_exists (seaf->fs_mgr,
                                            repo->store_id, repo->version,
                                            (char *)obj->internal)) {
            seaf_warning ("Dir %s doesn't exist.\n", (char *)obj->internal);
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                         "Dir doesn't exist.");
            ret = -1;
            goto out;
        }
    } else {
        obj->type = DOWNLOAD_MULTI;
        ret = parse_download_multi_data (obj, data);
        if (ret < 0) {
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                         "Failed to parse download multi data.");
            goto out;
        }
    }

    if (!validate_download_size (obj, error)) {
        ret = -1;
        goto out;
    }

    file_count = get_download_file_count (obj, error);
    if (file_count < 0) {
        ret = -1;
        goto out;
    }

    progress = g_new0 (Progress, 1);
    progress->total = file_count;
    progress->expire_ts = time(NULL) + PROGRESS_TTL;
    obj->progress = progress;

    pthread_mutex_lock (&priv->progress_lock);
    g_hash_table_replace (priv->progress_store, g_strdup (token), progress);
    pthread_mutex_unlock (&priv->progress_lock);

    g_thread_pool_push (priv->zip_tpool, obj, NULL);

out:
    if (ret < 0) {
        free_download_obj (obj);
    }

    return ret;
}

static Progress *
get_progress_obj (ZipDownloadMgrPriv *priv, const char *token)
{
    Progress *progress;

    pthread_mutex_lock (&priv->progress_lock);
    progress = g_hash_table_lookup (priv->progress_store, token);
    pthread_mutex_unlock (&priv->progress_lock);

    return progress;
}

char *
zip_download_mgr_query_zip_progress (ZipDownloadMgr *mgr,
                                     const char *token, GError **error)
{
    Progress *progress;
    json_t *obj;
    char *info;

    progress = get_progress_obj (mgr->priv, token);
    if (!progress) {
        seaf_warning ("Zip progress info not found for token %s: "
                      "invalid token or related zip task failed.\n", token);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Zip progress info not found.");
        return NULL;
    }

    obj = json_object ();
    json_object_set_int_member (obj, "zipped", g_atomic_int_get (&progress->zipped));
    json_object_set_int_member (obj, "total", progress->total);
    info = json_dumps (obj, JSON_COMPACT);
    json_decref (obj);

    return info;
}

char *
zip_download_mgr_get_zip_file_path (struct ZipDownloadMgr *mgr,
                                    const char *token)
{
    Progress *progress;

    progress = get_progress_obj (mgr->priv, token);
    if (!progress) {
        return NULL;
    }
    return progress->zip_file_path;
}

void
zip_download_mgr_del_zip_progress (ZipDownloadMgr *mgr,
                                   const char *token)
{
    remove_progress_by_token (mgr->priv, token);
}
