#include "common.h"

#include <ccnet/cevent.h>
#include "seafile-session.h"

#include "obj-backend.h"
#include "obj-store.h"

#define MAX_READER_THREADS 2
#define MAX_WRITER_THREADS 2
#define MAX_STAT_THREADS 2

typedef struct AsyncTask {
    guint32 rw_id;
    char    obj_id[41];
    void    *data;
    int     len;
    gboolean success;
} AsyncTask;

typedef struct OSCallbackStruct {
    OSAsyncCallback cb;
    void *cb_data;
} OSCallbackStruct;

struct SeafObjStore {
    ObjBackend   *bend;

    CEventManager *ev_mgr;

    /* For async read. */
    guint32      next_rd_id;
    GThreadPool *read_tpool;
    GHashTable  *readers;
    guint32      read_ev_id;

    /* For async write. */
    guint32      next_wr_id;
    GThreadPool *write_tpool;
    GHashTable  *writers;
    guint32      write_ev_id;

    /* For async stat. */
    guint32      next_st_id;
    GThreadPool *stat_tpool;
    GHashTable  *stats;
    guint32      stat_ev_id;
};
typedef struct SeafObjStore SeafObjStore;

#ifdef SEAFILE_SERVER
static ObjBackend*
load_obj_backend (GKeyFile *config, const char *obj_type);

static ObjBackend*
load_riak_obj_backend(GKeyFile *config, const char *bend_group);

extern ObjBackend *
obj_backend_riak_new (const char *host,
                      const char *port,
                      const char *bucket,
                      const char *write_policy);
#endif

static void
reader_thread (void *data, void *user_data);
static void
writer_thread (void *data, void *user_data);
static void
stat_thread (void *data, void *user_data);

static void
on_read_done (CEvent *event, void *data);
static void
on_write_done (CEvent *event, void *data);
static void
on_stat_done (CEvent *event, void *data);

extern ObjBackend *
obj_backend_fs_new (const char *obj_dir);

struct SeafObjStore *
seaf_obj_store_new (SeafileSession *seaf, const char *obj_type)
{
    SeafObjStore *store = g_new0 (SeafObjStore, 1);

    if (!store)
        return NULL;

#ifdef SEAFILE_SERVER
    store->bend = load_obj_backend (seaf->config, obj_type);
#endif
    if (!store->bend) {
        char *obj_dir;
        obj_dir = g_build_filename (seaf->seaf_dir, obj_type, NULL);
        store->bend = obj_backend_fs_new (obj_dir);
        g_free (obj_dir);
        if (!store->bend) {
            g_warning ("[Object store] Failed to load backend.\n");
            g_free (store);
            return NULL;
        }
    }

    return store;
}

static int
async_init (SeafObjStore *obj_store, CEventManager *ev_mgr)
{
    GError *error = NULL;

    obj_store->ev_mgr = ev_mgr;

    obj_store->read_tpool = g_thread_pool_new (reader_thread,
                                               obj_store,
                                               MAX_READER_THREADS,
                                               FALSE,
                                               &error);
    if (error) {
        g_warning ("Failed to start reader thread pool: %s.\n", error->message);
        g_clear_error (&error);
        return -1;
    }

    obj_store->readers = g_hash_table_new_full (g_direct_hash, g_direct_equal,
                                                NULL, g_free);
    obj_store->read_ev_id = cevent_manager_register (ev_mgr,
                                                     on_read_done,
                                                     obj_store);

    obj_store->write_tpool = g_thread_pool_new (writer_thread,
                                                obj_store,
                                                MAX_WRITER_THREADS,
                                                FALSE,
                                                &error);
    if (error) {
        g_warning ("Failed to start writer thread pool: %s.\n", error->message);
        g_clear_error (&error);
        return -1;
    }

    obj_store->writers = g_hash_table_new_full (g_direct_hash, g_direct_equal,
                                                NULL, g_free);
    obj_store->write_ev_id = cevent_manager_register (ev_mgr,
                                                      on_write_done,
                                                      obj_store);

    obj_store->stat_tpool = g_thread_pool_new (stat_thread,
                                               obj_store,
                                               MAX_STAT_THREADS,
                                               FALSE,
                                               &error);
    if (error) {
        g_warning ("Failed to start statr thread pool: %s.\n", error->message);
        g_clear_error (&error);
        return -1;
    }

    obj_store->stats = g_hash_table_new_full (g_direct_hash, g_direct_equal,
                                              NULL, g_free);
    obj_store->stat_ev_id = cevent_manager_register (ev_mgr,
                                                     on_stat_done,
                                                     obj_store);

    return 0;
}

int
seaf_obj_store_init (SeafObjStore *obj_store,
                     gboolean enable_async,
                     CEventManager *ev_mgr)
{
    if (enable_async && async_init (obj_store, ev_mgr) < 0)
        return -1;

    return 0;
}

int
seaf_obj_store_read_obj (struct SeafObjStore *obj_store,
                         const char *obj_id,
                         void **data,
                         int *len)
{
    ObjBackend *bend = obj_store->bend;

    return bend->read (bend, obj_id, data, len);
}

int
seaf_obj_store_write_obj (struct SeafObjStore *obj_store,
                          const char *obj_id,
                          void *data,
                          int len)
{
    ObjBackend *bend = obj_store->bend;

    return bend->write (bend, obj_id, data, len);
}

gboolean
seaf_obj_store_obj_exists (struct SeafObjStore *obj_store,
                           const char *obj_id)
{
    ObjBackend *bend = obj_store->bend;

    return bend->exists (bend, obj_id);
}

void
seaf_obj_store_delete_obj (struct SeafObjStore *obj_store,
                           const char *obj_id)
{
    ObjBackend *bend = obj_store->bend;

    return bend->delete (bend, obj_id);
}

#ifdef SEAFILE_SERVER
static ObjBackend*
load_filesystem_obj_backend(GKeyFile *config, const char *bend_group)
{
    ObjBackend *bend;
    char *obj_dir;
    
    obj_dir = g_key_file_get_string (config, bend_group, "object_dir", NULL);
    if (!obj_dir) {
        g_warning ("[Object store] Object dir not set in config for %s.\n",
                   bend_group);
        return NULL;
    }

    bend = obj_backend_fs_new (obj_dir);

    g_free (obj_dir);
    return bend;
}

static ObjBackend*
load_riak_obj_backend(GKeyFile *config, const char *bend_group)
{
    ObjBackend *bend;
    char *host, *port, *bucket, *write_policy;
    
    host = g_key_file_get_string (config, bend_group, "host", NULL);
    if (!host) {
        g_warning ("[Object store] Riak host not set in config for %s.\n",
                   bend_group);
        return NULL;
    }

    port = g_key_file_get_string (config, bend_group, "port", NULL);
    if (!port) {
        g_warning ("[Object store] Riak port not set in config for %s.\n",
                   bend_group);
        return NULL;
    }

    bucket = g_key_file_get_string (config, bend_group, "bucket", NULL);
    if (!bucket) {
        g_warning ("[Object store] Riak bucket not set in config for %s.\n",
                   bend_group);
        return NULL;
    }

    write_policy = g_key_file_get_string (config, bend_group, "write_policy", NULL);
    if (!write_policy) {
        g_warning ("[Object store] Riak write policy not set in config for %s.\n",
                   bend_group);
        return NULL;
    }

    bend = obj_backend_riak_new (host, port, bucket, write_policy);

    g_free (host);
    g_free (port);
    g_free (bucket);
    g_free (write_policy);
    return bend;
}

static ObjBackend*
load_obj_backend (GKeyFile *config, const char *obj_type)
{
    char *bend_group;
    char *backend;
    ObjBackend *bend;

    if (strcmp (obj_type, "commits") == 0)
        bend_group = "commit_object_backend";
    else if (strcmp (obj_type, "fs") == 0)
        bend_group = "fs_object_backend";
    else
        g_return_val_if_reached (NULL);

    backend = g_key_file_get_string (config, bend_group, "name", NULL);
    if (!backend) {
        return NULL;
    }

    if (strcmp(backend, "filesystem") == 0) {
        bend = load_filesystem_obj_backend (config, bend_group);
        g_free (backend);
        return bend;
    } else if (strcmp (backend, "riak") == 0) {
        bend = load_riak_obj_backend (config, bend_group);
        g_free (backend);
        return bend;
    }

    g_warning ("Unknown backend\n");
    return NULL;
}
#endif

static void
reader_thread (void *data, void *user_data)
{
    AsyncTask *task = data;
    SeafObjStore *obj_store = user_data;
    ObjBackend *bend = obj_store->bend;

    task->success = TRUE;

    if (bend->read (bend, task->obj_id, &task->data, &task->len) < 0)
        task->success = FALSE;

    cevent_manager_add_event (obj_store->ev_mgr, obj_store->read_ev_id,
                              task);
}

static void
stat_thread (void *data, void *user_data)
{
    AsyncTask *task = data;
    SeafObjStore *obj_store = user_data;
    ObjBackend *bend = obj_store->bend;

    task->success = TRUE;

    if (!bend->exists (bend, task->obj_id))
        task->success = FALSE;

    cevent_manager_add_event (obj_store->ev_mgr, obj_store->stat_ev_id,
                              task);
}

static void
writer_thread (void *data, void *user_data)
{
    AsyncTask *task = data;
    SeafObjStore *obj_store = user_data;
    ObjBackend *bend = obj_store->bend;

    task->success = TRUE;

    if (bend->write (bend, task->obj_id, task->data, task->len) < 0)
        task->success = FALSE;

    cevent_manager_add_event (obj_store->ev_mgr, obj_store->write_ev_id,
                              task);
}

static void
on_read_done (CEvent *event, void *user_data)
{
    AsyncTask *task = event->data;
    SeafObjStore *obj_store = user_data;
    OSCallbackStruct *callback;
    OSAsyncResult res;

    callback = g_hash_table_lookup (obj_store->readers,
                                    (gpointer)(long)(task->rw_id));
    if (callback) {
        res.rw_id = task->rw_id;
        memcpy (res.obj_id, task->obj_id, 41);
        res.data = task->data;
        res.len = task->len;
        res.success = task->success;

        callback->cb (&res, callback->cb_data);
    }

    g_free (task->data);
    g_free (task);
}

static void
on_stat_done (CEvent *event, void *user_data)
{
    AsyncTask *task = event->data;
    SeafObjStore *obj_store = user_data;
    OSCallbackStruct *callback;
    OSAsyncResult res;

    callback = g_hash_table_lookup (obj_store->stats,
                                    (gpointer)(long)(task->rw_id));
    if (callback) {
        res.rw_id = task->rw_id;
        memcpy (res.obj_id, task->obj_id, 41);
        res.data = NULL;
        res.len = task->len;
        res.success = task->success;

        callback->cb (&res, callback->cb_data);
    }

    g_free (task->data);
    g_free (task);
}

static void
on_write_done (CEvent *event, void *user_data)
{
    AsyncTask *task = event->data;
    SeafObjStore *obj_store = user_data;
    OSCallbackStruct *callback;
    OSAsyncResult res;

    callback = g_hash_table_lookup (obj_store->writers,
                                    (gpointer)(long)(task->rw_id));
    if (callback) {
        res.rw_id = task->rw_id;
        memcpy (res.obj_id, task->obj_id, 41);
        res.data = task->data;
        res.len = task->len;
        res.success = task->success;

        callback->cb (&res, callback->cb_data);
    }

    g_free (task->data);
    g_free (task);
}

guint32
seaf_obj_store_register_async_read (struct SeafObjStore *obj_store,
                                    OSAsyncCallback callback,
                                    void *cb_data)
{
    guint32 id = obj_store->next_rd_id++;
    OSCallbackStruct *cb_struct = g_new0 (OSCallbackStruct, 1);

    cb_struct->cb = callback;
    cb_struct->cb_data = cb_data;

    g_hash_table_insert (obj_store->readers, (gpointer)(long)id, cb_struct);

    return id;
}

void
seaf_obj_store_unregister_async_read (struct SeafObjStore *obj_store,
                                      guint32 reader_id)
{
    g_hash_table_remove (obj_store->readers, (gpointer)(long)reader_id);
}

int
seaf_obj_store_async_read (struct SeafObjStore *obj_store,
                           guint32 reader_id,
                           const char *obj_id)
{
    AsyncTask *task = g_new0 (AsyncTask, 1);
    GError *error = NULL;

    task->rw_id = reader_id;
    memcpy (task->obj_id, obj_id, 41);

    g_thread_pool_push (obj_store->read_tpool, task, &error);
    if (error) {
        g_warning ("Failed to start aysnc read of %s.\n", obj_id);
        return -1;
    }

    return 0;
}

guint32
seaf_obj_store_register_async_stat (struct SeafObjStore *obj_store,
                                    OSAsyncCallback callback,
                                    void *cb_data)
{
    guint32 id = obj_store->next_st_id++;
    OSCallbackStruct *cb_struct = g_new0 (OSCallbackStruct, 1);

    cb_struct->cb = callback;
    cb_struct->cb_data = cb_data;

    g_hash_table_insert (obj_store->stats, (gpointer)(long)id, cb_struct);

    return id;
}

void
seaf_obj_store_unregister_async_stat (struct SeafObjStore *obj_store,
                                      guint32 stat_id)
{
    g_hash_table_remove (obj_store->stats, (gpointer)(long)stat_id);
}

int
seaf_obj_store_async_stat (struct SeafObjStore *obj_store,
                           guint32 stat_id,
                           const char *obj_id)
{
    AsyncTask *task = g_new0 (AsyncTask, 1);
    GError *error = NULL;

    task->rw_id = stat_id;
    memcpy (task->obj_id, obj_id, 41);

    g_thread_pool_push (obj_store->stat_tpool, task, &error);
    if (error) {
        g_warning ("Failed to start aysnc stat of %s.\n", obj_id);
        return -1;
    }

    return 0;
}

guint32
seaf_obj_store_register_async_write (struct SeafObjStore *obj_store,
                                     OSAsyncCallback callback,
                                     void *cb_data)
{
    guint32 id = obj_store->next_rd_id++;
    OSCallbackStruct *cb_struct = g_new0 (OSCallbackStruct, 1);

    cb_struct->cb = callback;
    cb_struct->cb_data = cb_data;

    g_hash_table_insert (obj_store->writers, (gpointer)(long)id, cb_struct);

    return id;
}

void
seaf_obj_store_unregister_async_write (struct SeafObjStore *obj_store,
                                       guint32 writer_id)
{
    g_hash_table_remove (obj_store->writers, (gpointer)(long)writer_id);
}

int
seaf_obj_store_async_write (struct SeafObjStore *obj_store,
                            guint32 writer_id,
                            const char *obj_id,
                            const void *obj_data,
                            int data_len)
{
    AsyncTask *task = g_new0 (AsyncTask, 1);
    GError *error = NULL;

    task->rw_id = writer_id;
    memcpy (task->obj_id, obj_id, 41);
    task->data = g_memdup (obj_data, data_len);
    task->len = data_len;

    g_thread_pool_push (obj_store->write_tpool, task, &error);
    if (error) {
        g_warning ("Failed to start aysnc write of %s.\n", obj_id);
        return -1;
    }

    return 0;
}
