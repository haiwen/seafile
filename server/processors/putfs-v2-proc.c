/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#define DEBUG_FLAG SEAFILE_DEBUG_TRANSFER
#include "log.h"

#include <fcntl.h>
#include <sys/stat.h>

#include <ccnet.h>
#include "utils.h"

#include "seafile-session.h"
#include "commit-mgr.h"
#include "fs-mgr.h"
#include "processors/objecttx-common.h"
#include "putfs-v2-proc.h"

#include "diff-simple.h"

enum {
    CHECK_OBJECT_LIST = 0,
    SEND_OBJECTS,
};

typedef struct {
    char server_head[41];
    char client_head[41];

    /* Used for getting repo info */
    char        repo_id[37];
    char        store_id[37];
    int         repo_version;
    gboolean    success;

    GList *send_obj_list;

    gboolean registered;
    guint32 reader_id;

    gboolean calc_success;
} SeafilePutfsProcPriv;

#define GET_PRIV(o)  \
   (G_TYPE_INSTANCE_GET_PRIVATE ((o), SEAFILE_TYPE_PUTFS_V2_PROC, SeafilePutfsProcPriv))

#define USE_PRIV \
    SeafilePutfsProcPriv *priv = GET_PRIV(processor);

G_DEFINE_TYPE (SeafilePutfsV2Proc, seafile_putfs_v2_proc, CCNET_TYPE_PROCESSOR)

static int start (CcnetProcessor *processor, int argc, char **argv);
static void handle_update (CcnetProcessor *processor,
                           char *code, char *code_msg,
                           char *content, int clen);

static void *
calculate_send_object_list (void *vdata);

static void
calculate_send_object_list_done (void *vdata);

static void
release_resource(CcnetProcessor *processor)
{
    USE_PRIV;

    string_list_free (priv->send_obj_list);

    seaf_obj_store_unregister_async_read (seaf->fs_mgr->obj_store,
                                          priv->reader_id);

    CCNET_PROCESSOR_CLASS (seafile_putfs_v2_proc_parent_class)->release_resource (processor);
}


static void
seafile_putfs_v2_proc_class_init (SeafilePutfsV2ProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);

    proc_class->name = "putfs-v2-proc";
    proc_class->start = start;
    proc_class->handle_update = handle_update;
    proc_class->release_resource = release_resource;

    g_type_class_add_private (klass, sizeof(SeafilePutfsProcPriv));
}

static void
seafile_putfs_v2_proc_init (SeafilePutfsV2Proc *processor)
{
}

static void
fs_object_read_cb (OSAsyncResult *res, void *data);

static void
register_async_io (CcnetProcessor *processor)
{
    USE_PRIV;

    priv->registered = TRUE;
    priv->reader_id = seaf_obj_store_register_async_read (seaf->fs_mgr->obj_store,
                                                          priv->store_id,
                                                          priv->repo_version,
                                                          fs_object_read_cb,
                                                          processor);
}

static void *
get_repo_info_thread (void *data)
{
    CcnetProcessor *processor = data;
    USE_PRIV;
    SeafRepo *repo;

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, priv->repo_id);
    if (!repo) {
        seaf_warning ("Failed to get repo %s.\n", priv->repo_id);
        priv->success = FALSE;
        return data;
    }

    memcpy (priv->store_id, repo->store_id, 36);
    priv->repo_version = repo->version;
    priv->success = TRUE;

    seaf_repo_unref (repo);
    return data;
}

static void
get_repo_info_done (void *data)
{
    CcnetProcessor *processor = data;
    USE_PRIV;

    if (priv->success) {
        ccnet_processor_send_response (processor, SC_OK, SS_OK, NULL, 0);
        register_async_io (processor);

        ccnet_processor_thread_create (processor,
                                       seaf->job_mgr,
                                       calculate_send_object_list,
                                       calculate_send_object_list_done,
                                       processor);
    } else {
        ccnet_processor_send_response (processor, SC_SHUTDOWN, SS_SHUTDOWN,
                                       NULL, 0);
        ccnet_processor_done (processor, FALSE);
    }
}

static int
start (CcnetProcessor *processor, int argc, char **argv)
{
    char *session_token;
    USE_PRIV;

    if (argc < 2) {
        ccnet_processor_send_response (processor, SC_BAD_ARGS, SS_BAD_ARGS, NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return -1;
    }

    session_token = argv[0];

    if (strlen(argv[1]) != 40) {
        ccnet_processor_send_response (processor,
                                       SC_BAD_ARGS, SS_BAD_ARGS,
                                       NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return -1;
    }
    memcpy (priv->server_head, argv[1], 40);

    if (argc >= 3) {
        if (strlen(argv[2]) != 40) {
            ccnet_processor_send_response (processor,
                                           SC_BAD_ARGS, SS_BAD_ARGS,
                                           NULL, 0);
            ccnet_processor_done (processor, FALSE);
            return -1;
        }
        memcpy (priv->client_head, argv[2], 40);
    }

    if (seaf_token_manager_verify_token (seaf->token_mgr,
                                         NULL,
                                         processor->peer_id,
                                         session_token, priv->repo_id) == 0) {
        ccnet_processor_thread_create (processor,
                                       seaf->job_mgr,
                                       get_repo_info_thread,
                                       get_repo_info_done,
                                       processor);
        return 0;
    } else {
        ccnet_processor_send_response (processor, 
                                       SC_ACCESS_DENIED, SS_ACCESS_DENIED,
                                       NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return -1;
    }
}

/* Calculate send object list */

inline static gboolean
dirent_same (SeafDirent *denta, SeafDirent *dentb)
{
    return (strcmp (dentb->id, denta->id) == 0 && denta->mode == dentb->mode);
}

static int
collect_file_ids (int n, const char *basedir, SeafDirent *files[], void *data)
{
    SeafDirent *file1 = files[0];
    SeafDirent *file2 = files[1];
    GList **pret = data;

    if (file1 && (!file2 || !dirent_same (file1, file2)) &&
        strcmp (file1->id, EMPTY_SHA1) != 0)
        *pret = g_list_prepend (*pret, g_strdup(file1->id));

    return 0;
}

static int
collect_dir_ids (int n, const char *basedir, SeafDirent *dirs[], void *data,
                 gboolean *recurse)
{
    SeafDirent *dir1 = dirs[0];
    SeafDirent *dir2 = dirs[1];
    GList **pret = data;

    if (dir1 && (!dir2 || !dirent_same (dir1, dir2)) &&
        strcmp (dir1->id, EMPTY_SHA1) != 0)
        *pret = g_list_prepend (*pret, g_strdup(dir1->id));

    return 0;
}

static void *
calculate_send_object_list (void *vdata)
{
    CcnetProcessor *processor = vdata;
    USE_PRIV;
    SeafCommit *remote_head = NULL, *master_head = NULL;
    char *remote_head_root;

    master_head = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                                  priv->repo_id, priv->repo_version,
                                                  priv->server_head);
    if (!master_head) {
        seaf_warning ("Server head commit %s:%s not found.\n",
                      priv->repo_id, priv->server_head);
        priv->calc_success = FALSE;
        goto out;
    }

    if (priv->client_head[0] != 0) {
        remote_head = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                                      priv->repo_id,
                                                      priv->repo_version,
                                                      priv->client_head);
        if (!remote_head) {
            seaf_warning ("Remote head commit %s:%s not found.\n",
                          priv->repo_id, priv->client_head);
            priv->calc_success = FALSE;
            goto out;
        }
        remote_head_root = remote_head->root_id;
    } else
        remote_head_root = EMPTY_SHA1;

    /* Diff won't traverse the root object itself. */
    if (strcmp (remote_head_root, master_head->root_id) != 0 &&
        strcmp (master_head->root_id, EMPTY_SHA1) != 0)
        priv->send_obj_list = g_list_prepend (priv->send_obj_list,
                                              g_strdup(master_head->root_id));

    DiffOptions opts;
    memset (&opts, 0, sizeof(opts));
    memcpy (opts.store_id, priv->store_id, 36);
    opts.version = priv->repo_version;
    opts.file_cb = collect_file_ids;
    opts.dir_cb = collect_dir_ids;
    opts.data = &priv->send_obj_list;

    const char *trees[2];
    trees[0] = master_head->root_id;
    trees[1] = remote_head_root;
    if (diff_trees (2, trees, &opts) < 0) {
        seaf_warning ("Failed to diff remote and master head for repo %.8s.\n",
                      priv->repo_id);
        priv->calc_success = FALSE;
    }

    priv->calc_success = TRUE;

out:
    seaf_commit_unref (remote_head);
    seaf_commit_unref (master_head);
    return vdata;
}

#define OBJECT_LIST_SEGMENT_N 1000
#define OBJECT_LIST_SEGMENT_LEN 40 * 1000

static void
send_object_list_segments (CcnetProcessor *processor)
{
    USE_PRIV;
    char buf[OBJECT_LIST_SEGMENT_LEN];

    int i = 0;
    char *p = buf;
    char *obj_id;
    while (priv->send_obj_list != NULL) {
        obj_id = priv->send_obj_list->data;
        priv->send_obj_list = g_list_delete_link (priv->send_obj_list,
                                                  priv->send_obj_list);

        memcpy (p, obj_id, 40);
        p += 40;
        g_free (obj_id);
        if (++i == OBJECT_LIST_SEGMENT_N) {
            seaf_debug ("Send %d object ids.\n", i);
            ccnet_processor_send_response (processor,
                                           SC_OBJ_LIST_SEG, SS_OBJ_LIST_SEG,
                                           buf, i * 40);
            i = 0;
            p = buf;
        }
    }

    if (i > 0) {
        seaf_debug ("Send %d object ids.\n", i);
        ccnet_processor_send_response (processor,
                                       SC_OBJ_LIST_SEG, SS_OBJ_LIST_SEG,
                                       buf, i * 40);
    }

    ccnet_processor_send_response (processor,
                                   SC_OBJ_LIST_SEG_END, SS_OBJ_LIST_SEG_END,
                                   NULL, 0);
}

static void
calculate_send_object_list_done (void *vdata)
{
    CcnetProcessor *processor = vdata;
    USE_PRIV;

    if (!priv->calc_success) {
        ccnet_processor_send_response (processor, SC_SHUTDOWN, SS_SHUTDOWN, NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return;
    }

    if (priv->send_obj_list == NULL) {
        seaf_message ("No fs objects to put. Done.\n");
        ccnet_processor_send_response (processor, SC_END, SS_END, NULL, 0);
        ccnet_processor_done (processor, TRUE);
        return;
    }

    send_object_list_segments (processor);

    processor->state = SEND_OBJECTS;
}

/* Send objects */

static void
send_fs_object (CcnetProcessor *processor,
                const char *object_id, char *data, int len)
{
    ObjectPack *pack = NULL;
    int pack_size;

    pack_size = sizeof(ObjectPack) + len;
    pack = malloc (pack_size);
    memcpy (pack->id, object_id, 41);
    memcpy (pack->object, data, len);

    if (pack_size <= MAX_OBJ_SEG_SIZE) {
        ccnet_processor_send_response (processor, SC_OBJECT, SS_OBJECT,
                                     (char *)pack, pack_size);
    } else {
        int offset, n;

        offset = 0;
        while (offset < pack_size) {
            n = MIN(pack_size - offset, MAX_OBJ_SEG_SIZE);

            if (offset + n < pack_size) {
                ccnet_processor_send_response (processor,
                                             SC_OBJ_SEG, SS_OBJ_SEG,
                                             (char *)pack + offset, n);
            } else {
                ccnet_processor_send_response (processor,
                                             SC_OBJ_SEG_END, SS_OBJ_SEG_END,
                                             (char *)pack + offset, n);
            }

            seaf_debug ("Sent object %s segment<total = %d, offset = %d, n = %d>\n",
                        object_id, pack_size, offset, n);

            offset += n;
        }
    }

    seaf_debug ("Send fs object %.8s.\n", object_id);

    free (pack);
}

static void
fs_object_read_cb (OSAsyncResult *res, void *data)
{
    CcnetProcessor *processor = data;

    if (!res->success) {
        seaf_warning ("Failed to read fs object %.8s.\n", res->obj_id);
        ccnet_processor_send_response (processor, SC_NOT_FOUND, SS_NOT_FOUND,
                                       res->obj_id, 41);
        ccnet_processor_done (processor, FALSE);
        return;
    }

    send_fs_object (processor, res->obj_id, res->data, res->len);
}

static void
read_fs_object (CcnetProcessor *processor, const char *obj_id)
{
    USE_PRIV;

    seaf_obj_store_async_read (seaf->fs_mgr->obj_store,
                               priv->reader_id,
                               obj_id);
}

static void
process_object_list_segment (CcnetProcessor *processor, char *content, int clen)
{
    int n, i;
    char *p;

    if (clen % 40 != 0) {
        seaf_warning ("Invalid object list segment length %d.\n", clen);
        ccnet_processor_send_response (processor, SC_SHUTDOWN, SS_SHUTDOWN, NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return;
    }

    n = clen/40;
    p = content;

    seaf_debug ("%d objects are needed by the client.\n", n);

    char *obj_id;
    for (i = 0; i < n; ++i) {
        obj_id = g_strndup(p, 40);
        read_fs_object (processor, obj_id);
        g_free (obj_id);
        p += 40;
    }
}

static void
handle_update (CcnetProcessor *processor,
               char *code, char *code_msg,
               char *content, int clen)
{
    switch (processor->state) {
    case SEND_OBJECTS:
        if (strncmp (code, SC_OBJ_LIST_SEG, 3) == 0) {
            process_object_list_segment (processor, content, clen);
            return;
        } else if (strncmp (code, SC_END, 3) == 0) {
            seaf_debug ("All objects received. Done.\n");
            ccnet_processor_done (processor, TRUE);
            return;
        }
        break;
    default:
        g_return_if_reached ();
    }

    seaf_warning ("Bad update: %s %s.\n", code, code_msg);
    ccnet_processor_send_response (processor,
                                   SC_BAD_UPDATE_CODE, SS_BAD_UPDATE_CODE,
                                   NULL, 0);
    ccnet_processor_done (processor, FALSE);
}
