/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"
#include <fcntl.h>
#include <sys/stat.h>

#include <ccnet.h>
#include "utils.h"

#include "seafile-session.h"
#include "commit-mgr.h"
#include "fs-mgr.h"
#include "processors/objecttx-common.h"
#include "putfs-proc.h"

G_DEFINE_TYPE (SeafilePutfsProc, seafile_putfs_proc, CCNET_TYPE_PROCESSOR)

static int start (CcnetProcessor *processor, int argc, char **argv);
static void handle_update (CcnetProcessor *processor,
                           char *code, char *code_msg,
                           char *content, int clen);

static void
release_resource(CcnetProcessor *processor)
{
    /* FILL IT */

    CCNET_PROCESSOR_CLASS (seafile_putfs_proc_parent_class)->release_resource (processor);
}


static void
seafile_putfs_proc_class_init (SeafilePutfsProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);

    proc_class->name = "putfs-proc";
    proc_class->start = start;
    proc_class->handle_update = handle_update;
    proc_class->release_resource = release_resource;
}

static void
seafile_putfs_proc_init (SeafilePutfsProc *processor)
{
}


static int
start (CcnetProcessor *processor, int argc, char **argv)
{
    ccnet_processor_send_response (processor, SC_OK, SS_OK, NULL, 0);

    return 0;
}

static gboolean
send_fs_object (CcnetProcessor *processor, char *object_id)
{
    char *data;
    int len;
    ObjectPack *pack = NULL;
    int pack_size;

    if (seaf_obj_store_read_obj (seaf->fs_mgr->obj_store,
                                 object_id, (void**)&data, &len) < 0) {
        g_warning ("Failed to read fs object %s.\n", object_id);
        goto fail;
    }

    pack_size = sizeof(ObjectPack) + len;
    pack = malloc (pack_size);
    memcpy (pack->id, object_id, 41);
    memcpy (pack->object, data, len);

    ccnet_processor_send_response (processor, SC_OBJECT, SS_OBJECT,
                                   (char *)pack, pack_size);

    g_free (data);
    free (pack);
    return TRUE;

fail:
    ccnet_processor_send_response (processor, SC_NOT_FOUND, SS_NOT_FOUND,
                                   object_id, 41);
    ccnet_processor_done (processor, FALSE);
    return FALSE;
}

static void
send_fs_objects (CcnetProcessor *processor, char *content, int clen)
{
    char *object_id;
    int n_objects;
    int i;

    if (clen % 41 != 1 || content[clen-1] != '\0') {
        g_warning ("[putfs] Bad fs object list.\n");
        ccnet_processor_send_response (processor, SC_BAD_OL, SS_BAD_OL, NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return;
    }

    n_objects = clen/41;
    g_debug ("[putfs] send fs objects %d:\n%s", n_objects, content);

    object_id = content;
    for (i = 0; i < n_objects; ++i) {
        object_id[40] = '\0';
        g_debug ("[putfs] send fs object #%d:%s\n", i, object_id);
        if (send_fs_object (processor, object_id) == FALSE)
            return;
        object_id += 41;
    }
}

static void
handle_update (CcnetProcessor *processor,
               char *code, char *code_msg,
               char *content, int clen)
{
    if (strncmp(code, SC_GET_OBJECT, 3) == 0) {
        send_fs_objects (processor, content, clen);
    } else if (strncmp(code, SC_END, 3) == 0) {
        ccnet_processor_done (processor, TRUE);     
    } else {
        g_warning ("[putfs] Bad update: %s %s\n", code, code_msg);
        ccnet_processor_done (processor, FALSE);
    }
}
