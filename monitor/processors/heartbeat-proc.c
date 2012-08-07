/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include <ccnet.h>

#include "monitor.h"
#include "heartbeat-proc.h"

#define SC_BLOCK_INFO "301"
#define SS_BLOCK_INFO "Block info"

typedef struct  {
    int dummy;
} SeafileHeartbeatProcPriv;

static void
process_block_info (char *info, int len);

#define GET_PRIV(o)  \
   (G_TYPE_INSTANCE_GET_PRIVATE ((o), SEAFILE_TYPE_HEARTBEAT_PROC, SeafileHeartbeatProcPriv))

#define USE_PRIV \
    SeafileHeartbeatProcPriv *priv = GET_PRIV(processor);


G_DEFINE_TYPE (SeafileHeartbeatProc, seafile_heartbeat_proc, CCNET_TYPE_PROCESSOR)

static int start (CcnetProcessor *processor, int argc, char **argv);
static void handle_update (CcnetProcessor *processor,
                           char *code, char *code_msg,
                           char *content, int clen);

static void
release_resource(CcnetProcessor *processor)
{
    /* FILL IT */

    CCNET_PROCESSOR_CLASS (seafile_heartbeat_proc_parent_class)->release_resource (processor);
}


static void
seafile_heartbeat_proc_class_init (SeafileHeartbeatProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);

    proc_class->start = start;
    proc_class->handle_update = handle_update;
    proc_class->release_resource = release_resource;

    g_type_class_add_private (klass, sizeof (SeafileHeartbeatProcPriv));
}

static void
seafile_heartbeat_proc_init (SeafileHeartbeatProc *processor)
{
}


static int
start (CcnetProcessor *processor, int argc, char **argv)
{
    ccnet_processor_send_response (processor, SC_OK, SS_OK, NULL, 0);

    return 0;
}

static void
handle_update (CcnetProcessor *processor,
               char *code, char *code_msg,
               char *content, int clen)
{
    if (strncmp(code, SC_BLOCK_INFO, 3) == 0) {
        if (content[clen-1] != '\0') {
            g_warning ("[heartbeat] Bad content format.\n");
            /* Tolerate bad format, don't stop the processor. */
            return;
        }
        process_block_info (content, clen);
        return;
    }

    g_warning ("[heartbeat] Bad update: %s %s.\n", code, code_msg);
    ccnet_processor_done (processor, FALSE);
}

static void
set_block_size (char *line)
{
    char *block_id, *size_str;
    uint32_t size;
    char *space;

    space = strchr (line, ' ');
    if (!space || space - line != 40) {
        g_warning ("[heartbeat] Bad block size line format\n");
        return;
    }
    *space = '\0';
    block_id = line;
    size_str = space + 1;

    if (sscanf (size_str, "%u", &size) < 1) {
        g_warning ("[heartbeat] Bad block size format\n");
        return;
    }

    g_message ("[heartbeat] Setting block size: %s %s\n", block_id, size_str);

    seaf_monitor_set_block_size (singleton_monitor, block_id, size);
}

static void
process_block_info (char *info, int len)
{
    char *line;
    char *saveptr;

    line = strtok_r (info, "\n", &saveptr);
    if (!line)
        return;
    set_block_size (line);
    while (1) {
        line = strtok_r (NULL, "\n", &saveptr);
        if (!line)
            break;
        set_block_size (line);
    }
}
