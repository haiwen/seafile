/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */


#include "putbranch-proc.h"

G_DEFINE_TYPE (SeafilePutbranchProc, seafile_putbranch_proc, CCNET_TYPE_PROCESSOR)

static int start (CcnetProcessor *processor, int argc, char **argv);
static void handle_update (CcnetProcessor *processor,
                           char *code, char *code_msg,
                           char *content, int clen);

static void
release_resource(CcnetProcessor *processor)
{
    /* FILL IT */

    CCNET_PROCESSOR_CLASS (seafile_putbranch_proc_parent_class)->release_resource (processor);
}


static void
seafile_putbranch_proc_class_init (SeafilePutbranchProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);

    proc_class->name = "putbranch-proc";
    proc_class->start = start;
    proc_class->handle_update = handle_update;
    proc_class->release_resource = release_resource;
}

static void
seafile_putbranch_proc_init (SeafilePutbranchProc *processor)
{
}


static int
start (CcnetProcessor *processor, int argc, char **argv)
{
    

    return 0;
}


static void
handle_update (CcnetProcessor *processor,
               char *code, char *code_msg,
               char *content, int clen)
{
    USE_PRIV;

}
