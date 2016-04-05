/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <ccnet.h>
#include <string.h>
#include <ccnet/ccnet-object.h>

#include "seafile-session.h"
#include "recvbranch-v2-proc.h"
#include "vc-common.h"

#include "merge-new.h"
#include "diff-simple.h"

#include "log.h"

#define SC_BAD_COMMIT   "401"
#define SS_BAD_COMMIT   "Commit does not exist"
#define SC_NOT_FF       "402"
#define SS_NOT_FF       "Not fast forward"
#define SC_QUOTA_ERROR  "403"
#define SS_QUOTA_ERROR  "Failed to get quota"
#define SC_QUOTA_FULL   "404"
#define SS_QUOTA_FULL   "storage for the repo's owner is full"
#define SC_SERVER_ERROR "405"
#define SS_SERVER_ERROR "Internal server error"
#define SC_BAD_REPO     "406"
#define SS_BAD_REPO     "Repo does not exist"
#define SC_BAD_BRANCH   "407"
#define SS_BAD_BRANCH   "Branch does not exist"
#define SC_ACCESS_DENIED "410"
#define SS_ACCESS_DENIED "Access denied"

typedef struct {
    char repo_id[37];
    char *branch_name;
    char new_head[41];

    char *rsp_code;
    char *rsp_msg;
} SeafileRecvbranchProcPriv;

G_DEFINE_TYPE (SeafileRecvbranchV2Proc, seafile_recvbranch_v2_proc, CCNET_TYPE_PROCESSOR)

#define GET_PRIV(o)  \
   (G_TYPE_INSTANCE_GET_PRIVATE ((o), SEAFILE_TYPE_RECVBRANCH_V2_PROC, SeafileRecvbranchProcPriv))

#define USE_PRIV \
    SeafileRecvbranchProcPriv *priv = GET_PRIV(processor);

static int start (CcnetProcessor *processor, int argc, char **argv);
static void handle_update (CcnetProcessor *processor,
                           char *code, char *code_msg,
                           char *content, int clen);
static void *update_repo (void *vprocessor);
static void thread_done (void *result);

static void
release_resource(CcnetProcessor *processor)
{
    USE_PRIV;
    g_free (priv->branch_name);
    g_free (priv->rsp_code);
    g_free (priv->rsp_msg);

    CCNET_PROCESSOR_CLASS (seafile_recvbranch_v2_proc_parent_class)->release_resource (processor);
}


static void
seafile_recvbranch_v2_proc_class_init (SeafileRecvbranchV2ProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);

    proc_class->name = "recvbranch-v2-proc";
    proc_class->start = start;
    proc_class->handle_update = handle_update;
    proc_class->release_resource = release_resource;

    g_type_class_add_private (klass, sizeof (SeafileRecvbranchProcPriv));
}

static void
seafile_recvbranch_v2_proc_init (SeafileRecvbranchV2Proc *processor)
{
}

static int
start (CcnetProcessor *processor, int argc, char **argv)
{
    USE_PRIV;
    char *session_token;

    if (argc != 4) {
        ccnet_processor_send_response (processor, SC_BAD_ARGS, SS_BAD_ARGS, NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return -1;
    }

    if (!is_uuid_valid(argv[0]) || strlen(argv[2]) != 40) {
        ccnet_processor_send_response (processor, SC_BAD_ARGS, SS_BAD_ARGS, NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return -1;
    }
    memcpy (priv->repo_id, argv[0], 36);
    memcpy (priv->new_head, argv[2], 40);
    priv->branch_name = g_strdup(argv[1]);
    session_token = argv[3];

    if (seaf_token_manager_verify_token (seaf->token_mgr,
                                         NULL,
                                         processor->peer_id,
                                         session_token, NULL) < 0) {
        ccnet_processor_send_response (processor, 
                                       SC_ACCESS_DENIED, SS_ACCESS_DENIED,
                                       NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return -1;
    }

    ccnet_processor_thread_create (processor,
                                   seaf->job_mgr,
                                   update_repo,
                                   thread_done,
                                   processor);

    return 0;
}


static void
handle_update (CcnetProcessor *processor,
               char *code, char *code_msg,
               char *content, int clen)
{
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
        seaf_warning ("Failed to find head commit of %s:%s.\n",
                      repo_id, repo->head->commit_id);
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
            /* Sleep random time between 100 and 1000 millisecs. */
            usleep (g_random_int_range(1, 11) * 100 * 1000);
            goto retry;
        } else {
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

static void *
update_repo (void *vprocessor)
{
    CcnetProcessor *processor = vprocessor;
    USE_PRIV;
    char *repo_id, *new_head;
    SeafRepo *repo = NULL;
    SeafCommit *new_commit = NULL, *base = NULL;

    repo_id = priv->repo_id;
    new_head = priv->new_head;

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        /* repo is deleted on server */
        priv->rsp_code = g_strdup (SC_BAD_REPO);
        priv->rsp_msg = g_strdup (SC_BAD_REPO);
        goto out;

    }

    /* Since this is the last step of upload procedure, commit should exist. */
    new_commit = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                                 repo->id, repo->version,
                                                 new_head);
    if (!new_commit) {
        seaf_warning ("Failed to get commit %s for repo %s.\n",
                      new_head, repo->id);
        priv->rsp_code = g_strdup (SC_BAD_COMMIT);
        priv->rsp_msg = g_strdup (SS_BAD_COMMIT);
        goto out;
    }

    base = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                           repo->id, repo->version,
                                           new_commit->parent_id);
    if (!base) {
        seaf_warning ("Failed to get commit %s for repo %s.\n",
                      new_commit->parent_id, repo->id);
        priv->rsp_code = g_strdup (SC_BAD_COMMIT);
        priv->rsp_msg = g_strdup (SS_BAD_COMMIT);
        goto out;
    }

    if (seaf_quota_manager_check_quota (seaf->quota_mgr, repo_id) < 0) {
        priv->rsp_code = g_strdup(SC_QUOTA_FULL);
        priv->rsp_msg = g_strdup(SS_QUOTA_FULL);
        goto out;
    }

    if (fast_forward_or_merge (repo_id, base, new_commit) < 0) {
        priv->rsp_code = g_strdup(SC_SERVER_ERROR);
        priv->rsp_msg = g_strdup(SS_SERVER_ERROR);
        goto out;
    }

    seaf_repo_manager_cleanup_virtual_repos (seaf->repo_mgr, repo_id);
    seaf_repo_manager_merge_virtual_repo (seaf->repo_mgr, repo_id, NULL);

out:
    seaf_repo_unref (repo);
    seaf_commit_unref (new_commit);
    seaf_commit_unref (base);

    if (!priv->rsp_code) {
        priv->rsp_code = g_strdup (SC_OK);
        priv->rsp_msg = g_strdup (SS_OK);
    }

    return vprocessor;
}

static void 
thread_done (void *result)
{
    CcnetProcessor *processor = result;
    USE_PRIV;

    if (strcmp (priv->rsp_code, SC_OK) == 0) {
        /* Repo is updated, schedule repo size computation. */
        schedule_repo_size_computation (seaf->size_sched, priv->repo_id);

        ccnet_processor_send_response (processor, SC_OK, SS_OK, NULL, 0);
        ccnet_processor_done (processor, TRUE);
    } else {
        ccnet_processor_send_response (processor,
                                       priv->rsp_code, priv->rsp_msg,
                                       NULL, 0);
        ccnet_processor_done (processor, FALSE);
    }
}

