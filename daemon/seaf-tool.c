/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, 
 * Boston, MA 02111-1307, USA.
 */

#include "common.h"

#include "ccnet.h"
#include "utils.h"
#include "db.h"

#include "seafile-session.h"
#include "repo-mgr.h"
#include "branch-mgr.h"
#include "commit-mgr.h"
#include "block-mgr.h"
#include "index/index.h"

#define SEAFILE_INI "seafile.ini"

SeafileSession *seaf;

GTree *already_traversed_commits = NULL;
GTree *already_traversed_blocks = NULL;

static gboolean print_version = FALSE;
static gboolean verbose = FALSE;
static char *seaf_data_dir = NULL;
static char *ccnet_conf_dir = NULL;
static char *destroy_repo_id = NULL;
static char *worktree_dir = NULL;
static gboolean list_repos = FALSE;
static gboolean force_continue = FALSE;
static gboolean validate_data = FALSE;

static GOptionEntry entries[] = 
{
    { .long_name            = "version",
      .short_name           = 0,
      .flags                = 0,
      .arg                  = G_OPTION_ARG_NONE,
      .arg_data             = &print_version,
      .description          = "show version",
      .arg_description      = NULL },

    { .long_name            = "verbose",
      .short_name           = 'v',
      .flags                = 0,
      .arg                  = G_OPTION_ARG_NONE,
      .arg_data             = &verbose,
      .description          = "output more information",
      .arg_description      = NULL },

    { .long_name            = "conf-dir",
      .short_name           = 'c',
      .flags                = 0,
      .arg                  = G_OPTION_ARG_STRING,
      .arg_data             = &ccnet_conf_dir,
      .description          = "set ccnet configuration directory",
      .arg_description      = NULL },

    { .long_name            = "seafile-data-dir",
      .short_name           = 'd',
      .flags                = 0,
      .arg                  = G_OPTION_ARG_STRING,
      .arg_data             = &seaf_data_dir,
      .description          = "set seafile data directory",
      .arg_description      = NULL },

    { .long_name            = "worktree-dir",
      .short_name           = 'w',
      .flags                = 0,
      .arg                  = G_OPTION_ARG_STRING,
      .arg_data             = &worktree_dir,
      .description          = "set the directory for checkout files",
      .arg_description      = NULL },

    { .long_name            = "validate",
      .short_name           = 0,
      .flags                = 0,
      .arg                  = G_OPTION_ARG_NONE,
      .arg_data             = &validate_data,
      .description          = "validate seafile repos/branches/commits/blocks/indices",
      .arg_description      = NULL },

    { .long_name            = "list",
      .short_name           = 'l',
      .flags                = 0,
      .arg                  = G_OPTION_ARG_NONE,
      .arg_data             = &list_repos,
      .description          = "list all repos",
      .arg_description      = NULL },

    { .long_name            = "destroy",
      .short_name           = 0,
      .flags                = 0,
      .arg                  = G_OPTION_ARG_STRING,
      .arg_data             = &destroy_repo_id,
      .description          = "destroy a repo with the given repo-id",
      .arg_description      = NULL },

    { .long_name            = "force",
      .short_name           = 'f',
      .flags                = 0,
      .arg                  = G_OPTION_ARG_NONE,
      .arg_data             = &force_continue,
      .description          = "continue validation even when errors are found",
      .arg_description      = NULL },

    { NULL },
};

static void
usage ()
{
    printf ("Usage:\n"
            "  seaf-tool [OPTIONS...]\n\n"
            "  -h, --help                 show this help message and exit\n"             
            "  --version                  show version and exit\n"
            "  -v, --verbose              output more messages\n"
            "  -c, --conf-dir             set ccnet configuration directory\n"
            "  -d, --seafile-data-dir     set seafile data directory\n"
            "  -w, --worktree-dir         set seafile checkout files directory\n"
            "  -l, --list                 list all repos\n"
            "  --destroy repo-id          destory the repo with [repo_id]\n"
            "  --validate                 validate seafile repos/branches/commits/blocks/indices\n"
            "  -f, --force                continue validation even when errors are found\n"
            );
}

static void
show_version()
{
    printf ("seaf-tool version: 0.1\n");
}

static inline gboolean
seafile_is_running ()
{
    return (process_is_running("ccnet-applet") ||
            process_is_running ("seaf-daemon"));
}

static char *
get_seaf_data_dir (const char *dir)
{
    if (!dir)
        return NULL;

    if (!g_file_test (dir, G_FILE_TEST_IS_DIR)) {
        fprintf (stdout, "Not a directory: %s\n", dir);
        return NULL;
    }

    char *buf = g_build_filename(dir, SEAFILE_INI, NULL);
    if (!g_file_test (buf, G_FILE_TEST_IS_REGULAR)) {
        fprintf (stdout, SEAFILE_INI "not found in %s\n", dir);
        return NULL;
    }

    FILE *seaf_ini = fopen(buf, "r");
    if (!seaf_ini) {
        perror("Open seaf_ini failed");
        return NULL;
    }

    char data_dir[SEAF_PATH_MAX]; 
    size_t len = fread (data_dir, 1, SEAF_PATH_MAX, seaf_ini);
    if (len <= 0) {
        perror("Read seafile.ini failed");
        fclose(seaf_ini);
        return NULL;
    }

    char *p = data_dir + len - 1;
    while (*p == '\r' || *p == '\n' || *p == ' ' || *p == '\t')
        *p-- = '\0';

    data_dir[len] = '\0';
    
    fclose(seaf_ini);
    return g_strdup(data_dir);
}

static void
do_list_repos ()
{
    GList *repo_list = seaf_repo_manager_get_repo_list (seaf->repo_mgr, -1, -1);
    if (!repo_list) {
        printf ("You have no repo yet.\n");
        return;
    }
    printf ("You have these repos:\n");

    GList *ptr = repo_list;
    while (ptr) {
        SeafRepo *repo = ptr->data;
        printf ("%s\t%s\n", repo->id, repo->worktree);
        ptr = ptr->next;
    }
    g_list_free (repo_list);

    return;
}

static void
do_destroy_repo (char *repo_id)
{
    if (!repo_id) return;
    SeafRepo *repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        g_warning ("Repo %s does not exist\n", repo_id);  
        return;
    }
    printf("Deleting repo %s\n", repo_id);
    seaf_repo_manager_del_repo (seaf->repo_mgr, repo);
    printf("Done\n");
}
    
static void
cleanup ()
{
}

static void
validate_block (void *userdata, const char *block_id)
{
    g_message ("Checking for Block %s", block_id);
    if (g_tree_lookup(already_traversed_blocks, block_id)) {
        g_message (" [Skipped]\n");
        return;
    }
    g_message ("\n");

    if (!seaf_block_manager_block_exists(seaf->block_mgr, block_id)) {
        fprintf (stderr, "[ERROR] block %s does not exist\n", block_id);
        return;
    }
    char *id = g_strdup(block_id);
    g_tree_insert(already_traversed_blocks, id, id);
}


static gboolean
validate_commit (SeafCommit *commit, void *data, gboolean *stop)
{
    g_message ("Commit %s", commit->commit_id);
    *stop = FALSE;
    if (g_tree_lookup(already_traversed_commits, commit->commit_id)) {
        g_message (" [Skipped]\n");
        return TRUE;
    }
    g_message ("\n");

    if (seaf_fs_manager_traverse_tree
        (seaf->fs_mgr, commit->root_id, validate_block, NULL) < 0) {
        return FALSE;
    }

    char *id = g_strdup(commit->commit_id);
    g_tree_insert (already_traversed_commits, id, id);

    return TRUE;
}

static int
validate_branch(SeafBranch *branch)
{
    if (!branch) return -1;
    
    g_message ("Checking for branch %s\n", branch->name);
    if (!seaf_commit_manager_traverse_commit_tree
        (seaf->commit_mgr, branch->commit_id, validate_commit, NULL)) {
        return -1;
    }

    return 0;
}

static int validate_repo_index(SeafRepo *repo)
{
    if (!repo) return -1;
    g_message("Checking for index\n");

    char index_path[SEAF_PATH_MAX];
    struct index_state istate;
    memset (&istate, 0, sizeof(istate));

    snprintf (index_path, SEAF_PATH_MAX, "%s/%s", seaf->repo_mgr->index_dir, repo->id);
    if (read_index_from (&istate, index_path) < 0) {
        g_warning ("[ERROR] Failed to validate index for repo %s\n", repo->id);
        return -1;
    }
    return 0;
}

static int
validate_repo_token (const char *repo_id)
{
    if (!repo_id) return -1;

    g_message ("Checking for token \n");
    char *token = NULL;
    token = seaf_repo_manager_get_repo_token (seaf->repo_mgr, repo_id);

    if (!token) {
        g_warning ("[ERROR] Repo token doesn't exist for repo %s\n", repo_id); 
        return -1;
    }
    else {
        g_free (token);
        return 0;
    }
}


static int
validate_repo(SeafRepo *repo)
{
    if(!repo) return -1;

    printf (">>>>>>>>>>>>>>>>>>>>>>>>>>>>\n"
            "Checking for repo %s (%s)\n" ,
            repo->name, repo->id);

    GList *branch_list = seaf_branch_manager_get_branch_list(seaf->branch_mgr, repo->id);
    if (!branch_list) {
        g_warning ("Failed to get branch list of repo %s\n", repo->id); 
        return -1;
    }
    /* Check whether the "local" branch exists */
    GList *ptr = branch_list;
    while (ptr) {
        SeafBranch *branch = ptr->data;
        if (g_strcmp0(branch->name, "local") == 0)
            break;
        ptr = ptr->next;
    }
    if (!ptr) {
        /* No "local" branch  */
        g_warning ("[ERROR] The branch \"local\" doesn't exist for repo %s\n", repo->id);
        g_list_free (branch_list);
        return -1;
    }
    while (ptr) {
        SeafBranch *branch = ptr->data;
        ptr = ptr->next;
        if (validate_branch(branch) < 0 && !force_continue) {
            g_list_free (branch_list);
            return -1;
        }
    }

    g_list_free (branch_list);
    if (validate_repo_index(repo) < 0)
        return -1;
    if (validate_repo_token((const char*)repo->id) < 0)
        return -1;
    printf ("<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n");
    printf ("Done for repo %s\n", repo->id);
    return 0;
}

static int
do_validate()
{
    GList *repo_list = seaf_repo_manager_get_repo_list(seaf->repo_mgr, -1, -1);
    if (!repo_list) {
        printf ("There is no repo yet.\n");
        return 0;
    }

    GList *ptr = repo_list;
    while(ptr) {
        SeafRepo *repo = ptr->data;
        ptr = ptr->next;
        if (validate_repo(repo) < 0 && !force_continue) {
            return -1;
        }
    }
    return 0;
}

static int strcmp_wrapper(const void *id1, const void *id2, void *user_data)
{
    return g_strcmp0((const char *)id1, (const char *)id2);
}

static int do_validate_prepare ()
{
    already_traversed_commits = g_tree_new_full ((GCompareDataFunc)strcmp_wrapper,
                                         NULL, (GDestroyNotify)g_free, NULL);
    if (!already_traversed_commits) {
        fprintf (stderr, "[ERROR] Failed to create tree already_traversed_commits\n");
        return -1;
    }

    already_traversed_blocks = g_tree_new_full ((GCompareDataFunc)strcmp_wrapper,
                                         NULL, (GDestroyNotify)g_free, NULL);
    if (!already_traversed_blocks) {
        fprintf (stderr, "[ERROR] Failed to create tree already_traversed_blocks\n");
        return -1;
    }

    return 0;
}


/* Default: only log WARNINGS and above;
   When --verbose is specified, also log g_message
*/
static void 
seaf_tool_log (const gchar *log_domain, GLogLevelFlags log_level,
               const gchar *message,    gpointer user_data)
{
    GLogLevelFlags flag = G_LOG_LEVEL_WARNING;

    if (verbose) {
        flag = G_LOG_LEVEL_MESSAGE;
    }

    if (log_level <= flag)
        printf ("%s", message);
}

static void
log_init()
{
    g_log_set_handler (NULL, G_LOG_LEVEL_MASK | G_LOG_FLAG_FATAL
                       | G_LOG_FLAG_RECURSION, seaf_tool_log, NULL);
    
}

static gboolean
seaf_data_dir_is_valid ()
{
    char *path = seaf_data_dir;
    if (!path) return FALSE;
    printf ("validating seaf data dir : %s\n", path);

    const char *dbs[] = {
        "repo.db",
        "branch.db",
        "config.db",
        "info.db",
        "transfer.db",
        NULL,
    };
    const char *subdirs[] = {
        "blocks",
        "commits",
        "fs",
        "index",
        NULL,
    };

    const char **ptr = dbs;
    while(*ptr) {
        char *file = g_build_filename(path, *ptr, NULL);
        if (!g_file_test(file, G_FILE_TEST_IS_REGULAR)) {
            fprintf (stderr, "[ERROR] File %s doesn't exist.\n", file);
            g_free (file);
            return FALSE;
        }
        g_free (file);
        ptr++;
    }

    ptr = subdirs;
    while(*ptr) {
        char *subdir = g_build_filename(path, *ptr, NULL);
        if (!g_file_test(subdir, G_FILE_TEST_IS_DIR)) {
            fprintf (stderr, "[ERROR] Subdir %s doesn't exist.\n", subdir);
            g_free (subdir);
            return FALSE;
        }
        g_free (subdir);
        ptr++;
    }
        
    return TRUE;
}

int main(int argc, char *argv[])
{
    GError *error = NULL;
    GOptionContext *context;

    context = g_option_context_new (NULL);
    g_option_context_add_main_entries (context, entries, "seafile");

    if (argc == 1) {
        usage();
        return 0;
    }
    if (!g_option_context_parse (context, &argc, &argv, &error))
    {
        g_print ("Option parsing failed: %s\n", error->message);
        exit (1);
    }
    if (print_version) {
        show_version();
        return 0;
    }

    if (!seaf_data_dir) {
        if (!ccnet_conf_dir) {
            ccnet_conf_dir = ccnet_expand_path(DEFAULT_CONFIG_DIR);
            if (!ccnet_conf_dir) {
                fprintf (stderr, "[ERROR] Failed to get ccnet conf dir\n");
                return -1;
            }
        }
        seaf_data_dir = get_seaf_data_dir(ccnet_conf_dir);
        if (!seaf_data_dir) {
            fprintf (stderr, "[ERROR] Failed to get seafile data directory\n");
            return -1;
        }
        
        if(!seaf_data_dir_is_valid()) {
            fprintf (stderr, "[ERROR] seafile data directory is not valid.\n");
            return -1;
        }
    }

    printf ("[INFO] seafile data directory is %s\n", seaf_data_dir);
    g_type_init ();
    log_init();

    if (!worktree_dir)
        worktree_dir = g_build_filename (g_get_home_dir(), "seafile", NULL);

    seaf = seafile_session_new(seaf_data_dir, worktree_dir, NULL);
    seafile_session_prepare(seaf);
    if (!seaf) {
        fprintf (stderr, "[ERROR] Failed to initialize\n");
        return -1;
    }

    if (list_repos) {
        do_list_repos ();
    }

    if (validate_data) {
        if (do_validate_prepare() < 0)
            return -1;
        do_validate();
        return 0;
    }

    if (destroy_repo_id) {
        if (seafile_is_running()) {
            fprintf (stderr, "seafile is running, close it and try again.\n");
            return -1;
        }
        do_destroy_repo(destroy_repo_id);
        return 0;
    }

    cleanup ();
    return 0;
}


