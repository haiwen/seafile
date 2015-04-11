/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>

#include <glib.h>
#include <glib-object.h>

#include <ccnet.h>
#include <searpc-server.h>
#include <searpc-client.h>

#include "seafile-session.h"
#include "seafile-rpc.h"
#include <ccnet/rpcserver-proc.h>
#include <ccnet/threaded-rpcserver-proc.h>
#include "log.h"
#include "utils.h"

#include "processors/check-tx-slave-v2-proc.h"
#include "processors/check-tx-slave-v3-proc.h"
#include "processors/recvfs-proc.h"
#include "processors/putfs-proc.h"
#include "processors/recvbranch-proc.h"
#include "processors/sync-repo-slave-proc.h"
#include "processors/putcommit-v2-proc.h"
#include "processors/putcommit-v3-proc.h"
#include "processors/recvcommit-v3-proc.h"
#include "processors/putcs-v2-proc.h"
#include "processors/checkbl-proc.h"
#include "processors/checkff-proc.h"
#include "processors/putca-proc.h"
#include "processors/check-protocol-slave-proc.h"
#include "processors/recvfs-v2-proc.h"
#include "processors/recvbranch-v2-proc.h"
#include "processors/putfs-v2-proc.h"

#include "cdc/cdc.h"

SeafileSession *seaf;
SearpcClient *ccnetrpc_client;
SearpcClient *ccnetrpc_client_t;
SearpcClient *async_ccnetrpc_client;
SearpcClient *async_ccnetrpc_client_t;

char *pidfile = NULL;

static const char *short_options = "hvc:d:l:fg:G:P:mCD:";
static struct option long_options[] = {
    { "help", no_argument, NULL, 'h', },
    { "version", no_argument, NULL, 'v', },
    { "config-file", required_argument, NULL, 'c' },
    { "seafdir", required_argument, NULL, 'd' },
    { "log", required_argument, NULL, 'l' },
    { "debug", required_argument, NULL, 'D' },
    { "foreground", no_argument, NULL, 'f' },
    { "ccnet-debug-level", required_argument, NULL, 'g' },
    { "seafile-debug-level", required_argument, NULL, 'G' },
    { "master", no_argument, NULL, 'm'},
    { "pidfile", required_argument, NULL, 'P' },
    { "cloud-mode", no_argument, NULL, 'C'},
    { NULL, 0, NULL, 0, },
};

static void usage ()
{
    fprintf (stderr, "usage: seaf-server [-c config_dir] [-d seafile_dir]\n");
}

static void register_processors (CcnetClient *client)
{
    ccnet_register_service (client, "seafile-check-tx-slave-v2", "basic",
                            SEAFILE_TYPE_CHECK_TX_SLAVE_V2_PROC, NULL);
    ccnet_register_service (client, "seafile-check-tx-slave-v3", "basic",
                            SEAFILE_TYPE_CHECK_TX_SLAVE_V3_PROC, NULL);
    ccnet_register_service (client, "seafile-recvfs", "basic",
                            SEAFILE_TYPE_RECVFS_PROC, NULL);
    ccnet_register_service (client, "seafile-putfs", "basic",
                            SEAFILE_TYPE_PUTFS_PROC, NULL);
    ccnet_register_service (client, "seafile-recvbranch", "basic",
                            SEAFILE_TYPE_RECVBRANCH_PROC, NULL);
    ccnet_register_service (client, "seafile-sync-repo-slave", "basic",
                            SEAFILE_TYPE_SYNC_REPO_SLAVE_PROC, NULL);
    ccnet_register_service (client, "seafile-putcommit-v2", "basic",
                            SEAFILE_TYPE_PUTCOMMIT_V2_PROC, NULL);
    ccnet_register_service (client, "seafile-putcommit-v3", "basic",
                            SEAFILE_TYPE_PUTCOMMIT_V3_PROC, NULL);
    ccnet_register_service (client, "seafile-recvcommit-v3", "basic",
                            SEAFILE_TYPE_RECVCOMMIT_V3_PROC, NULL);
    ccnet_register_service (client, "seafile-putcs-v2", "basic",
                            SEAFILE_TYPE_PUTCS_V2_PROC, NULL);
    ccnet_register_service (client, "seafile-checkbl", "basic",
                            SEAFILE_TYPE_CHECKBL_PROC, NULL);
    ccnet_register_service (client, "seafile-checkff", "basic",
                            SEAFILE_TYPE_CHECKFF_PROC, NULL);
    ccnet_register_service (client, "seafile-putca", "basic",
                            SEAFILE_TYPE_PUTCA_PROC, NULL);
    ccnet_register_service (client, "seafile-check-protocol-slave", "basic",
                            SEAFILE_TYPE_CHECK_PROTOCOL_SLAVE_PROC, NULL);
    ccnet_register_service (client, "seafile-recvfs-v2", "basic",
                            SEAFILE_TYPE_RECVFS_V2_PROC, NULL);
    ccnet_register_service (client, "seafile-recvbranch-v2", "basic",
                            SEAFILE_TYPE_RECVBRANCH_V2_PROC, NULL);
    ccnet_register_service (client, "seafile-putfs-v2", "basic",
                            SEAFILE_TYPE_PUTFS_V2_PROC, NULL);
}

#include <searpc.h>
#include "searpc-signature.h"
#include "searpc-marshal.h"

static void start_rpc_service (CcnetClient *client, int cloud_mode)
{
    searpc_server_init (register_marshals);

    searpc_create_service ("seafserv-rpcserver");
    ccnet_register_service (client, "seafserv-rpcserver", "rpc-inner",
                            CCNET_TYPE_RPCSERVER_PROC, NULL);

    searpc_create_service ("seafserv-threaded-rpcserver");
    ccnet_register_service (client, "seafserv-threaded-rpcserver", "rpc-inner",
                            CCNET_TYPE_THREADED_RPCSERVER_PROC, NULL);

    /* threaded services */

    /* repo manipulation */
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_repo,
                                     "seafile_get_repo",
                                     searpc_signature_object__string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_destroy_repo,
                                     "seafile_destroy_repo",
                                     searpc_signature_int__string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_repo_list,
                                     "seafile_get_repo_list",
                                     searpc_signature_objlist__int_int());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_set_repo_owner,
                                     "seafile_set_repo_owner",
                                     searpc_signature_int__string_string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_repo_owner,
                                     "seafile_get_repo_owner",
                                     searpc_signature_string__string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_orphan_repo_list,
                                     "seafile_get_orphan_repo_list",
                                     searpc_signature_objlist__void());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_edit_repo,
                                     "seafile_edit_repo",
                                     searpc_signature_int__string_string_string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_change_repo_passwd,
                                     "seafile_change_repo_passwd",
                                     searpc_signature_int__string_string_string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_is_repo_owner,
                                     "seafile_is_repo_owner",
                                     searpc_signature_int__string_string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_list_owned_repos,
                                     "seafile_list_owned_repos",
                                     searpc_signature_objlist__string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_server_repo_size,
                                     "seafile_server_repo_size",
                                     searpc_signature_int64__string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_repo_set_access_property,
                                     "seafile_repo_set_access_property",
                                     searpc_signature_int__string_string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_repo_query_access_property,
                                     "seafile_repo_query_access_property",
                                     searpc_signature_string__string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_revert_on_server,
                                     "seafile_revert_on_server",
                                     searpc_signature_int__string_string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_diff,
                                     "seafile_diff",
                                     searpc_signature_objlist__string_string_string_int());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_post_file,
                                     "seafile_post_file",
                    searpc_signature_int__string_string_string_string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_post_file_blocks,
                                     "seafile_post_file_blocks",
                    searpc_signature_string__string_string_string_string_string_string_int64_int());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_post_multi_files,
                                     "seafile_post_multi_files",
                    searpc_signature_string__string_string_string_string_string_int());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_put_file,
                                     "seafile_put_file",
                    searpc_signature_string__string_string_string_string_string_string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_put_file_blocks,
                                     "seafile_put_file_blocks",
                    searpc_signature_string__string_string_string_string_string_string_string_int64());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_post_empty_file,
                                     "seafile_post_empty_file",
                        searpc_signature_int__string_string_string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_post_dir,
                                     "seafile_post_dir",
                        searpc_signature_int__string_string_string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_del_file,
                                     "seafile_del_file",
                        searpc_signature_int__string_string_string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_copy_file,
                                     "seafile_copy_file",
       searpc_signature_object__string_string_string_string_string_string_string_int_int());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_move_file,
                                     "seafile_move_file",
       searpc_signature_object__string_string_string_string_string_string_string_int_int());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_rename_file,
                                     "seafile_rename_file",
                    searpc_signature_int__string_string_string_string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_is_valid_filename,
                                     "seafile_is_valid_filename",
                                     searpc_signature_int__string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_create_repo,
                                     "seafile_create_repo",
                                     searpc_signature_string__string_string_string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_create_enc_repo,
                                     "seafile_create_enc_repo",
                                     searpc_signature_string__string_string_string_string_string_string_int());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_commit,
                                     "seafile_get_commit",
                                     searpc_signature_object__string_int_string());
    
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_list_dir,
                                     "seafile_list_dir",
                                     searpc_signature_objlist__string_string_int_int());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_list_dir_with_perm,
                                     "list_dir_with_perm",
                                     searpc_signature_objlist__string_string_string_string_int_int());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_list_file,
                                     "seafile_list_file",
                                     searpc_signature_string__string_string_int_int());
    
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_file_size,
                                     "seafile_get_file_size",
                                     searpc_signature_int64__string_int_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_dir_size,
                                     "seafile_get_dir_size",
                                     searpc_signature_int64__string_int_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_list_dir_by_path,
                                     "seafile_list_dir_by_path",
                                     searpc_signature_objlist__string_string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_dirid_by_path,
                                     "seafile_get_dirid_by_path",
                                     searpc_signature_string__string_string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_file_id_by_path,
                                     "seafile_get_file_id_by_path",
                                     searpc_signature_string__string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_dir_id_by_path,
                                     "seafile_get_dir_id_by_path",
                                     searpc_signature_string__string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_dirent_by_path,
                                     "seafile_get_dirent_by_path",
                                     searpc_signature_object__string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_list_file_revisions,
                                     "seafile_list_file_revisions",
                                     searpc_signature_objlist__string_string_int_int_int());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_calc_files_last_modified,
                                     "seafile_calc_files_last_modified",
                                     searpc_signature_objlist__string_string_int());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_revert_file,
                                     "seafile_revert_file",
                                     searpc_signature_int__string_string_string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_revert_dir,
                                     "seafile_revert_dir",
                                     searpc_signature_int__string_string_string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_deleted,
                                     "get_deleted",
                                     searpc_signature_objlist__string_int_string());

    /* share repo to user */
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_add_share,
                                     "seafile_add_share",
                                     searpc_signature_int__string_string_string_string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_list_share_repos,
                                     "seafile_list_share_repos",
                                     searpc_signature_objlist__string_string_int_int());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_remove_share,
                                     "seafile_remove_share",
                                     searpc_signature_int__string_string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_set_share_permission,
                                     "set_share_permission",
                                     searpc_signature_int__string_string_string_string());

    /* share repo to group */
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_group_share_repo,
                                     "seafile_group_share_repo",
                                     searpc_signature_int__string_int_string_string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_group_unshare_repo,
                                     "seafile_group_unshare_repo",
                                     searpc_signature_int__string_int_string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_shared_groups_by_repo,
                                     "seafile_get_shared_groups_by_repo",
                                     searpc_signature_string__string());
    
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_group_repoids,
                                     "seafile_get_group_repoids",
                                     searpc_signature_string__int());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_group_repos_by_owner,
                                     "get_group_repos_by_owner",
                                     searpc_signature_objlist__string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_group_repo_owner,
                                     "get_group_repo_owner",
                                     searpc_signature_string__string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_remove_repo_group,
                                     "seafile_remove_repo_group",
                                     searpc_signature_int__int_string());    

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_set_group_repo_permission,
                                     "set_group_repo_permission",
                                     searpc_signature_int__int_string_string());
    
    /* branch and commit */
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_branch_gets,
                                     "seafile_branch_gets",
                                     searpc_signature_objlist__string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_commit_list,
                                     "seafile_get_commit_list",
                                     searpc_signature_objlist__string_int_int());

    /* token */
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_generate_repo_token,
                                     "seafile_generate_repo_token",
                                     searpc_signature_string__string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_delete_repo_token,
                                     "seafile_delete_repo_token",
                                     searpc_signature_int__string_string_string());
    
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_list_repo_tokens,
                                     "seafile_list_repo_tokens",
                                     searpc_signature_objlist__string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_list_repo_tokens_by_email,
                                     "seafile_list_repo_tokens_by_email",
                                     searpc_signature_objlist__string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_delete_repo_tokens_by_peer_id,
                                     "seafile_delete_repo_tokens_by_peer_id",
                                     searpc_signature_int__string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_delete_repo_tokens_by_email,
                                     "delete_repo_tokens_by_email",
                                     searpc_signature_int__string());
    
    /* quota */
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_user_quota_usage,
                                     "seafile_get_user_quota_usage",
                                     searpc_signature_int64__string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_user_share_usage,
                                     "seafile_get_user_share_usage",
                                     searpc_signature_int64__string());

    /* virtual repo */
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_create_virtual_repo,
                                     "create_virtual_repo",
                                     searpc_signature_string__string_string_string_string_string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_virtual_repos_by_owner,
                                     "get_virtual_repos_by_owner",
                                     searpc_signature_objlist__string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_virtual_repo,
                                     "get_virtual_repo",
                                     searpc_signature_object__string_string_string());

    /* Clean trash */

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_clean_up_repo_history,
                                     "clean_up_repo_history",
                                     searpc_signature_int__string_int());

    /* -------- rpc services -------- */
    /* token for web access to repo */
    searpc_server_register_function ("seafserv-rpcserver",
                                     seafile_web_get_access_token,
                                     "seafile_web_get_access_token",
                                     searpc_signature_string__string_string_string_string_int());
    searpc_server_register_function ("seafserv-rpcserver",
                                     seafile_web_query_access_token,
                                     "seafile_web_query_access_token",
                                     searpc_signature_object__string());

    /* Copy task related. */

    searpc_server_register_function ("seafserv-rpcserver",
                                     seafile_get_copy_task,
                                     "get_copy_task",
                                     searpc_signature_object__string());

    searpc_server_register_function ("seafserv-rpcserver",
                                     seafile_cancel_copy_task,
                                     "cancel_copy_task",
                                     searpc_signature_int__string());

    /* chunk server manipulation */
    searpc_server_register_function ("seafserv-rpcserver",
                                     seafile_add_chunk_server,
                                     "seafile_add_chunk_server",
                                     searpc_signature_int__string());
    searpc_server_register_function ("seafserv-rpcserver",
                                     seafile_del_chunk_server,
                                     "seafile_del_chunk_server",
                                     searpc_signature_int__string());
    searpc_server_register_function ("seafserv-rpcserver",
                                     seafile_list_chunk_servers,
                                     "seafile_list_chunk_servers",
                                     searpc_signature_string__void());

    /* password management */
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_check_passwd,
                                     "seafile_check_passwd",
                                     searpc_signature_int__string_string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_set_passwd,
                                     "seafile_set_passwd",
                                     searpc_signature_int__string_string_string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_unset_passwd,
                                     "seafile_unset_passwd",
                                     searpc_signature_int__string_string());
    searpc_server_register_function ("seafserv-rpcserver",
                                     seafile_is_passwd_set,
                                     "seafile_is_passwd_set",
                                     searpc_signature_int__string_string());
    searpc_server_register_function ("seafserv-rpcserver",
                                     seafile_get_decrypt_key,
                                     "seafile_get_decrypt_key",
                                     searpc_signature_object__string_string());

    /* quota management */
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_set_user_quota,
                                     "set_user_quota",
                                     searpc_signature_int__string_int64());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_user_quota,
                                     "get_user_quota",
                                     searpc_signature_int64__string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_check_quota,
                                     "check_quota",
                                     searpc_signature_int__string());

    /* repo permission */
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_check_permission,
                                     "check_permission",
                                     searpc_signature_string__string_string());

    /* folder permission */
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_check_permission_by_path,
                                     "check_permission_by_path",
                                     searpc_signature_string__string_string_string());
    
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_file_id_by_commit_and_path,
                                     "seafile_get_file_id_by_commit_and_path",
                                     searpc_signature_string__string_string_string());

    if (!cloud_mode) {
        searpc_server_register_function ("seafserv-threaded-rpcserver",
                                         seafile_set_inner_pub_repo,
                                         "set_inner_pub_repo",
                                         searpc_signature_int__string_string());
        searpc_server_register_function ("seafserv-threaded-rpcserver",
                                         seafile_unset_inner_pub_repo,
                                         "unset_inner_pub_repo",
                                         searpc_signature_int__string());
        searpc_server_register_function ("seafserv-threaded-rpcserver",
                                         seafile_is_inner_pub_repo,
                                         "is_inner_pub_repo",
                                         searpc_signature_int__string());
        searpc_server_register_function ("seafserv-threaded-rpcserver",
                                         seafile_list_inner_pub_repos,
                                         "list_inner_pub_repos",
                                         searpc_signature_objlist__void());
        searpc_server_register_function ("seafserv-threaded-rpcserver",
                                         seafile_count_inner_pub_repos,
                                         "count_inner_pub_repos",
                                         searpc_signature_int64__void());
        searpc_server_register_function ("seafserv-threaded-rpcserver",
                                         seafile_list_inner_pub_repos_by_owner,
                                         "list_inner_pub_repos_by_owner",
                                         searpc_signature_objlist__string());
    }

    /* History */
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_set_repo_history_limit,
                                     "set_repo_history_limit",
                                     searpc_signature_int__string_int());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_repo_history_limit,
                                     "get_repo_history_limit",
                                     searpc_signature_int__string());

    /* System default library */
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_system_default_repo_id,
                                     "get_system_default_repo_id",
                                     searpc_signature_string__void());

    /* Trashed repos. */
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_trash_repo_list,
                                     "get_trash_repo_list",
                                     searpc_signature_objlist__int_int());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_del_repo_from_trash,
                                     "del_repo_from_trash",
                                     searpc_signature_int__string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_restore_repo_from_trash,
                                     "restore_repo_from_trash",
                                     searpc_signature_int__string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_trash_repos_by_owner,
                                     "get_trash_repos_by_owner",
                                     searpc_signature_objlist__string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_empty_repo_trash,
                                     "empty_repo_trash",
                                     searpc_signature_int__void());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_empty_repo_trash_by_owner,
                                     "empty_repo_trash_by_owner",
                                     searpc_signature_int__string());
}

static struct event sigusr1;

static void sigusr1Handler (int fd, short event, void *user_data)
{
    seafile_log_reopen ();
}

static void
set_signal_handlers (SeafileSession *session)
{
#ifndef WIN32
    signal (SIGPIPE, SIG_IGN);

    /* design as reopen log */
    event_set(&sigusr1, SIGUSR1, EV_SIGNAL | EV_PERSIST, sigusr1Handler, NULL);
    event_add(&sigusr1, NULL);
#endif
}

static void
create_sync_rpc_clients (const char *config_dir)
{
    CcnetClient *sync_client;

    /* sync client and rpc client */
    sync_client = ccnet_client_new ();
    if ( (ccnet_client_load_confdir(sync_client, config_dir)) < 0 ) {
        seaf_warning ("Read config dir error\n");
        exit(1);
    }

    if (ccnet_client_connect_daemon (sync_client, CCNET_CLIENT_SYNC) < 0)
    {
        seaf_warning ("Connect to server fail: %s\n", strerror(errno));
        exit(1);
    }

    ccnetrpc_client = ccnet_create_rpc_client (sync_client, NULL, "ccnet-rpcserver");
    ccnetrpc_client_t = ccnet_create_rpc_client (sync_client,
                                                 NULL,
                                                 "ccnet-threaded-rpcserver");
}

static void
create_async_rpc_clients (CcnetClient *client)
{
    async_ccnetrpc_client = ccnet_create_async_rpc_client (
        client, NULL, "ccnet-rpcserver");
    async_ccnetrpc_client_t = ccnet_create_async_rpc_client (
        client, NULL, "ccnet-threaded-rpcserver");
}

static void
remove_pidfile (const char *pidfile)
{
    if (pidfile) {
        g_unlink (pidfile);
    }
}

static int
write_pidfile (const char *pidfile_path)
{
    if (!pidfile_path)
        return -1;

    pid_t pid = getpid();

    FILE *pidfile = g_fopen(pidfile_path, "w");
    if (!pidfile) {
        seaf_warning ("Failed to fopen() pidfile %s: %s\n",
                      pidfile_path, strerror(errno));
        return -1;
    }

    char buf[32];
    snprintf (buf, sizeof(buf), "%d\n", pid);
    if (fputs(buf, pidfile) < 0) {
        seaf_warning ("Failed to write pidfile %s: %s\n",
                      pidfile_path, strerror(errno));
        fclose (pidfile);
        return -1;
    }

    fflush (pidfile);
    fclose (pidfile);
    return 0;
}

static void
load_history_config ()
{
    int keep_history_days;
    GError *error = NULL;

    seaf->keep_history_days = -1;

    keep_history_days = g_key_file_get_integer (seaf->config,
                                                "history", "keep_days",
                                                &error);
    if (error == NULL)
        seaf->keep_history_days = keep_history_days;
}

static void
on_seaf_server_exit(void)
{
    if (pidfile)
        remove_pidfile (pidfile);
}

#ifdef WIN32
/* Get the commandline arguments in unicode, then convert them to utf8  */
static char **
get_argv_utf8 (int *argc)
{
    int i = 0;
    char **argv = NULL;
    const wchar_t *cmdline = NULL;
    wchar_t **argv_w = NULL;

    cmdline = GetCommandLineW();
    argv_w = CommandLineToArgvW (cmdline, argc);
    if (!argv_w) {
        printf("failed to CommandLineToArgvW(), GLE=%lu\n", GetLastError());
        return NULL;
    }

    argv = (char **)malloc (sizeof(char*) * (*argc));
    for (i = 0; i < *argc; i++) {
        argv[i] = wchar_to_utf8 (argv_w[i]);
    }

    return argv;
}
#endif

int
main (int argc, char **argv)
{
    int c;
    char *config_dir = DEFAULT_CONFIG_DIR;
    char *seafile_dir = NULL;
    char *logfile = NULL;
    const char *debug_str = NULL;
    int daemon_mode = 1;
    int is_master = 0;
    CcnetClient *client;
    char *ccnet_debug_level_str = "info";
    char *seafile_debug_level_str = "debug";
    int cloud_mode = 0;

#ifdef WIN32
    argv = get_argv_utf8 (&argc);
#endif

    while ((c = getopt_long (argc, argv, short_options, 
                             long_options, NULL)) != EOF)
    {
        switch (c) {
        case 'h':
            exit (1);
            break;
        case 'v':
            exit (1);
            break;
        case 'c':
            config_dir = optarg;
            break;
        case 'd':
            seafile_dir = g_strdup(optarg);
            break;
        case 'f':
            daemon_mode = 0;
            break;
        case 'l':
            logfile = g_strdup(optarg);
            break;
        case 'D':
            debug_str = optarg;
            break;
        case 'g':
            ccnet_debug_level_str = optarg;
            break;
        case 'G':
            seafile_debug_level_str = optarg;
            break;
        case 'm':
            is_master = 1;
        case 'P':
            pidfile = optarg;
            break;
        case 'C':
            cloud_mode = 1;
            break;
        default:
            usage ();
            exit (1);
        }
    }

    argc -= optind;
    argv += optind;

#ifndef WIN32
    if (daemon_mode) {
#ifndef __APPLE__
        daemon (1, 0);
#else   /* __APPLE */
        /* daemon is deprecated under APPLE
         * use fork() instead
         * */
        switch (fork ()) {
          case -1:
              seaf_warning ("Failed to daemonize");
              exit (-1);
              break;
          case 0:
              /* all good*/
              break;
          default:
              /* kill origin process */
              exit (0);
        }
#endif  /* __APPLE */
    }
#endif /* !WIN32 */

    cdc_init ();

#if !GLIB_CHECK_VERSION(2, 35, 0)
    g_type_init();
#endif
#if !GLIB_CHECK_VERSION(2,32,0)
    g_thread_init (NULL);
#endif

    if (!debug_str)
        debug_str = g_getenv("SEAFILE_DEBUG");
    seafile_debug_set_flags_string (debug_str);

    if (seafile_dir == NULL)
        seafile_dir = g_build_filename (config_dir, "seafile", NULL);
    if (logfile == NULL)
        logfile = g_build_filename (seafile_dir, "seafile.log", NULL);

    if (seafile_log_init (logfile, ccnet_debug_level_str,
                          seafile_debug_level_str) < 0) {
        seaf_warning ("Failed to init log.\n");
        exit (1);
    }

    client = ccnet_init (config_dir);
    if (!client)
        exit (1);

    register_processors (client);

    start_rpc_service (client, cloud_mode);

    create_sync_rpc_clients (config_dir);
    create_async_rpc_clients (client);

    seaf = seafile_session_new (seafile_dir, client);
    if (!seaf) {
        seaf_warning ("Failed to create seafile session.\n");
        exit (1);
    }
    seaf->is_master = is_master;
    seaf->ccnetrpc_client = ccnetrpc_client;
    seaf->async_ccnetrpc_client = async_ccnetrpc_client;
    seaf->ccnetrpc_client_t = ccnetrpc_client_t;
    seaf->async_ccnetrpc_client_t = async_ccnetrpc_client_t;
    seaf->client_pool = ccnet_client_pool_new (config_dir);
    seaf->cloud_mode = cloud_mode;

    load_history_config ();

    g_free (seafile_dir);
    g_free (logfile);

    set_signal_handlers (seaf);

    /* init seaf */
    if (seafile_session_init (seaf) < 0)
        exit (1);

    if (seafile_session_start (seaf) < 0)
        exit (1);

    if (pidfile) {
        if (write_pidfile (pidfile) < 0) {
            ccnet_message ("Failed to write pidfile\n");
            return -1;
        }
    }
    atexit (on_seaf_server_exit);

    /* Create a system default repo to contain the tutorial file. */
    schedule_create_system_default_repo (seaf);

    ccnet_main (client);

    return 0;
}
