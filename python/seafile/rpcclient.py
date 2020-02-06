from pysearpc import searpc_func, SearpcError, NamedPipeClient


class SeafileRpcClient(NamedPipeClient):
    """RPC used in client"""

    def __init__(self, socket_path, *args, **kwargs):
         NamedPipeClient.__init__(
             self,
             socket_path,
             "seafile-rpcserver",
             *args,
             **kwargs
         )

    @searpc_func("string", ["int"])
    def seafile_sync_error_id_to_str():
        pass
    sync_error_id_to_str = seafile_sync_error_id_to_str

    @searpc_func("int", ["int"])
    def seafile_del_file_sync_error_by_id():
        pass
    del_file_sync_error_by_id = seafile_del_file_sync_error_by_id

    @searpc_func("int", ["string"])
    def seafile_calc_dir_size(path):
        pass
    calc_dir_size = seafile_calc_dir_size

    @searpc_func("int64", [])
    def seafile_get_total_block_size():
        pass
    get_total_block_size = seafile_get_total_block_size;

    @searpc_func("string", ["string"])
    def seafile_get_config(key):
        pass
    get_config = seafile_get_config

    @searpc_func("int", ["string", "string"])
    def seafile_set_config(key, value):
        pass
    set_config = seafile_set_config

    @searpc_func("int", ["string"])
    def seafile_get_config_int(key):
        pass
    get_config_int = seafile_get_config_int

    @searpc_func("int", ["string", "int"])
    def seafile_set_config_int(key, value):
        pass
    set_config_int = seafile_set_config_int

    @searpc_func("int", ["int"])
    def seafile_set_upload_rate_limit(limit):
        pass
    set_upload_rate_limit = seafile_set_upload_rate_limit

    @searpc_func("int", ["int"])
    def seafile_set_download_rate_limit(limit):
        pass
    set_download_rate_limit = seafile_set_download_rate_limit

    ### repo
    @searpc_func("objlist", ["int", "int"])
    def seafile_get_repo_list():
        pass
    get_repo_list = seafile_get_repo_list

    @searpc_func("object", ["string"])
    def seafile_get_repo():
        pass
    get_repo = seafile_get_repo

    @searpc_func("string", ["string", "string", "string", "string", "string", "int"])
    def seafile_create_repo(name, desc, passwd, base, relay_id, keep_history):
        pass
    create_repo = seafile_create_repo

    @searpc_func("int", ["string"])
    def seafile_destroy_repo(repo_id):
        pass
    remove_repo = seafile_destroy_repo

    @searpc_func("objlist", ["string", "string", "string", "int"])
    def seafile_diff():
        pass
    get_diff = seafile_diff

    @searpc_func("object", ["string", "int", "string"])
    def seafile_get_commit(repo_id, version, commit_id):
        pass
    get_commit = seafile_get_commit

    @searpc_func("objlist", ["string", "int", "int"])
    def seafile_get_commit_list():
        pass
    get_commit_list = seafile_get_commit_list

    @searpc_func("objlist", ["string"])
    def seafile_branch_gets(repo_id):
        pass
    branch_gets = seafile_branch_gets

    @searpc_func("int", ["string", "string"])
    def seafile_branch_add(repo_id, branch):
        pass
    branch_add = seafile_branch_add

    ##### clone related
    @searpc_func("string", ["string", "string"])
    def gen_default_worktree(worktree_parent, repo_name):
        pass

    @searpc_func("string", ["string", "int", "string", "string", "string", "string", "string", "string", "int", "string"])
    def seafile_clone(repo_id, repo_version, repo_name, worktree, token, password, magic, email, random_key, enc_version, more_info):
        pass
    clone = seafile_clone

    @searpc_func("string", ["string", "int", "string", "string", "string", "string", "string", "string", "int", "string"])
    def seafile_download(repo_id, repo_version, repo_name, wt_parent, token, password, magic, email, random_key, enc_version, more_info):
        pass
    download = seafile_download

    @searpc_func("int", ["string"])
    def seafile_cancel_clone_task(repo_id):
        pass
    cancel_clone_task = seafile_cancel_clone_task

    @searpc_func("objlist", [])
    def seafile_get_clone_tasks():
        pass
    get_clone_tasks = seafile_get_clone_tasks

    @searpc_func("object", ["string"])
    def seafile_find_transfer_task(repo_id):
        pass
    find_transfer_task = seafile_find_transfer_task

    ### sync
    @searpc_func("int", ["string", "string"])
    def seafile_sync(repo_id, peer_id):
        pass
    sync = seafile_sync

    @searpc_func("object", ["string"])
    def seafile_get_repo_sync_task():
        pass
    get_repo_sync_task = seafile_get_repo_sync_task

    @searpc_func("int", [])
    def seafile_is_auto_sync_enabled():
        pass
    is_auto_sync_enabled = seafile_is_auto_sync_enabled

    @searpc_func("objlist", ["int", "int"])
    def seafile_get_file_sync_errors():
        pass
    get_file_sync_errors = seafile_get_file_sync_errors

    ###### Property Management #########

    @searpc_func("int", ["string", "string"])
    def seafile_set_repo_passwd(repo_id, passwd):
        pass
    set_repo_passwd = seafile_set_repo_passwd

    @searpc_func("int", ["string", "string", "string"])
    def seafile_set_repo_property(repo_id, key, value):
        pass
    set_repo_property = seafile_set_repo_property

    @searpc_func("string", ["string", "string"])
    def seafile_get_repo_property(repo_id, key):
        pass
    get_repo_property = seafile_get_repo_property

    @searpc_func("string", ["string"])
    def seafile_get_repo_relay_address(repo_id):
        pass
    get_repo_relay_address = seafile_get_repo_relay_address

    @searpc_func("string", ["string"])
    def seafile_get_repo_relay_port(repo_id):
        pass
    get_repo_relay_port = seafile_get_repo_relay_port

    @searpc_func("int", ["string", "string", "string"])
    def seafile_update_repo_relay_info(repo_id, addr, port):
        pass
    update_repo_relay_info = seafile_update_repo_relay_info

    @searpc_func("int", ["string", "string"])
    def seafile_set_repo_token(repo_id, token):
        pass
    set_repo_token = seafile_set_repo_token

    @searpc_func("string", ["string"])
    def seafile_get_repo_token(repo_id):
        pass
    get_repo_token = seafile_get_repo_token

    @searpc_func("object", ["int", "string", "string"])
    def seafile_generate_magic_and_random_key(enc_version, repo_id, password):
        pass
    generate_magic_and_random_key = seafile_generate_magic_and_random_key

    @searpc_func("int", [])
    def seafile_shutdown():
        pass
    shutdown = seafile_shutdown
