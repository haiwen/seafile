
from service import ccnet_rpc, monitor_rpc, seafserv_rpc, \
    seafserv_threaded_rpc, ccnet_threaded_rpc

"""
WebAccess:

    string repo_id
    string obj_id
    string op
    string username
"""

class SeafileAPI(object):

    def __init__(self):
        pass

    # fileserver token
    def get_fileserver_access_token(self, repo_id, obj_id, op, username):
        """Generate token for access file/dir in fileserver

        op: the operation, 'view', 'download', 'download-dir'

        Return: the access token in string
        """
        return seafserv_rpc.web_get_access_token(repo_id, obj_id, op, username)

    def query_fileserver_access_token(self, token):
        """Get the WebAccess object

        token: the access token in string

        Return: the WebAccess object
        """
        return seafserv_rpc.web_query_access_token(token)

    # password
    def is_password_set(self, repo_id, username):
        return seafserv_rpc.is_passwd_set(repo_id, username)

    def get_decrypt_key(self, repo_id, username):
        return seafserv_rpc.get_decrypt_key(repo_id, username)

    # repo manipulation
    def create_repo(self, name, desc, username, passwd):
        return seafserv_threaded_rpc.create_repo(name, desc, username, passwd)

    def create_enc_repo(self, repo_id, name, desc, username, magic, random_key, enc_version):
        return seafserv_threaded_rpc.create_enc_repo(repo_id, name, desc, username, magic, random_key, enc_version)

    def get_repo(self, repo_id):
        return seafserv_threaded_rpc.get_repo(repo_id)

    def remove_repo(self, repo_id):
        return seafserv_threaded_rpc.remove_repo(repo_id)

    def get_repo_list(self, start, limit):
        return seafserv_threaded_rpc.get_repo_list(start, limit)

    def edit_repo(self, repo_id, name, description, username):
        return seafserv_threaded_rpc.edit_repo(repo_id, name, description, username)

    def is_repo_owner(self, username, repo_id):
        return seafserv_threaded_rpc.is_repo_owner(username, repo_id)

    def set_repo_owner(self, email, repo_id):
        return seafserv_threaded_rpc.set_repo_owner(email, repo_id)

    def get_repo_owner(self, repo_id):
        return seafserv_threaded_rpc.get_repo_owner(repo_id)

    def get_owned_repo_list(self, username):
        return seafserv_threaded_rpc.list_owned_repos(username)

    def get_orphan_repo_list(self):
        return seafserv_threaded_rpc.get_orphan_repo_list()
        
    def get_repo_size(self, repo_id):
        return seafserv_threaded_rpc.server_repo_size(repo_id)

    def revert_repo(self, repo_id, commit_id, username):
        return seafserv_threaded_rpc.revert_on_server(repo_id, commit_id, username)

    def diff_commits(self, repo_id, old_commit, new_commit, fold_dir_diff = 1):
        return seafserv_threaded_rpc.get_diff(repo_id, old_commit, new_commit, fold_dir_diff)

    def get_commit_list(self, repo_id, offset, limit):
        return seafserv_threaded_rpc.get_commit_list(repo_id, offset, limit)

    # repo permission checking
    def check_repo_access_permission(self, repo_id, username):
        """
        Returns 'rw', 'r' or None
        """
        return seafserv_threaded_rpc.check_permission(repo_id, username)

    # file/dir
    def post_file(self, repo_id, tmp_file_path, parent_dir, filename, username):
        """Add a file to a directory"""
        return seafserv_threaded_rpc.post_file(repo_id, tmp_file_path, parent_dir,
                                               filename, username)

    def post_empty_file(self, repo_id, parent_dir, filename, username):
        return seafserv_threaded_rpc.post_empty_file(repo_id, parent_dir,
                                                     filename, username)

    def put_file(self, repo_id, tmp_file_path, parent_dir, filename,
                 username, head_id):
        """Update an existing file

        head_id: the original commit id of the old file
        """
        return seafserv_threaded_rpc.put_file(repo_id, tmp_file_path, parent_dir,
                                              filename, username, head_id)

    def del_file(self, repo_id, parent_dir, filename, username):
        return seafserv_threaded_rpc.del_file(repo_id, parent_dir, filename, username)

    def copy_file(self, src_repo, src_dir, src_filename, dst_repo,
                  dst_dir, dst_filename, username, need_progress, synchronous=0):
        return seafserv_threaded_rpc.copy_file(src_repo, src_dir, src_filename,
                                               dst_repo, dst_dir, dst_filename,
                                               username, need_progress, synchronous)

    def move_file(self, src_repo, src_dir, src_filename, dst_repo, dst_dir,
                  dst_filename, username, need_progress, synchronous=0):
        return seafserv_threaded_rpc.move_file(src_repo, src_dir, src_filename,
                                               dst_repo, dst_dir, dst_filename,
                                               username, need_progress, synchronous)

    def get_copy_task(self, task_id):
        return seafserv_rpc.get_copy_task(task_id)

    def cancel_copy_task(self, task_id):
        return seafserv_rpc.cancel_copy_task(task_id)
    
    def rename_file(self, repo_id, parent_dir, oldname, newname, username):
        return seafserv_threaded_rpc.rename_file(repo_id, parent_dir,
                                                 oldname, newname, username)

    def is_valid_filename(self, repo_id, filename):
        return seafserv_threaded_rpc.is_valid_filename(repo_id, filename)

    def get_file_size(self, store_id, version, file_id):
        return seafserv_threaded_rpc.get_file_size(store_id, version, file_id)

    def get_file_id_by_path(self, repo_id, path):
        return seafserv_threaded_rpc.get_file_id_by_path(repo_id, path)

    def get_file_id_by_commit_and_path(self, repo_id, commit_id, path):
        return seafserv_threaded_rpc.get_file_id_by_commit_and_path(repo_id,
                                                                    commit_id, path)

    def get_dirent_by_path(self, repo_id, path):
        return seafserv_threaded_rpc.get_dirent_by_path(repo_id, path)

    def get_file_revisions(self, repo_id, path, max_revision, limit, show_days=7):
        return seafserv_threaded_rpc.list_file_revisions(repo_id, path,
                                                         max_revision, limit,
                                                         show_days)

    def get_files_last_modified(self, repo_id, parent_dir, limit):
        """Get last modification time for files in a dir

        limit: the max number of commits to analyze
        """
        return seafserv_threaded_rpc.calc_files_last_modified(repo_id,
                                                              parent_dir, limit)

    def post_dir(self, repo_id, parent_dir, dirname, username):
        """Add a directory"""
        return seafserv_threaded_rpc.post_dir(repo_id, parent_dir, dirname, username)

    def list_file_by_file_id(self, repo_id, file_id, offset=-1, limit=-1):
        return seafserv_threaded_rpc.list_file(repo_id, file_id, offset, limit)
    
    def get_dir_id_by_path(self, repo_id, path):
        return seafserv_threaded_rpc.get_dir_id_by_path(repo_id, path)
    
    def list_dir_by_dir_id(self, repo_id, dir_id, offset=-1, limit=-1):
        return seafserv_threaded_rpc.list_dir(repo_id, dir_id, offset, limit)

    def list_dir_by_path(self, repo_id, path, offset=-1, limit=-1):
        dir_id = seafserv_threaded_rpc.get_dir_id_by_path(repo_id, path)
        return seafserv_threaded_rpc.list_dir(repo_id, dir_id, offset, limit)

    def list_dir_by_commit_and_path(self, repo_id,
                                    commit_id, path, offset=-1, limit=-1):
        dir_id = seafserv_threaded_rpc.get_dirid_by_path(repo_id, commit_id, path)
        return seafserv_threaded_rpc.list_dir(repo_id, dir_id, offset, limit)
    
    def get_dir_id_by_commit_and_path(self, repo_id, commit_id, path):
        return seafserv_threaded_rpc.get_dirid_by_path(repo_id, commit_id, path)

    def revert_file(self, repo_id, commit_id, path, username):
        return seafserv_threaded_rpc.revert_file(repo_id, commit_id, path, username)

    def revert_dir(self, repo_id, commit_id, path, username):
        return seafserv_threaded_rpc.revert_dir(repo_id, commit_id, path, username)

    def get_deleted(self, repo_id, show_days):
        return seafserv_threaded_rpc.get_deleted(repo_id, show_days)

    # share repo to user
    def share_repo(self, repo_id, from_username, to_username, permission):
        return seafserv_threaded_rpc.add_share(repo_id, from_username,
                                               to_username, permission)

    def get_share_out_repo_list(self, username, start, limit):
        return seafserv_threaded_rpc.list_share_repos(username, "from_email",
                                                      start, limit)

    def get_share_in_repo_list(self, username, start, limit):
        return seafserv_threaded_rpc.list_share_repos(username, "to_email",
                                                      start, limit)

    def remove_share(self, repo_id, from_username, to_username):
        return seafserv_threaded_rpc.remove_share(repo_id, from_username,
                                                  to_username)
    
    def set_share_permission(self, repo_id, from_username, to_username, permission):
        return seafserv_threaded_rpc.set_share_permission(repo_id, from_username,
                                                          to_username, permission)

    # share repo to group
    def group_share_repo(self, repo_id, group_id, username, permission):
        # deprecated, use ``set_group_repo``
        return seafserv_threaded_rpc.group_share_repo(repo_id, group_id,
                                                      username, permission)

    def set_group_repo(self, repo_id, group_id, username, permission):
        return seafserv_threaded_rpc.group_share_repo(repo_id, group_id,
                                                      username, permission)

    def group_unshare_repo(self, repo_id, group_id, username):
        # deprecated, use ``unset_group_repo``
        return seafserv_threaded_rpc.group_unshare_repo(repo_id, group_id, username)

    def unset_group_repo(self, repo_id, group_id, username):
        return seafserv_threaded_rpc.group_unshare_repo(repo_id, group_id, username)

    def get_shared_groups_by_repo(self, repo_id):
        return seafserv_threaded_rpc.get_shared_groups_by_repo(repo_id)

    def get_group_repoids(self, group_id):
        """
        Return the list of group repo ids
        """
        repo_ids = seafserv_threaded_rpc.get_group_repoids(group_id)
        if not repo_ids:
            return []
        l = []
        for repo_id in repo_ids.split("\n"):
            if repo_id == '':
                continue
            l.append(repo_id)
        return l

    def get_group_repo_list(self, group_id):
        ret = []
        for repo_id in self.get_group_repoids(group_id):
            r = self.get_repo(repo_id)
            if r is None:
                continue
            ret.append(r)
        return ret    

    def get_group_repos_by_owner(self, username):
        return seafserv_threaded_rpc.get_group_repos_by_owner(username)

    def set_group_repo_permission(self, group_id, repo_id, permission):
        return seafserv_threaded_rpc.set_group_repo_permission(group_id, repo_id,
                                                               permission)

    # token
    def generate_repo_token(self, repo_id, username):
        """Generate a token for sync a repo
        """
        return seafserv_threaded_rpc.generate_repo_token(repo_id, username)

    def delete_repo_token(self, repo_id, token, user):
        return seafserv_threaded_rpc.delete_repo_token(repo_id, token, user)

    def list_repo_tokens(self, repo_id):
        return seafserv_threaded_rpc.list_repo_tokens(repo_id)

    def list_repo_tokens_by_email(self, username):
        return seafserv_threaded_rpc.list_repo_tokens_by_email(username)

    def delete_repo_tokens_by_peer_id(self, email, peer_id):
        return seafserv_threaded_rpc.delete_repo_tokens_by_peer_id(email, peer_id)

    def delete_repo_tokens_by_email(self, email):
        return seafserv_threaded_rpc.delete_repo_tokens_by_email(email)

    # quota
    def get_user_self_usage(self, username):
        """Get the sum of repos' size of the user"""
        return seafserv_threaded_rpc.get_user_quota_usage(username)

    def get_user_share_usage(self, username):
        return seafserv_threaded_rpc.get_user_share_usage(username)

    def get_user_quota(self, username):
        return seafserv_threaded_rpc.get_user_quota(username)

    def set_user_quota(self, username, quota):
        return seafserv_threaded_rpc.set_user_quota(username, quota)

    def get_user_share_quota(self, username):
        return -2               # unlimited

    def set_user_share_quota(self, username, quota):
        pass

    def check_quota(self, repo_id):
        pass

    # password management
    def check_passwd(self, repo_id, magic):
        return seafserv_threaded_rpc.check_passwd(repo_id, magic)

    def set_passwd(self, repo_id, user, passwd):
        return seafserv_threaded_rpc.set_passwd(repo_id, user, passwd)

    def unset_passwd(self, repo_id, user, passwd):
        return seafserv_threaded_rpc.unset_passwd(repo_id, user, passwd)

    # organization wide repo
    def add_inner_pub_repo(self, repo_id, permission):
        return seafserv_threaded_rpc.set_inner_pub_repo(repo_id, permission)

    def remove_inner_pub_repo(self, repo_id):
        return seafserv_threaded_rpc.unset_inner_pub_repo(repo_id)

    def get_inner_pub_repo_list(self):
        return seafserv_threaded_rpc.list_inner_pub_repos()

    def count_inner_pub_repos(self):
        return seafserv_threaded_rpc.count_inner_pub_repos()

    def is_inner_pub_repo(self, repo_id):
        return seafserv_threaded_rpc.is_inner_pub_repo(repo_id)


    # permission
    def check_permission(self, repo_id, user):
        return seafserv_threaded_rpc.check_permission(repo_id, user)

    # folder permission
    def check_permission_by_path(self, repo_id, path, user):
        return seafserv_threaded_rpc.check_permission_by_path(repo_id, path, user)

    # virtual repo
    def create_virtual_repo(self, origin_repo_id, path, repo_name, repo_desc, owner, passwd=''):
        return seafserv_threaded_rpc.create_virtual_repo(origin_repo_id,
                                                         path,
                                                         repo_name,
                                                         repo_desc,
                                                         owner,
                                                         passwd)

    def get_virtual_repos_by_owner(self, owner):
        return seafserv_threaded_rpc.get_virtual_repos_by_owner(owner)

    # @path must begin with '/', e.g. '/example'
    def get_virtual_repo(self, origin_repo, path, owner):
        return seafserv_threaded_rpc.get_virtual_repo(origin_repo, path, owner)

    def change_repo_passwd(self, repo_id, old_passwd, new_passwd, user):
        return seafserv_threaded_rpc.change_repo_passwd(repo_id, old_passwd,
                                                        new_passwd, user)

    def delete_repo_tokens_by_peer_id(self, username, device_id):
        return seafserv_threaded_rpc.delete_repo_tokens_by_peer_id(username, device_id)

    # Clean trash

    def clean_up_repo_history(self, repo_id, keep_days):
        return seafserv_threaded_rpc.clean_up_repo_history(repo_id, keep_days)

    # Trashed repos
    def get_trash_repo_list(self, start, limit):
        return seafserv_threaded_rpc.get_trash_repo_list(start, limit)

    def del_repo_from_trash(self, repo_id):
        return seafserv_threaded_rpc.del_repo_from_trash(repo_id)

    def restore_repo_from_trash(self, repo_id):
        return seafserv_threaded_rpc.restore_repo_from_trash(repo_id)

    def get_trash_repos_by_owner(self, owner):
        return seafserv_threaded_rpc.get_trash_repos_by_owner(owner)

    def empty_repo_trash(self):
        return seafserv_threaded_rpc.empty_repo_trash()

    def empty_repo_trash_by_owner(self, owner):
        return seafserv_threaded_rpc.empty_repo_trash_by_owner(owner)

seafile_api = SeafileAPI()
