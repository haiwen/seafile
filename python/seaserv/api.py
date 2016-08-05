
from service import seafserv_rpc, seafserv_threaded_rpc, ccnet_threaded_rpc
from pysearpc import SearpcError

"""
General rules for return values and exception handling of Seafile python API:
- Read operations return corresponding values. Raises exceptions on parameter errors
  or I/O errors in seaf-server.
- Write or set operations return 0 on success, -1 on error. On error, an exceptioin
  will be raised.

All paths in parameters can be in absolute path format (like '/test') or
relative path format (like 'test'). The API can handle both formats.
"""

class SeafileAPI(object):

    def __init__(self):
        pass

    # fileserver token

    def get_fileserver_access_token(self, repo_id, obj_id, op, username, use_onetime=True):
        """Generate token for access file/dir in fileserver

        op: the operation, can be 'view', 'download', 'download-dir', 'downloadblks',
            'upload', 'update', 'upload-blks-api', 'upload-blks-aj',
            'update-blks-api', 'update-blks-aj'

        Return: the access token in string
        """
        onetime = 1 if bool(use_onetime) else 0
        return seafserv_rpc.web_get_access_token(repo_id, obj_id, op, username,
                                                 onetime)

    def query_fileserver_access_token(self, token):
        """Get the WebAccess object

        token: the access token in string

        Return: the WebAccess object (lib/webaccess.vala)
        """
        return seafserv_rpc.web_query_access_token(token)

    def query_zip_progress(self, token):
        """Query zip progress for download-dir, download-multi
        token: obtained by get_fileserver_access_token
        Return: json formated string `{"zipped":, "total":}`, otherwise None.
        """
        return seafserv_rpc.query_zip_progress(token)

    # password

    def is_password_set(self, repo_id, username):
        """
        Return non-zero if True, otherwise 0.
        """
        return seafserv_rpc.is_passwd_set(repo_id, username)

    def get_decrypt_key(self, repo_id, username):
        """
        Return: a CryptKey object (lib/crypt.vala)
        """
        return seafserv_rpc.get_decrypt_key(repo_id, username)

    # repo manipulation

    def create_repo(self, name, desc, username, passwd):
        return seafserv_threaded_rpc.create_repo(name, desc, username, passwd)

    def create_enc_repo(self, repo_id, name, desc, username, magic, random_key, enc_version):
        return seafserv_threaded_rpc.create_enc_repo(repo_id, name, desc, username, magic, random_key, enc_version)

    def get_repo(self, repo_id):
        """
        Return: a Repo object (lib/repo.vala)
        """
        return seafserv_threaded_rpc.get_repo(repo_id)

    def remove_repo(self, repo_id):
        return seafserv_threaded_rpc.remove_repo(repo_id)

    def get_repo_list(self, start, limit):
        """
        Return: a list of Repo objects (lib/repo.vala)
        """
        return seafserv_threaded_rpc.get_repo_list(start, limit)

    def count_repos(self):
        return seafserv_threaded_rpc.count_repos()

    def edit_repo(self, repo_id, name, description, username):
        return seafserv_threaded_rpc.edit_repo(repo_id, name, description, username)

    def is_repo_owner(self, username, repo_id):
        """
        Return 1 if True, otherwise 0.
        """
        return seafserv_threaded_rpc.is_repo_owner(username, repo_id)

    def set_repo_owner(self, email, repo_id):
        return seafserv_threaded_rpc.set_repo_owner(email, repo_id)

    def get_repo_owner(self, repo_id):
        """
        Return: repo owner in string
        """
        return seafserv_threaded_rpc.get_repo_owner(repo_id)

    def get_owned_repo_list(self, username, ret_corrupted=False):
        """
        Return: a list of Repo objects
        """
        return seafserv_threaded_rpc.list_owned_repos(username,
                                                      1 if ret_corrupted else 0)

    def get_orphan_repo_list(self):
        return seafserv_threaded_rpc.get_orphan_repo_list()

    def get_repo_size(self, repo_id):
        return seafserv_threaded_rpc.server_repo_size(repo_id)

    def revert_repo(self, repo_id, commit_id, username):
        return seafserv_threaded_rpc.revert_on_server(repo_id, commit_id, username)

    def diff_commits(self, repo_id, old_commit, new_commit, fold_dir_diff = 1):
        """
        Return: a list of DiffEntry objects (lib/repo.vala)
        """
        return seafserv_threaded_rpc.get_diff(repo_id, old_commit, new_commit, fold_dir_diff)

    def get_commit_list(self, repo_id, offset, limit):
        """
        Return: a list of Commit objects (lib/commit.vala)
        """
        return seafserv_threaded_rpc.get_commit_list(repo_id, offset, limit)

    def change_repo_passwd(self, repo_id, old_passwd, new_passwd, user):
        return seafserv_threaded_rpc.change_repo_passwd(repo_id, old_passwd,
                                                        new_passwd, user)

    # File property and dir listing

    def is_valid_filename(self, repo_id, filename):
        """
        Return: 0 on invalid; 1 on valid.
        """
        return seafserv_threaded_rpc.is_valid_filename(repo_id, filename)

    def get_file_size(self, store_id, version, file_id):
        return seafserv_threaded_rpc.get_file_size(store_id, version, file_id)

    def get_dir_size(self, store_id, version, dir_id):
        """
        Return the size of a dir. It needs to recursively calculate the size
        of the dir. It can cause great delay before returning. Use with caution!
        """
        return seafserv_threaded_rpc.get_dir_size(store_id, version, dir_id)

    def get_file_id_by_path(self, repo_id, path):
        """
        Returns None if path not found. Only raise exception on parameter or IO error.
        """
        return seafserv_threaded_rpc.get_file_id_by_path(repo_id, path)

    def get_file_id_by_commit_and_path(self, repo_id, commit_id, path):
        return seafserv_threaded_rpc.get_file_id_by_commit_and_path(repo_id,
                                                                    commit_id,
                                                                    path)

    def get_dirent_by_path(self, repo_id, path):
        """
        Return: a Dirent object (lib/dirent.vala)
        """
        return seafserv_threaded_rpc.get_dirent_by_path(repo_id, path)

    def list_file_by_file_id(self, repo_id, file_id, offset=-1, limit=-1):
        # deprecated, use list_blocks_by_file_id instead.
        return seafserv_threaded_rpc.list_file_blocks(repo_id, file_id, offset, limit)

    def list_blocks_by_file_id(self, repo_id, file_id, offset=-1, limit=-1):
        """
        list block ids of a file.
        Return: a string containing block list. Each id is seperated by '\n'
        """
        return seafserv_threaded_rpc.list_file_blocks(repo_id, file_id, offset, limit)
    
    def get_dir_id_by_path(self, repo_id, path):
        return seafserv_threaded_rpc.get_dir_id_by_path(repo_id, path)

    def list_dir_by_dir_id(self, repo_id, dir_id, offset=-1, limit=-1):
        """
        Return: a list of Dirent objects. The objects are sorted as follows:
                - Directories are always before files
                - Entries are sorted by names in ascending order
        """
        return seafserv_threaded_rpc.list_dir(repo_id, dir_id, offset, limit)

    def list_dir_by_path(self, repo_id, path, offset=-1, limit=-1):
        dir_id = seafserv_threaded_rpc.get_dir_id_by_path(repo_id, path)
        if dir_id is None:
            return None
        return seafserv_threaded_rpc.list_dir(repo_id, dir_id, offset, limit)

    def list_dir_by_commit_and_path(self, repo_id,
                                    commit_id, path, offset=-1, limit=-1):
        dir_id = seafserv_threaded_rpc.get_dir_id_by_commit_and_path(repo_id, commit_id, path)
        if dir_id is None:
            return None
        return seafserv_threaded_rpc.list_dir(repo_id, dir_id, offset, limit)
    
    def get_dir_id_by_commit_and_path(self, repo_id, commit_id, path):
        return seafserv_threaded_rpc.get_dir_id_by_commit_and_path(repo_id, commit_id, path)

    # file/dir operations

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
                  dst_filename, replace, username, need_progress, synchronous=0):
        return seafserv_threaded_rpc.move_file(src_repo, src_dir, src_filename,
                                               dst_repo, dst_dir, dst_filename,
                                               replace, username, need_progress, synchronous)

    def get_copy_task(self, task_id):
        return seafserv_rpc.get_copy_task(task_id)

    def cancel_copy_task(self, task_id):
        return seafserv_rpc.cancel_copy_task(task_id)

    def rename_file(self, repo_id, parent_dir, oldname, newname, username):
        return seafserv_threaded_rpc.rename_file(repo_id, parent_dir,
                                                 oldname, newname, username)

    def post_dir(self, repo_id, parent_dir, dirname, username):
        """Add a directory"""
        return seafserv_threaded_rpc.post_dir(repo_id, parent_dir, dirname, username)

    def revert_file(self, repo_id, commit_id, path, username):
        return seafserv_threaded_rpc.revert_file(repo_id, commit_id, path, username)

    def revert_dir(self, repo_id, commit_id, path, username):
        return seafserv_threaded_rpc.revert_dir(repo_id, commit_id, path, username)

    def get_deleted(self, repo_id, show_days, path='/', scan_stat=None, limit=100):
        """
        Get list of deleted paths.

        @show_days: return deleted path in the last @show_days
        @path: return deleted files under this path. The path will be recursively traversed.
        @scan_stat: An opaque status returned by the last call. In the first call, None
                    must be passed. The last entry of the result list contains a 'scan_stat'
                    attribute. In the next call, pass in the returned 'scan_stat'.
        @limit: Advisory maximum number of result entries returned. Sometimes more than @limit
                entries will be returned.

        Return a list of DeletedEntry objects (lib/repo.vala).
        If no more deleted entries can be returned within the given time frame (specified by
        @show_days) or all deleted entries in the history have been returned, 'None' will be
        returned.
        """
        return seafserv_threaded_rpc.get_deleted(repo_id, show_days, path, scan_stat, limit)

    def get_file_revisions(self, repo_id, path, max_revision, limit, show_days=-1):
        return seafserv_threaded_rpc.list_file_revisions(repo_id, path,
                                                         max_revision, limit,
                                                         show_days)

    # This api is slow and should only be used for version 0 repos.
    def get_files_last_modified(self, repo_id, parent_dir, limit):
        """Get last modification time for files in a dir

        limit: the max number of commits to analyze
        """
        return seafserv_threaded_rpc.calc_files_last_modified(repo_id,
                                                              parent_dir, limit)

    def get_repo_history_limit(self, repo_id):
        """
        Return repo history limit in days. Returns -1 if it's unlimited.
        """
        return seafserv_threaded_rpc.get_repo_history_limit(repo_id)

    def set_repo_history_limit(self, repo_id, days):
        """
        Set repo history limit in days. Pass -1 if set to unlimited.
        """
        return seafserv_threaded_rpc.set_repo_history_limit(repo_id, days)

    def check_repo_blocks_missing(self, repo_id, blklist):
        return seafserv_threaded_rpc.check_repo_blocks_missing(repo_id, blklist)

    # file lock
    def check_file_lock(self, repo_id, path, user):
        """
        Always return 0 since CE doesn't support file locking.
        """
        return 0

    # share repo to user
    def share_repo(self, repo_id, from_username, to_username, permission):
        return seafserv_threaded_rpc.add_share(repo_id, from_username,
                                               to_username, permission)

    def remove_share(self, repo_id, from_username, to_username):
        return seafserv_threaded_rpc.remove_share(repo_id, from_username,
                                                  to_username)
    
    def set_share_permission(self, repo_id, from_username, to_username, permission):
        return seafserv_threaded_rpc.set_share_permission(repo_id, from_username,
                                                          to_username, permission)

    def share_subdir_to_user(self, repo_id, path, owner, share_user, permission, passwd=''):
        return seafserv_threaded_rpc.share_subdir_to_user(repo_id, path, owner,
                                                          share_user, permission, passwd)

    def unshare_subdir_for_user(self, repo_id, path, owner, share_user):
        return seafserv_threaded_rpc.unshare_subdir_for_user(repo_id, path, owner,
                                                             share_user)

    def update_share_subdir_perm_for_user(self, repo_id, path, owner,
                                          share_user, permission):
        return seafserv_threaded_rpc.update_share_subdir_perm_for_user(repo_id, path, owner,
                                                                       share_user, permission)

    def get_share_out_repo_list(self, username, start, limit):
        """
        Get repo list shared by this user.
        Return: a list of Repo objects
        """
        return seafserv_threaded_rpc.list_share_repos(username, "from_email",
                                                      start, limit)

    def get_share_in_repo_list(self, username, start, limit):
        """
        Get repo list shared to this user.
        """
        return seafserv_threaded_rpc.list_share_repos(username, "to_email",
                                                      start, limit)

    def list_repo_shared_to(self, from_user, repo_id):
        """
        Get user list this repo is shared to.
        Return: a list of SharedUser objects (lib/repo.vala)
        """
        return seafserv_threaded_rpc.list_repo_shared_to(from_user, repo_id)

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

    def get_shared_group_ids_by_repo(self, repo_id):
        """
        Return: a string containing list of group ids. Each id is seperated by '\n'
        """
        return seafserv_threaded_rpc.get_shared_groups_by_repo(repo_id)

    def list_repo_shared_group(self, from_user, repo_id):
        # deprecated, use list_repo_shared_group_by_user instead.
        return seafserv_threaded_rpc.list_repo_shared_group(from_user, repo_id)

    def list_repo_shared_group_by_user(self, from_user, repo_id):
        """
        Return: a list of SharedGroup objects (lib/repo.vala)
        """
        return seafserv_threaded_rpc.list_repo_shared_group(from_user, repo_id)

    def share_subdir_to_group(self, repo_id, path, owner, share_group, permission, passwd=''):
        return seafserv_threaded_rpc.share_subdir_to_group(repo_id, path, owner,
                                                           share_group, permission, passwd)

    def unshare_subdir_for_group(self, repo_id, path, owner, share_group):
        return seafserv_threaded_rpc.unshare_subdir_for_group(repo_id, path, owner,
                                                              share_group)

    def update_share_subdir_perm_for_group(self, repo_id, path, owner,
                                           share_group, permission):
        return seafserv_threaded_rpc.update_share_subdir_perm_for_group(repo_id, path, owner,
                                                                        share_group, permission)

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
        # deprecated, use get_repos_by_group instead.
        ret = []
        for repo_id in self.get_group_repoids(group_id):
            r = self.get_repo(repo_id)
            if r is None:
                continue
            ret.append(r)
        return ret

    def get_repos_by_group(self, group_id):
        """
        Return: a list of Repo objects
        """
        return seafserv_threaded_rpc.get_repos_by_group(group_id)

    def get_group_repos_by_owner(self, username):
        """
        Get all repos a user share to any group
        Return: a list of Repo objects
        """
        return seafserv_threaded_rpc.get_group_repos_by_owner(username)

    def remove_group_repos_by_owner(self, group_id, username):
        """
        Unshare all repos a user shared to a group.
        """
        return seafserv_threaded_rpc.remove_repo_group(group_id, username)

    def remove_group_repos(self, group_id):
        """
        Remove all repos under group.
        Return: 0 success; -1 failed
        """
        return seafserv_threaded_rpc.remove_repo_group(group_id, None)

    def set_group_repo_permission(self, group_id, repo_id, permission):
        return seafserv_threaded_rpc.set_group_repo_permission(group_id, repo_id,
                                                               permission)

    def get_shared_users_for_subdir(self, repo_id, path, from_user):
        """
        Get all users a path is shared to.
        Return: a list of SharedUser objects.
        """
        return seafserv_threaded_rpc.get_shared_users_for_subdir(repo_id, path, from_user)

    def get_shared_groups_for_subdir(self, repo_id, path, from_user):
        """
        Get all groups a path is shared to.
        Return: a list of SharedGroup objects.
        """
        return seafserv_threaded_rpc.get_shared_groups_for_subdir(repo_id, path, from_user)

    # organization wide repo
    def add_inner_pub_repo(self, repo_id, permission):
        return seafserv_threaded_rpc.set_inner_pub_repo(repo_id, permission)

    def remove_inner_pub_repo(self, repo_id):
        return seafserv_threaded_rpc.unset_inner_pub_repo(repo_id)

    def get_inner_pub_repo_list(self):
        """
        Return: a list of Repo objects.
        """
        return seafserv_threaded_rpc.list_inner_pub_repos()

    def list_inner_pub_repos_by_owner(self, repo_owner):
        """
        Return: a list of Repo objects.
        """
        return seafserv_threaded_rpc.list_inner_pub_repos_by_owner(repo_owner)

    def count_inner_pub_repos(self):
        return seafserv_threaded_rpc.count_inner_pub_repos()

    def is_inner_pub_repo(self, repo_id):
        return seafserv_threaded_rpc.is_inner_pub_repo(repo_id)

    # permission checks
    def check_permission(self, repo_id, user):
        """
        Check repo share permissions. Only check user share, group share and inner-pub
        shares.
        Return: 'r', 'rw', or None
        """
        return seafserv_threaded_rpc.check_permission(repo_id, user)

    def check_permission_by_path(self, repo_id, path, user):
        """
        Check both repo share permission and sub-folder access permissions.
        This function should be used when updating file/folder in a repo.
        In CE, this function is equivalent to check_permission.
        Return: 'r', 'rw', or None
        """
        return seafserv_threaded_rpc.check_permission_by_path(repo_id, path, user)

    # token
    def generate_repo_token(self, repo_id, username):
        """Generate a token for sync a repo
        """
        return seafserv_threaded_rpc.generate_repo_token(repo_id, username)

    def delete_repo_token(self, repo_id, token, user):
        return seafserv_threaded_rpc.delete_repo_token(repo_id, token, user)

    def list_repo_tokens(self, repo_id):
        """
        Return: a list of RepoTokenInfo objects.
        """
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
        # sum (repo_size * number_of_shares)
        return seafserv_threaded_rpc.get_user_share_usage(username)

    def get_user_quota(self, username):
        """
        Return: -2 if quota is unlimited; otherwise it must be number > 0.
        """
        return seafserv_threaded_rpc.get_user_quota(username)

    def set_user_quota(self, username, quota):
        return seafserv_threaded_rpc.set_user_quota(username, quota)

    def get_user_share_quota(self, username):
        return -2               # unlimited

    def set_user_share_quota(self, username, quota):
        pass

    def check_quota(self, repo_id):
        pass

    # encrypted repo password management
    def check_passwd(self, repo_id, magic):
        return seafserv_threaded_rpc.check_passwd(repo_id, magic)

    def set_passwd(self, repo_id, user, passwd):
        return seafserv_threaded_rpc.set_passwd(repo_id, user, passwd)

    def unset_passwd(self, repo_id, user, passwd):
        return seafserv_threaded_rpc.unset_passwd(repo_id, user, passwd)

    def generate_magic_and_random_key(self, enc_version, repo_id, password):
        return seafserv_threaded_rpc.generate_magic_and_random_key(enc_version, repo_id, password)

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

    def get_virtual_repo(self, origin_repo, path, owner):
        return seafserv_threaded_rpc.get_virtual_repo(origin_repo, path, owner)

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

class CcnetAPI(object):

    def __init__(self):
        pass

    # user management
    def add_emailuser(self, email, passwd, is_staff, is_active):
        return ccnet_threaded_rpc.add_emailuser(email, passwd, is_staff, is_active)
    
    def remove_emailuser(self, source, email):
        """
        source can be 'DB' or 'LDAP'.
        - 'DB': remove a user created in local database
        - 'LDAP': remove a user imported from LDAP
        """
        return ccnet_threaded_rpc.remove_emailuser(source, email)
    
    def validate_emailuser(self, email, passwd):
        """
        Verify user's password on login. Can be used to verify DB and LDAP users.
        The function first verify password with LDAP, then local database.
        """
        return ccnet_threaded_rpc.validate_emailuser(email, passwd)

    def get_emailuser(self, email):
        """
        Only return local database user or imported LDAP user.
        It first lookup user from local database, if not found, lookup imported
        LDAP user.
        Return: a list of EmailUser objects (ccnet/lib/ccnetobj.vala)
        The 'source' attribute of EmailUser object is set to 'LDAPImport' for LDAP
        imported user, and 'DB' for local database user.
        """
        return ccnet_threaded_rpc.get_emailuser(email)

    def get_emailuser_with_import(self, email):
        """
        The same as get_emailuser() but import the user from LDAP if it was not
        imported yet.
        """
        return ccnet_threaded_rpc.get_emailuser_with_import(email)

    def get_emailuser_by_id(self, user_id):
        """
        Get a user from local database with the db index id.
        """
        return ccnet_threaded_rpc.get_emailuser_by_id(user_id)

    def get_emailusers(self, source, start, limit, is_active=None):
        """
        source:
          - 'DB': return local db users
          - 'LDAPImport': return imported LDAP users
          - 'LDAP': retrieve users directly from LDAP server
        start: offset to start retrieving, -1 to start from the beginning
        limit: number of users to get, -1 to get all user from start
        is_active: True to return only active users; False to return inactive users;
                   None to return all users.
        Return: a list of EmailUser objects.
        """
        if is_active is True:
            status = "active"       # list active users
        elif is_active is False:
            status = "inactive"     # list inactive users
        else:
            status = ""             # list all users

        return ccnet_threaded_rpc.get_emailusers(source, start, limit, status)

    def search_emailusers(self, source, email_patt, start, limit):
        """
        Search for users whose name contains @email_patt.
        source: 'DB' for local db users; 'LDAP' for imported LDAP users.
                This function cannot search LDAP users directly in LDAP server.
        """
        return ccnet_threaded_rpc.search_emailusers(source, email_patt, start, limit)

    def search_ldapusers(self, keyword, start, limit):
        """
        Search for users whose name contains @keyword directly from LDAP server.
        """
        return ccnet_threaded_rpc.search_ladpusers(keyword, start, limit)
    
    def count_emailusers(self, source):
        """
        Return the number of active users by source.
        source: 'DB' for local db users; 'LDAP' for imported LDAP users.
        """
        return ccnet_threaded_rpc.count_emailusers(source)

    def count_inactive_emailusers(self, source):
        """
        Return the number of inactive users by source.
        source: 'DB' for local db users; 'LDAP' for imported LDAP users.
        """
        return ccnet_threaded_rpc.count_inactive_emailusers(source)

    def update_emailuser(self, source, user_id, password, is_staff, is_active):
        """
        source: 'DB' for local db user; 'LDAP' for imported LDAP user.
        user_id: usually not changed.
        password: new password in plain text. Only effective for DB users.
                  If '!' is passed, the password won't be updated.
        is_staff: change superuser status
        is_active: activate or deactivate user
        """
        return ccnet_threaded_rpc.update_emailuser(source, user_id, password, is_staff, is_active)

    def update_role_emailuser(self, email, role):
        return ccnet_threaded_rpc.update_role_emailuser(email, role)

    def get_superusers(self):
        """
        Return: a list of EmailUser objects.
        """
        return ccnet_threaded_rpc.get_superusers()

    # group management
    def create_group(self, group_name, user_name, gtype=None):
        """
        For CE, gtype is not used and should always be None.
        """
        return ccnet_threaded_rpc.create_group(group_name, user_name, gtype)

    def create_org_group(self, org_id, group_name, user_name):
        return ccnet_threaded_rpc.create_org_group(org_id, group_name, user_name)
    
    def remove_group(self, group_id):
        """
        permission check should be done before calling this function.
        """
        return ccnet_threaded_rpc.remove_group(group_id)

    def group_add_member(self, group_id, user_name, member_name):
        """
        user_name: unused.
        """
        return ccnet_threaded_rpc.group_add_member(group_id, user_name, member_name)
    
    def group_remove_member(self, group_id, user_name, member_name):
        """
        user_name: unused.
        """
        return ccnet_threaded_rpc.group_remove_member(group_id, user_name, member_name)

    def group_set_admin(self, group_id, member_name):
        """
        No effect if member_name is not in the group.
        """
        return ccnet_threaded_rpc.group_set_admin(group_id, member_name)

    def group_unset_admin(self, group_id, member_name):
        """
        No effect if member_name is not in the group.
        """
        return ccnet_threaded_rpc.group_unset_admin(group_id, member_name)

    def set_group_name(self, group_id, group_name):
        return ccnet_threaded_rpc.set_group_name(group_id, group_name)
    
    def quit_group(self, group_id, user_name):
        return ccnet_threaded_rpc.quit_group(group_id, user_name)

    def get_groups(self, user_name):
        """
        Get all groups the user belongs to.
        Return: a list of Group objects (ccnet/lib/ccnetobj.vala)
        """
        return ccnet_threaded_rpc.get_groups(user_name)

    def get_all_groups(self, start, limit, source=None):
        """
        For CE, source is not used and should alwasys be None.
        """
        return ccnet_threaded_rpc.get_all_groups(start, limit, source)
    
    def get_group(self, group_id):
        return ccnet_threaded_rpc.get_group(group_id)

    def get_group_members(self, group_id):
        """
        Return a list of GroupUser objects (ccnet/lib/ccnetobj.vala)
        """
        return ccnet_threaded_rpc.get_group_members(group_id)

    def check_group_staff(self, group_id, username):
        """
        Return non-zero value if true, 0 if not true
        """
        return ccnet_threaded_rpc.check_group_staff(group_id, username)

    def remove_group_user(self, username):
        return ccnet_threaded_rpc.remove_group_user(username)
    
    def is_group_user(self, group_id, user):
        """
        Return non-zero value if true, 0 if not true
        """
        return ccnet_threaded_rpc.is_group_user(group_id, user)

    def set_group_creator(self, group_id, user_name):
        return ccnet_threaded_rpc.set_group_creator(group_id, user_name)

    # organization management
    def create_org(self, org_name, url_prefix, creator):
        return ccnet_threaded_rpc.create_org(org_name, url_prefix, creator)

    def remove_org(self, org_id):
        return ccnet_threaded_rpc.remove_org(org_id)
    
    def get_all_orgs(self, start, limit):
        """
        Return a list of Organization objects (ccnet/lib/ccnetobj.vala)
        """
        return ccnet_threaded_rpc.get_all_orgs(start, limit)

    def count_orgs(self):
        return ccnet_threaded_rpc.count_orgs()

    def get_org_by_url_prefix(self, url_prefix):
        """
        Return an Organizaion object.
        """
        return ccnet_threaded_rpc.get_org_by_url_prefix(url_prefix)

    def get_org_by_id(self, org_id):
        return ccnet_threaded_rpc.get_org_by_id(org_id)
    
    def add_org_user(self, org_id, email, is_staff):
        return ccnet_threaded_rpc.add_org_user(org_id, email, is_staff)

    def remove_org_user(self, org_id, email):
        return ccnet_threaded_rpc.remove_org_user(org_id, email)
    
    def get_orgs_by_user(self, email):
        return ccnet_threaded_rpc.get_orgs_by_user(email)
    
    def get_org_emailusers(self, url_prefix, start, limit):
        """
        Return a list of EmailUser objects.
        """
        return ccnet_threaded_rpc.get_org_emailusers(url_prefix, start, limit)

    def add_org_group(self, org_id, group_id):
        return ccnet_threaded_rpc.add_org_group(org_id, group_id)

    def remove_org_group(self, org_id, group_id):
        return ccnet_threaded_rpc.remove_org_group(org_id, group_id)

    def is_org_group(self, group_id):
        """
        Return non-zero if True, otherwise 0.
        """
        return ccnet_threaded_rpc.is_org_group(group_id)

    def get_org_id_by_group(self, group_id):
        return ccnet_threaded_rpc.get_org_id_by_group(group_id)
    
    def get_org_groups(self, org_id, start, limit):
        """
        Return a list of int, each int is group id.
        """
        return ccnet_threaded_rpc.get_org_groups(org_id, start, limit)
    
    def org_user_exists(self, org_id, email):
        """
        Return non-zero if True, otherwise 0.
        """
        return ccnet_threaded_rpc.org_user_exists(org_id, email)

    def is_org_staff(self, org_id, user):
        """
        Return non-zero if True, otherwise 0.
        """
        return ccnet_threaded_rpc.is_org_staff(org_id, user)

    def set_org_staff(self, org_id, user):
        return ccnet_threaded_rpc.set_org_staff(org_id, user)

    def unset_org_staff(self, org_id, user):
        return ccnet_threaded_rpc.unset_org_staff(org_id, user)

    def set_org_name(self, org_id, org_name):
        return ccnet_threaded_rpc.set_org_name(org_id, org_name)

ccnet_api = CcnetAPI()
