
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

    # httpserver token
    def get_httpserver_access_token(self, repo_id, obj_id, op, username):
        """Generate token for access file/dir in httpserver

        op: the operation, 'view', 'download', 'download-dir'

        Return: the access token in string
        """
        return seafserv_rpc.web_get_access_token(repo_id, obj_id, op, username)

    def query_httpserver_access_token(self, token):
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

    def get_repo_owner(self, repo_id):
        return seafserv_threaded_rpc.get_repo_owner(repo_id)

    def get_owned_repo_list(self, username):
        return seafserv_threaded_rpc.list_owned_repos(username)

    def get_repo_size(self, repo_id):
        return seafserv_threaded_rpc.server_repo_size(repo_id)

    def revert_repo(self, repo_id, commit_id, username):
        return seafserv_threaded_rpc.revert_on_server(repo_id, commit_id, username)

    def diff_commits(self, repo_id, old_commit, new_commit):
        return seafserv_threaded_rpc.get_diff(repo_id, old_commit, new_commit)

    def get_commit_list(self, repo_id, offset, limit):
        return seafserv_threaded_rpc.get_commit_list(repo_id, offset, limit)

    # repo permission checking
    def check_repo_access_permission(self, repo_id, username):
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
                  dst_dir, dst_filename, username):
        return seafserv_threaded_rpc.copy_file(src_repo, src_dir, src_filename,
                                               dst_repo, dst_dir, dst_filename,
                                               username)

    def move_file(self, src_repo, src_dir, src_filename, dst_repo, dst_dir,
                  dst_filename, username):
        return seafserv_threaded_rpc.move_file(src_repo, src_dir, src_filename,
                                               dst_repo, dst_dir, dst_filename,
                                               username)
    
    def rename_file(self, repo_id, parent_dir, oldname, newname, username):
        return seafserv_threaded_rpc.rename_file(repo_id, parent_dir,
                                                 oldname, newname, username)

    def is_valid_filename(self, repo_id, filename):
        return seafserv_threaded_rpc.is_valid_filename(repo_id, filename)

    def get_file_size(self, file_id):
        return seafserv_threaded_rpc.get_file_size(file_id)

    def get_file_id_by_path(self, repo_id, path):
        return seafserv_threaded_rpc.get_file_id_by_path(repo_id, path)

    def get_file_id_by_commit_and_path(self, commit_id, path):
        return seafserv_threaded_rpc.get_file_id_by_commit_and_path(commit_id, path)

    def get_file_revisions(self, repo_id, path, max_revision, limit):
        return seafserv_threaded_rpc.list_file_revisions(repo_id, path,
                                                         max_revision, limit)

    def get_files_last_modified(self, repo_id, parent_dir, limit):
        """Get last modification time for files in a dir

        limit: the max number of commits to analyze
        """
        return seafserv_threaded_rpc.calc_files_last_modified(repo_id,
                                                              parent_dir, limit)

    def list_dir_by_dir_id(self, dir_id):
        return seafserv_threaded_rpc.list_dir(dir_id)

    def post_dir(self, repo_id, parent_dir, dirname, username):
        """Add a directory"""
        return seafserv_threaded_rpc.post_dir(repo_id, parent_dir, dirname, username)
    
    def get_dir_id_by_path(self, repo_id, path):
        return seafserv_threaded_rpc.get_dir_id_by_path(repo_id, path)
    
    def list_dir_by_path(self, repo_id, path):
        dir_id = seafserv_threaded_rpc.get_dir_id_by_path(repo_id, path)
        return seafserv_threaded_rpc.list_dir(dir_id)
    
    def get_dir_id_by_commit_and_path(self, commit_id, path):
        return seafserv_threaded_rpc.get_dirid_by_path(commit_id, path)

    def list_dir_by_commit_and_path(self, commit_id, path):
        dir_id = seafserv_threaded_rpc.get_dir_id_by_commit_and_path(repo_id, path)
        return seafserv_threaded_rpc.list_dir(dir_id)
    
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
        return seafserv_threaded_rpc.group_share_repo(repo_id, group_id,
                                                      username, permission)

    def group_unshare_repo(self, repo_id, group_id, username):
        return seafserv_threaded_rpc.group_unshare_repo(repo_id, group_id, username)

    def get_shared_groups_by_repo(self, repo_id):
        return seafserv_threaded_rpc.get_shared_groups_by_repo(repo_id)

    def get_group_repoids(self, group_id):
        return seafserv_threaded_rpc.get_group_repoids(group_id)

    def get_group_repos_by_owner(self, username):
        return seafserv_threaded_rpc.get_group_repos_by_owner(username)

    def set_group_repo_permission(self, group_id, repo_id, permission):
        return seafserv_threaded_rpc.set_group_repo_permission(group_id, repo_id,
                                                               permission)

    # token
    def generate_repo_token(self, repo_id, username):
        """Generate a token for sync a repo
        """
        pass

    # quota
    def get_user_self_usage(self, username):
        """Get the sum of repos' size of the user"""
        return seafserv_threaded_rpc.get_user_quota_usage(username)

    def get_user_share_usage(self, username):
        return seafserv_threaded_rpc.get_user_share_usage(username)

    def get_user_quota(self, username):
        return seafserv_threaded_rpc.get_user_quota(username)

    def set_user_quota(self, username):
        return seafserv_threaded_rpc.set_user_quota(username)

    def check_quota(self, repo_id):
        pass

    # password management
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

