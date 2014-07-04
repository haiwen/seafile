"""

Repo:
    id:                      Repo ID
    name:                    Repo Name
    desc:                    Repo description
    worktree:                The full path of the worktree of the repo
    worktree_changed:        True if the worktree is changed
    worktree_checktime:      The last check time of whether worktree is changed
    head_branch:             The name of the head branch
    enctrypted:              True if the repo is encrypted
    passwd:                  The password
    

Branch:
    name:
    commit_id:
    repo_id:

Commit:
    id:
    creator_name:
    creator:                 The id of the creator
    desc:
    ctime:
    repo_id:
    root_id:
    parent_id:
    second_parent_id:


"""


from datetime import datetime
import json
import logging
import os
import sys
import ConfigParser
from urlparse import urlparse

import ccnet
import seafile
import re
from pysearpc import SearpcError

ENVIRONMENT_VARIABLES = ('CCNET_CONF_DIR', 'SEAFILE_CONF_DIR')

# Used to fix bug in some rpc calls, will be removed in near future.
MAX_INT = 2147483647            

### Loading ccnet and seafile configurations ###
'''ccnet'''
try:
    CCNET_CONF_PATH = os.environ[ENVIRONMENT_VARIABLES[0]]
    if not CCNET_CONF_PATH: # If it's set but is an empty string.
        raise KeyError
except KeyError:
    raise ImportError("Seaserv cannot be imported, because environment variable %s is undefined." % ENVIRONMENT_VARIABLES[0])
else:
    print "Loading ccnet config from " + CCNET_CONF_PATH

CCNET_CONF_PATH = os.path.normpath(os.path.expanduser(CCNET_CONF_PATH))

pool = ccnet.ClientPool(CCNET_CONF_PATH)
ccnet_rpc = ccnet.CcnetRpcClient(pool, req_pool=True)
ccnet_threaded_rpc = ccnet.CcnetThreadedRpcClient(pool, req_pool=True)
monitor_rpc = seafile.MonitorRpcClient(pool)
seafserv_rpc = seafile.ServerRpcClient(pool, req_pool=True)
seafserv_threaded_rpc = seafile.ServerThreadedRpcClient(pool, req_pool=True)

# load ccnet server addr and port from ccnet.conf.
# 'addr:port' is used when downloading a repo
config = ConfigParser.ConfigParser()
config.read(os.path.join(CCNET_CONF_PATH, 'ccnet.conf'))

if config.has_option('General', 'SERVICE_URL') and \
   config.has_option('Network', 'PORT'):
    service_url = config.get('General', 'SERVICE_URL')
    hostname = urlparse(service_url).hostname

    SERVICE_URL = service_url
    CCNET_SERVER_ADDR = hostname
    CCNET_SERVER_PORT = config.get('Network', 'PORT')
else:
    print "Warning: SERVICE_URL not set in ccnet.conf"
    CCNET_SERVER_ADDR = None
    CCNET_SERVER_PORT = None
    SERVICE_URL = None

SERVER_ID = config.get('General', 'ID')

'''seafile'''
try:
    SEAFILE_CONF_DIR = os.environ[ENVIRONMENT_VARIABLES[1]]
    if not SEAFILE_CONF_DIR: # If it's set but is an empty string.
        raise KeyError
except KeyError:
    raise ImportError("Seaserv cannot be imported, because environment variable %s is undefined." % ENVIRONMENT_VARIABLES[1])
else:
    print "Loading seafile config from " + SEAFILE_CONF_DIR

SEAFILE_CONF_DIR = os.path.normpath(os.path.expanduser(SEAFILE_CONF_DIR))
config.read(os.path.join(SEAFILE_CONF_DIR, 'seafile.conf'))

def get_fileserver_option(key, default):
    '''
    "fileserver" used to be "httpserver"
    '''
    for section in ('fileserver', 'httpserver'):
        if config.has_option(section, key):
            return config.get(section, key)

    return default

MAX_UPLOAD_FILE_SIZE = None # Defaults to no limit
try:
    max_upload_size_mb = int(get_fileserver_option('max_upload_size', 0))
    if max_upload_size_mb > 0:
        MAX_UPLOAD_FILE_SIZE = max_upload_size_mb * (2 ** 20)
except ValueError:
    pass

MAX_DOWNLOAD_DIR_SIZE = 100 * (2 ** 20) # Default max size of a downloadable dir
try:
    max_download_dir_size_mb = int(get_fileserver_option('max_download_dir_size', 0))
    if max_download_dir_size_mb > 0:
        MAX_DOWNLOAD_DIR_SIZE = max_download_dir_size_mb * (2 ** 20)
except ValueError:
    pass

FILE_SERVER_PORT = get_fileserver_option('port', '8082')

if CCNET_SERVER_ADDR:
    FILE_SERVER_ROOT = 'http://' + CCNET_SERVER_ADDR + ':' + FILE_SERVER_PORT
else:
    FILE_SERVER_ROOT = None

CALC_SHARE_USAGE = False
if config.has_option('quota', 'calc_share_usage'):
    CALC_SHARE_USAGE = config.getboolean('quota', 'calc_share_usage')

# Get an instance of a logger
logger = logging.getLogger(__name__)

#### Basic ccnet API ####

def get_emailusers(source, start, limit):
    try:
        users = ccnet_threaded_rpc.get_emailusers(source, start, limit)
    except SearpcError:
        users = []
    return users

def count_emailusers():
    try:
        ret = ccnet_threaded_rpc.count_emailusers()
    except SearpcError:
        ret = -1
    return 0 if ret < 0 else ret

def get_session_info():
    return ccnet_rpc.get_session_info()

# group
def get_group(group_id):
    group_id_int = int(group_id)
    try:
        group = ccnet_threaded_rpc.get_group(group_id_int)
    except SearpcError:
        group = None
    return group

def get_personal_groups(start, limit):
    try:
        groups_all = ccnet_threaded_rpc.get_all_groups(start, limit)
    except SearpcError:
        return []
    return [ x for x in groups_all if not is_org_group(x.id) ]

def get_personal_groups_by_user(email):
    try:
        groups_all = ccnet_threaded_rpc.get_groups(email)
    except SearpcError:
        return []

    return [ x for x in groups_all if not is_org_group(x.id) ]
    
# group user
def is_group_user(group_id, user):
    try:
        ret = ccnet_threaded_rpc.is_group_user(group_id, user)
    except SearpcError:
        ret = 0
    return ret

def check_group_staff(group_id, username):
    """Check where user is group staff"""
    group_id = int(group_id)
    try:
        ret = ccnet_threaded_rpc.check_group_staff(group_id, username)
    except SearpcError, e:
        logger.error(e)
        ret = 0

    return True if ret == 1 else False

def remove_group_user(user):
    """
    Remove group user relationship.
    """
    return ccnet_threaded_rpc.remove_group_user(user)

def get_group_members(group_id, start=-1, limit=-1):
    group_id_int = int(group_id)
    try:
        members = ccnet_threaded_rpc.get_group_members(group_id_int)
    except SearpcError:
        members = []
    return members

# org group
def is_org_group(group_id):
    try:
        ret = ccnet_threaded_rpc.is_org_group(group_id)
    except SearpcError:
        ret = -1
    return True if ret == 1 else False

def get_org_id_by_group(group_id):
    try:
        org_id = ccnet_threaded_rpc.get_org_id_by_group(group_id)
    except SearpcError:
        org_id = -1
    return org_id

def get_org_groups(org_id, start, limit):
    try:
        groups = ccnet_threaded_rpc.get_org_groups(org_id, start, limit)
    except SearpcError:
        groups = []
    return groups

def get_org_groups_by_user(org_id, user):
    """
    Get user's groups in org.
    """
    try:
        groups_all = ccnet_threaded_rpc.get_groups(user)
    except SearpcError:
        return []

    return [ x for x in groups_all if org_id == get_org_id_by_group(x.id) ]
    
# org
def create_org(org_name, url_prefix, username):
    ccnet_threaded_rpc.create_org(org_name, url_prefix, username)

def get_org_by_url_prefix(url_prefix):
    try:
        org = ccnet_threaded_rpc.get_org_by_url_prefix(url_prefix)
    except SearpcError:
        org = None

    return org

def get_org_by_id(org_id):
    try:
        org = ccnet_threaded_rpc.get_org_by_id(org_id)
    except SearpcError:
        org = None

    return org

# org user
def add_org_user(org_id, email, is_staff):
    try:
        ccnet_threaded_rpc.add_org_user(org_id, email, is_staff)
    except SearpcError:
        pass

def remove_org_user(org_id, email):
    try:
        ccnet_threaded_rpc.remove_org_user(org_id, email)
    except SearpcError:
        pass

def org_user_exists(org_id, user):
    try:
        ret = ccnet_threaded_rpc.org_user_exists(org_id, user)
    except SearpcError:
        ret = -1
    return True if ret == 1 else False

def get_org_users_by_url_prefix(url_prefix, start, limit):
    """
    List org users.
    """
    try:
        users = ccnet_threaded_rpc.get_org_emailusers(url_prefix, start, limit)
    except:
        users = []
    return users

def get_orgs_by_user(user):
    try:
        orgs = ccnet_threaded_rpc.get_orgs_by_user(user)
    except SearpcError:
        orgs = []

    return orgs

def is_org_staff(org_id, user):
    """
    Check whether user is staff of a org.
    """
    try:
        ret = ccnet_threaded_rpc.is_org_staff(org_id, user)
    except SearpcError:
        ret = -1
    return True if ret == 1 else False

def get_user_current_org(user, url_prefix):
    orgs = get_orgs_by_user(user)
    for org in orgs:
        if org.url_prefix == url_prefix:
            return org
    return None

def send_command(command):
    client = pool.get_client()
    client.send_cmd(command)
    ret = client.response[2]
    pool.return_client(client)
    return ret

def send_message(msg_type, content):
    client = pool.get_client()
    client.send_message(msg_type, content)
    pool.return_client(client)

def get_binding_peerids(email):
    """Get peer ids of a given email"""
    try:
        peer_ids = ccnet_threaded_rpc.get_binding_peerids(email)
    except SearpcError:
        return []

    if not peer_ids:
        return []
    
    peerid_list = []
    for peer_id in peer_ids.split("\n"):
        if peer_id == '':
            continue
        peerid_list.append(peer_id)
    return peerid_list

######## seafserv API ####

# repo
def get_repos():
    """
    Return repository list.

    """
    return seafserv_threaded_rpc.get_repo_list("", 100)

def get_repo(repo_id):
    return seafserv_threaded_rpc.get_repo(repo_id)

def edit_repo(repo_id, name, desc, user):
    try:
        ret = seafserv_threaded_rpc.edit_repo(repo_id, name, desc, user)
    except SearpcError, e:
        ret = -1
    return True if ret == 0 else False

def create_repo(name, desc, user, passwd):
    """
    Return repo id if successfully created a repo, otherwise None.
    """
    try:
        ret = seafserv_threaded_rpc.create_repo(name, desc, user, passwd)
    except SearpcError, e:
        logger.error(e)
        ret = None
    return ret
    
def remove_repo(repo_id):
    """
    Return true if successfully removed a repo, otherwise false.
    """
    try:
        ret = seafserv_threaded_rpc.remove_repo(repo_id)
    except SearpcError, e:
        logger.error(e)
        ret = -1
    return True if ret == 0 else False

def list_personal_repos_by_owner(owner):
    """
    List users owned repos in personal context.
    """
    try:
        repos = seafserv_threaded_rpc.list_owned_repos(owner)
    except SearpcError:
        repos = []
    return repos

def get_repo_token_nonnull(repo_id, username):
    return seafserv_threaded_rpc.get_repo_token_nonnull (repo_id, username)

def get_repo_owner(repo_id):
    """
    Get owner of a repo.
    """
    try:
        ret = seafserv_threaded_rpc.get_repo_owner(repo_id)
    except SearpcError:
        ret = ''
    return ret
    
def is_repo_owner(user, repo_id):
    """
    Check whether user is repo owner.
    """
    try:
        ret = seafserv_threaded_rpc.is_repo_owner(user, repo_id)
    except SearpcError:
        ret = 0
    return ret

def server_repo_size(repo_id):
    try:
        size = seafserv_threaded_rpc.server_repo_size(repo_id)
    except SearpcError:
        size = 0
    return size

# org repo
def create_org_repo(repo_name, repo_desc, user, passwd, org_id):
    """
    Create org repo, return valid repo id if success.
    """
    try:
        repo_id = seafserv_threaded_rpc.create_org_repo(repo_name, repo_desc,
                                                        user, passwd, org_id)
    except SearpcError:
        repo_id = None
        
    return repo_id

def is_org_repo(repo_id):
    org_id = get_org_id_by_repo_id(repo_id)
    return True if org_id > 0 else False

def list_org_repos_by_owner(org_id, user):
    try:
        repos = seafserv_threaded_rpc.list_org_repos_by_owner(org_id, user)
    except SearpcError:
        repos = []
    return repos

def get_org_repos(org_id, start, limit):
    """
    List repos created in org.
    """
    try:
        repos = seafserv_threaded_rpc.get_org_repo_list(org_id, start, limit)
    except SearpcError:
        repos = []

    if repos:
        for r in repos:
            r.owner = get_org_repo_owner(r.id)
            
    return repos

def get_org_id_by_repo_id(repo_id):
    """
    Get org id according repo id.
    """
    try:
        org_id = seafserv_threaded_rpc.get_org_id_by_repo_id(repo_id)
    except SearpcError:
        org_id = -1
    return org_id

def is_org_repo_owner(org_id, repo_id, user):
    """
    Check whether user is org repo owner.
    NOTE:
    	`org_id` may used in future.
    """
    owner = get_org_repo_owner(repo_id)
    if not owner:
        return False 
    return True if owner == user else False

def get_org_repo_owner(repo_id):
    """
    Get owner of org repo.
    """
    try:
        owner = seafserv_threaded_rpc.get_org_repo_owner(repo_id)
    except SearpcError:
        owner = None
    return owner

# commit
def get_commit(repo_id, repo_version, cmt_id):
    """ Get a commit. """
    try:
        ret = seafserv_threaded_rpc.get_commit(repo_id, repo_version, cmt_id)
    except SearpcError:
        ret = None
    return ret
    
def get_commits(repo_id, offset, limit):
    """Get commit lists."""
    try:
        ret = seafserv_threaded_rpc.get_commit_list(repo_id, offset, limit)
    except SearpcError:
        ret = None
    return ret

# branch
def get_branches(repo_id):
    """Get branches of a given repo"""
    return seafserv_threaded_rpc.branch_gets(repo_id)

# group repo
def get_group_repos_by_owner(user):
    """
    List user's repos that are sharing to groups
    """
    try:
        ret = seafserv_threaded_rpc.get_group_repos_by_owner(user)
    except SearpcError:
        ret = []
    return ret

def get_shared_groups_by_repo(repo_id):
    try:
        group_ids = seafserv_threaded_rpc.get_shared_groups_by_repo(repo_id)
    except SearpcError:
        group_ids = ''
    if not group_ids:
        return []

    groups = []
    for group_id in group_ids.split('\n'):
        if not group_id:
            continue
        group = get_group(group_id)
        if group:
            groups.append(group)
    return groups

def conv_repoids_to_list(repo_ids):
    """
    Convert repo ids seperated by "\n" to list.
    """
    if not repo_ids:
        return []

    repoid_list = []
    for repo_id in repo_ids.split("\n"):
        if repo_id == '':
            continue
        repoid_list.append(repo_id)
    return repoid_list
    
def get_group_repoids(group_id):
    """Get repo ids of a given group id."""
    try:
        repo_ids = seafserv_threaded_rpc.get_group_repoids(group_id)
    except SearpcError:
        return []

    return conv_repoids_to_list(repo_ids)

def get_group_repos(group_id, user):
    """Get repos of a given group id."""
    repoid_list = get_group_repoids(group_id)

    repos = []
    for repo_id in repoid_list:
        if not repo_id:
            continue
        repo = get_repo(repo_id)
        if not repo:
            continue

        repo.owner = seafserv_threaded_rpc.get_group_repo_owner(repo_id)
        repo.share_from_me = True if user == repo.owner else False

        last_commit = get_commits(repo.id, 0, 1)[0]
        repo.latest_modify = last_commit.ctime if last_commit else None

        repos.append(repo)
    repos.sort(lambda x, y: cmp(y.latest_modify, x.latest_modify))
    
    return repos

# org group repo
def del_org_group_repo(repo_id, org_id, group_id):
    seafserv_threaded_rpc.del_org_group_repo(repo_id, org_id, group_id)

def get_org_group_repoids(org_id, group_id):
    try:
        repo_ids = seafserv_threaded_rpc.get_org_group_repoids(org_id, group_id)
    except SearpcError:
        repo_ids = ''

    return conv_repoids_to_list(repo_ids)

def get_org_group_repos(org_id, group_id, user):
    """Get org repos of a given group id."""
    repoid_list = get_org_group_repoids(org_id, group_id)
    if not repoid_list:
        return []
    
    repos = []
    for repo_id in repoid_list:
        if not repo_id:
            continue
        repo = get_repo(repo_id)
        if not repo:
            continue

        repo.owner = seafserv_threaded_rpc.get_org_group_repo_owner(org_id,
                                                                    group_id,
                                                                    repo_id)
        repo.sharecd_from_me = True if user == repo.owner else False

        last_commit = get_commits(repo.id, 0, 1)[0]
        repo.latest_modify = last_commit.ctime if last_commit else None

        repos.append(repo)
    repos.sort(lambda x, y: cmp(y.latest_modify, x.latest_modify))
    
    return repos

def get_org_groups_by_repo(org_id, repo_id):
    try:
        group_ids = seafserv_threaded_rpc.get_org_groups_by_repo(org_id,
                                                                 repo_id)
    except SearpcError:
        group_ids = ''
    if not group_ids:
        return []

    groups = []
    for group_id in group_ids.split('\n'):
        if not group_id:
            continue
        group = get_group(group_id)
        if group:
            groups.append(group)
    return groups
    
# inner pub repo
def list_inner_pub_repos_by_owner(user):
    """
    List a user's inner pub repos.
    """
    try:
        ret = seafserv_threaded_rpc.list_inner_pub_repos_by_owner(user)
    except SearpcError:
        ret = []
    return ret

def list_inner_pub_repos(username):
    """
    List inner pub repos, which can be access by everyone.
    """
    try:
        shared_repos = seafserv_threaded_rpc.list_inner_pub_repos()
    except:
        shared_repos = []

    for repo in shared_repos:
        repo.user_perm = check_permission(repo.props.repo_id, username)

    shared_repos.sort(lambda x, y: cmp(y.props.last_modified, x.props.last_modified))
    return shared_repos

def count_inner_pub_repos():
    try:
        ret = seafserv_threaded_rpc.count_inner_pub_repos()
    except SearpcError:
        ret = -1
    return 0 if ret < 0 else ret

def is_inner_pub_repo(repo_id):
    """
    Check whether a repo is public.
    Return 0 if repo is not inner public, otherwise non-zero.
    """
    try:
        ret = seafserv_threaded_rpc.is_inner_pub_repo(repo_id)
    except SearpcError:
        ret = 0

    return ret

def unset_inner_pub_repo(repo_id):
    seafserv_threaded_rpc.unset_inner_pub_repo(repo_id)
        
# org inner pub repo
def list_org_inner_pub_repos(org_id, username, start=None, limit=None):
    """
    List org inner pub repos, which can be access by all org members.
    """
    try:
        shared_repos = seafserv_threaded_rpc.list_org_inner_pub_repos(org_id)
    except SearpcError:
        shared_repos = []

    for repo in shared_repos:
        repo.user_perm = check_permission(repo.props.repo_id, username)

    # sort repos by last modify time
    shared_repos.sort(lambda x, y: cmp(y.props.last_modified, x.props.last_modified))
    return shared_repos

# repo permissoin
def check_permission(repo_id, user):
    """
    Check whether user has permission to access repo.
    Return values can be 'rw' or 'r' or None.
    """
    try:
        ret = seafserv_threaded_rpc.check_permission(repo_id, user)
    except SearpcError:
        ret = None
    return ret

def is_personal_repo(repo_id):
    """
    Check whether repo is personal repo.
    """
    try:
        owner = seafserv_threaded_rpc.get_repo_owner(repo_id)
    except SearpcError:
        owner = ''
    return True if owner else False

# shared repo
def list_share_repos(user, share_type, start, limit):
    try:
        ret = seafserv_threaded_rpc.list_share_repos(user, share_type,
                                                     start, limit)
    except SearpcError:
        ret = []
    return ret

def remove_share(repo_id, from_user, to_user):
    seafserv_threaded_rpc.remove_share(repo_id, from_user, to_user)

def unshare_group_repo(repo_id, group_id, from_user):
    return seafserv_threaded_rpc.group_unshare_repo(repo_id, int(group_id),
                                                    from_user)
        
def list_personal_shared_repos(user, user_type, start, limit):
    """
    List personal repos that user share with others.
    If `user_type` is 'from_email', list repos user shares to others;
    If `user_type` is 'to_email', list repos others share to user.
    """
    share_repos = list_share_repos(user, user_type, start, limit)
    for repo in share_repos:
        repo.user_perm = check_permission(repo.props.repo_id, user)

    share_repos.sort(lambda x, y: cmp(y.last_modified, x.last_modified))
    return share_repos

def list_org_shared_repos(org_id, user, user_type, start, limit):
    """
    List org repos that user share with others.
    If `user_type` is 'from_email', list repos user shares to others;
    If `user_type` is 'to_email', list repos others sahre to user.
    """
    try:
        share_repos = seafserv_threaded_rpc.list_org_share_repos(org_id,
                                                                 user, user_type,
                                                                 start, limit)
    except SearpcError:
        share_repos = []

    for repo in share_repos:
        repo.user_perm = check_permission(repo.props.repo_id, user)

    share_repos.sort(lambda x, y: cmp(y.last_modified, x.last_modified))
    return share_repos

# dir
def list_dir_by_path(repo_id, commit_id, path):
    try:
        ret = seafserv_threaded_rpc.list_dir_by_path(repo_id, commit_id, path)
    except SearpcError:
        ret = None
    return ret

# file
def post_empty_file(repo_id, parent_dir, file_name, user):
    """
    Return true if successfully make a new file, otherwise false.
    """
    try:
        ret = seafserv_threaded_rpc.post_empty_file(repo_id, parent_dir,
                                              file_name, user)
    except SearpcError, e:
        logger.error(e)
        ret = -1
    return True if ret == 0 else False

def del_file(repo_id, parent_dir, file_name, user):
    """
    Return true if successfully delete a file, otherwise false.
    """
    try:
        ret = seafserv_threaded_rpc.del_file(repo_id, parent_dir,
                                             file_name, user)
    except SearpcError, e:
        logger.error(e)
        ret = -1
    return True if ret == 0 else False

# misc functions
def is_valid_filename(file_or_dir):
    """
    Check whether file name or directory name is valid.
    """
    try:
        ret = seafserv_threaded_rpc.is_valid_filename('', file_or_dir)
    except SearpcError:
        ret = 0

    return ret

def get_file_size(store_id, version, file_id):
    try:
        fs = seafserv_threaded_rpc.get_file_size(store_id, version, file_id)
    except SearpcError, e:
        fs = 0
    return fs

def get_file_id_by_path(repo_id, path):
    try:
        ret = seafserv_threaded_rpc.get_file_id_by_path(repo_id, path)
    except SearpcError, e:
        ret = ''
    return ret

def get_related_users_by_repo(repo_id):
    """Give a repo id, returns a list of users of:
    - the repo owner
    - members of groups to which the repo is shared
    - users to which the repo is shared
    """
    owner = seafserv_threaded_rpc.get_repo_owner(repo_id)
    if not owner:
        # Can't happen
        return []

    users = [owner]

    groups = get_shared_groups_by_repo(repo_id)

    for group in groups:
        members = get_group_members(group.id)
        for member in members:
            if member.user_name not in users:
                users.append(member.user_name)

    share_repos = list_share_repos(owner, 'from_email', -1, -1)
    for repo in share_repos:
        if repo.repo_id == repo_id:
            if repo.user not in users:
                users.append(repo.user)

    return users

def get_related_users_by_org_repo(org_id, repo_id):
    """Org version of get_related_users_by_repo
    """
    owner = get_org_repo_owner(repo_id)

    if not owner:
        # Can't happen
        return []

    users = [owner]

    groups = get_org_groups_by_repo(org_id, repo_id)

    for group in groups:
        members = get_group_members(group.id)
        for member in members:
            if member.user_name not in users:
                users.append(member.user_name)

    share_repos = seafserv_threaded_rpc.list_org_share_repos(org_id, \
                                        owner, 'from_email', -1, -1)

    for repo in share_repos:
        if repo.repo_id == repo_id:
            if repo.user not in users:
                users.append(repo.user)

    return users

# quota
def check_quota(repo_id):
    try:
        ret = seafserv_threaded_rpc.check_quota(repo_id)
    except SearpcError, e:
        logger.error(e)
        ret = -1
    return ret

def get_user_quota(user):
    try:
        ret = seafserv_threaded_rpc.get_user_quota(user)
    except SearpcError, e:
        logger.error(e)
        ret = 0
    return ret

def get_user_quota_usage(user):
    try:
        ret = seafserv_threaded_rpc.get_user_quota_usage(user)
    except SearpcError, e:
        logger.error(e)
        ret = 0
    return ret

def get_user_share_usage(user):
    try:
        ret = seafserv_threaded_rpc.get_user_share_usage(user)
    except SearpcError, e:
        logger.error(e)
        ret = 0
    return ret
    
# access token
def web_get_access_token(repo_id, obj_id, op, username):
    try:
        ret = seafserv_rpc.web_get_access_token(repo_id, obj_id, op, username)
    except SearpcError, e:
        ret = ''
    return ret
    
# password management
def unset_repo_passwd(repo_id, user):
    """
    Remove user password of a encrypt repo.
    Arguments:
    - `repo_id`: encrypt repo id
    - `user`: username
    """
    try:
        ret = seafserv_threaded_rpc.unset_passwd(repo_id, user)
    except SearpcError, e:
        ret = -1
    return ret

def is_passwd_set(repo_id, user):
    try:
        ret = seafserv_rpc.is_passwd_set(repo_id, user)
    except SearpcError, e:
        ret = -1
    return True if ret == 1 else False

# repo history limit
def get_repo_history_limit(repo_id):
    try:
        ret = seafserv_threaded_rpc.get_repo_history_limit(repo_id)
    except SearpcError, e:
        ret = -1
    return ret

def set_repo_history_limit(repo_id, days):
    try:
        ret = seafserv_threaded_rpc.set_repo_history_limit(repo_id, days)
    except SearpcError, e:
        ret = -1
    return ret
