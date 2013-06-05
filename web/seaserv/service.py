"""
Peer:
    peer.props.id:           Peer's ID.
    peer.props.name          peer's name
    peer.props.user_id       The ID of the user this peer belong to.
    peer.props.timestamp     Last modification time in milliseconds.
    peer.props.role_list     The roles I give to this peer's user.
    peer.props.myrole_list   This roles this peer's user gives to me.

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


Task:
    tx_id
    ttype
    repo_id
    from_branch
    to_branch
    state
    rt_state
    error_str
    block_total
    block_done
    rate

"""


import os
import sys

import ccnet
import seafile
from appletRpc import AppletRpcClient
from pysearpc import SearpcError

if sys.platform == 'darwin' and 'LANG' not in os.environ:
    os.environ['LANG'] = 'en_US.UTF-8'
    os.environ['LC_ALL'] = 'en_US.UTF-8'

if 'win32' in sys.platform:
    DEFAULT_CCNET_CONF_PATH = '~/ccnet'
    
    import ctypes
    def _getenv_u(name):
        '''Return the value of environment variable in unicode. The param
        'name' must be in unicode

        '''
        n= ctypes.windll.kernel32.GetEnvironmentVariableW(name, None, 0)
        if n == 0:
            return None
        buf = ctypes.create_unicode_buffer(u'\0' * n)
        ctypes.windll.kernel32.GetEnvironmentVariableW(name, buf, n)
        return buf.value
        
    if 'CCNET_CONF_DIR' in os.environ:
        CCNET_CONF_PATH = _getenv_u(u'CCNET_CONF_DIR').encode('UTF-8')
    else:
        CCNET_CONF_PATH = DEFAULT_CCNET_CONF_PATH
else:
    # Linux and MacOS
    DEFAULT_CCNET_CONF_PATH = '~/.ccnet'
    if 'CCNET_CONF_DIR' in os.environ:
        CCNET_CONF_PATH = os.environ['CCNET_CONF_DIR']
    else:
        CCNET_CONF_PATH = DEFAULT_CCNET_CONF_PATH

# Now CCNET_CONF_PATH is in UTF-8
# We process it and make it unicode
CCNET_CONF_PATH = os.path.normpath(os.path.expanduser(CCNET_CONF_PATH)).decode('UTF-8')

print u'Load config from ' + CCNET_CONF_PATH

pool = ccnet.ClientPool(CCNET_CONF_PATH.encode('utf-8'))
ccnet_rpc = ccnet.CcnetRpcClient(pool, req_pool=True)
applet_rpc = AppletRpcClient(pool, req_pool=True)
seafile_rpc = seafile.RpcClient(pool, req_pool=True)
seafile_threaded_rpc = seafile.ThreadedRpcClient(pool)
monitor_rpc = seafile.MonitorRpcClient(pool)
    

#### Basic ccnet API ####

def get_peers_by_role(role):    
    return ccnet_rpc.get_peers_by_role(role)

def get_peers():
    peer_ids = ccnet_rpc.list_peers()
    if not peer_ids:
        return []
    peers = []
    for peer_id in peer_ids.split("\n"):
        # too handle the ending '\n'
        if peer_id == '':
            continue
        peer = ccnet_rpc.get_peer(peer_id)
        peers.append(peer)
    return peers


def send_command(command):
    client = pool.get_client()
    client.send_cmd(command)
    ret = client.response[2]
    pool.return_client(client)
    return ret

def get_ccnet_config(key, default_value):
    value = ccnet_rpc.get_config(key)
    if value is None:
        return default_value
    else:
        return value


######## seafile API ####

def get_repos():
    """
    Return repository list.

    """
    return seafile_rpc.get_repo_list(-1, -1)

def get_repo(repo_id):
    return seafile_rpc.get_repo(repo_id)

def get_commits(repo_id, offset, limit):
    """Get commit lists."""
    return seafile_rpc.get_commit_list(repo_id, offset, limit)


def checkout(repo_id, commit_id):
    return seafile_rpc.checkout(repo_id, commit_id)

def get_branches(repo_id):
    """Get branches of a given repo"""
    return seafile_rpc.branch_gets(repo_id)

def get_diff(repo_id, arg1, arg2):

    # New Removed Renamed Modified Newdir Deldir
    lists = ([], [], [], [], [], [])

    diff_result = seafile_rpc.get_diff(repo_id, arg1, arg2)
    if not diff_result:
        return lists

    for d in diff_result:
        if d.status == "add":
            lists[0].append(d.name)
        elif d.status == "del":
            lists[1].append(d.name)
        elif d.status == "mov":
            lists[2].append(d.name + " ==> " + d.new_name)
        elif d.status == "mod":
            lists[3].append(d.name)
        elif d.status == "newdir":
            lists[4].append(d.name)
        elif d.status == "deldir":
            lists[5].append(d.name)

    return lists

def list_dir(root_id):
    dirent_list = seafile_rpc.list_dir(root_id);

    return dirent_list


######## ccnet-applet API #####
class CcnetError(Exception):

    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return self.msg


def open_dir(path):
     """Call remote service `opendir`."""
     client = pool.get_client()
     req_id = client.get_request_id()
     req = "applet-opendir " + os.path.normpath(path)
     client.send_request(req_id, req)
     if client.read_response() < 0:
         raise CcnetError("Read response error")
     
     rsp = client.response
     pool.return_client(client)
     if rsp[0] != "200":
         raise CcnetError("Error received: %s %s" % (rsp[0], rsp[1]))
         
def get_default_relay():
    relay_id = ccnet_rpc.get_session_info().props.default_relay
    if not relay_id:
        return None
    return ccnet_rpc.get_peer(relay_id)

def remove_repos_on_relay(relay_id):
    """remove all repos on this relay"""
    for repo in get_repos():
        if repo.relay_id == relay_id:
            seafile_rpc.remove_repo(repo.id)
            
def get_default_seafile_worktree():
    """get seaf-daemon default worktree"""
    wt = seafile_rpc.get_config("wktree")
    return wt.rstrip('/\\').replace('/\\', os.path.sep)

def get_seafile_config(key, default_value):
    value = seafile_rpc.get_config(key)
    if value is None:
        seafile_rpc.set_config(key, default_value)
        return default_value
    else:
        return value

def get_seafile_config_int(key, default_value):
    try:
        value = seafile_rpc.get_config_int(key)
    except SearpcError, e:
        return default_value
    return value/1024

def get_current_prefs():
    """returns a dict contains current configs
    """
    prefs = {}
    prefs['notify_sync'] = get_seafile_config('notify_sync', 'on')
    prefs['auto_start'] = 'on' if applet_rpc.get_auto_start() == 1 else 'off'
    prefs['encrypt_channel'] = get_ccnet_config('encrypt_channel', 'off')
    prefs['upload_limit'] = get_seafile_config_int('upload_limit', 0)
    prefs['download_limit'] = get_seafile_config_int('download_limit', 0)
    return prefs
