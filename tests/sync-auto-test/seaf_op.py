'''

seaf-cli is command line interface for seafile client.

Subcommands:

    init:           create config files for seafile client
    start:          start and run seafile client as daemon
    stop:           stop seafile client
    list:           list local liraries
    status:         show syncing status
    download:       download a library from seafile server
    sync:           synchronize an existing folder with a library in
                        seafile server
    desync:         desynchronize a library with seafile server
    create:         create a new library


Detail
======

Seafile client stores all its configure information in a config dir. The default location is `~/.ccnet`. All the commands below accept an option `-c <config-dir>`.

init
----
Initialize seafile client. This command initializes the config dir. It also creates sub-directories `seafile-data` and `seafile` under `parent-dir`. `seafile-data` is used to store internal data, while `seafile` is used as the default location put downloaded libraries.

    seaf-cli init [-c <config-dir>] -d <parent-dir>

start
-----
Start seafile client. This command start `ccnet` and `seaf-daemon`, `ccnet` is the network part of seafile client, `seaf-daemon` manages the files.

    seaf-cli start [-c <config-dir>]

stop
----
Stop seafile client.

    seaf-cli stop [-c <config-dir>]


Download
--------
Download a library from seafile server

    seaf-cli download -l <library-id> -s <seahub-server-url> -d <parent-directory> -u <username> -p <password>


sync
----
Synchronize a library with an existing folder.

    seaf-cli sync -l <library-id> -s <seahub-server-url> -d <existing-folder> -u <username> -p <password>

desync
------
Desynchronize a library from seafile server

    seaf-cli desync -d <existing-folder>

create
------
Create a new library

    seaf-cli create -s <seahub-server-url> -n <library-name> -u <username> -p <password> -t <description> [-e <library-password>]

'''

import os
import json
import subprocess
import sys
import time
import urllib
import urllib2
import httplib
from urlparse import urlparse

import ccnet
import seafile

def _check_seafile():
    ''' Check ccnet and seafile have been installed '''

    sep = ':' if os.name != 'nt' else ';'
    dirs = os.environ['PATH'].split(sep)
    def exist_in_path(prog):
        ''' Check whether 'prog' exists in system path '''
        for d in dirs:
            if d == '':
                continue
            path = os.path.join(d, prog)
            if os.path.exists(path):
                return True

    progs = [ 'ccnet', 'seaf-daemon' ]

    for prog in progs:
        if os.name == 'nt':
            prog += '.exe'
        if not exist_in_path(prog):
            print "%s not found in PATH. Have you installed seafile?" % prog
            sys.exit(1)

def run_argv(argv, cwd=None, env=None, suppress_stdout=False, suppress_stderr=False, wait=True):
    '''Run a program and wait it to finish, and return its exit code. The
    standard output of this program is supressed.

    '''
    with open(os.devnull, 'w') as devnull:
        if suppress_stdout:
            stdout = devnull
        else:
            stdout = sys.stdout

        if suppress_stderr:
            stderr = devnull
        else:
            stderr = sys.stderr

        proc = subprocess.Popen(argv,
                                cwd=cwd,
                                stdout=stdout,
                                stderr=stderr,
                                env=env)
        if wait:
            return proc.wait()
        return 0

def get_env():
    env = dict(os.environ)
    ld_library_path = os.environ.get('SEAFILE_LD_LIBRARY_PATH', '')
    if ld_library_path:
        env['LD_LIBRARY_PATH'] = ld_library_path

    return env

class NoRedirect(urllib2.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, hdrs, newurl):
        pass

def urlopen(url, data=None, headers=None, follow_redirect=True):
    if data:
        data = urllib.urlencode(data)
    headers = headers or {}
    req = urllib2.Request(url, data=data, headers=headers)
    if follow_redirect:
        resp = urllib2.urlopen(req)
    else:
        try:
            opener = urllib2.build_opener(NoRedirect())
            resp = opener.open(req)
        except urllib2.HTTPError:
            return None
    return resp.read()

def get_token(url, username, password):
    data = {
        'username': username,
        'password': password,
    }
    token_json = urlopen("%s/api2/auth-token/" % url, data=data)
    tmp = json.loads(token_json)
    token = tmp['token']
    return token

def get_repo_downlod_info(url, token):
    headers = { 'Authorization': 'Token %s' % token }
    repo_info = urlopen(url, headers=headers)
    return json.loads(repo_info)

def seaf_init(conf_dir):
    ''' initialize config directorys'''

    _check_seafile()

    seafile_ini = os.path.join(conf_dir, "seafile.ini")
    seafile_data = os.path.join(conf_dir, "seafile-data")
    fp = open(seafile_ini, 'w')
    fp.write(seafile_data)
    fp.close()

    print 'Init ccnet config success.'

def seaf_start_all(conf_dir):
    ''' start ccnet and seafile daemon '''

    seaf_start_ccnet(conf_dir)
    # wait ccnet process
    time.sleep(1)
    seaf_start_seafile(conf_dir)

    print 'Start ccnet, seafile daemon success.'

def seaf_start_ccnet(conf_dir):
    ''' start ccnet daemon '''

    cmd = [ "ccnet", "--daemon", "-c", conf_dir ]
    wait = False if os.name == 'nt' else True
    if run_argv(cmd, env=get_env(), suppress_stdout=True, wait=wait) != 0:
        print 'Failed to start ccnet daemon.'
        sys.exit(1)

def seaf_start_seafile(conf_dir):
    ''' start seafile daemon '''

    cmd = [ "seaf-daemon", "--daemon", "-c", conf_dir,
            "-d", os.path.join(conf_dir, 'seafile-data'),
            "-w", os.path.join(conf_dir, 'seafile') ]
    wait = False if os.name == 'nt' else True
    if run_argv(cmd, env=get_env(), suppress_stdout=True, wait=wait) != 0:
        print 'Failed to start seafile daemon'
        sys.exit(1)

def seaf_stop(conf_dir):
    '''stop seafile daemon '''

    pool = ccnet.ClientPool(conf_dir)
    client = pool.get_client()
    try:
        client.send_cmd("shutdown")
    except:
        # ignore NetworkError("Failed to read from socket")
        pass

    print 'Stop ccnet, seafile daemon success.'

def get_base_url(url):
    parse_result = urlparse(url)
    scheme = parse_result.scheme
    netloc = parse_result.netloc

    if scheme and netloc:
        return '%s://%s' % (scheme, netloc)

    return None

def get_netloc(url):
    parse_result = urlparse(url)
    return parse_result.netloc

def seaf_sync(conf_dir, server_url, repo_id, worktree, username, passwd):
    ''' synchronize a library from seafile server '''

    pool = ccnet.ClientPool(conf_dir)
    seafile_rpc = seafile.RpcClient(pool, req_pool=False)

    token = get_token(server_url, username, passwd)
    tmp = get_repo_downlod_info("%s/api2/repos/%s/download-info/" % (server_url, repo_id), token)

    encrypted = tmp['encrypted']
    magic = tmp.get('magic', None)
    enc_version = tmp.get('enc_version', None)
    random_key = tmp.get('random_key', None)

    clone_token = tmp['token']
    relay_id = tmp['relay_id']
    relay_addr = tmp['relay_addr']
    relay_port = str(tmp['relay_port'])
    email = tmp['email']
    repo_name = tmp['repo_name']
    version = tmp.get('repo_version', 0)

    more_info = None
    base_url = get_base_url(server_url)
    if base_url:
        more_info = json.dumps({'server_url': base_url})

    if encrypted == 1:
        repo_passwd = 's123'
    else:
        repo_passwd = None

    seafile_rpc.clone(repo_id,
                      version,
                      relay_id,
                      repo_name.encode('utf-8'),
                      worktree,
                      clone_token,
                      repo_passwd, magic,
                      relay_addr,
                      relay_port,
                      email, random_key, enc_version, more_info)

    print 'Synchronize repo test success.'

def seaf_desync(conf_dir, repo_path):
    '''Desynchronize a library from seafile server'''

    pool = ccnet.ClientPool(conf_dir)
    seafile_rpc = seafile.RpcClient(pool, req_pool=False)

    repos = seafile_rpc.get_repo_list(-1, -1)
    repo = None
    for r in repos:
        if r.worktree.replace('/', '\\') == repo_path.decode('utf-8').replace('/', '\\'):
            repo = r
            break

    if repo:
        print "Desynchronize repo test success."
        seafile_rpc.remove_repo(repo.id)
    else:
        print "%s is not a library worktree" % repo_path

def seaf_create(conf_dir, server_url, username, passwd, enc_repo):
    '''Create a library'''

    # curl -d 'username=<USERNAME>&password=<PASSWORD>' http://127.0.0.1:8000/api2/auth-token
    token = get_token(server_url, username, passwd)

    headers = { 'Authorization': 'Token %s' % token }
    data = {
        'name': 'test',
        'desc': 'test',
    }
    if enc_repo:
        data['passwd'] = 's123'

    repo_info_json =  urlopen("%s/api2/repos/" % server_url, data=data, headers=headers)
    repo_info = json.loads(repo_info_json)

    if enc_repo:
        print 'Create encrypted repo test success.'
    else:
        print 'Create non encrypted repo test success.'

    return repo_info['repo_id']

def seaf_delete(conf_dir, server_url, username, passwd, repo_id):
    '''Delete a library'''

    token = get_token(server_url, username, passwd)
    headers = { 'Authorization': 'Token %s' % token }

    conn = httplib.HTTPConnection(get_netloc(server_url))
    conn.request('DELETE', '/api2/repos/%s/' % repo_id, None, headers)
    resp = conn.getresponse()
    if resp.status == 200:
        print 'Delete repo test success.'
    else:
        print 'Delete repo test failed: %s.' % resp.reason

def seaf_get_repo(conf_dir, repo_id):
    pool = ccnet.ClientPool(conf_dir)
    seafile_rpc = seafile.RpcClient(pool, req_pool=False)
    return seafile_rpc.seafile_get_repo(repo_id)
