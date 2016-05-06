#!/usr/bin/env python
#coding: UTF-8

import os
from os.path import abspath, basename, exists, dirname, join
import sys
import argparse
import re
from collections import namedtuple

import requests
from pexpect import spawn

from utils import green, red, debug, info, warning, cd, shell, chdir, setup_logging

USERNAME = 'test@seafiletest.com'
PASSWORD = 'testtest'
ADMIN_USERNAME = 'admin@seafiletest.com'
ADMIN_PASSWORD = 'adminadmin'
MYSQL_ROOT_PASSWD = 's123'

ServerConfig = namedtuple('ServerConfig', [
    'installdir',
    'tarball',
    'version',
    'initmode',
])


def setup_server(cfg, db):
    '''Setup seafile server with the setup-seafile.sh script. We use pexpect to
    interactive with the setup process of the script.
    '''
    info('uncompressing server tarball')
    shell('tar xf seafile-server_{}_x86-64.tar.gz -C {}'
          .format(cfg.version, cfg.installdir))
    if db == 'mysql':
        autosetup_mysql(cfg)
    else:
        autosetup_sqlite3(cfg)

    with open(join(cfg.installdir, 'conf/seahub_settings.py'), 'a') as fp:
        fp.write('\n')
        fp.write('DEBUG = True')
        fp.write('\n')
        fp.write('''\
REST_FRAMEWORK = {
    'DEFAULT_THROTTLE_RATES': {
        'ping': '600/minute',
        'anon': '1000/minute',
        'user': '1000/minute',
    },
}''')
        fp.write('\n')


def autosetup_sqlite3(cfg):
    setup_script = get_script(cfg, 'setup-seafile.sh')
    shell('''sed -i -e '/^check_root;.*/d' "{}"'''.format(setup_script))

    if cfg.initmode == 'prompt':
        setup_sqlite3_prompt(setup_script)
    else:
        setup_sqlite3_auto(setup_script)

def setup_sqlite3_prompt(setup_script):
    info('setting up seafile server with pexepct, script %s', setup_script)
    answers = [
        ('ENTER', ''),
        # server name
        ('server name', 'my-seafile'),
        # ip or domain
        ('ip or domain', '127.0.0.1'),
        # seafile data dir
        ('seafile-data', ''),
        # fileserver port
        ('seafile fileserver', ''),
        ('ENTER', ''),
        ('ENTER', ''),
    ]
    _answer_questions(setup_script, answers)

def setup_sqlite3_auto(setup_script):
    info('setting up seafile server in auto mode, script %s', setup_script)
    env = os.environ.copy()
    env['SERVER_IP'] = '127.0.0.1'
    shell('%s auto -n my-seafile' % setup_script, env=env)

def createdbs():
    sql = '''\
create database `ccnet-existing` character set = 'utf8';
create database `seafile-existing` character set = 'utf8';
create database `seahub-existing` character set = 'utf8';

create user 'seafile'@'localhost' identified by 'seafile';

GRANT ALL PRIVILEGES ON `ccnet-existing`.* to `seafile`@localhost;
GRANT ALL PRIVILEGES ON `seafile-existing`.* to `seafile`@localhost;
GRANT ALL PRIVILEGES ON `seahub-existing`.* to `seafile`@localhost;
    '''

    shell('mysql -u root -p%s' % MYSQL_ROOT_PASSWD, inputdata=sql)


def autosetup_mysql(cfg):
    setup_script = get_script(cfg, 'setup-seafile-mysql.sh')
    if not exists(setup_script):
        print 'please specify seafile script path'

    if cfg.initmode == 'prompt':
        createdbs()
        setup_mysql_prompt(setup_script)
    else :
        # in auto mode, test create new db
        setup_mysql_auto(setup_script)

def setup_mysql_prompt(setup_script):
    info('setting up seafile server with pexepct, script %s', setup_script)
    answers = [
        ('ENTER', ''),
        # server name
        ('server name', 'my-seafile'),
        # ip or domain
        ('ip or domain', '127.0.0.1'),
        # seafile data dir
        ('seafile-data', ''),
        # fileserver port
        ('seafile fileserver', ''),
        # use existing
        ('choose a way to initialize seafile databases', '2'),
        ('host of mysql server', ''),
        ('port of mysql server', ''),
        ('Which mysql user', 'seafile'),
        ('password for mysql user', 'seafile'),
        ('ccnet database', 'ccnet-existing'),
        ('seafile database', 'seafile-existing'),
        ('seahub database', 'seahub-existing'),
        ('ENTER', ''),
    ]
    _answer_questions(abspath(setup_script), answers)

def setup_mysql_auto(setup_script):
    info('setting up seafile server in auto mode, script %s', setup_script)
    env = os.environ.copy()
    env['MYSQL_USER'] = 'seafile-new'
    env['MYSQL_USER_PASSWD'] = 'seafile'
    env['MYSQL_ROOT_PASSWD']= MYSQL_ROOT_PASSWD
    env['CCNET_DB'] = 'ccnet-new'
    env['SEAFILE_DB'] = 'seafile-new'
    env['SEAHUB_DB'] = 'seahub-new'
    shell('%s auto -n my-seafile -e 0' % setup_script, env=env)

def start_server(cfg):
    with cd(cfg.installdir):
        shell('find . -maxdepth 2 | sort | xargs ls -lhd')
    seafile_sh = get_script(cfg, 'seafile.sh')
    shell('{} start'.format(seafile_sh))

    info('starting seahub')
    seahub_sh = get_script(cfg, 'seahub.sh')
    answers = [
        # admin email/pass
        ('admin email', ADMIN_USERNAME),
        ('admin password', ADMIN_PASSWORD),
        ('admin password again', ADMIN_PASSWORD),
    ]
    _answer_questions('{} start'.format(abspath(seahub_sh)), answers)
    with cd(cfg.installdir):
        shell('find . -maxdepth 2 | sort | xargs ls -lhd')
    # shell('sqlite3 ccnet/PeerMgr/usermgr.db "select * from EmailUser"', cwd=INSTALLDIR)
    shell('http -v localhost:8000/api2/server-info/ || true')
    # shell('http -v -f POST localhost:8000/api2/auth-token/ username=admin@seafiletest.com password=adminadmin || true')
    shell('netstat -nltp')


def _answer_questions(cmd, answers):
    info('expect: spawing %s', cmd)
    child = spawn(cmd)
    child.logfile = sys.stdout

    def autofill(pattern, line):
        child.expect(pattern)
        child.sendline(line)

    for k, v in answers:
        autofill(k, v)
    child.sendline('')
    child.logfile = None
    child.interact()


def get_script(cfg, path):
    """
    :type cfg: ServerConfig
    """
    return join(server_dir(cfg), path)


def server_dir(cfg):
    """
    :type cfg: ServerConfig
    """
    return join(cfg.installdir, 'seafile-server-{}'.format(cfg.version))


def apiurl(path):
    path = path.lstrip('/')
    root = os.environ.get('SEAFILE_SERVER', 'http://127.0.0.1:8000')
    return '{}/api2/{}'.format(root, path)


def create_test_user(cfg):
    data = {'username': ADMIN_USERNAME, 'password': ADMIN_PASSWORD, }
    res = requests.post(apiurl('/auth-token/'), data=data)
    debug('%s %s', res.status_code, res.text)
    token = res.json()['token']
    data = {'password': PASSWORD, }
    headers = {'Authorization': 'Token ' + token}
    res = requests.put(
        apiurl('/accounts/{}/'.format(USERNAME)),
        data=data,
        headers=headers)
    assert res.status_code == 201


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('-v', '--verbose', action='store_true')
    ap.add_argument('--db', choices=('sqlite3', 'mysql'), default='sqlite3')
    ap.add_argument('installdir')
    ap.add_argument('tarball')
    args = ap.parse_args()

    if not exists(args.installdir):
        print 'directory {} does not exist'.format(args.installdir)
        sys.exit(1)

    if os.listdir(args.installdir):
        print 'directory {} is not empty'.format(args.installdir)
        sys.exit(1)

    if not exists(args.tarball):
        print 'file {} does not exist'.format(args.tarball)
        sys.exit(1)

    m = re.match(r'^.*?_([\d\.]+).*?\.tar\.gz$', basename(args.tarball))
    version = m.group(1)

    cfg = ServerConfig(installdir=args.installdir,
                       tarball=args.tarball,
                       version=version)
    setup_server(cfg, args.db)
    start_server(cfg)
    create_test_user(cfg)


if __name__ == '__main__':
    setup_logging()
    main()
