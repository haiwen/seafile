#!/usr/bin/env python

import os
from os.path import abspath, basename, exists, expanduser, join
import sys
import re
import glob
import json
import logging
import requests

import termcolor
from pexpect import spawn
from utils import green, red, debug, info, warning, cd, shell, chdir, setup_logging
from autosetup import (setup_server, ServerConfig, get_script, server_dir,
                       start_server, create_test_user, MYSQL_ROOT_PASSWD)

TOPDIR = abspath(join(os.getcwd(), '..'))
PREFIX = expanduser('~/opt/local')
SRCDIR = '/tmp/src'
INSTALLDIR = '/tmp/haiwen'
THIRDPARTDIR = expanduser('~/thirdpart')

logger = logging.getLogger(__file__)
seafile_version = ''

TRAVIS_BRANCH = os.environ.get('TRAVIS_BRANCH', 'master')


def make_build_env():
    env = dict(os.environ)
    libsearpc_dir = abspath(join(TOPDIR, 'libsearpc'))
    ccnet_dir = abspath(join(TOPDIR, 'ccnet'))

    def _env_add(*a, **kw):
        kw['env'] = env
        return prepend_env_value(*a, **kw)

    _env_add('CPPFLAGS', '-I%s' % join(PREFIX, 'include'), seperator=' ')

    _env_add('LDFLAGS', '-L%s' % os.path.join(PREFIX, 'lib'), seperator=' ')

    _env_add('LDFLAGS', '-L%s' % os.path.join(PREFIX, 'lib64'), seperator=' ')

    _env_add('PATH', os.path.join(PREFIX, 'bin'))
    _env_add('PATH', THIRDPARTDIR)
    _env_add('PKG_CONFIG_PATH', os.path.join(PREFIX, 'lib', 'pkgconfig'))
    _env_add('PKG_CONFIG_PATH', os.path.join(PREFIX, 'lib64', 'pkgconfig'))
    _env_add('PKG_CONFIG_PATH', libsearpc_dir)
    _env_add('PKG_CONFIG_PATH', ccnet_dir)

    for key in ('PATH', 'PKG_CONFIG_PATH', 'CPPFLAGS', 'LDFLAGS',
                'PYTHONPATH'):
        info('%s: %s', key, env.get(key, ''))
    return env


def prepend_env_value(name, value, seperator=':', env=None):
    '''append a new value to a list'''
    env = env or os.environ
    current_value = env.get(name, '')
    new_value = value
    if current_value:
        new_value += seperator + current_value

    env[name] = new_value
    return env


def get_project_branch(project, default_branch='master'):
    if project.name == 'seafile':
        return TRAVIS_BRANCH
    conf = json.loads(requests.get(
        'https://raw.githubusercontent.com/haiwen/seafile-test-deploy/master/branches.json').text)
    return conf.get(TRAVIS_BRANCH, {}).get(project.name,
                                           default_branch)


class Project(object):
    configure_cmd = './configure'

    def __init__(self, name):
        self.name = name
        self.version = ''

    @property
    def url(self):
        return 'https://www.github.com/haiwen/{}.git'.format(self.name)

    @property
    def projectdir(self):
        return join(TOPDIR, self.name)

    @property
    def branch(self):
        return get_project_branch(self)

    def clone(self):
        if exists(self.name):
            with cd(self.name):
                shell('git fetch origin --tags')
        else:
            shell('git clone --depth=1 --branch {} {}'.format(self.branch,
                                                              self.url))

    @chdir
    def make_dist(self):
        info('making tarball for %s', self.name)
        if exists('./autogen.sh'):
            shell('./autogen.sh')
            shell(self.configure_cmd, env=make_build_env())
        shell('make dist')

    @chdir
    def copy_dist(self):
        self.make_dist()
        tarball = glob.glob('*.tar.gz')[0]
        info('copying %s to %s', tarball, SRCDIR)
        shell('cp {} {}'.format(tarball, SRCDIR))
        m = re.match('{}-(.*).tar.gz'.format(self.name), basename(tarball))
        if m:
            self.version = m.group(1)

    @chdir
    def use_branch(self, branch):
        shell('git checkout {}'.format(branch))


class Ccnet(Project):
    def __init__(self):
        super(Ccnet, self).__init__('ccnet')


class Seafile(Project):
    configure_cmd = './configure --enable-client --enable-server'

    def __init__(self):
        super(Seafile, self).__init__('seafile')

    @chdir
    def copy_dist(self):
        super(Seafile, self).copy_dist()
        global seafile_version
        seafile_version = self.version


class Seahub(Project):
    def __init__(self):
        super(Seahub, self).__init__('seahub')

    @chdir
    def make_dist(self):
        cmds = [
            # 'git add -f media/css/*.css',
            # 'git commit -a -m "%s"' % msg,
            './tools/gen-tarball.py --version={} --branch=HEAD >/dev/null'
            .format(seafile_version),
        ]
        for cmd in cmds:
            shell(cmd, env=make_build_env())


class SeafDAV(Project):
    def __init__(self):
        super(SeafDAV, self).__init__('seafdav')

    @chdir
    def make_dist(self):
        shell('make')


class SeafObj(Project):
    def __init__(self):
        super(SeafObj, self).__init__('seafobj')

    @chdir
    def make_dist(self):
        shell('make dist')


def build_server(libsearpc, ccnet, seafile):
    cmd = [
        'python',
        join(TOPDIR, 'seafile/scripts/build/build-server.py'),
        '--yes',
        '--version=%s' % seafile.version,
        '--libsearpc_version=%s' % libsearpc.version,
        '--ccnet_version=%s' % ccnet.version,
        '--seafile_version=%s' % seafile.version,
        '--thirdpartdir=%s' % THIRDPARTDIR,
        '--srcdir=%s' % SRCDIR,
        '--jobs=4',
    ]
    shell(cmd, shell=False, env=make_build_env())


def fetch_and_build():
    libsearpc = Project('libsearpc')
    ccnet = Ccnet()
    seafile = Seafile()
    seahub = Seahub()
    seafobj = SeafObj()
    seafdav = SeafDAV()

    for project in (libsearpc, ccnet, seafile, seahub, seafdav, seafobj):
        if project.name != 'seafile':
            project.clone()
        project.copy_dist()

    build_server(libsearpc, ccnet, seafile)


def run_tests(cfg):
    # run_python_seafile_tests()
    # run_seafdav_tests(cfg)
    # must stop seafile server before running seaf-gc
    shell('{} stop'.format(get_script(cfg, 'seafile.sh')))
    shell('{} stop'.format(get_script(cfg, 'seahub.sh')))
    shell('{} --verbose --rm-deleted'.format(get_script(cfg, 'seaf-gc.sh')))


def run_python_seafile_tests():
    python_seafile = Project('python-seafile')
    if not exists(python_seafile.projectdir):
        python_seafile.clone()
        shell('pip install -r {}/requirements.txt'.format(
            python_seafile.projectdir))

    with cd(python_seafile.projectdir):
        # install python-seafile because seafdav tests needs it
        shell('python setup.py install')
        shell('py.test')


def _seafdav_env(cfg):
    env = dict(os.environ)
    env['CCNET_CONF_DIR'] = join(INSTALLDIR, 'ccnet')
    env['SEAFILE_CONF_DIR'] = join(INSTALLDIR, 'seafile-data')
    env['SEAFILE_CENTRAL_CONF_DIR'] = join(INSTALLDIR, 'conf')
    for path in glob.glob(join(
            server_dir(cfg), 'seafile/lib*/python*/*-packages')):
        prepend_env_value('PYTHONPATH', path, env=env)
    return env


def run_seafdav_tests(cfg):
    seafdav = SeafDAV()
    shell('pip install -r {}/test-requirements.txt'.format(seafdav.projectdir))
    with cd(seafdav.projectdir):
        shell('nosetests -v -s', env=_seafdav_env(cfg))


def _mkdirs(*paths):
    for path in paths:
        if not exists(path):
            os.mkdir(path)


def main():
    _mkdirs(SRCDIR, INSTALLDIR)
    setup_logging()
    fetch_and_build()
    for db in ('sqlite3', 'mysql'):
        if db == 'mysql':
            shell('mysqladmin -u root password %s' % MYSQL_ROOT_PASSWD)
        for i in ('prompt', 'auto'):
            shell('rm -rf {}/*'.format(INSTALLDIR))
            setup_and_test(db, i)


def setup_and_test(db, initmode):
    cfg = ServerConfig(
        installdir=INSTALLDIR,
        tarball=join(TOPDIR, 'seafile-server_{}_x86-64.tar.gz'.format(
            seafile_version)),
        version=seafile_version,
        initmode=initmode)
    info('Setting up seafile server with %s database', db)
    setup_server(cfg, db)
    # enable webdav, we're going to seafdav tests later
    shell('''sed -i -e "s/enabled = false/enabled = true/g" {}'''
          .format(join(INSTALLDIR, 'conf/seafdav.conf')))
    try:
        start_server(cfg)
        info('Testing seafile server with %s database', db)
        create_test_user(cfg)
        run_tests(cfg)
    except:
        for logfile in glob.glob('{}/logs/*.log'.format(INSTALLDIR)):
            shell('echo {0}; cat {0}'.format(logfile))
        for logfile in glob.glob('{}/seafile-server-{}/runtime/*.log'.format(
                INSTALLDIR, seafile_version)):
            shell('echo {0}; cat {0}'.format(logfile))
        raise


if __name__ == '__main__':
    os.chdir(TOPDIR)
    main()
