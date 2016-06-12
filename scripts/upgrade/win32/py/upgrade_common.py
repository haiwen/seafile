# coding: UTF-8

import os
import sys
import sqlite3
import subprocess
import ccnet
import glob


# Directory layout:
#
# - SeafileProgram/
#   - seafserv.ini
#   - seafile-server-1.7.0/
#   - seafile-server-1.8.0/
#   - seafile-server-1.9.0/
#     - upgrade/
#       - sql/
#         - 1.8.0/
#           - sqlite3
#             - ccnet.sql
#             - seafile.sql
#             - seahub.sql
#       - upgrade_1.7_1.8.bat
#       - upgrade_1.8_1.9.bat
#       - py/
#         - upgrade_1.7_1.8.py
#         - upgrade_1.8_1.9.py

pyscript_dir = os.path.dirname(os.path.abspath(__file__))
upgrade_dir = os.path.dirname(pyscript_dir)
sql_dir = os.path.join(upgrade_dir, 'sql')
install_path = os.path.dirname(upgrade_dir)
program_top_dir = os.path.dirname(install_path)

seafserv_dir = ''
ccnet_dir = ''
seafile_dir = ''
central_config_dir = ''

def run_argv(argv, cwd=None, env=None, suppress_stdout=False, suppress_stderr=False):
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
        return proc.wait()

def error(message):
    print message
    sys.exit(1)

def read_seafserv_dir():
    global seafserv_dir, ccnet_dir, seafile_dir, central_config_dir
    seafserv_ini = os.path.join(program_top_dir, 'seafserv.ini')
    if not os.path.exists(seafserv_ini):
        error('%s not found' % seafserv_ini)

    with open(seafserv_ini, 'r') as fp:
        seafserv_dir = fp.read().strip()

    ccnet_dir = os.path.join(seafserv_dir, 'ccnet')
    seafile_dir = os.path.join(seafserv_dir, 'seafile-data')
    central_config_dir = os.path.join(seafserv_dir, 'conf')

def apply_sqls(db_path, sql_path):
    with open(sql_path, 'r') as fp:
        lines = fp.read().split(';')

    with sqlite3.connect(db_path) as conn:
        for line in lines:
            line = line.strip()
            if not line:
                continue
            else:
                conn.execute(line)

def _get_ccnet_db(ccnet_dir, dbname):
    dbs = (
        'ccnet.db',
        'GroupMgr/groupmgr.db',
        'misc/config.db',
        'OrgMgr/orgmgr.db',
    )
    for db in dbs:
        if os.path.splitext(os.path.basename(db))[0] == dbname:
            return os.path.join(ccnet_dir, db)

def _handle_ccnet_sqls(version):
    for sql_path in glob.glob(os.path.join(sql_dir, version, 'sqlite3', 'ccnet', '*.sql')):
        dbname = os.path.splitext(os.path.basename(sql_path))[0]
        apply_sqls(_get_ccnet_db(ccnet_dir, dbname), sql_path)

def upgrade_db(version):
    ensure_server_not_running()
    print 'upgrading databases ...'
    ccnet_db = os.path.join(ccnet_dir, 'ccnet.db')
    seafile_db = os.path.join(seafile_dir, 'seafile.db')
    seahub_db = os.path.join(seafserv_dir, 'seahub.db')

    def get_sql(prog):
        ret = os.path.join(sql_dir, version, 'sqlite3', '%s.sql' % prog)
        return ret

    ccnet_sql = get_sql('ccnet')
    seafile_sql = get_sql('seafile')
    seahub_sql = get_sql('seahub')

    if os.path.exists(ccnet_sql):
        print '    upgrading ccnet databases ...'
        apply_sqls(ccnet_db, ccnet_sql)
    _handle_ccnet_sqls(version)

    if os.path.exists(seafile_sql):
        print '    upgrading seafile databases ...'
        apply_sqls(seafile_db, seafile_sql)

    if os.path.exists(seahub_sql):
        print '    upgrading seahub databases ...'
        apply_sqls(seahub_db, seahub_sql)

def get_current_version():
    return os.path.basename(install_path).split('-')[-1]

def ensure_server_not_running():
    if os.path.exists(os.path.join(central_config_dir, 'ccnet.conf')):
        client = ccnet.SyncClient(ccnet_dir,
                                  central_config_dir=central_config_dir)
    else:
        client = ccnet.SyncClient(ccnet_dir)
    try:
        client.connect_daemon()
    except ccnet.NetworkError:
        pass
    else:
        raise Exception('Seafile server is running! You must turn it off before running this script!')


read_seafserv_dir()
