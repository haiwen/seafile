#!/usr/bin/env python

import os
import sys
import re
import ConfigParser
import getpass
from collections import namedtuple

try:
    import MySQLdb
    HAS_MYSQLDB = True
except ImportError:
    HAS_MYSQLDB = False

MySQLDBInfo = namedtuple('MySQLDBInfo', 'host port username password db')

class EnvManager(object):
    def __init__(self):
        self.upgrade_dir = os.path.abspath(os.path.dirname(__file__))
        self.install_path = os.path.dirname(self.upgrade_dir)
        self.top_dir = os.path.dirname(self.install_path)
        self.ccnet_dir = os.environ['CCNET_CONF_DIR']
        self.seafile_dir = os.environ['SEAFILE_CONF_DIR']

env_mgr = EnvManager()

class Utils(object):
    @staticmethod
    def highlight(content, is_error=False):
        '''Add ANSI color to content to get it highlighted on terminal'''
        if is_error:
            return '\x1b[1;31m%s\x1b[m' % content
        else:
            return '\x1b[1;32m%s\x1b[m' % content

    @staticmethod
    def info(msg):
        print Utils.highlight('[INFO] ') + msg

    @staticmethod
    def error(msg):
        print Utils.highlight('[ERROR] ') + msg
        sys.exit(1)

    @staticmethod
    def read_config(config_path, defaults):
        cp = ConfigParser.ConfigParser(defaults)
        cp.read(config_path)
        return cp

def get_ccnet_mysql_info():
    ccnet_conf = os.path.join(env_mgr.ccnet_dir, 'ccnet.conf')
    defaults = {
        'HOST': '127.0.0.1',
        'PORT': '3306',
    }

    config = Utils.read_config(ccnet_conf, defaults)
    db_section = 'Database'

    if not config.has_section(db_section):
        return None

    type = config.get(db_section, 'ENGINE')
    if type != 'mysql':
        return None

    try:
        host = config.get(db_section, 'HOST')
        port = config.getint(db_section, 'PORT')
        username = config.get(db_section, 'USER')
        password = config.get(db_section, 'PASSWD')
        db = config.get(db_section, 'DB')
    except ConfigParser.NoOptionError, e:
        Utils.error('Database config in ccnet.conf is invalid: %s' % e)

    info = MySQLDBInfo(host, port, username, password, db)
    return info

def get_seafile_mysql_info():
    seafile_conf = os.path.join(env_mgr.seafile_dir, 'seafile.conf')
    defaults = {
        'HOST': '127.0.0.1',
        'PORT': '3306',
    }
    config = Utils.read_config(seafile_conf, defaults)
    db_section = 'database'

    if not config.has_section(db_section):
        return None

    type = config.get(db_section, 'type')
    if type != 'mysql':
        return None

    try:
        host = config.get(db_section, 'host')
        port = config.getint(db_section, 'port')
        username = config.get(db_section, 'user')
        password = config.get(db_section, 'password')
        db = config.get(db_section, 'db_name')
    except ConfigParser.NoOptionError, e:
        Utils.error('Database config in seafile.conf is invalid: %s' % e)

    info = MySQLDBInfo(host, port, username, password, db)
    return info

def get_seahub_mysql_info():
    sys.path.insert(0, env_mgr.top_dir)
    try:
        import seahub_settings# pylint: disable=F0401
    except ImportError, e:
        Utils.error('Failed to import seahub_settings.py: %s' % e)

    if not hasattr(seahub_settings, 'DATABASES'):
        return None

    try:
        d = seahub_settings.DATABASES['default']
        if d['ENGINE'] != 'django.db.backends.mysql':
            return None

        host = d.get('HOST', '127.0.0.1')
        port = int(d.get('PORT', 3306))
        username = d['USER']
        password = d['PASSWORD']
        db = d['NAME']
    except KeyError:
        Utils.error('Database config in seahub_settings.py is invalid: %s' % e)

    info = MySQLDBInfo(host, port, username, password, db)
    return info

def get_seafile_db_infos():
    ccnet_db_info = get_ccnet_mysql_info()
    seafile_db_info = get_seafile_mysql_info()
    seahub_db_info = get_seahub_mysql_info()

    infos = [ccnet_db_info, seafile_db_info, seahub_db_info]

    for info in infos:
        if info is None:
            return None
        if info.host not in ('localhost', '127.0.0.1'):
            return None
    return infos

def ask_root_password(port):
    while True:
        desc = 'What is the root password for mysql? '
        password = getpass.getpass(desc).strip()
        if password:
            try:
                return check_mysql_user('root', password, port)
            except InvalidAnswer, e:
                print '\n%s\n' % e
                continue

class InvalidAnswer(Exception):
    def __init__(self, msg):
        Exception.__init__(self)
        self.msg = msg

    def __str__(self):
        return self.msg

def check_mysql_user(user, password, port):
    print '\nverifying password of root user %s ... ' % user,
    kwargs = dict(host='localhost',
                  port=port,
                  user=user,
                  passwd=password)

    try:
        conn = MySQLdb.connect(**kwargs)
    except Exception, e:
        if isinstance(e, MySQLdb.OperationalError):
            raise InvalidAnswer('Failed to connect to mysql server using user "%s" and password "***": %s'
                                % (user, e.args[1]))
        else:
            raise InvalidAnswer('Failed to connect to mysql server using user "%s" and password "***": %s'
                                % (user, e))

    print 'done'
    return conn

def apply_fix(root_conn, user, dbs):
    for db in dbs:
        grant_db_permission(root_conn, user, db)

    cursor = root_conn.cursor()
    sql = """
    SELECT *
    FROM mysql.user
    WHERE Host = '%%'
      AND password = ''
      AND User = '%s'
    """ % user
    cursor.execute(sql)
    if cursor.rowcount > 0:
        sql = 'DROP USER `%s`@`%%`' % user
        cursor.execute(sql)

def grant_db_permission(conn, user, db):
    cursor = conn.cursor()
    sql = '''GRANT ALL PRIVILEGES ON `%s`.* to `%s`@localhost ''' \
          % (db, user)

    try:
        cursor.execute(sql)
    except Exception, e:
        if isinstance(e, MySQLdb.OperationalError):
            Utils.error('Failed to grant permission of database %s: %s' % (db, e.args[1]))
        else:
            Utils.error('Failed to grant permission of database %s: %s' % (db, e))

    finally:
        cursor.close()

def main():
    dbinfos = get_seafile_db_infos()
    if not dbinfos:
        return
    if dbinfos[0].username == 'root':
        return

    if not HAS_MYSQLDB:
        Utils.error('Python MySQLdb module is not found')
    root_conn = ask_root_password(dbinfos[0].port)
    apply_fix(root_conn, dbinfos[0].username, [info.db for info in dbinfos])

if __name__ == '__main__':
    main()
