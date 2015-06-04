#coding: UTF-8

import sys
import os
import ConfigParser
import glob

HAS_MYSQLDB = True
try:
    import MySQLdb
except ImportError:
    HAS_MYSQLDB = False

HAS_SQLITE3 = True
try:
    import sqlite3
except ImportError:
    HAS_SQLITE3 = False

class EnvManager(object):
    def __init__(self):
        self.upgrade_dir = os.path.dirname(__file__)
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


class MySQLDBInfo(object):
    def __init__(self, host, port, username, password, db, unix_socket=None):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.db = db
        self.unix_socket = unix_socket


class DBUpdater(object):
    def __init__(self, version, name):
        self.sql_dir = os.path.join(env_mgr.upgrade_dir, 'sql', version, name)

    @staticmethod
    def get_instance(version):
        '''Detect whether we are using mysql or sqlite3'''
        ccnet_db_info = DBUpdater.get_ccnet_mysql_info()
        seafile_db_info = DBUpdater.get_seafile_mysql_info()
        seahub_db_info = DBUpdater.get_seahub_mysql_info()

        if ccnet_db_info and seafile_db_info and seahub_db_info:
            Utils.info('You are using MySQL')
            if not HAS_MYSQLDB:
                Utils.error('Python MySQLdb module is not found')
            updater = MySQLDBUpdater(version, ccnet_db_info, seafile_db_info, seahub_db_info)

        elif (ccnet_db_info is None) and (seafile_db_info is None) and (seahub_db_info is None):
            Utils.info('You are using SQLite3')
            if not HAS_SQLITE3:
                Utils.error('Python sqlite3 module is not found')
            updater = SQLiteDBUpdater(version)

        else:
            def to_db_string(info):
                if info is None:
                    return 'SQLite3'
                else:
                    return 'MySQL'
            Utils.error('Error:\n ccnet is using %s\n seafile is using %s\n seahub is using %s\n'
                        % (to_db_string(ccnet_db_info),
                           to_db_string(seafile_db_info),
                           to_db_string(seahub_db_info)))

        return updater

    def update_db(self):
        ccnet_sql = os.path.join(self.sql_dir, 'ccnet.sql')
        seafile_sql = os.path.join(self.sql_dir, 'seafile.sql')
        seahub_sql = os.path.join(self.sql_dir, 'seahub.sql')

        if os.path.exists(ccnet_sql):
            Utils.info('updating ccnet database...')
            self.update_ccnet_sql(ccnet_sql)

        if os.path.exists(seafile_sql):
            Utils.info('updating seafile database...')
            self.update_seafile_sql(seafile_sql)

        if os.path.exists(seahub_sql):
            Utils.info('updating seahub database...')
            self.update_seahub_sql(seahub_sql)

    @staticmethod
    def get_ccnet_mysql_info():
        ccnet_conf = os.path.join(env_mgr.ccnet_dir, 'ccnet.conf')
        defaults = {
            'HOST': '127.0.0.1',
            'PORT': '3306',
            'UNIX_SOCKET': '',
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
            unix_socket = config.get(db_section, 'UNIX_SOCKET')
        except ConfigParser.NoOptionError, e:
            Utils.error('Database config in ccnet.conf is invalid: %s' % e)

        info = MySQLDBInfo(host, port, username, password, db, unix_socket)
        return info

    @staticmethod
    def get_seafile_mysql_info():
        seafile_conf = os.path.join(env_mgr.seafile_dir, 'seafile.conf')
        defaults = {
            'HOST': '127.0.0.1',
            'PORT': '3306',
            'UNIX_SOCKET': '',
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
            unix_socket = config.get(db_section, 'unix_socket')
        except ConfigParser.NoOptionError, e:
            Utils.error('Database config in seafile.conf is invalid: %s' % e)

        info = MySQLDBInfo(host, port, username, password, db, unix_socket)
        return info

    @staticmethod
    def get_seahub_mysql_info():
        sys.path.insert(0, env_mgr.top_dir)
        try:
            import seahub_settings # pylint: disable=F0401
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
            unix_socket = host if host.startswith('/') else None
        except KeyError:
            Utils.error('Database config in seahub_settings.py is invalid: %s' % e)

        info = MySQLDBInfo(host, port, username, password, db, unix_socket)
        return info

    def update_ccnet_sql(self, ccnet_sql):
        raise NotImplementedError

    def update_seafile_sql(self, seafile_sql):
        raise NotImplementedError

    def update_seahub_sql(self, seahub_sql):
        raise NotImplementedError

class CcnetSQLiteDB(object):
    def __init__(self, ccnet_dir):
        self.ccnet_dir = ccnet_dir

    def get_db(self, dbname):
        dbs = (
            'ccnet.db',
            'GroupMgr/groupmgr.db',
            'misc/config.db',
            'OrgMgr/orgmgr.db',
        )
        for db in dbs:
            if os.path.splitext(os.path.basename(db))[0] == dbname:
                return os.path.join(self.ccnet_dir, db)

class SQLiteDBUpdater(DBUpdater):
    def __init__(self, version):
        DBUpdater.__init__(self, version, 'sqlite3')

        self.ccnet_db = CcnetSQLiteDB(env_mgr.ccnet_dir)
        self.seafile_db = os.path.join(env_mgr.seafile_dir, 'seafile.db')
        self.seahub_db = os.path.join(env_mgr.top_dir, 'seahub.db')

    def update_db(self):
        super(SQLiteDBUpdater, self).update_db()
        for sql_path in glob.glob(os.path.join(self.sql_dir, 'ccnet', '*.sql')):
            self.update_ccnet_sql(sql_path)

    def apply_sqls(self, db_path, sql_path):
        with open(sql_path, 'r') as fp:
            lines = fp.read().split(';')

        with sqlite3.connect(db_path) as conn:
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                else:
                    conn.execute(line)

    def update_ccnet_sql(self, sql_path):
        dbname = os.path.splitext(os.path.basename(sql_path))[0]
        self.apply_sqls(self.ccnet_db.get_db(dbname), sql_path)

    def update_seafile_sql(self, sql_path):
        self.apply_sqls(self.seafile_db, sql_path)

    def update_seahub_sql(self, sql_path):
        self.apply_sqls(self.seahub_db, sql_path)


class MySQLDBUpdater(DBUpdater):
    def __init__(self, version, ccnet_db_info, seafile_db_info, seahub_db_info):
        DBUpdater.__init__(self, version, 'mysql')
        self.ccnet_db_info = ccnet_db_info
        self.seafile_db_info = seafile_db_info
        self.seahub_db_info = seahub_db_info

    def update_ccnet_sql(self, ccnet_sql):
        self.apply_sqls(self.ccnet_db_info, ccnet_sql)

    def update_seafile_sql(self, seafile_sql):
        self.apply_sqls(self.seafile_db_info, seafile_sql)

    def update_seahub_sql(self, seahub_sql):
        self.apply_sqls(self.seahub_db_info, seahub_sql)

    def get_conn(self, info):
        kw = dict(
            user=info.username,
            passwd=info.password,
            db=info.db,
        )
        if info.unix_socket:
            kw['unix_socket'] = info.unix_socket
        else:
            kw['host'] = info.host
            kw['port'] = info.port
        try:
            conn = MySQLdb.connect(**kw)
        except Exception, e:
            if isinstance(e, MySQLdb.OperationalError):
                msg = str(e.args[1])
            else:
                msg = str(e)
            Utils.error('Failed to connect to mysql database %s: %s' % (info.db, msg))

        return conn

    def execute_sql(self, conn, sql):
        cursor = conn.cursor()
        try:
            cursor.execute(sql)
            conn.commit()
        except Exception, e:
            if isinstance(e, MySQLdb.OperationalError):
                msg = str(e.args[1])
            else:
                msg = str(e)

            Utils.error('Failed to execute sql: %s' % msg)

    def apply_sqls(self, info, sql_path):
        with open(sql_path, 'r') as fp:
            lines = fp.read().split(';')

        conn = self.get_conn(info)

        for line in lines:
            line = line.strip()
            if not line:
                continue
            else:
                self.execute_sql(conn, line)


def main():
    version = sys.argv[1]
    db_updater = DBUpdater.get_instance(version)
    db_updater.update_db()

    return 0

if __name__ == '__main__':
    main()
