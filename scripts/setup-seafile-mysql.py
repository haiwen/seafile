#coding: UTF-8

'''This script would guide the seafile admin to setup seafile with MySQL'''

import sys
import os
import time
import re
import shutil
import glob
import subprocess
import hashlib
import getpass
import uuid
import warnings
import MySQLdb
import argparse
import socket

from ConfigParser import ConfigParser

try:
    import readline # pylint: disable=W0611
except ImportError:
    pass


SERVER_MANUAL_HTTP = 'https://github.com/haiwen/seafile/wiki'

class Utils(object):
    '''Groups all helper functions here'''
    @staticmethod
    def welcome():
        '''Show welcome message'''
        welcome_msg = '''\
-----------------------------------------------------------------
This script will guide you to setup your seafile server using MySQL.
Make sure you have read seafile server manual at

        %s

Press ENTER to continue
-----------------------------------------------------------------''' % SERVER_MANUAL_HTTP
        print welcome_msg
        raw_input()

    @staticmethod
    def highlight(content):
        '''Add ANSI color to content to get it highlighted on terminal'''
        return '\x1b[33m%s\x1b[m' % content

    @staticmethod
    def info(msg):
        print msg

    @staticmethod
    def error(msg):
        '''Print error and exit'''
        print
        print 'Error: ' + msg
        sys.exit(1)

    @staticmethod
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

    @staticmethod
    def run(cmdline, cwd=None, env=None, suppress_stdout=False, suppress_stderr=False):
        '''Like run_argv but specify a command line string instead of argv'''
        with open(os.devnull, 'w') as devnull:
            if suppress_stdout:
                stdout = devnull
            else:
                stdout = sys.stdout

            if suppress_stderr:
                stderr = devnull
            else:
                stderr = sys.stderr

            proc = subprocess.Popen(cmdline,
                                    cwd=cwd,
                                    stdout=stdout,
                                    stderr=stderr,
                                    env=env,
                                    shell=True)
            return proc.wait()

    @staticmethod
    def prepend_env_value(name, value, env=None, seperator=':'):
        '''prepend a new value to a list'''
        if env is None:
            env = os.environ

        try:
            current_value = env[name]
        except KeyError:
            current_value = ''

        new_value = value
        if current_value:
            new_value += seperator + current_value

        env[name] = new_value

    @staticmethod
    def must_mkdir(path):
        '''Create a directory, exit on failure'''
        if os.path.exists(path):
            return
        try:
            os.mkdir(path)
        except OSError, e:
            Utils.error('failed to create directory %s:%s' % (path, e))

    @staticmethod
    def must_copy(src, dst):
        '''Copy src to dst, exit on failure'''
        try:
            shutil.copy(src, dst)
        except Exception, e:
            Utils.error('failed to copy %s to %s: %s' % (src, dst, e))

    @staticmethod
    def find_in_path(prog):
        if 'win32' in sys.platform:
            sep = ';'
        else:
            sep = ':'

        dirs = os.environ['PATH'].split(sep)
        for d in dirs:
            d = d.strip()
            if d == '':
                continue
            path = os.path.join(d, prog)
            if os.path.exists(path):
                return path

        return None

    @staticmethod
    def get_python_executable():
        '''Return the python executable. This should be the PYTHON environment
        variable which is set in setup-seafile-mysql.sh

        '''
        return os.environ['PYTHON']

    @staticmethod
    def read_config(fn):
        '''Return a case sensitive ConfigParser by reading the file "fn"'''
        cp = ConfigParser()
        cp.optionxform = str
        cp.read(fn)

        return cp

    @staticmethod
    def write_config(cp, fn):
        '''Return a case sensitive ConfigParser by reading the file "fn"'''
        with open(fn, 'w') as fp:
            cp.write(fp)

    @staticmethod
    def ask_question(desc,
                     key=None,
                     note=None,
                     default=None,
                     validate=None,
                     yes_or_no=False,
                     password=False):
        '''Ask a question, return the answer.
        @desc description, e.g. "What is the port of ccnet?"

        @key a name to represent the target of the question, e.g. "port for
        ccnet server"

        @note additional information for the question, e.g. "Must be a valid
        port number"

        @default the default value of the question. If the default value is
        not None, when the user enter nothing and press [ENTER], the default
        value would be returned

        @validate a function that takes the user input as the only parameter
        and validate it. It should return a validated value, or throws an
        "InvalidAnswer" exception if the input is not valid.

        @yes_or_no If true, the user must answer "yes" or "no", and a boolean
        value would be returned

        @password If true, the user input would not be echoed to the
        console

        '''
        assert key or yes_or_no
        # Format description
        print
        if note:
            desc += '\n' + note

        desc += '\n'
        if yes_or_no:
            desc += '[ yes or no ]'
        else:
            if default:
                desc += '[ default "%s" ]' % default
            else:
                desc += '[ %s ]' % key

        desc += ' '
        while True:
            # prompt for user input
            if password:
                answer = getpass.getpass(desc).strip()
            else:
                answer = raw_input(desc).strip()

            # No user input: use default
            if not answer:
                if default:
                    answer = default
                else:
                    continue

            # Have user input: validate answer
            if yes_or_no:
                if answer not in ['yes', 'no']:
                    print Utils.highlight('\nPlease answer yes or no\n')
                    continue
                else:
                    return answer == 'yes'
            else:
                if validate:
                    try:
                        return validate(answer)
                    except InvalidAnswer, e:
                        print Utils.highlight('\n%s\n' % e)
                        continue
                else:
                    return answer

    @staticmethod
    def validate_port(port):
        try:
            port = int(port)
        except ValueError:
            raise InvalidAnswer('%s is not a valid port' % Utils.highlight(port))

        if port <= 0 or port > 65535:
            raise InvalidAnswer('%s is not a valid port' % Utils.highlight(port))

        return port


class InvalidAnswer(Exception):
    def __init__(self, msg):
        Exception.__init__(self)
        self.msg = msg
    def __str__(self):
        return self.msg

class InvalidParams(Exception):
    def __init__(self, msg):
        Exception.__init__(self)
        self.msg = msg
    def __str__(self):
        return self.msg

### END of Utils
####################

class EnvManager(object):
    '''System environment and directory layout'''
    def __init__(self):
        self.install_path = os.path.dirname(os.path.abspath(__file__))
        self.top_dir = os.path.dirname(self.install_path)
        self.bin_dir = os.path.join(self.install_path, 'seafile', 'bin')
        self.central_config_dir = os.path.join(self.top_dir, 'conf')
        Utils.must_mkdir(self.central_config_dir)

    def check_pre_condiction(self):
        def error_if_not_exists(path):
            if not os.path.exists(path):
                Utils.error('"%s" not found' % path)

        paths = [
            os.path.join(self.install_path, 'seafile'),
            os.path.join(self.install_path, 'seahub'),
            os.path.join(self.install_path, 'runtime'),
        ]

        for path in paths:
            error_if_not_exists(path)

        if os.path.exists(ccnet_config.ccnet_dir):
            Utils.error('Ccnet config dir \"%s\" already exists.' % ccnet_config.ccnet_dir)

    def get_seahub_env(self):
        '''Prepare for seahub syncdb'''
        env = dict(os.environ)
        env['CCNET_CONF_DIR'] = ccnet_config.ccnet_dir
        env['SEAFILE_CONF_DIR'] = seafile_config.seafile_dir
        self.setup_python_path(env)
        return env

    def setup_python_path(self, env):
        '''And PYTHONPATH and CCNET_CONF_DIR/SEAFILE_CONF_DIR to env, which is
        needed by seahub

        '''
        install_path = self.install_path
        pro_pylibs_dir = os.path.join(install_path, 'pro', 'python')
        extra_python_path = [
            pro_pylibs_dir,

            os.path.join(install_path, 'seahub', 'thirdpart'),

            os.path.join(install_path, 'seafile/lib/python2.6/site-packages'),
            os.path.join(install_path, 'seafile/lib64/python2.6/site-packages'),
            os.path.join(install_path, 'seafile/lib/python2.7/site-packages'),
            os.path.join(install_path, 'seafile/lib64/python2.7/site-packages'),
        ]

        for path in extra_python_path:
            Utils.prepend_env_value('PYTHONPATH', path, env=env)

    def get_binary_env(self):
        '''Set LD_LIBRARY_PATH for seafile server executables'''
        env = dict(os.environ)
        lib_dir = os.path.join(self.install_path, 'seafile', 'lib')
        lib64_dir = os.path.join(self.install_path, 'seafile', 'lib64')
        Utils.prepend_env_value('LD_LIBRARY_PATH', lib_dir, env=env)
        Utils.prepend_env_value('LD_LIBRARY_PATH', lib64_dir, env=env)
        return env

class AbstractConfigurator(object):
    '''Abstract Base class for ccnet/seafile/seahub/db configurator'''
    def __init__(self):
        pass

    def ask_questions(self):
        raise NotImplementedError

    def generate(self):
        raise NotImplementedError


class AbstractDBConfigurator(AbstractConfigurator):
    '''Abstract class for database related configuration'''
    def __init__(self):
        AbstractConfigurator.__init__(self)
        self.mysql_host = 'localhost'
        self.mysql_port = 3306
        self.mysql_userhost = 'localhost'

        self.use_existing_db = False

        self.seafile_mysql_user = ''
        self.seafile_mysql_password = ''

        self.ccnet_db_name = ''
        self.seafile_db_name = ''
        self.seahub_db_name = ''

        self.seahub_admin_email = ''
        self.seahub_admin_password = ''

    @staticmethod
    def ask_use_existing_db():
        def validate(choice):
            if choice not in ['1', '2']:
                raise InvalidAnswer('Please choose 1 or 2')

            return choice == '2'

        question = '''\
-------------------------------------------------------
Please choose a way to initialize seafile databases:
-------------------------------------------------------
'''

        note = '''\
[1] Create new ccnet/seafile/seahub databases
[2] Use existing ccnet/seafile/seahub databases
'''
        return Utils.ask_question(question,
                                  key='1 or 2',
                                  note=note,
                                  validate=validate)

    def validate_mysql_host(self, host):
        if not re.match(r'^[a-zA-Z0-9_\-\.]+$', host):
            raise InvalidAnswer('%s is not a valid host' % Utils.highlight(host))

        if host == 'localhost':
            host = '127.0.0.1'
        return host

    def ask_mysql_host(self):
        question = 'What is the host of mysql server?'
        key = 'mysql server host'
        default = 'localhost'
        self.mysql_host = Utils.ask_question(question,
                                             key=key,
                                             default=default,
                                             validate=self.validate_mysql_host)

    def validate_mysql_user_host(self, mysql_userhost):
        if mysql_userhost != '%':
            if not re.match(r'^[^.].+\..+[^.]$', mysql_userhost):
                raise InvalidAnswer('%s is not a valid ip or domain' % mysql_userhost)
        return mysql_userhost

    def ask_mysql_user_host(self):
        question = 'Which hosts should be able to use your MySQL Account?'
        key = 'mysql user host'
        default = '%'
        self.mysql_userhost = Utils.ask_question(question,
                                                 key=key,
                                                 default=default,
                                                 validate=self.validate_mysql_user_host)

    def ask_mysql_port(self):
        question = 'What is the port of mysql server?'
        key = 'mysql server port'
        default = '3306'
        port = Utils.ask_question(question,
                                  key=key,
                                  default=default,
                                  validate=Utils.validate_port)

        # self.check_mysql_server(host, port)
        self.mysql_port = port

    def ask_mysql_host_port(self):
        self.ask_mysql_host()
        if self.mysql_host != '127.0.0.1':
            self.ask_mysql_user_host()
        self.ask_mysql_port()

    def check_mysql_server(self, host, port):
        print '\nverifying mysql server running ... ',
        try:
            dummy = MySQLdb.connect(host=host, port=port)
        except Exception:
            print
            raise InvalidAnswer('Failed to connect to mysql server at "%s:%s"' \
                                % (host, port))

        print 'done'

    def check_mysql_user(self, user, password):
        print '\nverifying password of user %s ... ' % user,
        kwargs = dict(host=self.mysql_host,
                      port=self.mysql_port,
                      user=user,
                      passwd=password)

        try:
            conn = MySQLdb.connect(**kwargs)
        except Exception, e:
            if isinstance(e, MySQLdb.OperationalError):
                raise InvalidAnswer('Failed to connect to mysql server using user "%s" and password "***": %s' \
                                    % (user, e.args[1]))
            else:
                raise InvalidAnswer('Failed to connect to mysql server using user "%s" and password "***": %s' \
                                    % (user, e))

        print 'done'
        return conn

    def create_seahub_admin(self):
        try:
            conn = MySQLdb.connect(host=self.mysql_host,
                                   port=self.mysql_port,
                                   user=self.seafile_mysql_user,
                                   passwd=self.seafile_mysql_password,
                                   db=self.ccnet_db_name)
        except Exception, e:
            if isinstance(e, MySQLdb.OperationalError):
                Utils.error('Failed to connect to mysql database %s: %s' % (self.ccnet_db_name, e.args[1]))
            else:
                Utils.error('Failed to connect to mysql database %s: %s' % (self.ccnet_db_name, e))

        cursor = conn.cursor()
        sql = '''\
CREATE TABLE IF NOT EXISTS EmailUser (id INTEGER NOT NULL PRIMARY KEY AUTO_INCREMENT, email VARCHAR(255), passwd CHAR(64), is_staff BOOL NOT NULL, is_active BOOL NOT NULL, ctime BIGINT, UNIQUE INDEX (email)) ENGINE=INNODB'''

        try:
            cursor.execute(sql)
        except Exception, e:
            if isinstance(e, MySQLdb.OperationalError):
                Utils.error('Failed to create ccnet user table: %s' % e.args[1])
            else:
                Utils.error('Failed to create ccnet user table: %s' % e)

        sql = '''REPLACE INTO EmailUser(email, passwd, is_staff, is_active, ctime) VALUES ('%s', '%s', 1, 1, 0)''' \
              % (seahub_config.admin_email, seahub_config.hashed_admin_password())

        try:
            cursor.execute(sql)
        except Exception, e:
            if isinstance(e, MySQLdb.OperationalError):
                Utils.error('Failed to create admin user: %s' % e.args[1])
            else:
                Utils.error('Failed to create admin user: %s' % e)

        conn.commit()

    def ask_questions(self):
        '''Ask questions and do database operations'''
        raise NotImplementedError


class NewDBConfigurator(AbstractDBConfigurator):
    '''Handles the case of creating new mysql databases for ccnet/seafile/seahub'''
    def __init__(self):
        AbstractDBConfigurator.__init__(self)

        self.root_password = ''
        self.root_conn = ''

    def ask_questions(self):
        self.ask_mysql_host_port()

        self.ask_root_password()
        self.ask_seafile_mysql_user_password()

        self.ask_db_names()

    def generate(self):
        if not self.mysql_user_exists(self.seafile_mysql_user):
            self.create_user()
        self.create_databases()

    def validate_root_passwd(self, password):
        self.root_conn = self.check_mysql_user('root', password)
        return password

    def ask_root_password(self):
        question = 'What is the password of the mysql root user?'
        key = 'root password'
        self.root_password = Utils.ask_question(question,
                                                key=key,
                                                validate=self.validate_root_passwd,
                                                password=True)

    def mysql_user_exists(self, user):
        cursor = self.root_conn.cursor()

        sql = '''SELECT EXISTS(SELECT 1 FROM mysql.user WHERE user = '%s')''' % user

        try:
            cursor.execute(sql)
            return cursor.fetchall()[0][0]
        except Exception, e:
            if isinstance(e, MySQLdb.OperationalError):
                Utils.error('Failed to check mysql user %s: %s' % (user, e.args[1]))
            else:
                Utils.error('Failed to check mysql user %s: %s' % (user, e))
        finally:
            cursor.close()


    def ask_seafile_mysql_user_password(self):
        def validate(user):
            if user == 'root':
                self.seafile_mysql_password = self.root_password
            else:
                question = 'Enter the password for mysql user "%s":' % Utils.highlight(user)
                key = 'password for %s' % user
                password = Utils.ask_question(question, key=key, password=True)
                # If the user already exists, check the password here
                if self.mysql_user_exists(user):
                    self.check_mysql_user(user, password)
                self.seafile_mysql_password = password

            return user


        question = 'Enter the name for mysql user of seafile. It would be created if not exists.'
        key = 'mysql user for seafile'
        default = 'root'
        self.seafile_mysql_user = Utils.ask_question(question,
                                                     key=key,
                                                     default=default,
                                                     validate=validate)

    def ask_db_name(self, program, default):
        question = 'Enter the database name for %s:' % program
        key = '%s database' % program
        return Utils.ask_question(question,
                                  key=key,
                                  default=default,
                                  validate=self.validate_db_name)

    def ask_db_names(self):
        self.ccnet_db_name = self.ask_db_name('ccnet-server', 'ccnet-db')
        self.seafile_db_name = self.ask_db_name('seafile-server', 'seafile-db')
        self.seahub_db_name = self.ask_db_name('seahub', 'seahub-db')

    def validate_db_name(self, db_name):
        return db_name

    def create_user(self):
        cursor = self.root_conn.cursor()
        sql = '''CREATE USER '%s'@'%s' IDENTIFIED BY '%s' ''' \
              % (self.seafile_mysql_user, self.mysql_userhost, self.seafile_mysql_password)

        try:
            cursor.execute(sql)
        except Exception, e:
            if isinstance(e, MySQLdb.OperationalError):
                Utils.error('Failed to create mysql user %s@%s: %s' % (self.seafile_mysql_user, self.mysql_userhost, e.args[1]))
            else:
                Utils.error('Failed to create mysql user %s@%s: %s' % (self.seafile_mysql_user, self.mysql_userhost, e))
        finally:
            cursor.close()


    def create_db(self, db_name):
        cursor = self.root_conn.cursor()
        sql = '''CREATE DATABASE IF NOT EXISTS `%s` CHARACTER SET UTF8''' \
              % db_name

        try:
            cursor.execute(sql)
        except Exception, e:
            if isinstance(e, MySQLdb.OperationalError):
                Utils.error('Failed to create database %s: %s' % (db_name, e.args[1]))
            else:
                Utils.error('Failed to create database %s: %s' % (db_name, e))
        finally:
            cursor.close()

    def grant_db_permission(self, db_name):
        cursor = self.root_conn.cursor()
        sql = '''GRANT ALL PRIVILEGES ON `%s`.* to `%s`@`%s` ''' \
              % (db_name, self.seafile_mysql_user, self.mysql_userhost)

        try:
            cursor.execute(sql)
        except Exception, e:
            if isinstance(e, MySQLdb.OperationalError):
                Utils.error('Failed to grant permission of database %s: %s' % (db_name, e.args[1]))
            else:
                Utils.error('Failed to grant permission of database %s: %s' % (db_name, e))
        finally:
            cursor.close()

    def create_databases(self):
        self.create_db(self.ccnet_db_name)
        self.create_db(self.seafile_db_name)
        self.create_db(self.seahub_db_name)

        if self.seafile_mysql_user != 'root':
            self.grant_db_permission(self.ccnet_db_name)
            self.grant_db_permission(self.seafile_db_name)
            self.grant_db_permission(self.seahub_db_name)


class ExistingDBConfigurator(AbstractDBConfigurator):
    '''Handles the case of use existing mysql databases for ccnet/seafile/seahub'''
    def __init__(self):
        AbstractDBConfigurator.__init__(self)
        self.use_existing_db = True

    def ask_questions(self):
        self.ask_mysql_host_port()

        self.ask_existing_mysql_user_password()

        self.ccnet_db_name = self.ask_db_name('ccnet')
        self.seafile_db_name = self.ask_db_name('seafile')
        self.seahub_db_name = self.ask_db_name('seahub')

    def generate(self):
        pass

    def ask_existing_mysql_user_password(self):
        def validate(user):
            question = 'What is the password for mysql user "%s"?' % Utils.highlight(user)
            key = 'password for %s' % user
            password = Utils.ask_question(question, key=key, password=True)
            self.check_mysql_user(user, password)
            self.seafile_mysql_password = password
            return user

        question = 'Which mysql user to use for seafile?'
        key = 'mysql user for seafile'
        self.seafile_mysql_user = Utils.ask_question(question,
                                                     key=key,
                                                     validate=validate)

    def validate_db_name(self, db_name):
        self.check_user_db_access(db_name)
        return db_name

    def ask_db_name(self, program):
        question = 'Enter the existing database name for %s:' % program
        key = '%s database' % program
        return Utils.ask_question(question,
                                  key=key,
                                  validate=self.validate_db_name)

    def check_user_db_access(self, db_name):
        user = self.seafile_mysql_user
        password = self.seafile_mysql_password

        print '\nverifying user "%s" access to database %s ... ' % (user, db_name),
        try:
            conn = MySQLdb.connect(host=self.mysql_host,
                                   port=self.mysql_port,
                                   user=user,
                                   passwd=password,
                                   db=db_name)

            cursor = conn.cursor()
            cursor.execute('show tables')
            cursor.close()
        except Exception, e:
            if isinstance(e, MySQLdb.OperationalError):
                raise InvalidAnswer('Failed to access database %s using user "%s" and password "***": %s' \
                                    % (db_name, user, e.args[1]))
            else:
                raise InvalidAnswer('Failed to access database %s using user "%s" and password "***": %s' \
                                    % (db_name, user, e))

        print 'done'

        return conn


class CcnetConfigurator(AbstractConfigurator):
    SERVER_NAME_REGEX = r'^[a-zA-Z0-9_\-]{3,15}$'
    SERVER_IP_OR_DOMAIN_REGEX = r'^[^.].+\..+[^.]$'

    def __init__(self):
        '''Initialize default values of ccnet configuration'''
        AbstractConfigurator.__init__(self)
        self.ccnet_dir = os.path.join(env_mgr.top_dir, 'ccnet')
        self.port = 10001
        self.server_name = None
        self.ip_or_domain = None
        self.ccnet_conf = os.path.join(env_mgr.central_config_dir, 'ccnet.conf')

    def ask_questions(self):
        if not self.server_name:
            self.ask_server_name()
        if not self.ip_or_domain:
            self.ask_server_ip_or_domain()
        # self.ask_port()

    def generate(self):
        print 'Generating ccnet configuration ...\n'
        ccnet_init = os.path.join(env_mgr.bin_dir, 'ccnet-init')
        argv = [
            ccnet_init,
            '-F', env_mgr.central_config_dir,
            '--config-dir', self.ccnet_dir,
            '--name', self.server_name,
            '--host', self.ip_or_domain,
        ]

        if Utils.run_argv(argv, env=env_mgr.get_binary_env()) != 0:
            Utils.error('Failed to generate ccnet configuration')

        time.sleep(1)
        self.generate_db_conf()

    def generate_db_conf(self):
        config = Utils.read_config(self.ccnet_conf)
        # [Database]
        # ENGINE=
        # HOST=
        # USER=
        # PASSWD=
        # DB=
        db_section = 'Database'
        if not config.has_section(db_section):
            config.add_section(db_section)
        config.set(db_section, 'ENGINE', 'mysql')
        config.set(db_section, 'HOST', db_config.mysql_host)
        config.set(db_section, 'PORT', db_config.mysql_port)
        config.set(db_section, 'USER', db_config.seafile_mysql_user)
        config.set(db_section, 'PASSWD', db_config.seafile_mysql_password)
        config.set(db_section, 'DB', db_config.ccnet_db_name)
        config.set(db_section, 'CONNECTION_CHARSET', 'utf8')

        Utils.write_config(config, self.ccnet_conf)

    def validate_server_name(self, name):
        if not re.match(self.SERVER_NAME_REGEX, name):
            raise InvalidAnswer('%s is not a valid name' % Utils.highlight(name))
        return name

    def ask_server_name(self):
        question = 'What is the name of the server? It will be displayed on the client.'
        key = 'server name'
        note = '3 - 15 letters or digits'
        self.server_name = Utils.ask_question(question,
                                              key=key,
                                              note=note,
                                              validate=self.validate_server_name)

    def validate_server_ip(self, ip_or_domain):
        if not re.match(self.SERVER_IP_OR_DOMAIN_REGEX, ip_or_domain):
            raise InvalidAnswer('%s is not a valid ip or domain' % ip_or_domain)
        return ip_or_domain

    def ask_server_ip_or_domain(self):
        question = 'What is the ip or domain of the server?'
        key = 'This server\'s ip or domain'
        note = 'For example: www.mycompany.com, 192.168.1.101'
        self.ip_or_domain = Utils.ask_question(question,
                                               key=key,
                                               note=note,
                                               validate=self.validate_server_ip)

    def ask_port(self):
        def validate(port):
            return Utils.validate_port(port)

        question = 'Which port do you want to use for the ccnet server?'
        key = 'ccnet server port'
        default = 10001
        self.port = Utils.ask_question(question,
                                       key=key,
                                       default=default,
                                       validate=validate)


class SeafileConfigurator(AbstractConfigurator):
    def __init__(self):
        AbstractConfigurator.__init__(self)
        self.seafile_dir = None
        self.port = 12001
        self.fileserver_port = None
        self.seafile_conf = os.path.join(env_mgr.central_config_dir, 'seafile.conf')

    def ask_questions(self):
        if not self.seafile_dir:
            self.ask_seafile_dir()
        # self.ask_port()
        if not self.fileserver_port:
            self.ask_fileserver_port()

    def generate(self):
        print 'Generating seafile configuration ...\n'
        seafserv_init = os.path.join(env_mgr.bin_dir, 'seaf-server-init')
        argv = [
            seafserv_init,
            '-F', env_mgr.central_config_dir,
            '--seafile-dir', self.seafile_dir,
            '--fileserver-port', str(self.fileserver_port),
        ]

        if Utils.run_argv(argv, env=env_mgr.get_binary_env()) != 0:
            Utils.error('Failed to generate ccnet configuration')

        time.sleep(1)
        self.generate_db_conf()
        self.write_seafile_ini()
        print 'done'

    def generate_db_conf(self):
        config = Utils.read_config(self.seafile_conf)
        # [database]
        # type=
        # host=
        # user=
        # password=
        # db_name=
        # unix_socket=
        db_section = 'database'
        if not config.has_section(db_section):
            config.add_section(db_section)
        config.set(db_section, 'type', 'mysql')
        config.set(db_section, 'host', db_config.mysql_host)
        config.set(db_section, 'port', db_config.mysql_port)
        config.set(db_section, 'user', db_config.seafile_mysql_user)
        config.set(db_section, 'password', db_config.seafile_mysql_password)
        config.set(db_section, 'db_name', db_config.seafile_db_name)
        config.set(db_section, 'connection_charset', 'utf8')

        Utils.write_config(config, self.seafile_conf)

    def validate_seafile_dir(self, path):
        if os.path.exists(path):
            raise InvalidAnswer('%s already exists' % Utils.highlight(path))
        return path

    def ask_seafile_dir(self):
        question = 'Where do you want to put your seafile data?'
        key = 'seafile-data'
        note = 'Please use a volume with enough free space'
        default = os.path.join(env_mgr.top_dir, 'seafile-data')
        self.seafile_dir = Utils.ask_question(question,
                                              key=key,
                                              note=note,
                                              default=default,
                                              validate=self.validate_seafile_dir)

    def ask_port(self):
        def validate(port):
            port = Utils.validate_port(port)
            if port == ccnet_config.port:
                raise InvalidAnswer('%s is used by ccnet server, choose another one' \
                                    % Utils.highlight(port))
            return port

        question = 'Which port do you want to use for the seafile server?'
        key = 'seafile server port'
        default = 12001
        self.port = Utils.ask_question(question,
                                       key=key,
                                       default=default,
                                       validate=validate)

    def ask_fileserver_port(self):
        question = 'Which port do you want to use for the seafile fileserver?'
        key = 'seafile fileserver port'
        default = 8082
        self.fileserver_port = Utils.ask_question(question,
                                                  key=key,
                                                  default=default,
                                                  validate=Utils.validate_port)

    def write_seafile_ini(self):
        seafile_ini = os.path.join(ccnet_config.ccnet_dir, 'seafile.ini')
        with open(seafile_ini, 'w') as fp:
            fp.write(self.seafile_dir)

class SeahubConfigurator(AbstractConfigurator):
    def __init__(self):
        AbstractConfigurator.__init__(self)
        self.admin_email = ''
        self.admin_password = ''
        self.seahub_settings_py = os.path.join(env_mgr.central_config_dir, 'seahub_settings.py')

    def hashed_admin_password(self):
        return hashlib.sha1(self.admin_password).hexdigest() # pylint: disable=E1101

    def ask_questions(self):
        pass
        # self.ask_admin_email()
        # self.ask_admin_password()

    def generate(self):
        '''Generating seahub_settings.py'''
        print 'Generating seahub configuration ...\n'
        time.sleep(1)
        self.write_secret_key()
        with open(self.seahub_settings_py, 'a') as fp:
            self.write_database_config(fp)

    def write_secret_key(self):
        Utils.run_argv([Utils.get_python_executable(),
                        os.path.join(env_mgr.install_path, 'seahub',
                                     'tools', 'secret_key_generator.py'),
                        self.seahub_settings_py])

    def write_database_config(self, fp):
        template = '''\
\nDATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': '%(name)s',
        'USER': '%(username)s',
        'PASSWORD': '%(password)s',
        'HOST': '%(host)s',
        'PORT': '%(port)s'
    }
}

'''
        text = template % dict(name=db_config.seahub_db_name,
                               username=db_config.seafile_mysql_user,
                               password=db_config.seafile_mysql_password,
                               host=db_config.mysql_host,
                               port=db_config.mysql_port)

        fp.write(text)

    def ask_admin_email(self):
        print
        print '----------------------------------------'
        print 'Now let\'s create the admin account'
        print '----------------------------------------'
        def validate(email):
            # whitespace is not allowed
            if re.match(r'[\s]', email):
                raise InvalidAnswer('%s is not a valid email address' % Utils.highlight(email))
            # must be a valid email address
            if not re.match(r'^.+@.*\..+$', email):
                raise InvalidAnswer('%s is not a valid email address' % Utils.highlight(email))

            return email

        key = 'admin email'
        question = 'What is the ' + Utils.highlight('email') + ' for the admin account?'
        self.admin_email = Utils.ask_question(question,
                                              key=key,
                                              validate=validate)

    def ask_admin_password(self):
        def validate(password):
            key = 'admin password again'
            question = 'Enter the ' + Utils.highlight('password again:')
            password_again = Utils.ask_question(question,
                                                key=key,
                                                password=True)

            if password_again != password:
                raise InvalidAnswer('password mismatch')

            return password

        key = 'admin password'
        question = 'What is the ' + Utils.highlight('password') + ' for the admin account?'
        self.admin_password = Utils.ask_question(question,
                                                 key=key,
                                                 password=True,
                                                 validate=validate)

    def do_syncdb(self):
        print '----------------------------------------'
        print 'Now creating seahub database tables ...\n'
        print '----------------------------------------'

        try:
            conn = MySQLdb.connect(host=db_config.mysql_host,
                                   port=db_config.mysql_port,
                                   user=db_config.seafile_mysql_user,
                                   passwd=db_config.seafile_mysql_password,
                                   db=db_config.seahub_db_name)
        except Exception, e:
            if isinstance(e, MySQLdb.OperationalError):
                Utils.error('Failed to connect to mysql database %s: %s' % (db_config.seahub_db_name, e.args[1]))
            else:
                Utils.error('Failed to connect to mysql database %s: %s' % (db_config.seahub_db_name, e))

        cursor = conn.cursor()

        sql_file = os.path.join(env_mgr.install_path, 'seahub', 'sql', 'mysql.sql')
        with open(sql_file, 'r') as fp:
            content = fp.read()

        sqls = [line.strip() for line in content.split(';') if line.strip()]
        for sql in sqls:
            try:
                cursor.execute(sql)
            except Exception, e:
                if isinstance(e, MySQLdb.OperationalError):
                    Utils.error('Failed to init seahub database: %s' % e.args[1])
                else:
                    Utils.error('Failed to init seahub database: %s' % e)

        conn.commit()

    def prepare_avatar_dir(self):
        # media_dir=${INSTALLPATH}/seahub/media
        # orig_avatar_dir=${INSTALLPATH}/seahub/media/avatars
        # dest_avatar_dir=${TOPDIR}/seahub-data/avatars

        # if [[ ! -d ${dest_avatar_dir} ]]; then
        #     mkdir -p "${TOPDIR}/seahub-data"
        #     mv "${orig_avatar_dir}" "${dest_avatar_dir}"
        #     ln -s ../../../seahub-data/avatars ${media_dir}
        # fi

        try:
            media_dir = os.path.join(env_mgr.install_path, 'seahub', 'media')
            orig_avatar_dir = os.path.join(media_dir, 'avatars')

            seahub_data_dir = os.path.join(env_mgr.top_dir, 'seahub-data')
            dest_avatar_dir = os.path.join(seahub_data_dir, 'avatars')

            if os.path.exists(dest_avatar_dir):
                return

            if not os.path.exists(seahub_data_dir):
                os.mkdir(seahub_data_dir)

            shutil.move(orig_avatar_dir, dest_avatar_dir)
            os.symlink('../../../seahub-data/avatars', orig_avatar_dir)
        except Exception, e:
            Utils.error('Failed to prepare seahub avatars dir: %s' % e)

class SeafDavConfigurator(AbstractConfigurator):
    def __init__(self):
        AbstractConfigurator.__init__(self)
        self.seafdav_conf = None

    def ask_questions(self):
        pass

    def generate(self):
        self.seafdav_conf = os.path.join(env_mgr.central_config_dir, 'seafdav.conf')
        text = '''
[WEBDAV]
enabled = false
port = 8080
fastcgi = false
share_name = /
'''

        with open(self.seafdav_conf, 'w') as fp:
            fp.write(text)

class UserManualHandler(object):
    def __init__(self):
        self.src_docs_dir = os.path.join(env_mgr.install_path, 'seafile', 'docs')
        self.library_template_dir = None

    def copy_user_manuals(self):
        self.library_template_dir = os.path.join(seafile_config.seafile_dir, 'library-template')
        Utils.must_mkdir(self.library_template_dir)

        pattern = os.path.join(self.src_docs_dir, '*.doc')

        for doc in glob.glob(pattern):
            Utils.must_copy(doc, self.library_template_dir)

def report_config():
    print
    print '---------------------------------'
    print 'This is your configuration'
    print '---------------------------------'
    print

    template = '''\
    server name:            %(server_name)s
    server ip/domain:       %(ip_or_domain)s

    seafile data dir:       %(seafile_dir)s
    fileserver port:        %(fileserver_port)s

    database:               %(use_existing_db)s
    ccnet database:         %(ccnet_db_name)s
    seafile database:       %(seafile_db_name)s
    seahub database:        %(seahub_db_name)s
    database user:          %(db_user)s

'''
    config = {
        'server_name' :         ccnet_config.server_name,
        'ip_or_domain' :        ccnet_config.ip_or_domain,

        'seafile_dir' :         seafile_config.seafile_dir,
        'fileserver_port' :     seafile_config.fileserver_port,

        'admin_email' :         seahub_config.admin_email,


        'use_existing_db':       'use existing' if db_config.use_existing_db else 'create new',
        'ccnet_db_name':        db_config.ccnet_db_name,
        'seafile_db_name':      db_config.seafile_db_name,
        'seahub_db_name':       db_config.seahub_db_name,
        'db_user':              db_config.seafile_mysql_user
    }

    print template % config

    if need_pause:
        print
        print '---------------------------------'
        print 'Press ENTER to continue, or Ctrl-C to abort'
        print '---------------------------------'

        raw_input()


def create_seafile_server_symlink():
    print '\ncreating seafile-server-latest symbolic link ... ',
    seafile_server_symlink = os.path.join(env_mgr.top_dir, 'seafile-server-latest')
    try:
        os.symlink(os.path.basename(env_mgr.install_path), seafile_server_symlink)
    except Exception, e:
        print '\n'
        Utils.error('Failed to create symbolic link %s: %s' % (seafile_server_symlink, e))
    else:
        print 'done\n\n'

def set_file_perm():
    filemode = 0600
    dirmode = 0700
    files = [
        seahub_config.seahub_settings_py,
    ]
    dirs = [
        env_mgr.central_config_dir,
        ccnet_config.ccnet_dir,
        seafile_config.seafile_dir,
        seahub_config.seahub_settings_py,
    ]
    for fpath in files:
        os.chmod(fpath, filemode)
    for dpath in dirs:
        os.chmod(dpath, dirmode)

env_mgr = EnvManager()
ccnet_config = CcnetConfigurator()
seafile_config = SeafileConfigurator()
seafdav_config = SeafDavConfigurator()
seahub_config = SeahubConfigurator()
user_manuals_handler = UserManualHandler()
# Would be created after AbstractDBConfigurator.ask_use_existing_db()
db_config = None
need_pause = True

def get_param_val(arg, env, default=None):
    return arg or os.environ.get(env, default)

def check_params(args):
    host_name = socket.gethostname()
    if len(host_name) > 15:
        host_name = host_name[0:15]
    server_name = get_param_val(args.server_name, 'SERVER_NAME', host_name)
    ccnet_config.server_name = ccnet_config.validate_server_name(server_name)

    server_ip = get_param_val(args.server_ip, 'SERVER_IP',
                              socket.gethostbyname(socket.gethostname()))
    ccnet_config.ip_or_domain = ccnet_config.validate_server_ip(server_ip)

    fileserver_port = get_param_val(args.fileserver_port, 'FILESERVER_PORT', '8082')
    seafile_config.fileserver_port = Utils.validate_port(fileserver_port)

    seafile_dir = get_param_val(args.seafile_dir, 'SEAFILE_DIR',
                                os.path.join(env_mgr.top_dir, 'seafile-data'))
    seafile_config.seafile_dir = seafile_config.validate_seafile_dir(seafile_dir)

    global db_config

    use_existing_db = get_param_val(args.use_existing_db, 'USE_EXISTING_DB', '0')
    if use_existing_db == '0':
        db_config = NewDBConfigurator()
    elif use_existing_db == '1':
        db_config = ExistingDBConfigurator()
    else:
        raise InvalidParams('Invalid use existing db parameter, the value can only be 0 or 1')

    mysql_host = get_param_val(args.mysql_host, 'MYSQL_HOST', '127.0.0.1')
    if not mysql_host:
        raise InvalidParams('Incomplete mysql configuration parameters, ' \
                            'missing mysql host parameter')
    db_config.mysql_host = db_config.validate_mysql_host(mysql_host)

    mysql_port = get_param_val(args.mysql_port, 'MYSQL_PORT', '3306')
    db_config.mysql_port = Utils.validate_port(mysql_port)

    mysql_user = get_param_val(args.mysql_user, 'MYSQL_USER')
    if not mysql_user:
        raise InvalidParams('Incomplete mysql configuration parameters, ' \
                            'missing mysql user name parameter')

    mysql_user_passwd = get_param_val(args.mysql_user_passwd, 'MYSQL_USER_PASSWD')
    if not mysql_user_passwd:
        raise InvalidParams('Incomplete mysql configuration parameters, ' \
                            'missing mysql user password parameter')

    ccnet_db = get_param_val(args.ccnet_db, 'CCNET_DB', 'ccnet_db')
    if not ccnet_db:
        raise InvalidParams('Incomplete mysql configuration parameters, ' \
                            'missing ccnet db name parameter')

    seafile_db = get_param_val(args.seafile_db, 'SEAFILE_DB', 'seafile_db')
    if not seafile_db:
        raise InvalidParams('Incomplete mysql configuration parameters, ' \
                            'missing seafile db name parameter')

    seahub_db = get_param_val(args.seahub_db, 'SEAHUB_DB', 'seahub_db')
    if not seahub_db:
        raise InvalidParams('Incomplete mysql configuration parameters, ' \
                            'missing seahub db name parameter')

    mysql_user_host = get_param_val(args.mysql_user_host, 'MYSQL_USER_HOST')
    mysql_root_passwd = get_param_val(args.mysql_root_passwd, 'MYSQL_ROOT_PASSWD')

    if db_config.use_existing_db:
        db_config.check_mysql_user(mysql_user, mysql_user_passwd)
        db_config.seafile_mysql_user = mysql_user
        db_config.seafile_mysql_password = mysql_user_passwd
        db_config.ccnet_db_name = db_config.validate_db_name(ccnet_db)
        db_config.seafile_db_name = db_config.validate_db_name(seafile_db)
        db_config.seahub_db_name = db_config.validate_db_name(seahub_db)
    else:
        if db_config.mysql_host != '127.0.0.1' and not mysql_user_host:
            raise InvalidParams('mysql user host parameter is missing in creating new db mode')
        if not mysql_user_host:
            db_config.mysql_userhost = 'localhost'
        else:
            db_config.mysql_userhost = db_config.validate_mysql_user_host(mysql_user_host)

        if not mysql_root_passwd:
            raise InvalidParams('mysql root password parameter is missing in creating new db mode')
        db_config.root_password = db_config.validate_root_passwd(mysql_root_passwd)

        if mysql_user == 'root':
            db_config.seafile_mysql_user = 'root'
            db_config.seafile_mysql_password = db_config.root_password
        else:
            if db_config.mysql_user_exists(mysql_user):
                db_config.check_mysql_user(mysql_user, mysql_user_passwd)
            db_config.seafile_mysql_user = mysql_user
            db_config.seafile_mysql_password = mysql_user_passwd
        db_config.ccnet_db_name = ccnet_db
        db_config.seafile_db_name = seafile_db
        db_config.seahub_db_name = seahub_db

    global need_pause
    need_pause = False


def main():
    if len(sys.argv) > 2 and sys.argv[1] == 'auto':
        sys.argv.remove('auto')
        parser = argparse.ArgumentParser()
        parser.add_argument('-n', '--server-name', help='server name')
        parser.add_argument('-i', '--server-ip', help='server ip or domain')
        parser.add_argument('-p', '--fileserver-port', help='fileserver port')
        parser.add_argument('-d', '--seafile-dir', help='seafile dir to store seafile data')
        parser.add_argument('-e', '--use-existing-db',
                            help='use mysql existing dbs or create new dbs, '
                            '0: create new dbs 1: use existing dbs')
        parser.add_argument('-o', '--mysql-host', help='mysql host')
        parser.add_argument('-t', '--mysql-port', help='mysql port')
        parser.add_argument('-u', '--mysql-user', help='mysql user name')
        parser.add_argument('-w', '--mysql-user-passwd', help='mysql user password')
        parser.add_argument('-q', '--mysql-user-host', help='mysql user host')
        parser.add_argument('-r', '--mysql-root-passwd', help='mysql root password')
        parser.add_argument('-c', '--ccnet-db', help='ccnet db name')
        parser.add_argument('-s', '--seafile-db', help='seafile db name')
        parser.add_argument('-b', '--seahub-db', help='seahub db name')

        args = parser.parse_args()

        try:
            check_params(args)
        except (InvalidAnswer, InvalidParams) as e:
            print Utils.highlight('\n%s\n' % e)
            sys.exit(-1)

    global db_config

    if need_pause:
        Utils.welcome()
    warnings.filterwarnings('ignore', category=MySQLdb.Warning)

    env_mgr.check_pre_condiction()

    # Part 1: collect configuration
    ccnet_config.ask_questions()
    seafile_config.ask_questions()
    seahub_config.ask_questions()

    if not db_config:
        if AbstractDBConfigurator.ask_use_existing_db():
            db_config = ExistingDBConfigurator()
        else:
            db_config = NewDBConfigurator()

        db_config.ask_questions()

    report_config()

    # Part 2: generate configuration
    db_config.generate()
    ccnet_config.generate()
    seafile_config.generate()
    seafdav_config.generate()
    seahub_config.generate()

    seahub_config.do_syncdb()
    seahub_config.prepare_avatar_dir()
    # db_config.create_seahub_admin()
    user_manuals_handler.copy_user_manuals()
    create_seafile_server_symlink()

    set_file_perm()

    report_success()

def report_success():
    message = '''\


-----------------------------------------------------------------
Your seafile server configuration has been finished successfully.
-----------------------------------------------------------------

run seafile server:     ./seafile.sh { start | stop | restart }
run seahub  server:     ./seahub.sh  { start <port> | stop | restart <port> }

-----------------------------------------------------------------
If you are behind a firewall, remember to allow input/output of these tcp ports:
-----------------------------------------------------------------

port of seafile fileserver:   %(fileserver_port)s
port of seahub:               8000

When problems occur, Refer to

        %(server_manual_http)s

for information.

'''

    print message % dict(fileserver_port=seafile_config.fileserver_port,
                         server_manual_http=SERVER_MANUAL_HTTP)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print
        print Utils.highlight('The setup process is aborted')
        print
