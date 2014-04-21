#coding: UTF-8

'''This script would check if there is admin, and prompt the user to create a new one if non exist'''

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

### END of Utils
####################

class RPC(object):
    def __init__(self):
        import ccnet
        ccnet_dir = os.environ['CCNET_CONF_DIR']
        self.rpc_client = ccnet.CcnetThreadedRpcClient(ccnet.ClientPool(ccnet_dir))

    def get_db_email_users(self):
        return self.rpc_client.get_emailusers('DB', 0, 1)

    def create_admin(self, email, user):
        return self.rpc_client.add_emailuser(email, user, 1, 1)

def need_create_admin():
    users = rpc.get_db_email_users()
    return len(users) == 0

def create_admin(email, passwd):
    if rpc.create_admin(email, passwd) < 0:
        raise Exception('failed to create admin')
    else:
        print '\n\n'
        print '----------------------------------------'
        print 'Successfully created seafile admin'
        print '----------------------------------------'
        print '\n\n'

def ask_admin_email():
    print
    print '----------------------------------------'
    print 'It\'s the first time you start the seafile server. Now let\'s create the admin account'
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
    return Utils.ask_question(question,
                              key=key,
                              validate=validate)

def ask_admin_password():
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
    return Utils.ask_question(question,
                              key=key,
                              password=True,
                              validate=validate)

rpc = RPC()

def main():
    if not need_create_admin():
        return

    email = ask_admin_email()
    passwd = ask_admin_password()

    create_admin(email, passwd)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print '\n\n\n'
        print Utils.highlight('Aborted.')
        print
        sys.exit(1)
    except Exception, e:
        print
        print Utils.highlight('Error happened during creating seafile admin.')
        print
