#!/usr/bin/env python
# coding: UTF-8

'''This scirpt builds the seafile command line client (With no gui).

Some notes:

'''

import sys

####################
### Requires Python 2.6+
####################
if sys.version_info[0] == 3:
    print 'Python 3 not supported yet. Quit now.'
    sys.exit(1)
if sys.version_info[1] < 6:
    print 'Python 2.6 or above is required. Quit now.'
    sys.exit(1)

import os
import commands
import tempfile
import shutil
import re
import subprocess
import optparse
import atexit

####################
### Global variables
####################

# command line configuartion
conf = {}

# key names in the conf dictionary.
CONF_VERSION            = 'version'
CONF_SEAFILE_VERSION    = 'seafile_version'
CONF_LIBSEARPC_VERSION  = 'libsearpc_version'
CONF_CCNET_VERSION      = 'ccnet_version'
CONF_SRCDIR             = 'srcdir'
CONF_KEEP               = 'keep'
CONF_BUILDDIR           = 'builddir'
CONF_OUTPUTDIR          = 'outputdir'
CONF_THIRDPARTDIR       = 'thirdpartdir'
CONF_NO_STRIP           = 'nostrip'

####################
### Common helper functions
####################
def highlight(content, is_error=False):
    '''Add ANSI color to content to get it highlighted on terminal'''
    if is_error:
        return '\x1b[1;31m%s\x1b[m' % content
    else:
        return '\x1b[1;32m%s\x1b[m' % content

def info(msg):
    print highlight('[INFO] ') + msg

def exist_in_path(prog):
    '''Test whether prog exists in system path'''
    dirs = os.environ['PATH'].split(':')
    for d in dirs:
        if d == '':
            continue
        path = os.path.join(d, prog)
        if os.path.exists(path):
            return True

    return False

def prepend_env_value(name, value, seperator=':'):
    '''append a new value to a list'''
    try:
        current_value = os.environ[name]
    except KeyError:
        current_value = ''

    new_value = value
    if current_value:
        new_value += seperator + current_value

    os.environ[name] = new_value

def error(msg=None, usage=None):
    if msg:
        print highlight('[ERROR] ') + msg
    if usage:
        print usage
    sys.exit(1)

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

def must_mkdir(path):
    '''Create a directory, exit on failure'''
    try:
        os.mkdir(path)
    except OSError, e:
        error('failed to create directory %s:%s' % (path, e))

def must_copy(src, dst):
    '''Copy src to dst, exit on failure'''
    try:
        shutil.copy(src, dst)
    except Exception, e:
        error('failed to copy %s to %s: %s' % (src, dst, e))

class Project(object):
    '''Base class for a project'''
    # Probject name, i.e. libseaprc/ccnet/seafile/
    name = ''

    # A list of shell commands to configure/build the project
    build_commands = []

    def __init__(self):
        # the path to pass to --prefix=/<prefix>
        self.prefix = os.path.join(conf[CONF_BUILDDIR], 'seafile-cli')
        self.version = self.get_version()
        self.src_tarball = os.path.join(conf[CONF_SRCDIR],
                            '%s-%s.tar.gz' % (self.name, self.version))
        # project dir, like <builddir>/seafile-1.2.2/
        self.projdir = os.path.join(conf[CONF_BUILDDIR], '%s-%s' % (self.name, self.version))

    def get_version(self):
        # libsearpc and ccnet can have different versions from seafile.
        raise NotImplementedError

    def get_source_commit_id(self):
        '''By convetion, we record the commit id of the source code in the
        file "<projdir>/latest_commit"

        '''
        latest_commit_file = os.path.join(self.projdir, 'latest_commit')
        with open(latest_commit_file, 'r') as fp:
            commit_id = fp.read().strip('\n\r\t ')

        return commit_id

    def append_cflags(self, macros):
        cflags = ' '.join([ '-D%s=%s' % (k, macros[k]) for k in macros ])
        prepend_env_value('CPPFLAGS',
                          cflags,
                          seperator=' ')

    def uncompress(self):
        '''Uncompress the source from the tarball'''
        info('Uncompressing %s' % self.name)

        if run('tar xf %s' % self.src_tarball) < 0:
            error('failed to uncompress source of %s' % self.name)

    def before_build(self):
        '''Hook method to do project-specific stuff before running build commands'''
        pass

    def build(self):
        '''Build the source'''
        self.before_build()
        info('Building %s' % self.name)
        for cmd in self.build_commands:
            if run(cmd, cwd=self.projdir) != 0:
                error('error when running command:\n\t%s\n' % cmd)

class Libsearpc(Project):
    name = 'libsearpc'

    def __init__(self):
        Project.__init__(self)
        self.build_commands = [
            './configure --prefix=%s --disable-compile-demo' % self.prefix,
            'make',
            'make install'
        ]

    def get_version(self):
        return conf[CONF_LIBSEARPC_VERSION]

class Ccnet(Project):
    name = 'ccnet'
    def __init__(self):
        Project.__init__(self)
        self.build_commands = [
            './configure --prefix=%s --disable-compile-demo' % self.prefix,
            'make',
            'make install'
        ]

    def get_version(self):
        return conf[CONF_CCNET_VERSION]

    def before_build(self):
        macros = {}
        # SET CCNET_SOURCE_COMMIT_ID, so it can be printed in the log
        macros['CCNET_SOURCE_COMMIT_ID'] = '\\"%s\\"' % self.get_source_commit_id()

        self.append_cflags(macros)

class Seafile(Project):
    name = 'seafile'
    def __init__(self):
        Project.__init__(self)
        self.build_commands = [
            './configure --prefix=%s --disable-gui' % self.prefix,
            'make',
            'make install'
        ]

    def get_version(self):
        return conf[CONF_SEAFILE_VERSION]

    def update_cli_version(self):
        '''Substitute the version number in seaf-cli'''
        cli_py = os.path.join(self.projdir, 'app', 'seaf-cli')
        with open(cli_py, 'r') as fp:
            lines = fp.readlines()

        ret = []
        for line in lines:
            old = '''SEAF_CLI_VERSION = ""'''
            new = '''SEAF_CLI_VERSION = "%s"''' % conf[CONF_VERSION]
            line = line.replace(old, new)
            ret.append(line)

        with open(cli_py, 'w') as fp:
            fp.writelines(ret)

    def before_build(self):
        self.update_cli_version()
        macros = {}
        # SET SEAFILE_SOURCE_COMMIT_ID, so it can be printed in the log
        macros['SEAFILE_SOURCE_COMMIT_ID'] = '\\"%s\\"' % self.get_source_commit_id()
        self.append_cflags(macros)

def check_targz_src(proj, version, srcdir):
    src_tarball = os.path.join(srcdir, '%s-%s.tar.gz' % (proj, version))
    if not os.path.exists(src_tarball):
        error('%s not exists' % src_tarball)

def validate_args(usage, options):
    required_args = [
        CONF_VERSION,
        CONF_LIBSEARPC_VERSION,
        CONF_CCNET_VERSION,
        CONF_SEAFILE_VERSION,
        CONF_SRCDIR,
    ]

    # fist check required args
    for optname in required_args:
        if getattr(options, optname, None) == None:
            error('%s must be specified' % optname, usage=usage)

    def get_option(optname):
        return getattr(options, optname)

    # [ version ]
    def check_project_version(version):
        '''A valid version must be like 1.2.2, 1.3'''
        if not re.match('^[0-9]+(\.([0-9])+)+$', version):
            error('%s is not a valid version' % version, usage=usage)

    version = get_option(CONF_VERSION)
    seafile_version = get_option(CONF_SEAFILE_VERSION)
    libsearpc_version = get_option(CONF_LIBSEARPC_VERSION)
    ccnet_version = get_option(CONF_CCNET_VERSION)

    check_project_version(version)
    check_project_version(libsearpc_version)
    check_project_version(ccnet_version)
    check_project_version(seafile_version)

    # [ srcdir ]
    srcdir = get_option(CONF_SRCDIR)
    check_targz_src('libsearpc', libsearpc_version, srcdir)
    check_targz_src('ccnet', ccnet_version, srcdir)
    check_targz_src('seafile', seafile_version, srcdir)

    # [ builddir ]
    builddir = get_option(CONF_BUILDDIR)
    if not os.path.exists(builddir):
        error('%s does not exist' % builddir, usage=usage)

    builddir = os.path.join(builddir, 'seafile-cli-build')

    # [ outputdir ]
    outputdir = get_option(CONF_OUTPUTDIR)
    if outputdir:
        if not os.path.exists(outputdir):
            error('outputdir %s does not exist' % outputdir, usage=usage)
    else:
        outputdir = os.getcwd()

    # [ keep ]
    keep = get_option(CONF_KEEP)

    # [ no strip]
    nostrip = get_option(CONF_NO_STRIP)

    conf[CONF_VERSION] = version
    conf[CONF_LIBSEARPC_VERSION] = libsearpc_version
    conf[CONF_SEAFILE_VERSION] = seafile_version
    conf[CONF_CCNET_VERSION] = ccnet_version

    conf[CONF_BUILDDIR] = builddir
    conf[CONF_SRCDIR] = srcdir
    conf[CONF_OUTPUTDIR] = outputdir
    conf[CONF_KEEP] = keep
    conf[CONF_NO_STRIP] = nostrip

    prepare_builddir(builddir)
    show_build_info()

def show_build_info():
    '''Print all conf information. Confirm before continue.'''
    info('------------------------------------------')
    info('Seafile command line client %s: BUILD INFO' % conf[CONF_VERSION])
    info('------------------------------------------')
    info('seafile:          %s' % conf[CONF_SEAFILE_VERSION])
    info('ccnet:            %s' % conf[CONF_CCNET_VERSION])
    info('libsearpc:        %s' % conf[CONF_LIBSEARPC_VERSION])
    info('builddir:         %s' % conf[CONF_BUILDDIR])
    info('outputdir:        %s' % conf[CONF_OUTPUTDIR])
    info('source dir:       %s' % conf[CONF_SRCDIR])
    info('strip symbols:    %s' % (not conf[CONF_NO_STRIP]))
    info('clean on exit:    %s' % (not conf[CONF_KEEP]))
    info('------------------------------------------')
    info('press any key to continue ')
    info('------------------------------------------')
    dummy = raw_input()

def prepare_builddir(builddir):
    must_mkdir(builddir)

    if not conf[CONF_KEEP]:
        def remove_builddir():
            '''Remove the builddir when exit'''
            info('remove builddir before exit')
            shutil.rmtree(builddir, ignore_errors=True)
        atexit.register(remove_builddir)

    os.chdir(builddir)

    must_mkdir(os.path.join(builddir, 'seafile-cli'))

def parse_args():
    parser = optparse.OptionParser()
    def long_opt(opt):
        return '--' + opt

    parser.add_option(long_opt(CONF_VERSION),
                      dest=CONF_VERSION,
                      nargs=1,
                      help='the version to build. Must be digits delimited by dots, like 1.3.0')

    parser.add_option(long_opt(CONF_SEAFILE_VERSION),
                      dest=CONF_SEAFILE_VERSION,
                      nargs=1,
                      help='the version of seafile as specified in its "configure.ac". Must be digits delimited by dots, like 1.3.0')

    parser.add_option(long_opt(CONF_LIBSEARPC_VERSION),
                      dest=CONF_LIBSEARPC_VERSION,
                      nargs=1,
                      help='the version of libsearpc as specified in its "configure.ac". Must be digits delimited by dots, like 1.3.0')

    parser.add_option(long_opt(CONF_CCNET_VERSION),
                      dest=CONF_CCNET_VERSION,
                      nargs=1,
                      help='the version of ccnet as specified in its "configure.ac". Must be digits delimited by dots, like 1.3.0')

    parser.add_option(long_opt(CONF_BUILDDIR),
                      dest=CONF_BUILDDIR,
                      nargs=1,
                      help='the directory to build the source. Defaults to /tmp',
                      default=tempfile.gettempdir())

    parser.add_option(long_opt(CONF_OUTPUTDIR),
                      dest=CONF_OUTPUTDIR,
                      nargs=1,
                      help='the output directory to put the generated tarball. Defaults to the current directory.',
                      default=os.getcwd())

    parser.add_option(long_opt(CONF_SRCDIR),
                      dest=CONF_SRCDIR,
                      nargs=1,
                      help='''Source tarballs must be placed in this directory.''')

    parser.add_option(long_opt(CONF_KEEP),
                      dest=CONF_KEEP,
                      action='store_true',
                      help='''keep the build directory after the script exits. By default, the script would delete the build directory at exit.''')

    parser.add_option(long_opt(CONF_NO_STRIP),
                      dest=CONF_NO_STRIP,
                      action='store_true',
                      help='''do not strip debug symbols''')
    usage = parser.format_help()
    options, remain = parser.parse_args()
    if remain:
        error(usage=usage)

    validate_args(usage, options)

def setup_build_env():
    '''Setup environment variables, such as export PATH=$BUILDDDIR/bin:$PATH'''
    prefix = os.path.join(conf[CONF_BUILDDIR], 'seafile-cli')

    prepend_env_value('CPPFLAGS',
                     '-I%s' % os.path.join(prefix, 'include'),
                     seperator=' ')

    prepend_env_value('CPPFLAGS',
                     '-DSEAFILE_CLIENT_VERSION=\\"%s\\"' % conf[CONF_VERSION],
                     seperator=' ')

    if conf[CONF_NO_STRIP]:
        prepend_env_value('CPPFLAGS',
                         '-g -O0',
                         seperator=' ')

    prepend_env_value('LDFLAGS',
                     '-L%s' % os.path.join(prefix, 'lib'),
                     seperator=' ')

    prepend_env_value('LDFLAGS',
                     '-L%s' % os.path.join(prefix, 'lib64'),
                     seperator=' ')

    prepend_env_value('PATH', os.path.join(prefix, 'bin'))
    prepend_env_value('PKG_CONFIG_PATH', os.path.join(prefix, 'lib', 'pkgconfig'))
    prepend_env_value('PKG_CONFIG_PATH', os.path.join(prefix, 'lib64', 'pkgconfig'))

def copy_scripts_and_libs():
    '''Copy scripts and shared libs'''
    builddir = conf[CONF_BUILDDIR]
    seafile_dir = os.path.join(builddir, Seafile().projdir)
    scripts_srcdir = os.path.join(seafile_dir, 'scripts')
    doc_dir = os.path.join(seafile_dir, 'doc')
    cli_dir = os.path.join(builddir, 'seafile-cli')

    # copy the wrapper shell script for seaf-cli.py
    src = os.path.join(scripts_srcdir, 'seaf-cli-wrapper.sh')
    dst = os.path.join(cli_dir, 'seaf-cli')

    must_copy(src, dst)

    # copy Readme for cli client
    src = os.path.join(doc_dir, 'cli-readme.txt')
    dst = os.path.join(cli_dir, 'Readme.txt')

    must_copy(src, dst)

    # rename seaf-cli to seaf-cli.py to avoid confusing users
    src = os.path.join(cli_dir, 'bin', 'seaf-cli')
    dst = os.path.join(cli_dir, 'bin', 'seaf-cli.py')

    try:
        shutil.move(src, dst)
    except Exception, e:
        error('failed to move %s to %s: %s' % (src, dst, e))

    # copy shared c libs
    copy_shared_libs()

def get_dependent_libs(executable):
    syslibs = ['libsearpc', 'libccnet', 'libseafile', 'libpthread.so', 'libc.so', 'libm.so', 'librt.so', 'libdl.so', 'libselinux.so']
    def is_syslib(lib):
        for syslib in syslibs:
            if syslib in lib:
                return True
        return False

    ldd_output = commands.getoutput('ldd %s' % executable)
    ret = []
    for line in ldd_output.splitlines():
        tokens = line.split()
        if len(tokens) != 4:
            continue
        if is_syslib(tokens[0]):
            continue

        ret.append(tokens[2])

    return ret

def copy_shared_libs():
    '''copy shared c libs, such as libevent, glib, libmysqlclient'''
    builddir = conf[CONF_BUILDDIR]

    dst_dir = os.path.join(builddir,
                           'seafile-cli',
                           'lib')

    ccnet_daemon_path = os.path.join(builddir,
                                     'seafile-cli',
                                     'bin',
                                     'ccnet')

    seaf_daemon_path = os.path.join(builddir,
                                    'seafile-cli',
                                    'bin',
                                    'seaf-daemon')

    ccnet_daemon_libs = get_dependent_libs(ccnet_daemon_path)
    seaf_daemon_libs = get_dependent_libs(seaf_daemon_path)

    libs = ccnet_daemon_libs
    for lib in seaf_daemon_libs:
        if lib not in libs:
            libs.append(lib)

    for lib in libs:
        info('Copying %s' % lib)
        shutil.copy(lib, dst_dir)

def strip_symbols():
    def do_strip(fn):
        run('chmod u+w %s' % fn)
        info('stripping:    %s' % fn)
        run('strip "%s"' % fn)

    def remove_static_lib(fn):
        info('removing:     %s' % fn)
        os.remove(fn)

    builddir = conf[CONF_BUILDDIR]
    topdir = os.path.join(builddir, 'seafile-cli')
    for parent, dnames, fnames in os.walk(topdir):
        dummy = dnames          # avoid pylint 'unused' warning
        for fname in fnames:
            fn = os.path.join(parent, fname)
            if os.path.isdir(fn):
                continue

            if fn.endswith(".a") or fn.endswith(".la"):
                remove_static_lib(fn)
                continue

            if os.path.islink(fn):
                continue

            finfo = commands.getoutput('file "%s"' % fn)

            if 'not stripped' in finfo:
                do_strip(fn)

def create_tarball(tarball_name):
    '''call tar command to generate a tarball'''
    version  = conf[CONF_VERSION]

    cli_dir = 'seafile-cli'
    versioned_cli_dir = 'seafile-cli-' + version

    # move seafile-cli to seafile-cli-${version}
    try:
        shutil.move(cli_dir, versioned_cli_dir)
    except Exception, e:
        error('failed to move %s to %s: %s' % (cli_dir, versioned_cli_dir, e))

    ignored_patterns = [
        # common ignored files
        '*.pyc',
        '*~',
        '*#',

        # seafile
        os.path.join(versioned_cli_dir, 'share*'),
        os.path.join(versioned_cli_dir, 'include*'),
        os.path.join(versioned_cli_dir, 'lib', 'pkgconfig*'),
        os.path.join(versioned_cli_dir, 'lib64', 'pkgconfig*'),
        os.path.join(versioned_cli_dir, 'bin', 'ccnet-demo*'),
        os.path.join(versioned_cli_dir, 'bin', 'ccnet-tool'),
        os.path.join(versioned_cli_dir, 'bin', 'ccnet-servtool'),
        os.path.join(versioned_cli_dir, 'bin', 'searpc-codegen.py'),
        os.path.join(versioned_cli_dir, 'bin', 'seafile-admin'),
        os.path.join(versioned_cli_dir, 'bin', 'seafile'),
    ]

    excludes_list = [ '--exclude=%s' % pattern for pattern in ignored_patterns ]
    excludes = ' '.join(excludes_list)

    tar_cmd = 'tar czvf %(tarball_name)s %(versioned_cli_dir)s %(excludes)s' \
              % dict(tarball_name=tarball_name,
                     versioned_cli_dir=versioned_cli_dir,
                     excludes=excludes)

    if run(tar_cmd) != 0:
        error('failed to generate the tarball')

def gen_tarball():
    # strip symbols of libraries to reduce size
    if not conf[CONF_NO_STRIP]:
        try:
            strip_symbols()
        except Exception, e:
            error('failed to strip symbols: %s' % e)

    # determine the output name
    # 64-bit: seafile-cli_1.2.2_x86-64.tar.gz
    # 32-bit: seafile-cli_1.2.2_i386.tar.gz
    version = conf[CONF_VERSION]
    arch = os.uname()[-1].replace('_', '-')
    if arch != 'x86-64':
        arch = 'i386'

    dbg = ''
    if conf[CONF_NO_STRIP]:
        dbg = '.dbg'

    tarball_name = 'seafile-cli_%(version)s_%(arch)s%(dbg)s.tar.gz' \
                   % dict(version=version, arch=arch, dbg=dbg)
    dst_tarball = os.path.join(conf[CONF_OUTPUTDIR], tarball_name)

    # generate the tarball
    try:
        create_tarball(tarball_name)
    except Exception, e:
        error('failed to generate tarball: %s' % e)

    # move tarball to outputdir
    try:
        shutil.copy(tarball_name, dst_tarball)
    except Exception, e:
        error('failed to copy %s to %s: %s' % (tarball_name, dst_tarball, e))

    print '---------------------------------------------'
    print 'The build is successfully. Output is:\t%s' % dst_tarball
    print '---------------------------------------------'

def main():
    parse_args()
    setup_build_env()

    libsearpc = Libsearpc()
    ccnet = Ccnet()
    seafile = Seafile()

    libsearpc.uncompress()
    libsearpc.build()

    ccnet.uncompress()
    ccnet.build()

    seafile.uncompress()
    seafile.build()

    copy_scripts_and_libs()
    gen_tarball()

if __name__ == '__main__':
    main()
