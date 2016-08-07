#!/usr/bin/env python
# coding: UTF-8

'''This script builds the seafile server tarball.

Some notes:

1. The working directory is always the 'builddir'. 'os.chdir' is only called
to change to the 'builddir'. We make use of the 'cwd' argument in
'subprocess.Popen' to run a command in a specific directory.

2. django/djangorestframework/djblets/gunicorn/flup must be easy_install-ed to
a directory before running this script. That directory is passed in as the
'--thirdpartdir' arguments.

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
import glob
import commands
import tempfile
import shutil
import re
import subprocess
import optparse
import atexit
import platform

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
CONF_ENABLE_S3          = 's3'
CONF_YES                = 'yes'
CONF_JOBS               = 'jobs'

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

def find_in_path(prog):
    '''Find a file in system path'''
    dirs = os.environ['PATH'].split(':')
    for d in dirs:
        if d == '':
            continue
        path = os.path.join(d, prog)
        if os.path.exists(path):
            return path

    return None

def error(msg=None, usage=None):
    if msg:
        print highlight('[ERROR] ') + msg
    if usage:
        print usage
    sys.exit(1)

def run_argv(argv, cwd=None, env=None, suppress_stdout=False, suppress_stderr=False):
    '''Run a program and wait for it to finish, and return its exit code. The
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
    # Probject name, i.e. libseaprc/ccnet/seafile/seahub
    name = ''

    # A list of shell commands to configure/build the project
    build_commands = []

    def __init__(self):
        # the path to pass to --prefix=/<prefix>
        self.prefix = os.path.join(conf[CONF_BUILDDIR], 'seafile-server', 'seafile')
        self.version = self.get_version()
        self.src_tarball = os.path.join(conf[CONF_SRCDIR],
                            '%s-%s.tar.gz' % (self.name, self.version))
        # project dir, like <builddir>/seafile-1.2.2/
        self.projdir = os.path.join(conf[CONF_BUILDDIR], '%s-%s' % (self.name, self.version))

    def get_version(self):
        # libsearpc and ccnet can have different versions from seafile.
        raise NotImplementedError

    def uncompress(self):
        '''Uncompress the source from the tarball'''
        info('Uncompressing %s' % self.name)

        if run('tar xf %s' % self.src_tarball) < 0:
            error('failed to uncompress source of %s' % self.name)

    def build(self):
        '''Build the source'''
        info('Building %s' % self.name)
        for cmd in self.build_commands:
            if run(cmd, cwd=self.projdir) != 0:
                error('error when running command:\n\t%s\n' % cmd)

class Libsearpc(Project):
    name = 'libsearpc'

    def __init__(self):
        Project.__init__(self)
        self.build_commands = [
            './configure --prefix=%s' % self.prefix,
            'make -j%s' % conf[CONF_JOBS],
            'make install'
        ]

    def get_version(self):
        return conf[CONF_LIBSEARPC_VERSION]

class Ccnet(Project):
    name = 'ccnet'
    def __init__(self):
        Project.__init__(self)
        self.build_commands = [
            './configure --prefix=%s --disable-client --enable-server --enable-pgsql --enable-ldap' % self.prefix,
            'make -j%s' % conf[CONF_JOBS],
            'make install'
        ]

    def get_version(self):
        return conf[CONF_CCNET_VERSION]

class Seafile(Project):
    name = 'seafile'
    def __init__(self):
        Project.__init__(self)
        s3_support = ''
        if conf[CONF_ENABLE_S3]:
            s3_support = '--enable-s3'

        self.build_commands = [
            './configure --prefix=%s --disable-client --enable-server --enable-pgsql %s' \
                % (self.prefix, s3_support),
            'make -j%s' % conf[CONF_JOBS],
            'make install'
        ]

    def get_version(self):
        return conf[CONF_SEAFILE_VERSION]

class Seahub(Project):
    name = 'seahub'
    def __init__(self):
        Project.__init__(self)
        # nothing to do for seahub
        self.build_commands = [
        ]

    def get_version(self):
        return conf[CONF_SEAFILE_VERSION]

    def build(self):
        self.write_version_to_settings_py()

        Project.build(self)

    def write_version_to_settings_py(self):
        '''Write the version of current seafile server to seahub'''
        settings_py = os.path.join(self.projdir, 'seahub', 'settings.py')

        line = '\nSEAFILE_VERSION = "%s"\n' % conf[CONF_VERSION]
        with open(settings_py, 'a+') as fp:
            fp.write(line)


def check_seahub_thirdpart(thirdpartdir):
    '''The ${thirdpartdir} must have django/djblets/gunicorn pre-installed. So
    we can copy it to seahub/thirdpart

    '''
    thirdpart_libs = [
        'Django',
        # 'Djblets',
        'gunicorn',
        'flup',
        'chardet',
        'python_dateutil',
        'django_picklefield',
        'django_constance',
        # 'SQLAlchemy',
        # 'python_daemon',
        # 'lockfile',
        # 'six',
    ]
    def check_thirdpart_lib(name):
        name += '*'
        if not glob.glob(os.path.join(thirdpartdir, name)):
            error('%s not found in %s' % (name, thirdpartdir))

    for lib in thirdpart_libs:
        check_thirdpart_lib(lib)

def check_targz_src(proj, version, srcdir):
    src_tarball = os.path.join(srcdir, '%s-%s.tar.gz' % (proj, version))
    if not os.path.exists(src_tarball):
        error('%s not exists' % src_tarball)

def check_targz_src_no_version(proj, srcdir):
    src_tarball = os.path.join(srcdir, '%s.tar.gz' % proj)
    if not os.path.exists(src_tarball):
        error('%s not exists' % src_tarball)

def check_pdf2htmlEX():
    pdf2htmlEX_executable = find_in_path('pdf2htmlEX')
    if pdf2htmlEX_executable is None:
        error('pdf2htmlEX not found')

def validate_args(usage, options):
    required_args = [
        CONF_VERSION,
        CONF_LIBSEARPC_VERSION,
        CONF_CCNET_VERSION,
        CONF_SEAFILE_VERSION,
        CONF_SRCDIR,
        CONF_THIRDPARTDIR,
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
    check_targz_src('seahub', seafile_version, srcdir)
    check_targz_src_no_version('seafdav', srcdir)
    check_targz_src_no_version('seafobj', srcdir)

    # check_pdf2htmlEX()

    # [ builddir ]
    builddir = get_option(CONF_BUILDDIR)
    if not os.path.exists(builddir):
        error('%s does not exist' % builddir, usage=usage)

    builddir = os.path.join(builddir, 'seafile-server-build')

    # [ thirdpartdir ]
    thirdpartdir = get_option(CONF_THIRDPARTDIR)
    check_seahub_thirdpart(thirdpartdir)

    # [ outputdir ]
    outputdir = get_option(CONF_OUTPUTDIR)
    if outputdir:
        if not os.path.exists(outputdir):
            error('outputdir %s does not exist' % outputdir, usage=usage)
    else:
        outputdir = os.getcwd()

    # [ yes ]
    yes = get_option(CONF_YES)

    # [ jobs ]
    jobs = get_option(CONF_JOBS)

    # [ keep ]
    keep = get_option(CONF_KEEP)

    # [ no strip]
    nostrip = get_option(CONF_NO_STRIP)

    # [ s3 ]
    s3 = get_option(CONF_ENABLE_S3)

    conf[CONF_VERSION] = version
    conf[CONF_LIBSEARPC_VERSION] = libsearpc_version
    conf[CONF_SEAFILE_VERSION] = seafile_version
    conf[CONF_CCNET_VERSION] = ccnet_version

    conf[CONF_BUILDDIR] = builddir
    conf[CONF_SRCDIR] = srcdir
    conf[CONF_OUTPUTDIR] = outputdir
    conf[CONF_KEEP] = keep
    conf[CONF_THIRDPARTDIR] = thirdpartdir
    conf[CONF_NO_STRIP] = nostrip
    conf[CONF_ENABLE_S3] = s3
    conf[CONF_YES] = yes
    conf[CONF_JOBS] = jobs

    prepare_builddir(builddir)
    show_build_info()

def show_build_info():
    '''Print all conf information. Confirm before continue.'''
    info('------------------------------------------')
    info('Seafile server %s: BUILD INFO' % conf[CONF_VERSION])
    info('------------------------------------------')
    info('seafile:          %s' % conf[CONF_SEAFILE_VERSION])
    info('ccnet:            %s' % conf[CONF_CCNET_VERSION])
    info('libsearpc:        %s' % conf[CONF_LIBSEARPC_VERSION])
    info('builddir:         %s' % conf[CONF_BUILDDIR])
    info('outputdir:        %s' % conf[CONF_OUTPUTDIR])
    info('source dir:       %s' % conf[CONF_SRCDIR])
    info('strip symbols:    %s' % (not conf[CONF_NO_STRIP]))
    info('s3 support:       %s' % (conf[CONF_ENABLE_S3]))
    info('clean on exit:    %s' % (not conf[CONF_KEEP]))
    if conf[CONF_YES]:
        return
    info('------------------------------------------')
    info('press any key to continue ')
    info('------------------------------------------')
    raw_input()

def prepare_builddir(builddir):
    must_mkdir(builddir)

    if not conf[CONF_KEEP]:
        def remove_builddir():
            '''Remove the builddir when exit'''
            info('remove builddir before exit')
            shutil.rmtree(builddir, ignore_errors=True)
        atexit.register(remove_builddir)

    os.chdir(builddir)

    must_mkdir(os.path.join(builddir, 'seafile-server'))
    must_mkdir(os.path.join(builddir, 'seafile-server', 'seafile'))

def parse_args():
    parser = optparse.OptionParser()
    def long_opt(opt):
        return '--' + opt

    parser.add_option(long_opt(CONF_YES),
                      dest=CONF_YES,
                      action='store_true')

    parser.add_option(long_opt(CONF_JOBS),
                      dest=CONF_JOBS,
                      default=2,
                      type=int)

    parser.add_option(long_opt(CONF_THIRDPARTDIR),
                      dest=CONF_THIRDPARTDIR,
                      nargs=1,
                      help='where to find the thirdpart libs for seahub')

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
                      help='the output directory to put the generated server tarball. Defaults to the current directory.',
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

    parser.add_option(long_opt(CONF_ENABLE_S3),
                      dest=CONF_ENABLE_S3,
                      action='store_true',
                      help='''enable amazon s3 support''')
    usage = parser.format_help()
    options, remain = parser.parse_args()
    if remain:
        error(usage=usage)

    validate_args(usage, options)

def setup_build_env():
    '''Setup environment variables, such as export PATH=$BUILDDDIR/bin:$PATH'''
    prefix = os.path.join(conf[CONF_BUILDDIR], 'seafile-server', 'seafile')
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

    prepend_env_value('CPPFLAGS',
                     '-I%s' % os.path.join(prefix, 'include'),
                     seperator=' ')

    prepend_env_value('CPPFLAGS',
                     '-DLIBICONV_PLUG',
                     seperator=' ')

    if conf[CONF_NO_STRIP]:
        prepend_env_value('CPPFLAGS',
                         '-g -O0',
                         seperator=' ')

        prepend_env_value('CFLAGS',
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

def copy_user_manuals():
    builddir = conf[CONF_BUILDDIR]
    # src_pattern = os.path.join(builddir, Seafile().projdir, 'doc', '*.doc')
    src_pattern = os.path.join(builddir, Seafile().projdir, 'doc', 'seafile-tutorial.doc')
    dst_dir = os.path.join(builddir, 'seafile-server', 'seafile', 'docs')

    must_mkdir(dst_dir)

    for path in glob.glob(src_pattern):
        must_copy(path, dst_dir)

def copy_seafdav():
    dst_dir = os.path.join(conf[CONF_BUILDDIR], 'seafile-server', 'seahub', 'thirdpart')
    tarball = os.path.join(conf[CONF_SRCDIR], 'seafdav.tar.gz')
    if run('tar xf %s -C %s' % (tarball, dst_dir)) != 0:
        error('failed to uncompress %s' % tarball)

    dst_dir = os.path.join(conf[CONF_BUILDDIR], 'seafile-server', 'seahub', 'thirdpart')
    tarball = os.path.join(conf[CONF_SRCDIR], 'seafobj.tar.gz')
    if run('tar xf %s -C %s' % (tarball, dst_dir)) != 0:
        error('failed to uncompress %s' % tarball)

def copy_scripts_and_libs():
    '''Copy server release scripts and shared libs, as well as seahub
    thirdpart libs

    '''
    builddir = conf[CONF_BUILDDIR]
    scripts_srcdir = os.path.join(builddir, Seafile().projdir, 'scripts')
    serverdir = os.path.join(builddir, 'seafile-server')

    must_copy(os.path.join(scripts_srcdir, 'setup-seafile.sh'),
              serverdir)
    must_copy(os.path.join(scripts_srcdir, 'setup-seafile-mysql.sh'),
              serverdir)
    must_copy(os.path.join(scripts_srcdir, 'setup-seafile-mysql.py'),
              serverdir)
    must_copy(os.path.join(scripts_srcdir, 'seafile.sh'),
              serverdir)
    must_copy(os.path.join(scripts_srcdir, 'seahub.sh'),
              serverdir)
    must_copy(os.path.join(scripts_srcdir, 'reset-admin.sh'),
              serverdir)
    must_copy(os.path.join(scripts_srcdir, 'seaf-fuse.sh'),
              serverdir)
    must_copy(os.path.join(scripts_srcdir, 'check_init_admin.py'),
              serverdir)
    must_copy(os.path.join(scripts_srcdir, 'seaf-gc.sh'),
              serverdir)
    must_copy(os.path.join(scripts_srcdir, 'seaf-fsck.sh'),
              serverdir)

    # copy update scripts
    update_scriptsdir = os.path.join(scripts_srcdir, 'upgrade')
    dst_update_scriptsdir = os.path.join(serverdir, 'upgrade')
    try:
        shutil.copytree(update_scriptsdir, dst_update_scriptsdir)
    except Exception, e:
        error('failed to copy upgrade scripts: %s' % e)

    # copy runtime/seahub.conf
    runtimedir = os.path.join(serverdir, 'runtime')
    must_mkdir(runtimedir)
    must_copy(os.path.join(scripts_srcdir, 'seahub.conf'),
              runtimedir)

    # move seahub to seafile-server/seahub
    src_seahubdir = Seahub().projdir
    dst_seahubdir = os.path.join(serverdir, 'seahub')
    try:
        shutil.move(src_seahubdir, dst_seahubdir)
    except Exception, e:
        error('failed to move seahub to seafile-server/seahub: %s' % e)

    # copy seahub thirdpart libs
    seahub_thirdpart = os.path.join(dst_seahubdir, 'thirdpart')
    copy_seahub_thirdpart_libs(seahub_thirdpart)
    copy_seafdav()


    # copy_pdf2htmlex()

    # copy shared c libs
    copy_shared_libs()
    copy_user_manuals()

def copy_pdf2htmlex():
    '''Copy pdf2htmlEX exectuable and its dependent libs'''
    pdf2htmlEX_executable = find_in_path('pdf2htmlEX')
    libs = get_dependent_libs(pdf2htmlEX_executable)

    builddir = conf[CONF_BUILDDIR]
    dst_lib_dir = os.path.join(builddir,
                               'seafile-server',
                               'seafile',
                               'lib')

    dst_bin_dir = os.path.join(builddir,
                               'seafile-server',
                               'seafile',
                               'bin')

    for lib in libs:
        dst_file = os.path.join(dst_lib_dir, os.path.basename(lib))
        if os.path.exists(dst_file):
            continue
        info('Copying %s' % lib)
        must_copy(lib, dst_lib_dir)

    must_copy(pdf2htmlEX_executable, dst_bin_dir)

def get_dependent_libs(executable):
    syslibs = ['libsearpc', 'libccnet', 'libseafile', 'libpthread.so', 'libc.so', 'libm.so', 'librt.so', 'libdl.so', 'libselinux.so', 'libresolv.so' ]
    def is_syslib(lib):
        for syslib in syslibs:
            if syslib in lib:
                return True
        return False

    ldd_output = commands.getoutput('ldd %s' % executable)
    ret = set()
    for line in ldd_output.splitlines():
        tokens = line.split()
        if len(tokens) != 4:
            continue
        if is_syslib(tokens[0]):
            continue

        ret.add(tokens[2])

    return ret

def copy_shared_libs():
    '''copy shared c libs, such as libevent, glib, libmysqlclient'''
    builddir = conf[CONF_BUILDDIR]

    dst_dir = os.path.join(builddir,
                           'seafile-server',
                           'seafile',
                           'lib')

    seafile_path = os.path.join(builddir,
                                   'seafile-server',
                                   'seafile',
                                   'bin',
                                   'seaf-server')

    ccnet_server_path = os.path.join(builddir,
                                     'seafile-server',
                                     'seafile',
                                     'bin',
                                     'ccnet-server')

    seaf_fuse_path = os.path.join(builddir,
                                  'seafile-server',
                                  'seafile',
                                  'bin',
                                  'seaf-fuse')

    libs = set()
    libs.update(get_dependent_libs(ccnet_server_path))
    libs.update(get_dependent_libs(seafile_path))
    libs.update(get_dependent_libs(seaf_fuse_path))

    for lib in libs:
        dst_file = os.path.join(dst_dir, os.path.basename(lib))
        if os.path.exists(dst_file):
            continue
        info('Copying %s' % lib)
        shutil.copy(lib, dst_dir)

def copy_seahub_thirdpart_libs(seahub_thirdpart):
    '''copy django/djblets/gunicorn from ${thirdpartdir} to
    seahub/thirdpart

    '''
    src = conf[CONF_THIRDPARTDIR]
    dst = seahub_thirdpart

    pattern = os.path.join(src, '*')
    try:
        for path in glob.glob(pattern):
            target_path = os.path.join(dst, os.path.basename(path))
            if os.path.isdir(path):
                shutil.copytree(path, target_path)
            else:
                shutil.copy(path, target_path)
    except Exception, e:
        error('failed to copy seahub thirdpart libs: %s' % e)

def strip_symbols():
    def do_strip(fn):
        run('chmod u+w %s' % fn)
        info('stripping:    %s' % fn)
        run('strip "%s"' % fn)

    def remove_static_lib(fn):
        info('removing:     %s' % fn)
        os.remove(fn)

    for parent, dnames, fnames in os.walk('seafile-server/seafile'):
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

    serverdir = 'seafile-server'
    versioned_serverdir = 'seafile-server-' + version

    # move seafile-server to seafile-server-${version}
    try:
        shutil.move(serverdir, versioned_serverdir)
    except Exception, e:
        error('failed to move %s to %s: %s' % (serverdir, versioned_serverdir, e))

    ignored_patterns = [
        # common ignored files
        '*.pyc',
        '*~',
        '*#',

        # seahub
        os.path.join(versioned_serverdir, 'seahub', '.git*'),
        os.path.join(versioned_serverdir, 'seahub', 'media', 'flexpaper*'),
        os.path.join(versioned_serverdir, 'seahub', 'avatar', 'testdata*'),

        # seafile
        os.path.join(versioned_serverdir, 'seafile', 'share*'),
        os.path.join(versioned_serverdir, 'seafile', 'include*'),
        os.path.join(versioned_serverdir, 'seafile', 'lib', 'pkgconfig*'),
        os.path.join(versioned_serverdir, 'seafile', 'lib64', 'pkgconfig*'),
        os.path.join(versioned_serverdir, 'seafile', 'bin', 'ccnet-demo*'),
        os.path.join(versioned_serverdir, 'seafile', 'bin', 'ccnet-tool'),
        os.path.join(versioned_serverdir, 'seafile', 'bin', 'ccnet-servtool'),
        os.path.join(versioned_serverdir, 'seafile', 'bin', 'searpc-codegen.py'),
        os.path.join(versioned_serverdir, 'seafile', 'bin', 'seafile-admin'),
        os.path.join(versioned_serverdir, 'seafile', 'bin', 'seafile'),
    ]

    excludes_list = [ '--exclude=%s' % pattern for pattern in ignored_patterns ]
    excludes = ' '.join(excludes_list)

    tar_cmd = 'tar czf %(tarball_name)s %(versioned_serverdir)s %(excludes)s' \
              % dict(tarball_name=tarball_name,
                     versioned_serverdir=versioned_serverdir,
                     excludes=excludes)

    if run(tar_cmd) < 0:
        error('failed to generate the tarball')

def gen_tarball():
    # strip symbols of libraries to reduce size
    if not conf[CONF_NO_STRIP]:
        try:
            strip_symbols()
        except Exception, e:
            error('failed to strip symbols: %s' % e)

    # determine the output name
    # 64-bit: seafile-server_1.2.2_x86-64.tar.gz
    # 32-bit: seafile-server_1.2.2_i386.tar.gz
    version = conf[CONF_VERSION]
    arch = os.uname()[-1].replace('_', '-')
    if 'arm' in platform.machine():
        arch = 'pi'
    elif arch != 'x86-64':
        arch = 'i386'

    dbg = ''
    if conf[CONF_NO_STRIP]:
        dbg = '.dbg'

    tarball_name = 'seafile-server_%(version)s_%(arch)s%(dbg)s.tar.gz' \
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
    print 'The build is successful. Output is:\t%s' % dst_tarball
    print '---------------------------------------------'

def main():
    parse_args()
    setup_build_env()

    libsearpc = Libsearpc()
    ccnet = Ccnet()
    seafile = Seafile()
    seahub = Seahub()

    libsearpc.uncompress()
    libsearpc.build()

    ccnet.uncompress()
    ccnet.build()

    seafile.uncompress()
    seafile.build()

    seahub.uncompress()
    seahub.build()

    copy_scripts_and_libs()
    gen_tarball()

if __name__ == '__main__':
    main()
