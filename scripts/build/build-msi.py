#!/usr/bin/env python
# coding: UTF-8

'''This scirpt builds the seafile windows msi installer.

Some notes:

1. The working directory is always the 'builddir'. 'os.chdir' is only called
to change to the 'builddir'. We make use of the 'cwd' argument in
'subprocess.Popen' to run a command in a specific directory.

2. When invoking commands like 'tar', we must convert the path to posix path with the function to_mingw_path. E.g., 'c:\\seafile' should be converted to '/c/seafile'.

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

import multiprocessing
import os
import glob
import shutil
import re
import subprocess
import optparse
import atexit
import csv
import time

error_exit = False
####################
### Global variables
####################

# command line configuartion
conf = {}

# The retry times when sign programs
RETRY_COUNT = 3

# key names in the conf dictionary.
CONF_VERSION            = 'version'
CONF_LIBSEARPC_VERSION  = 'libsearpc_version'
CONF_SEAFILE_VERSION    = 'seafile_version'
CONF_SEAFILE_CLIENT_VERSION  = 'seafile_client_version'
CONF_SRCDIR             = 'srcdir'
CONF_KEEP               = 'keep'
CONF_BUILDDIR           = 'builddir'
CONF_OUTPUTDIR          = 'outputdir'
CONF_DEBUG              = 'debug'
CONF_ONLY_CHINESE       = 'onlychinese'
CONF_QT_ROOT            = 'qt_root'
CONF_EXTRA_LIBS_DIR     = 'extra_libs_dir'
CONF_QT5                = 'qt5'
CONF_BRAND              = 'brand'
CONF_CERTFILE           = 'certfile'
CONF_NO_STRIP           = 'nostrip'

####################
### Common helper functions
####################
def to_mingw_path(path):
    if len(path) < 2 or path[1] != ':' :
        return path.replace('\\', '/')

    drive = path[0]
    return '/%s%s' % (drive.lower(), path[2:].replace('\\', '/'))

def to_win_path(path):
    if len(path) < 2 or path[1] == ':' :
        return path.replace('/', '\\')

    drive = path[1]
    return '%s:%s' % (drive.lower(), path[2:].replace('/', '\\'))

def highlight(content, is_error=False):
    '''Add ANSI color to content to get it highlighted on terminal'''
    dummy = is_error
    return content
    # if is_error:
    #     return '\x1b[1;31m%s\x1b[m' % content
    # else:
    #     return '\x1b[1;32m%s\x1b[m' % content

def info(msg):
    print highlight('[INFO] ') + msg

def find_in_path(prog):
    '''Test whether prog exists in system path'''
    dirs = os.environ['PATH'].split(';')
    for d in dirs:
        if d == '':
            continue
        path = os.path.join(d, prog)
        if os.path.exists(path):
            return path

    return None

def prepend_env_value(name, value, seperator=':'):
    '''prepend a new value to a list'''
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
    info('running %s, cwd=%s' % (cmdline, cwd if cwd else os.getcwd()))
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
        ret = proc.wait()
        if 'depend' not in cmdline and ret != 0:
            global error_exit
            error_exit = True
        return ret

def must_mkdir(path):
    '''Create a directory, exit on failure'''
    try:
        os.makedirs(path)
    except OSError, e:
        error('failed to create directory %s:%s' % (path, e))

def must_copy(src, dst):
    '''Copy src to dst, exit on failure'''
    try:
        shutil.copy(src, dst)
    except Exception, e:
        error('failed to copy %s to %s: %s' % (src, dst, e))

def must_copytree(src, dst):
    '''Copy dir src to dst, exit on failure'''
    try:
        shutil.copytree(src, dst)
    except Exception, e:
        error('failed to copy dir %s to %s: %s' % (src, dst, e))

def must_move(src, dst):
    '''Move src to dst, exit on failure'''
    try:
        shutil.move(src, dst)
    except Exception, e:
        error('failed to move %s to %s: %s' % (src, dst, e))

class Project(object):
    '''Base class for a project'''
    # Probject name, i.e. libseaprc/seafile/seahub
    name = ''

    # A list of shell commands to configure/build the project
    build_commands = []

    def __init__(self):
        self.prefix = os.path.join(conf[CONF_BUILDDIR], 'usr')
        self.version = self.get_version()
        self.src_tarball = os.path.join(conf[CONF_SRCDIR],
                            '%s-%s.tar.gz' % (self.name, self.version))

        # project dir, like <builddir>/seafile-1.2.2/
        self.projdir = os.path.join(conf[CONF_BUILDDIR], '%s-%s' % (self.name, self.version))

    def get_version(self):
        # libsearpc can have different versions from seafile.
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

        tarball = to_mingw_path(self.src_tarball)
        if run('tar xf %s' % tarball) != 0:
            error('failed to uncompress source of %s' % self.name)

    def before_build(self):
        '''Hook method to do project-specific stuff before running build commands'''
        pass

    def build(self):
        '''Build the source'''
        self.before_build()
        info('Building %s' % self.name)
        dump_env()
        for cmd in self.build_commands:
            if run(cmd, cwd=self.projdir) != 0:
                error('error when running command:\n\t%s\n' % cmd)

def get_make_path():
    return find_in_path('make.exe')

def concurrent_make():
    return '%s -j%s' % (get_make_path(), multiprocessing.cpu_count())

class Libsearpc(Project):
    name = 'libsearpc'

    def __init__(self):
        Project.__init__(self)
        self.build_commands = [
            'sh ./configure --prefix=%s --disable-compile-demo' % to_mingw_path(self.prefix),
            concurrent_make(),
            '%s install' % get_make_path(),
        ]

    def get_version(self):
        return conf[CONF_LIBSEARPC_VERSION]

class Seafile(Project):
    name = 'seafile'
    def __init__(self):
        Project.__init__(self)
        enable_breakpad = '--enable-breakpad'
        self.build_commands = [
            'sh ./configure %s --prefix=%s' % (enable_breakpad, to_mingw_path(self.prefix)),
            concurrent_make(),
            '%s install' % get_make_path(),
        ]

    def get_version(self):
        return conf[CONF_SEAFILE_VERSION]

    def before_build(self):
        macros = {}
        # SET SEAFILE_SOURCE_COMMIT_ID, so it can be printed in the log
        macros['SEAFILE_SOURCE_COMMIT_ID'] = '\\"%s\\"' % self.get_source_commit_id()
        self.append_cflags(macros)

class SeafileClient(Project):
    name = 'seafile-client'
    def __init__(self):
        Project.__init__(self)
        ninja = find_in_path('ninja.exe')
        seafile_prefix = Seafile().prefix
        generator = 'Ninja' if ninja else 'MSYS Makefiles'
        build_type = 'Debug' if conf[CONF_DEBUG] else 'Release'
        flags = {
            'BUILD_SPARKLE_SUPPORT': 'ON',
            'USE_QT5': 'ON' if conf[CONF_QT5] else 'OFF',
            'BUILD_SHIBBOLETH_SUPPORT': 'ON',
            'CMAKE_BUILD_TYPE': build_type,
            'CMAKE_INSTALL_PREFIX': to_mingw_path(self.prefix),
            # ninja invokes cmd.exe which doesn't support msys/mingw path
            # change the value but don't override CMAKE_EXE_LINKER_FLAGS,
            # which is in use
            'CMAKE_EXE_LINKER_FLAGS_%s' % build_type.upper(): '-L%s' % (os.path.join(seafile_prefix, 'lib') if ninja else to_mingw_path(os.path.join(seafile_prefix, 'lib'))),
        }
        flags_str = ' '.join(['-D%s=%s' % (k, v) for k, v in flags.iteritems()])
        make = ninja or concurrent_make()
        self.build_commands = [
            'cmake -G "%s" %s .' % (generator, flags_str),
            make,
            '%s install' % make,
            "bash extensions/build.sh",
        ]

    def get_version(self):
        return conf[CONF_SEAFILE_CLIENT_VERSION]

    def before_build(self):
        shutil.copy(os.path.join(conf[CONF_EXTRA_LIBS_DIR], 'winsparkle.lib'), self.projdir)

class SeafileShellExt(Project):
    name = 'seafile-shell-ext'
    def __init__(self):
        Project.__init__(self)
        self.build_commands = [
            "bash extensions/build.sh",
            "bash shellext-fix/build.sh",
        ]

    def get_version(self):
        return conf[CONF_SEAFILE_CLIENT_VERSION]

def check_targz_src(proj, version, srcdir):
    src_tarball = os.path.join(srcdir, '%s-%s.tar.gz' % (proj, version))
    if not os.path.exists(src_tarball):
        error('%s not exists' % src_tarball)

def validate_args(usage, options):
    required_args = [
        CONF_VERSION,
        CONF_LIBSEARPC_VERSION,
        CONF_SEAFILE_VERSION,
        CONF_SEAFILE_CLIENT_VERSION,
        CONF_SRCDIR,
        CONF_QT_ROOT,
        CONF_EXTRA_LIBS_DIR,
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
        if not re.match(r'^[0-9]+(\.[0-9]+)+$', version):
            error('%s is not a valid version' % version, usage=usage)

    version = get_option(CONF_VERSION)
    libsearpc_version = get_option(CONF_LIBSEARPC_VERSION)
    seafile_version = get_option(CONF_SEAFILE_VERSION)
    seafile_client_version = get_option(CONF_SEAFILE_CLIENT_VERSION)
    seafile_shell_ext_version = get_option(CONF_SEAFILE_CLIENT_VERSION)

    check_project_version(version)
    check_project_version(libsearpc_version)
    check_project_version(seafile_version)
    check_project_version(seafile_client_version)
    check_project_version(seafile_shell_ext_version)

    # [ srcdir ]
    srcdir = to_win_path(get_option(CONF_SRCDIR))
    check_targz_src('libsearpc', libsearpc_version, srcdir)
    check_targz_src('seafile', seafile_version, srcdir)
    check_targz_src('seafile-client', seafile_client_version, srcdir)
    check_targz_src('seafile-shell-ext', seafile_shell_ext_version, srcdir)

    # [ builddir ]
    builddir = to_win_path(get_option(CONF_BUILDDIR))
    if not os.path.exists(builddir):
        error('%s does not exist' % builddir, usage=usage)

    builddir = os.path.join(builddir, 'seafile-msi-build')

    # [ outputdir ]
    outputdir = to_win_path(get_option(CONF_OUTPUTDIR))
    if not os.path.exists(outputdir):
        error('outputdir %s does not exist' % outputdir, usage=usage)

    # [ keep ]
    keep = get_option(CONF_KEEP)

    # [ no strip]
    debug = get_option(CONF_DEBUG)

    # [ no strip]
    nostrip = get_option(CONF_NO_STRIP)

    # [only chinese]
    onlychinese = get_option(CONF_ONLY_CHINESE)

    # [ qt root]
    qt_root = get_option(CONF_QT_ROOT)
    def check_qt_root(qt_root):
        if not os.path.exists(os.path.join(qt_root, 'plugins')):
            error('%s is not a valid qt root' % qt_root)
    check_qt_root(qt_root)

    # [ sparkle dir]
    extra_libs_dir = get_option(CONF_EXTRA_LIBS_DIR)
    def check_extra_libs_dir(extra_libs_dir):
        for fn in ['winsparkle.lib']:
            if not os.path.exists(os.path.join(extra_libs_dir, fn)):
                error('%s is missing in %s' % (fn, extra_libs_dir))
    check_extra_libs_dir(extra_libs_dir)

    # [qt5]
    qt5 = get_option(CONF_QT5)
    brand = get_option(CONF_BRAND)
    cert = get_option(CONF_CERTFILE)
    if cert is not None:
        if not os.path.exists(cert):
            error('cert file "{}" does not exist'.format(cert))

    conf[CONF_VERSION] = version
    conf[CONF_LIBSEARPC_VERSION] = libsearpc_version
    conf[CONF_SEAFILE_VERSION] = seafile_version
    conf[CONF_SEAFILE_CLIENT_VERSION] = seafile_client_version

    conf[CONF_BUILDDIR] = builddir
    conf[CONF_SRCDIR] = srcdir
    conf[CONF_OUTPUTDIR] = outputdir
    conf[CONF_KEEP] = True
    conf[CONF_DEBUG] = debug or nostrip
    conf[CONF_NO_STRIP] = debug or nostrip
    conf[CONF_ONLY_CHINESE] = onlychinese
    conf[CONF_QT_ROOT] = qt_root
    conf[CONF_EXTRA_LIBS_DIR] = extra_libs_dir
    conf[CONF_QT5] = qt5
    conf[CONF_BRAND] = brand
    conf[CONF_CERTFILE] = cert

    prepare_builddir(builddir)
    show_build_info()

def show_build_info():
    '''Print all conf information. Confirm before continue.'''
    info('------------------------------------------')
    info('Seafile msi installer: BUILD INFO')
    info('------------------------------------------')
    info('seafile:                  %s' % conf[CONF_VERSION])
    info('libsearpc:                %s' % conf[CONF_LIBSEARPC_VERSION])
    info('seafile:                  %s' % conf[CONF_SEAFILE_VERSION])
    info('seafile-client:           %s' % conf[CONF_SEAFILE_CLIENT_VERSION])
    info('qt-root:                  %s' % conf[CONF_QT_ROOT])
    info('builddir:                 %s' % conf[CONF_BUILDDIR])
    info('outputdir:                %s' % conf[CONF_OUTPUTDIR])
    info('source dir:               %s' % conf[CONF_SRCDIR])
    info('debug:                    %s' % conf[CONF_DEBUG])
    info('build english version:    %s' % (not conf[CONF_ONLY_CHINESE]))
    info('clean on exit:            %s' % (not conf[CONF_KEEP]))
    info('------------------------------------------')
    info('press any key to continue ')
    info('------------------------------------------')
    dummy = raw_input()

def prepare_builddir(builddir):
    must_mkdir(builddir)

    if not conf[CONF_KEEP]:
        def remove_builddir():
            '''Remove the builddir when exit'''
            if not error_exit:
                info('remove builddir before exit')
                shutil.rmtree(builddir, ignore_errors=True)
        atexit.register(remove_builddir)

    os.chdir(builddir)

def parse_args():
    parser = optparse.OptionParser()
    def long_opt(opt):
        return '--' + opt

    parser.add_option(long_opt(CONF_VERSION),
                      dest=CONF_VERSION,
                      nargs=1,
                      help='the version to build. Must be digits delimited by dots, like 1.3.0')

    parser.add_option(long_opt(CONF_LIBSEARPC_VERSION),
                      dest=CONF_LIBSEARPC_VERSION,
                      nargs=1,
                      help='the version of libsearpc as specified in its "configure.ac". Must be digits delimited by dots, like 1.3.0')

    parser.add_option(long_opt(CONF_SEAFILE_VERSION),
                      dest=CONF_SEAFILE_VERSION,
                      nargs=1,
                      help='the version of seafile as specified in its "configure.ac". Must be digits delimited by dots, like 1.3.0')

    parser.add_option(long_opt(CONF_SEAFILE_CLIENT_VERSION),
                      dest=CONF_SEAFILE_CLIENT_VERSION,
                      nargs=1,
                      help='the version of seafile-client. Must be digits delimited by dots, like 1.3.0')

    parser.add_option(long_opt(CONF_BUILDDIR),
                      dest=CONF_BUILDDIR,
                      nargs=1,
                      help='the directory to build the source. Defaults to /c',
                      default='c:\\')

    parser.add_option(long_opt(CONF_OUTPUTDIR),
                      dest=CONF_OUTPUTDIR,
                      nargs=1,
                      help='the output directory to put the generated server tarball. Defaults to the current directory.',
                      default=os.getcwd())

    parser.add_option(long_opt(CONF_SRCDIR),
                      dest=CONF_SRCDIR,
                      nargs=1,
                      help='''Source tarballs must be placed in this directory.''')

    parser.add_option(long_opt(CONF_QT_ROOT),
                      dest=CONF_QT_ROOT,
                      nargs=1,
                      help='''qt root directory.''')

    parser.add_option(long_opt(CONF_EXTRA_LIBS_DIR),
                      dest=CONF_EXTRA_LIBS_DIR,
                      nargs=1,
                      help='''where we can find winsparkle.lib''')

    parser.add_option(long_opt(CONF_KEEP),
                      dest=CONF_KEEP,
                      action='store_true',
                      help='''keep the build directory after the script exits. By default, the script would delete the build directory at exit.''')

    parser.add_option(long_opt(CONF_DEBUG),
                      dest=CONF_DEBUG,
                      action='store_true',
                      help='''compile in debug mode''')

    parser.add_option(long_opt(CONF_ONLY_CHINESE),
                      dest=CONF_ONLY_CHINESE,
                      action='store_true',
                      help='''only build the Chinese version. By default both Chinese and English versions would be built.''')

    parser.add_option(long_opt(CONF_QT5),
                      dest=CONF_QT5,
                      action='store_true',
                      help='''build seafile client with qt5''')

    parser.add_option(long_opt(CONF_BRAND),
                      dest=CONF_BRAND,
                      default='seafile',
                      help='''brand name of the package''')

    parser.add_option(long_opt(CONF_CERTFILE),
                      nargs=1,
                      default=None,
                      dest=CONF_CERTFILE,
                      help='''The cert for signing the executables and the installer.''')

    parser.add_option(long_opt(CONF_NO_STRIP),
                      dest=CONF_NO_STRIP,
                      action='store_true',
                      help='''do not strip the symbols.''')

    usage = parser.format_help()
    options, remain = parser.parse_args()
    if remain:
        error(usage=usage)

    validate_args(usage, options)

def setup_build_env():
    '''Setup environment variables, such as export PATH=$BUILDDDIR/bin:$PATH'''
    prefix = Seafile().prefix
    prepend_env_value('CPPFLAGS',
                     '-I%s' % to_mingw_path(os.path.join(prefix, 'include')),
                     seperator=' ')

    prepend_env_value('CPPFLAGS',
                     '-DSEAFILE_CLIENT_VERSION=\\"%s\\"' % conf[CONF_VERSION],
                     seperator=' ')

    prepend_env_value('CPPFLAGS',
                      '-g -fno-omit-frame-pointer',
                      seperator=' ')
    if conf[CONF_DEBUG]:
        prepend_env_value('CPPFLAGS', '-O0', seperator=' ')

    prepend_env_value('LDFLAGS',
                     '-L%s' % to_mingw_path(os.path.join(prefix, 'lib')),
                     seperator=' ')

    prepend_env_value('PATH',
                      os.path.join(prefix, 'bin'),
                      seperator=';')

    prepend_env_value('PKG_CONFIG_PATH',
                      os.path.join(prefix, 'lib', 'pkgconfig'),
                      seperator=';')
                      # to_mingw_path(os.path.join(prefix, 'lib', 'pkgconfig')))

    # specifiy the directory for wix temporary files
    wix_temp_dir = os.path.join(conf[CONF_BUILDDIR], 'wix-temp')
    os.environ['WIX_TEMP'] = wix_temp_dir

    must_mkdir(wix_temp_dir)

def dependency_walk(applet):
    output = os.path.join(conf[CONF_BUILDDIR], 'depends.csv')
    cmd = 'depends.exe -c -f 1 -oc %s %s' % (output, applet)

    # See the manual of Dependency walker
    if run(cmd) > 0x100:
        error('failed to run dependency walker for %s' % applet)

    if not os.path.exists(output):
        error('failed to run dependency walker for %s' % applet)

    shared_libs = parse_depends_csv(output)
    return shared_libs

def parse_depends_csv(path):
    '''parse the output of dependency walker'''
    libs = set()
    our_libs = ['libsearpc', 'libseafile']
    def should_ignore_lib(lib):
        lib = lib.lower()
        if not os.path.exists(lib):
            return True

        if lib.startswith('c:\\windows'):
            return True

        if lib.endswith('exe'):
            return True

        for name in our_libs:
            if name in lib:
                return True

        return False

    with open(path, 'r') as fp:
        reader = csv.reader(fp)
        for row in reader:
            if len(row) < 2:
                continue
            lib = row[1]
            if not should_ignore_lib(lib):
                libs.add(lib)

    return set(libs)

def copy_shared_libs(exes):
    '''Copy shared libs need by seafile-applet.exe, such as libsearpc,
    libseafile, etc. First we use Dependency walker to analyse
    seafile-applet.exe, and get an output file in csv format. Then we parse
    the csv file to get the list of shared libs.

    '''

    shared_libs = set()
    for exectuable in exes:
        shared_libs.update(dependency_walk(exectuable))

    pack_bin_dir = os.path.join(conf[CONF_BUILDDIR], 'pack', 'bin')
    for lib in shared_libs:
        must_copy(lib, pack_bin_dir)

    if not any([os.path.basename(lib).lower().startswith('libssl') for lib in shared_libs]):
        ssleay32 = find_in_path('ssleay32.dll')
        must_copy(ssleay32, pack_bin_dir)

def copy_dll_exe():
    prefix = Seafile().prefix
    destdir = os.path.join(conf[CONF_BUILDDIR], 'pack', 'bin')

    filelist = [
        os.path.join(prefix, 'bin', 'libsearpc-1.dll'),
        os.path.join(prefix, 'bin', 'libseafile-0.dll'),
        os.path.join(prefix, 'bin', 'seaf-daemon.exe'),
        os.path.join(SeafileClient().projdir, 'seafile-applet.exe'),
        os.path.join(SeafileShellExt().projdir, 'shellext-fix', 'shellext-fix.exe'),
    ]

    for name in filelist:
        must_copy(name, destdir)

    extdlls = [
        os.path.join(SeafileShellExt().projdir, 'extensions', 'lib', 'seafile_ext.dll'),
        os.path.join(SeafileShellExt().projdir, 'extensions', 'lib', 'seafile_ext64.dll'),
    ]

    customdir = os.path.join(conf[CONF_BUILDDIR], 'pack', 'custom')
    for dll in extdlls:
        must_copy(dll, customdir)

    copy_shared_libs([ f for f in filelist if f.endswith('.exe') ])
    copy_qt_plugins_imageformats()
    copy_qt_plugins_platforms()
    copy_qt_translations()

def copy_qt_plugins_imageformats():
    destdir = os.path.join(conf[CONF_BUILDDIR], 'pack', 'bin', 'imageformats')
    must_mkdir(destdir)

    qt_plugins_srcdir = os.path.join(conf[CONF_QT_ROOT], 'plugins', 'imageformats')

    src = os.path.join(qt_plugins_srcdir, 'qico4.dll')
    if conf[CONF_QT5]:
        src = os.path.join(qt_plugins_srcdir, 'qico.dll')
    must_copy(src, destdir)

    src = os.path.join(qt_plugins_srcdir, 'qgif4.dll')
    if conf[CONF_QT5]:
        src = os.path.join(qt_plugins_srcdir, 'qgif.dll')
    must_copy(src, destdir)

    src = os.path.join(qt_plugins_srcdir, 'qjpeg.dll')
    if conf[CONF_QT5]:
        src = os.path.join(qt_plugins_srcdir, 'qjpeg.dll')
    must_copy(src, destdir)

def copy_qt_plugins_platforms():
    if not conf[CONF_QT5]:
        return

    destdir = os.path.join(conf[CONF_BUILDDIR], 'pack', 'bin', 'platforms')
    must_mkdir(destdir)

    qt_plugins_srcdir = os.path.join(conf[CONF_QT_ROOT], 'plugins', 'platforms')

    src = os.path.join(qt_plugins_srcdir, 'qwindows.dll')
    must_copy(src, destdir)

    src = os.path.join(qt_plugins_srcdir, 'qminimal.dll')
    must_copy(src, destdir)

def copy_qt_translations():
    destdir = os.path.join(conf[CONF_BUILDDIR], 'pack', 'bin')

    qt_translation_dir = os.path.join(conf[CONF_QT_ROOT], 'translations')

    i18n_dir = os.path.join(SeafileClient().projdir, 'i18n')
    qm_pattern = os.path.join(i18n_dir, 'seafile_*.qm')

    qt_qms = set()
    def add_lang(lang):
        if not lang:
            return
        qt_qm = os.path.join(qt_translation_dir, 'qt_%s.qm' % lang)
        if os.path.exists(qt_qm):
            qt_qms.add(qt_qm)
        elif '_' in lang:
            add_lang(lang[:lang.index('_')])

    for fn in glob.glob(qm_pattern):
        name = os.path.basename(fn)
        m = re.match(r'seafile_(.*)\.qm', name)
        lang = m.group(1)
        add_lang(lang)

    for src in qt_qms:
        must_copy(src, destdir)

def prepare_msi():
    pack_dir = os.path.join(conf[CONF_BUILDDIR], 'pack')

    msi_dir = os.path.join(Seafile().projdir, 'msi')

    # These files are in seafile-shell-ext because they're shared between seafile/seadrive
    ext_wxi = os.path.join(SeafileShellExt().projdir, 'msi', 'ext.wxi')
    must_copy(ext_wxi, msi_dir)
    shell_wxs = os.path.join(SeafileShellExt().projdir, 'msi', 'shell.wxs')
    must_copy(shell_wxs, msi_dir)

    must_copytree(msi_dir, pack_dir)
    must_mkdir(os.path.join(pack_dir, 'bin'))

    if run('make', cwd=os.path.join(pack_dir, 'custom')) != 0:
        error('Error when compiling seafile msi custom dlls')

    copy_dll_exe()

def sign_executables():
    certfile = conf.get(CONF_CERTFILE)
    if certfile is None:
        info('exectuable signing is skipped since no cert is provided.')
        return

    pack_dir = os.path.join(conf[CONF_BUILDDIR], 'pack')
    exectuables = glob.glob(os.path.join(pack_dir, 'bin', '*.exe'))
    for exe in exectuables:
        do_sign(certfile, exe)

def sign_installers():
    certfile = conf.get(CONF_CERTFILE)
    if certfile is None:
        info('msi signing is skipped since no cert is provided.')
        return

    pack_dir = os.path.join(conf[CONF_BUILDDIR], 'pack')
    installers = glob.glob(os.path.join(pack_dir, '*.msi'))
    for fn in installers:
        name = conf[CONF_BRAND]
        if name == 'seafile':
            name = 'Seafile'
        do_sign(certfile, fn, desc='{} Installer'.format(name))

def do_sign(certfile, fn, desc=None):
    certfile = to_win_path(certfile)
    fn = to_win_path(fn)
    info('signing file {} using cert "{}"'.format(fn, certfile))

    if desc:
        desc_flags = '-d "{}"'.format(desc)
    else:
        desc_flags = ''

    # https://support.comodo.com/index.php?/Knowledgebase/Article/View/68/0/time-stamping-server
    signcmd = 'signtool.exe sign -fd sha256 -t http://timestamp.comodoca.com -f {} {} {}'.format(certfile, desc_flags, fn)
    i = 0
    while i < RETRY_COUNT:
        time.sleep(30)
        ret = run(signcmd, cwd=os.path.dirname(fn))
        if ret == 0:
            break
        i = i + 1
        if i == RETRY_COUNT:
            error('Failed to sign file "{}"'.format(fn))

def strip_symbols():
    bin_dir = os.path.join(conf[CONF_BUILDDIR], 'pack', 'bin')
    def do_strip(fn, stripcmd='strip'):
        run('%s "%s"' % (stripcmd, fn))
        info('stripping: %s' % fn)

    for dll in glob.glob(os.path.join(bin_dir, '*.dll')):
        name = os.path.basename(dll).lower()
        if 'qt' in name:
            do_strip(dll)
        if name == 'seafile_ext.dll':
            do_strip(dll)
        elif name == 'seafile_ext64.dll':
            do_strip(dll, stripcmd='x86_64-w64-mingw32-strip')

def edit_fragment_wxs():
    '''In the main wxs file(seafile.wxs) we need to reference to the id of
    seafile-applet.exe, which is listed in fragment.wxs. Since fragments.wxs is
    auto generated, the id is sequentially generated, so we need to change the
    id of seafile-applet.exe manually.

    '''
    file_path = os.path.join(conf[CONF_BUILDDIR], 'pack', 'fragment.wxs')
    new_lines = []
    with open(file_path, 'r') as fp:
        for line in fp:
            if 'seafile-applet.exe' in line:
                # change the id of 'seafile-applet.exe' to 'seafileapplet.exe'
                new_line = re.sub('file_bin_[\d]+', 'seafileapplet.exe', line)
                new_lines.append(new_line)
            else:
                new_lines.append(line)

    content = '\r\n'.join(new_lines)
    with open(file_path, 'w') as fp:
        fp.write(content)


def generate_breakpad_symbols():
    """
    Generate seafile and seafile-gui breakpad symbols
    :return: None
    """
    seafile_src = Seafile().projdir
    seafile_gui_src = SeafileClient().projdir
    generate_breakpad_symbols_script = os.path.join(seafile_src, 'scripts/breakpad.py')

    # generate seafile the breakpad symbols
    seafile_name = 'seaf-daemon.exe'
    seafile_symbol_name = 'seaf-daemon.exe.sym-%s' % conf[CONF_VERSION]
    seafile_symbol_output = os.path.join(seafile_src, seafile_symbol_name)

    if run('python %s  --projectSrc %s --name %s --output %s'
           % (generate_breakpad_symbols_script, seafile_src, seafile_name, seafile_symbol_output)) != 0:
        error('Error when generating breakpad symbols')

    # generate seafile gui breakpad symbols
    seafile_gui_name = 'seafile-applet.exe'
    seafile_gui_symbol_name = 'seafile-applet.exe.sym-%s' % conf[CONF_VERSION]
    seafile_gui_symbol_output = os.path.join(seafile_gui_src, seafile_gui_symbol_name)

    if run('python %s --projectSrc %s --name %s --output %s'
            % (generate_breakpad_symbols_script, seafile_gui_src, seafile_gui_name, seafile_gui_symbol_output)) != 0:
        error('Error when generating seafile gui client breakpad symbol')

    # move symbols to output directory
    dst_seafile_symbol_file = os.path.join(conf[CONF_OUTPUTDIR], seafile_symbol_name)
    dst_seafile_gui_symbol_file = os.path.join(conf[CONF_OUTPUTDIR], seafile_gui_symbol_name)
    must_copy(seafile_symbol_output, dst_seafile_symbol_file)
    must_copy(seafile_gui_symbol_output, dst_seafile_gui_symbol_file)


def build_msi():
    prepare_msi()
    generate_breakpad_symbols()
    if conf[CONF_DEBUG] or conf[CONF_NO_STRIP]:
        info('Would not strip exe/dll symbols since --debug or --nostrip is specified')
    else:
        strip_symbols()

    # Only sign the exectuables after stripping symbols.
    if need_sign():
        sign_executables()

    pack_dir = os.path.join(conf[CONF_BUILDDIR], 'pack')
    if run('make fragment.wxs', cwd=pack_dir) != 0:
        error('Error when make fragement.wxs')

    edit_fragment_wxs()

    if run('make', cwd=pack_dir) != 0:
        error('Error when make seafile.msi')

def build_english_msi():
    '''The extra work to build the English msi.'''
    pack_dir = os.path.join(conf[CONF_BUILDDIR], 'pack')

    if run('make en', cwd=pack_dir) != 0:
        error('Error when make seafile-en.msi')

def build_german_msi():
    '''The extra work to build the German msi.'''
    pack_dir = os.path.join(conf[CONF_BUILDDIR], 'pack')

    if run('make de', cwd=pack_dir) != 0:
        error('Error when make seafile-de.msi')

def move_msi():
    pack_dir = os.path.join(conf[CONF_BUILDDIR], 'pack')
    src_msi = os.path.join(pack_dir, 'seafile.msi')
    brand = conf[CONF_BRAND]
    dst_msi = os.path.join(conf[CONF_OUTPUTDIR], '%s-%s.msi' % (brand, conf[CONF_VERSION]))

    # move msi to outputdir
    must_copy(src_msi, dst_msi)

    if not conf[CONF_ONLY_CHINESE]:
        src_msi_en = os.path.join(pack_dir, 'seafile-en.msi')
        dst_msi_en = os.path.join(conf[CONF_OUTPUTDIR], '%s-%s-en.msi' % (brand, conf[CONF_VERSION]))
        must_copy(src_msi_en, dst_msi_en)

    print '---------------------------------------------'
    print 'The build is successfully. Output is:'
    print '>>\t%s' % dst_msi
    if not conf[CONF_ONLY_CHINESE]:
        print '>>\t%s' % dst_msi_en
        # print '>>\t%s' % dst_msi_de
    print '---------------------------------------------'

def check_tools():
    tools = [
        'Paraffin',
        'candle',
        'light',
        'depends',
    ]

    for prog in tools:
        if not find_in_path(prog + '.exe'):
            error('%s not found' % prog)

def dump_env():
    print 'Dumping environment variables:'
    for k, v in os.environ.iteritems():
        print '%s: %s' % (k, v)

def need_sign():
    return conf[CONF_BRAND].lower() == 'seafile'

def main():
    dump_env()
    parse_args()
    setup_build_env()
    check_tools()

    libsearpc = Libsearpc()
    seafile = Seafile()
    seafile_client = SeafileClient()
    seafile_shell_ext = SeafileShellExt()

    libsearpc.uncompress()
    libsearpc.build()

    seafile.uncompress()
    seafile.build()

    seafile_client.uncompress()
    seafile_shell_ext.uncompress()

    seafile_client.build()
    seafile_shell_ext.build()

    build_msi()
    if not conf[CONF_ONLY_CHINESE]:
        build_english_msi()
        # build_german_msi()

    if need_sign():
        sign_installers()
    move_msi()

if __name__ == '__main__':
    main()
