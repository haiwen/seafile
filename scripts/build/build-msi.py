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

import os
import glob
import shutil
import re
import subprocess
import optparse
import atexit
import csv

from distutils.core import setup as dist_setup
import py2exe

####################
### Global variables
####################

# command line configuartion
conf = {}

# key names in the conf dictionary.
CONF_VERSION            = 'version'
CONF_LIBSEARPC_VERSION  = 'libsearpc_version'
CONF_CCNET_VERSION      = 'ccnet_version'
CONF_SEAFILE_VERSION    = 'seafile_version'
CONF_SRCDIR             = 'srcdir'
CONF_KEEP               = 'keep'
CONF_BUILDDIR           = 'builddir'
CONF_OUTPUTDIR          = 'outputdir'
CONF_NO_STRIP           = 'nostrip'
CONF_ONLY_CHINESE       = 'onlychinese'

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
    # Probject name, i.e. libseaprc/ccnet/seafile/seahub
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
        # libsearpc and ccnet can have different versions from seafile.
        raise NotImplementedError

    def uncompress(self):
        '''Uncompress the source from the tarball'''
        info('Uncompressing %s' % self.name)

        tarball = to_mingw_path(self.src_tarball)
        if run('tar xf %s' % tarball) != 0:
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
            'sh ./configure --prefix=%s --disable-compile-demo' % to_mingw_path(self.prefix),
            'make',
            'make install',
        ]

    def get_version(self):
        return conf[CONF_LIBSEARPC_VERSION]

class Ccnet(Project):
    name = 'ccnet'

    def __init__(self):
        Project.__init__(self)
        self.build_commands = [
            'sh ./configure --prefix=%s --disable-compile-demo' % to_mingw_path(self.prefix),
            'make',
            'make install',
        ]

    def get_version(self):
        return conf[CONF_CCNET_VERSION]

class Seafile(Project):
    name = 'seafile'
    def __init__(self):
        Project.__init__(self)
        self.build_commands = [
            'sh ./configure --prefix=%s' % to_mingw_path(self.prefix),
            'make',
            'make install',
        ]

    def get_version(self):
        return conf[CONF_SEAFILE_VERSION]

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
        if not re.match('^[0-9]\.[0-9](\.[0-9])?$', version):
            error('%s is not a valid version' % version, usage=usage)

    version = get_option(CONF_VERSION)
    libsearpc_version = get_option(CONF_LIBSEARPC_VERSION)
    ccnet_version = get_option(CONF_CCNET_VERSION)
    seafile_version = get_option(CONF_SEAFILE_VERSION)

    check_project_version(version)
    check_project_version(libsearpc_version)
    check_project_version(ccnet_version)
    check_project_version(seafile_version)

    # [ srcdir ]
    srcdir = to_win_path(get_option(CONF_SRCDIR))
    check_targz_src('libsearpc', libsearpc_version, srcdir)
    check_targz_src('ccnet', ccnet_version, srcdir)
    check_targz_src('seafile', seafile_version, srcdir)

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
    nostrip = get_option(CONF_NO_STRIP)

    # [only chinese]
    onlychinese = get_option(CONF_ONLY_CHINESE)

    conf[CONF_VERSION] = version
    conf[CONF_LIBSEARPC_VERSION] = libsearpc_version
    conf[CONF_CCNET_VERSION] = ccnet_version
    conf[CONF_SEAFILE_VERSION] = seafile_version

    conf[CONF_BUILDDIR] = builddir
    conf[CONF_SRCDIR] = srcdir
    conf[CONF_OUTPUTDIR] = outputdir
    conf[CONF_KEEP] = keep
    conf[CONF_NO_STRIP] = nostrip
    conf[CONF_ONLY_CHINESE] = onlychinese

    prepare_builddir(builddir)
    show_build_info()

def show_build_info():
    '''Print all conf information. Confirm before continue.'''
    info('------------------------------------------')
    info('Seafile msi installer: BUILD INFO')
    info('------------------------------------------')
    info('seafile:                  %s' % conf[CONF_VERSION])
    info('libsearpc:                %s' % conf[CONF_LIBSEARPC_VERSION])
    info('ccnet:                    %s' % conf[CONF_CCNET_VERSION])
    info('seafile:                  %s' % conf[CONF_SEAFILE_VERSION])
    info('builddir:                 %s' % conf[CONF_BUILDDIR])
    info('outputdir:                %s' % conf[CONF_OUTPUTDIR])
    info('source dir:               %s' % conf[CONF_SRCDIR])
    info('strip symbols:            %s' % (not conf[CONF_NO_STRIP]))
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

    parser.add_option(long_opt(CONF_CCNET_VERSION),
                      dest=CONF_CCNET_VERSION,
                      nargs=1,
                      help='the version of ccnet as specified in its "configure.ac". Must be digits delimited by dots, like 1.3.0')

    parser.add_option(long_opt(CONF_SEAFILE_VERSION),
                      dest=CONF_SEAFILE_VERSION,
                      nargs=1,
                      help='the version of seafile as specified in its "configure.ac". Must be digits delimited by dots, like 1.3.0')

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

    parser.add_option(long_opt(CONF_KEEP),
                      dest=CONF_KEEP,
                      action='store_true',
                      help='''keep the build directory after the script exits. By default, the script would delete the build directory at exit.''')

    parser.add_option(long_opt(CONF_NO_STRIP),
                      dest=CONF_NO_STRIP,
                      action='store_true',
                      help='''do not strip debug symbols''')

    parser.add_option(long_opt(CONF_ONLY_CHINESE),
                      dest=CONF_ONLY_CHINESE,
                      action='store_true',
                      help='''only build the Chinese version. By default both Chinese and English versions would be built.''')

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

    if conf[CONF_NO_STRIP]:
        prepend_env_value('CPPFLAGS',
                         '-g -O0',
                         seperator=' ')

    prepend_env_value('LDFLAGS',
                     '-L%s' % to_mingw_path(os.path.join(prefix, 'lib')),
                     seperator=' ')

    prepend_env_value('PATH',
                      to_mingw_path(os.path.join(prefix, 'bin')))

    prepend_env_value('PKG_CONFIG_PATH',
                      to_mingw_path(os.path.join(prefix, 'lib', 'pkgconfig')))

    # specifiy the directory for wix temporary files
    wix_temp_dir = os.path.join(conf[CONF_BUILDDIR], 'wix-temp')
    os.environ['WIX_TEMP'] = wix_temp_dir

    must_mkdir(wix_temp_dir)

def web_py2exe():
    webdir = os.path.join(Seafile().projdir, 'web')
    os.chdir(webdir)

    original_argv = sys.argv
    sys.argv = [sys.argv[0], 'py2exe']
    sys.path.insert(0, webdir)

    targetname = 'seafile-web'
    targetfile = targetname + '.py'
    must_copy('main.py', targetfile)

    packages=["mako.cache", "utils"]
    ex_files=[]
    option = {"py2exe":
              {"includes" :[targetname],
               "packages" : packages,
               "bundle_files" : 3}}

    prepend_env_value('PATH',
                      os.path.join(Seafile().prefix, 'bin'),
                      seperator=';')
    try:
        dist_setup(name=targetname,
                   options = option,
                   windows=[{"script":targetfile}],
                   data_files=ex_files)
    except Exception as e:
        error('Error when calling py2exe: %s' % e)

    pack_bin_dir = os.path.join(conf[CONF_BUILDDIR], 'pack', 'bin')

    for name in glob.glob('dist/*'):
        must_copy(name, pack_bin_dir)

    must_copytree('i18n', os.path.join(pack_bin_dir, 'i18n'))
    must_copytree('static', os.path.join(pack_bin_dir, 'static'))
    must_copytree('templates', os.path.join(pack_bin_dir, 'templates'))

    sys.path.pop(0)
    sys.argv = original_argv
    os.chdir(conf[CONF_BUILDDIR])

def parse_depends_csv(path):
    '''parse the output of dependency walker'''
    libs = []
    def should_ignore_lib(lib):
        if not os.path.exists(lib):
            return True

        if lib.lower().startswith('c:\\windows'):
            return True

        return False

    with open(path, 'r') as fp:
        reader = csv.reader(fp)
        for row in reader:
            if len(row) < 2:
                continue
            lib = row[1]
            if not should_ignore_lib(lib):
                libs.append(lib)

    return libs

def copy_shared_libs():
    '''Copy shared libs need by seafile-applet.exe, such as libccnet,
    libseafile, etc. First we use Dependency walker to analyse
    seafile-applet.exe, and get an output file in csv format. Then we parse
    the csv file to get the list of shared libs.

    '''

    output = os.path.join(conf[CONF_BUILDDIR], 'depends.csv')
    applet = os.path.join(Seafile().projdir, 'gui', 'win', 'seafile-applet.exe')
    cmd = 'depends.exe -c -f 1 -oc %s %s' % (output, applet)

    # See the manual of Dependency walker
    if run(cmd) > 0x100:
        error('failed to run dependency walker for seafile-applet.exe')

    if not os.path.exists(output):
        error('failed to run dependency walker for seafile-applet.exe')

    shared_libs = parse_depends_csv(output)
    pack_bin_dir = os.path.join(conf[CONF_BUILDDIR], 'pack', 'bin')
    for lib in shared_libs:
        must_copy(lib, pack_bin_dir)

    # libsqlite3 can not be found automatically
    libsqlite3 = find_in_path('libsqlite3-0.dll')
    must_copy(libsqlite3, pack_bin_dir)

def copy_dll_exe():
    prefix = Seafile().prefix
    destdir = os.path.join(conf[CONF_BUILDDIR], 'pack', 'bin')

    filelist = [
        os.path.join(prefix, 'bin', 'libsearpc-1.dll'),
        os.path.join(prefix, 'bin', 'libsearpc-json-glib-0.dll'),
        os.path.join(prefix, 'bin', 'libccnet-0.dll'),
        os.path.join(prefix, 'bin', 'libseafile-0.dll'),
        os.path.join(prefix, 'bin', 'ccnet.exe'),
        os.path.join(prefix, 'bin', 'seaf-daemon.exe'),
        os.path.join(Seafile().projdir, 'gui', 'win', 'seafile-applet.exe')
    ]

    for name in filelist:
        must_copy(name, destdir)

    copy_shared_libs()

def prepare_msi():
    pack_dir = os.path.join(conf[CONF_BUILDDIR], 'pack')

    msi_dir = os.path.join(Seafile().projdir, 'msi')

    must_copytree(msi_dir, pack_dir)

    if run('make', cwd=os.path.join(pack_dir, 'custom')) != 0:
        error('Error when compiling seafile msi custom dlls')

    web_py2exe()
    copy_dll_exe()

    if not conf[CONF_NO_STRIP]:
        strip_symbols()

    # copy seafile-applet mo file
    src_mo = os.path.join(Seafile().prefix, 'share', 'locale', 'zh_CN', 'LC_MESSAGES', 'seafile.mo')
    dst_mo = os.path.join(pack_dir, 'bin', 'i18n', 'zh_CN', 'LC_MESSAGES', 'seafile.mo')
    must_copy(src_mo, dst_mo)

def strip_symbols():
    bin_dir = os.path.join(conf[CONF_BUILDDIR], 'pack', 'bin')
    ignored = []
    def do_strip(fn):
        run('strip "%s"' % fn)
        info('stripping: %s' % fn)

    def should_ignore(path):
        '''Do not strip python.dll and msvc*.dll '''
        name = os.path.basename(path).lower()
        return name.startswith('python') or name.startswith('msvc')

    for dll in glob.glob(os.path.join(bin_dir, '*.dll')):
        if should_ignore(dll):
            ignored.append(dll)
        else:
            do_strip(dll)

    for exe in glob.glob(os.path.join(bin_dir, '*.exe')):
        do_strip(exe)

    info('----------------------------')
    info('ignored:')
    for name in ignored:
        info('>> %s' % name)

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

def build_msi():
    prepare_msi()
    pack_dir = os.path.join(conf[CONF_BUILDDIR], 'pack')
    if run('make fragment.wxs', cwd=pack_dir) != 0:
        error('Error when make fragement.wxs')

    edit_fragment_wxs()

    if run('make', cwd=pack_dir) != 0:
        error('Error when make seafile.msi')

def build_english_msi():
    '''The extra work to build the English msi.'''
    gui_win = os.path.join(Seafile().projdir, 'gui', 'win')
    pack_dir = os.path.join(conf[CONF_BUILDDIR], 'pack')
    pack_bin_dir = os.path.join(conf[CONF_BUILDDIR], 'pack', 'bin')

    applet_en_name = 'seafile-applet.en.exe'
    if run('make clean', cwd=gui_win) != 0:
        error('Failed to run make clean in gui/win')

    if run('make en', cwd=gui_win) != 0:
        error('Failed to run make en in gui/win')

    if not conf[CONF_NO_STRIP]:
        if run('strip %s' % applet_en_name, cwd=gui_win) != 0:
            error('Failed to strip seafile-applet.en.exe')

    applet_en = os.path.join(gui_win, applet_en_name)
    dst_applet_en = os.path.join(pack_bin_dir, 'seafile-applet.exe')

    must_copy(applet_en, dst_applet_en)

    if run('make en', cwd=pack_dir) != 0:
        error('Error when make seafile-en.msi')

def move_msi():
    pack_dir = os.path.join(conf[CONF_BUILDDIR], 'pack')
    src_msi = os.path.join(pack_dir, 'seafile.msi')
    dst_msi = os.path.join(conf[CONF_OUTPUTDIR], 'seafile-%s.msi' % conf[CONF_VERSION])

    # move msi to outputdir
    must_copy(src_msi, dst_msi)

    if not conf[CONF_ONLY_CHINESE]:
        src_msi_en = os.path.join(pack_dir, 'seafile-en.msi')
        dst_msi_en = os.path.join(conf[CONF_OUTPUTDIR], 'seafile-%s-en.msi' % conf[CONF_VERSION])
        must_copy(src_msi_en, dst_msi_en)

    print '---------------------------------------------'
    print 'The build is successfully. Output is:'
    print '>>\t%s' % dst_msi
    if not conf[CONF_ONLY_CHINESE]:
        print '>>\t%s' % dst_msi_en
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

def main():
    parse_args()
    setup_build_env()
    check_tools()

    libsearpc = Libsearpc()
    ccnet = Ccnet()
    seafile = Seafile()

    libsearpc.uncompress()
    libsearpc.build()

    ccnet.uncompress()
    ccnet.build()

    seafile.uncompress()
    seafile.build()

    build_msi()
    if not conf[CONF_ONLY_CHINESE]:
        build_english_msi()
    move_msi()

if __name__ == '__main__':
    main()
