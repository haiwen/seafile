#!/usr/bin/env python
# coding: UTF-8

'''This script builds the seafile mac client.
'''

import atexit
import logging
import commands
from contextlib import contextmanager
import glob
import multiprocessing
import optparse
import os
from os.path import abspath, basename, dirname, join, exists, expanduser
import re
import shutil
import subprocess
import sys
import tempfile

FINAL_APP = 'Seafile Client.app'
FSPLUGIN_APPEX_NAME = 'Seafile FinderSync.appex'
CERT_ID = '79AB1AF435DD2CBC5FDB3EBBD45B0DA17727B299'

BUILDDIR = join(os.getcwd(), "../../../")

####################
### Requires Python 2.6+
####################
if sys.version_info[0] == 3:
    print 'Python 3 not supported yet. Quit now.'
    sys.exit(1)
if sys.version_info[1] < 6:
    print 'Python 2.6 or above is required. Quit now.'
    sys.exit(1)

####################
### Global variables
####################
# command line configuartion
conf = {}

# key names in the conf dictionary.
# pylint: disable=bad-whitespace
CONF_VERSION            = 'version'
CONF_NO_STRIP           = 'nostrip'
CONF_BRAND              = 'brand'

NUM_CPU = multiprocessing.cpu_count()
PID = os.getpid()

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
    logging.info(highlight('[INFO][{}] ').format(msg))

@contextmanager
def cd(path):
    oldpwd = os.getcwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(oldpwd)

def exist_in_path(prog):
    '''Test whether prog exists in system path'''
    return bool(find_in_path(prog))

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

def find_in_path(prog):
    '''Find a file in system path'''
    dirs = os.environ['PATH'].split(':')
    for d in dirs:
        if d == '':
            continue
        path = join(d, prog)
        if exists(path):
            return path

    return None

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
    info('running %s, cwd=%s' % (' '.join(['"{}"'.format(a) for a in argv]), cwd or os.getcwd()))
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
    info('running %s, cwd=%s' % (cmdline, cwd or os.getcwd()))
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

def must_run(cmdline, *a, **kw):
    ret = run(cmdline, *a, **kw)
    if ret != 0:
        error('failed to run %s' % cmdline)

def check_remove(path):
    """
    Remove the file/dir specified by `path`, if exists.
    """
    path = abspath(path)
    assert path.count('/') >= 2
    if exists(path):
        is_dir = os.path.isdir(path)
        info('removing {} {}'.format('dir' if is_dir else 'file', path))
        if is_dir:
            shutil.rmtree(path)
        else:
            os.unlink(path)

def must_mkdir(path):
    '''Create a directory, exit on failure'''
    try:
        if not exists(path):
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
    '''Copy src tree to dst, exit on failure'''
    try:
        shutil.copytree(src, dst)
    except Exception, e:
        error('failed to copy %s to %s: %s' % (src, dst, e))

def check_project_version(version):
    '''A valid version must be like 1.2.2, 1.3'''
    if not re.match(r'^[0-9]+(\.[0-9]+)+$', version):
        error('%s is not a valid version' % version, usage="build-mac-local.py 8.0.0")

def check_cmd_para():
    args = sys.argv
    if len(args) != 2:
        error('The number of parameters is incorrect', usage="build-mac-local.py 8.0.0")
    global version
    version = args[1]
    check_project_version(version)


class Project(object):
    '''Base class for a project'''
    # Probject name, i.e. libseaprc/seafile/
    name = ''

    # A list of shell commands to configure/build the project
    build_commands = []

    def __init__(self):
        # the path to pass to --prefix=/<prefix>
        self.prefix = join(BUILDDIR, 'usr')
        # project dir, like <builddir>/seafile/
        self.projdir = join(BUILDDIR, '{}' .format(self.name))

    def get_version(self):
        # libsearpc can have different versions from seafile.
        raise NotImplementedError

    def get_source_commit_id(self):
        '''By convetion, we record the commit id of the source code in the
        file "<projdir>/latest_commit"

        '''
        latest_commit_file = join(self.projdir, 'latest_commit')
        with open(latest_commit_file, 'r') as fp:
            commit_id = fp.read().strip('\n\r\t ')

        return commit_id

    def append_cflags(self, macros):
        cflags = ' '.join(['-D%s=%s' % (k, macros[k]) for k in macros])
        prepend_env_value('CPPFLAGS',
                          cflags,
                          seperator=' ')

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

def concurrent_make():
    return 'make -j%s' % NUM_CPU

class Libsearpc(Project):
    name = 'libsearpc'

    def __init__(self):
        Project.__init__(self)
        self.build_commands = [
            './autogen.sh',
            './configure --prefix=%s --disable-compile-demo' % self.prefix,
            concurrent_make(),
            'make install'
        ]

class Seafile(Project):
    name = 'seafile'
    def __init__(self):
        Project.__init__(self)
        self.build_commands = [
            './autogen.sh',
            './configure --prefix=%s --disable-fuse' % self.prefix,
            concurrent_make(),
            'make install'
        ]

    def update_cli_version(self):
        '''Substitute the version number in seaf-cli'''
        cli_py = join(self.projdir, 'app', 'seaf-cli')
        with open(cli_py, 'r') as fp:
            lines = fp.readlines()

        ret = []
        for line in lines:
            old = '''SEAF_CLI_VERSION = ""'''
            new = '''SEAF_CLI_VERSION = "%s"''' %conf[CONF_VERSION]
            line = line.replace(old, new)
            ret.append(line)

        with open(cli_py, 'w') as fp:
            fp.writelines(ret)

    def before_build(self):
        self.update_cli_version()
        macros = {}
        # SET SEAFILE_SOURCE_COMMIT_ID, so it can be printed in the log
        # macros['SEAFILE_SOURCE_COMMIT_ID'] = '\\"%s\\"' % self.get_source_commit_id()
        # self.append_cflags(macros)

class SeafileClient(Project):

    name = 'seafile-client'

    def __init__(self):
        Project.__init__(self)
        cmake_defines = {
            'CMAKE_OSX_ARCHITECTURES': 'x86_64',
            'CMAKE_OSX_DEPLOYMENT_TARGET': '10.9',
            'CMAKE_BUILD_TYPE': 'Release',
            'BUILD_SHIBBOLETH_SUPPORT': 'ON',
            'BUILD_SPARKLE_SUPPORT': 'ON',
        }
        cmake_defines_formatted = ' '.join(['-D{}={}'.format(k, v) for k, v in cmake_defines.iteritems()])
        self.build_commands = [
            'rm -f CMakeCache.txt',
            'cmake -GXcode {}'.format(cmake_defines_formatted),
            'xcodebuild -target seafile-applet -configuration Release -jobs {}'.format(NUM_CPU),
            'rm -rf seafile-applet.app',
            'cp -r Release/seafile-applet.app seafile-applet.app',
            'mkdir -p seafile-applet.app/Contents/Frameworks',
            'macdeployqt seafile-applet.app',
        ]

    def before_build(self):
        pass

class SeafileDMGLayout(Seafile):

    def __init__(self):
        Seafile.__init__(self)
        self.build_commands = [
        ]

class SeafileFinderSyncPlugin(SeafileClient):

    def __init__(self):
        SeafileClient.__init__(self)
        self.build_commands = [
            'fsplugin/build.sh'
        ]

def prepare_builddir(builddir):
    must_mkdir(builddir)

    # if not conf[CONF_KEEP]:
    #     def remove_builddir():
    #         '''Remove the builddir when exit'''
    #         info('remove builddir before exit')
    #         shutil.rmtree(builddir, ignore_errors=True)
    #     atexit.register(remove_builddir)

    os.chdir(builddir)

    must_mkdir(join(builddir, 'usr'))

def parse_args():
    parser = optparse.OptionParser()
    def long_opt(opt):
        return '--' + opt

    parser.add_option(long_opt(CONF_VERSION),
                      dest=CONF_VERSION,
                      nargs=1,
                      help='the version to build. Must be digits delimited by dots, like 1.3.0')

    parser.add_option(long_opt(CONF_NO_STRIP),
                      dest=CONF_NO_STRIP,
                      action='store_true',
                      help='''do not strip debug symbols''')

    parser.add_option(long_opt(CONF_BRAND),
                      dest=CONF_BRAND,
                      help='the brand')

    usage = parser.format_help()
    options, remain = parser.parse_args()
    if remain:
        error(usage=usage)

    validate_args(usage, options)

def validate_args(usage, options):
    required_args = [
        CONF_VERSION,
        CONF_NO_STRIP,
        CONF_BRAND,
    ]

    # fist check required args
    for optname in required_args:
        if getattr(options, optname, None) is None:
            error('%s must be specified' % optname, usage=usage)

    def get_option(optname):
        return getattr(options, optname)

    # [ version ]
    def check_project_version(version):
        '''A valid version must be like 1.2.2, 1.3'''
        if not re.match(r'^[0-9]+(\.[0-9]+)+$', version):
            error('%s is not a valid version' % version, usage=usage)

    version = get_option(CONF_VERSION)
    check_project_version(version)

    # [ no strip]
    nostrip = get_option(CONF_NO_STRIP)

    brand = get_option(CONF_BRAND)

    conf[CONF_VERSION] = version
    conf[CONF_NO_STRIP] = nostrip
    conf[CONF_BRAND] = brand

def setup_build_env():
    '''Setup environment variables, such as export PATH=$BUILDDDIR/bin:$PATH'''
    # os.environ.update({
    # })
    prefix = join(BUILDDIR, 'usr')

    prepend_env_value('CFLAGS',
                      '-Wall -O2 -g -DNDEBUG -I/opt/local/include -mmacosx-version-min=10.7',
                      seperator=' ')

    prepend_env_value('CXXFLAGS',
                      '-Wall -O2 -g -DNDEBUG -I/opt/local/include -mmacosx-version-min=10.7',
                      seperator=' ')

    prepend_env_value('CPPFLAGS',
                      '-I%s' % join(prefix, 'include'),
                      seperator=' ')

    prepend_env_value('CPPFLAGS',
                      '-DSEAFILE_CLIENT_VERSION=\\"%s\\"' % conf[CONF_VERSION],
                      seperator=' ')

    if conf[CONF_NO_STRIP]:
        prepend_env_value('CPPFLAGS',
                          '-g -O0',
                          seperator=' ')

    prepend_env_value('LDFLAGS',
                      '-L%s' % join(prefix, 'lib'),
                      seperator=' ')

    prepend_env_value('LDFLAGS',
                      '-L%s' % join(prefix, 'lib64'),
                      seperator=' ')

    prepend_env_value('LDFLAGS',
                      '-L/opt/local/lib -Wl,-headerpad_max_install_names -mmacosx-version-min=10.7',
                      seperator=' ')

    prepend_env_value('PATH', join(prefix, 'bin'))
    prepend_env_value('PKG_CONFIG_PATH', join(prefix, 'lib', 'pkgconfig'))
    prepend_env_value('PKG_CONFIG_PATH', join(prefix, 'lib64', 'pkgconfig'))

path_pattern = re.compile(r'^\s+(\S+)\s+\(compatibility.*')
def get_dependent_libs(executable):
    def is_syslib(lib):
        if lib.startswith('/usr/lib'):
            return True
        if lib.startswith('/System/'):
            return True
        return False

    otool_output = commands.getoutput('otool -L %s' % executable)
    libs = set()
    for line in otool_output.splitlines():
        m = path_pattern.match(line)
        if not m:
            continue
        path = m.group(1)
        if not is_syslib(path):
            libs.add(path)
    return libs

def copy_shared_libs():
    '''copy shared c libs, such as libevent, glib'''
    builddir = BUILDDIR
    frameworks_dir = join(SeafileClient().projdir, 'seafile-applet.app/Contents/Frameworks')

    must_mkdir(frameworks_dir)
    seafile_path = join(builddir, 'usr/bin/seaf-daemon')

    libs = set()
    libs.update(get_dependent_libs(seafile_path))

    # Get deps of deps recursively until no more deps can be included
    while True:
        newlibs = set(libs)
        for lib in libs:
            newlibs.update(get_dependent_libs(lib))
        if newlibs == libs:
            break
        libs = newlibs

    for lib in libs:
        dst_file = join(frameworks_dir, basename(lib))
        if exists(dst_file):
            continue
        info('Copying %s' % lib)
        shutil.copy(lib, frameworks_dir)

    change_rpaths()

def change_rpaths():
    """
    Chagne the rpath of the referenced dylibs so the app can be relocated
    anywhere in the user's system.
    See:
      - https://blogs.oracle.com/dipol/entry/dynamic_libraries_rpath_and_mac
      - https://developer.apple.com/library/content/documentation/DeveloperTools/Conceptual/DynamicLibraries/100-Articles/RunpathDependentLibraries.html
    """
    contents_dir = join(SeafileClient().projdir, 'seafile-applet.app/Contents')
    frameworks_dir = join(contents_dir, 'Frameworks')
    resources_dir = join(contents_dir, 'Resources')
    macos_dir = join(contents_dir, 'MacOS')

    seafile_applet = join(macos_dir, 'seafile-applet')
    binaries = [
        seafile_applet,
        join(resources_dir, 'seaf-daemon')
    ]

    RPATH_RE = re.compile(r'^path\s+(\S+)\s+\(offset .*$')
    def get_rpaths(fn):
        rpaths = []
        output = commands.getoutput('otool -l {} | grep -A2 RPATH || true'.format(fn))
        # The output is like
            #           cmd LC_RPATH
            #       cmdsize 24
            #          path /usr/local (offset 12)
            # --
            #           cmd LC_RPATH
            #       cmdsize 48
            #          path @executable_path/../Frameworks (offset 12)
        for line in output.splitlines():
            m = RPATH_RE.match(line.strip())
            if m:
                rpaths.append(m.group(1))
        return rpaths

    def has_rpath(fn, path):
        return path in get_rpaths(fn)

    def add_frameworks_dir_to_rpath(fn, executable=True):
        relpath = 'executable_path' if executable else 'loader_path'
        relative_frameworks_dir = '@{}/../Frameworks'.format(relpath)
        if not has_rpath(fn, relative_frameworks_dir):
            must_run('install_name_tool -add_rpath {} {}' .format(relative_frameworks_dir, fn))

    def remove_local_rpaths(fn):
        local_paths = ['/usr/local/lib', '/opt/local/lib']
        for path in local_paths:
            if has_rpath(fn, path):
                must_run('install_name_tool -delete_rpath {} {}'.format(path, fn))

    def change_deps_rpath(fn):
        deps = get_dependent_libs(fn)
        for dep in deps:
            bn = basename(dep)
            if 'framework' in bn or bn.startswith('Qt') or bn == 'Sparkle':
                continue
            must_run('install_name_tool -change {} @rpath/{} {}'.format(dep, basename(dep), fn))

    for binary in binaries:
        add_frameworks_dir_to_rpath(binary)
        remove_local_rpaths(binary)
        change_deps_rpath(binary)

    libs = os.listdir(frameworks_dir)
    for lib_name in libs:
        lib = join(frameworks_dir, lib_name)
        if os.path.isdir(lib):
            continue
        must_run('install_name_tool -id @rpath/{} {}'.format(basename(lib), lib))
        add_frameworks_dir_to_rpath(lib, executable=False)
        change_deps_rpath(lib)
        remove_local_rpaths(lib)

DROPDMG = '/Applications/DropDMG.app/Contents/Frameworks/DropDMGFramework.framework/Versions/A/dropdmg'

def gen_dmg():
    output_dmg = 'app-{}.dmg'.format(conf[CONF_VERSION])
    parentdir = 'app-{}'.format(conf[CONF_VERSION])
    appdir = join(parentdir, 'seafile-applet.app')
    app_plugins_dir = join(appdir, 'Contents/PlugIns')

    layout = SeafileDMGLayout()
    layout_folder = join(layout.projdir, 'dmg/seafileLayout')

    args = [
        DROPDMG,
        parentdir,
        '--format', 'bzip2',
        '--layout-folder', layout_folder,
        '--volume-name', conf[CONF_BRAND] or 'Seafile Client',
    ]

    with cd(BUILDDIR):
        check_remove(parentdir)
        check_remove(output_dmg)
        must_mkdir(parentdir)
        must_run('tar xf seafile-applet.app.tar.gz -C {}'.format(parentdir))
        # Remove the Qt Bearer plugin because it would run a background thread
        # to scan wifi networks. See
        # https://trello.com/c/j28eOIo1/359-explicitly-exclude-qt-bearer-plugins-for-the-windows-and-mac-packages
        # for details.
        must_run('rm -rf "{}"'.format(join(app_plugins_dir, 'bearer')))
        # fsplugin must be copied before we sign the final .app dir
        copy_fsplugin(app_plugins_dir)
        sign_files(appdir)

        # Rename the .app dir to 'Seafile Client.app', and create the shortcut
        # to '/Applications' so the user can drag into it when opening the DMG.
        brand = conf.get('CONF_BRAND', '')
        if brand:
            final_app = '{}.app'.format(brand)
        else:
            final_app = FINAL_APP
        must_run('mv {}/seafile-applet.app "{}/{}"'.format(parentdir, parentdir, final_app))
        must_run('ln -sf /Applications {}/'.format(parentdir))

        # Open DropDMG manually, or dropdmg command line may fail.
        run(''' osascript -e 'tell application "DropDMG" to quit' || true ''')
        run(''' osascript -e 'open application "DropDMG"' || true ''')
        run(''' osascript -e 'activate application "DropDMG"' || true ''')

        # Sometimes DropDmg would fail if there are two many Finder windows.
        run(''' osascript -e 'tell application "Finder" to close every window' ''')
        if run_argv(args) != 0:
            error('failed to run {}'.format(args))

def sign_in_parallel(files_to_sign):
    import threading
    import Queue
    queue = Queue.Queue()
    POISON_PILL = ''

    class SignThread(threading.Thread):
        def __init__(self, index):
            threading.Thread.__init__(self)
            self.index = index

        def run(self):
            info('sign thread {} started'.format(self.index))
            while True:
                try:
                    fn = queue.get(timeout=1)
                except Queue.Empty:
                    continue
                else:
                    if fn == POISON_PILL:
                        break
                    else:
                        do_sign(fn)
            info('sign thread {} stopped'.format(self.index))

    TOTAL_THREADS = max(NUM_CPU / 2, 1)
    threads = []
    for i in xrange(TOTAL_THREADS):
        t = SignThread(i)
        t.start()
        threads.append(t)

    for fn in files_to_sign:
        queue.put(fn)

    for _ in xrange(TOTAL_THREADS):
        queue.put(POISON_PILL)

    for i in xrange(TOTAL_THREADS):
        threads[i].join()

def sign_files(appdir):
    webengine_app = join(
        appdir,
        'Contents/Frameworks/QtWebEngineCore.framework/Versions/5/Helpers/QtWebEngineProcess.app'
    )

    def _glob(pattern, *a, **kw):
        return glob.glob(join(appdir, pattern), *a, **kw)

    # The webengine app must be signed first, otherwise the sign of
    # QtWebengineCore.framework would fail.
    if exists(webengine_app):
        entitlements = join(Seafile().projdir, 'scripts/build/osx.entitlements')
        do_sign(
            webengine_app,
            extra_args=['--entitlements', entitlements]
        )

    # Strip the get-task-allow entitlements for Sparkle binaries
    for fn in _glob('Contents/Frameworks/Sparkle.framework/Versions/A/Resources/Autoupdate.app/Contents/MacOS/*'):
        do_sign(fn, preserve_entitlemenets=False)

    # Sign the nested contents of Sparkle before we sign
    # Sparkle.Framework in the thread pool.
    for fn in (
            'Contents/Frameworks/Sparkle.framework/Versions/A/Resources/Autoupdate.app',
            'Contents/Frameworks/Sparkle.framework/Versions/A/Sparkle',
    ):
        do_sign(join(appdir, fn))

    patterns = [
        'Contents/Frameworks/*.framework',
        'Contents/PlugIns/*/*.dylib',
        'Contents/Frameworks/*.dylib',
        'Contents/Resources/seaf-daemon',
        'Contents/MacOS/seadrive-gui',
    ]

    files_to_sign = []
    for p in patterns:
        files_to_sign.extend(_glob(p))

    info('{} files to sign'.format(len(files_to_sign)))

    sign_in_parallel(files_to_sign)
    # for fn in files_to_sign:
    #     do_sign(fn)

    do_sign(appdir)
    # do_sign(appdir, extra_args=['--deep'])

_keychain_unlocked = False
def unlock_keychain():
    """
    Unlock the keychain when we're using ssh instead of using the terminal from
    GUI. See http://stackoverflow.com/a/20208104/1467959
    """
    global _keychain_unlocked
    if not _keychain_unlocked:
        _keychain_unlocked = True
        run('security -v unlock-keychain -p vagrant || true')

def do_sign(path, extra_args=None, preserve_entitlemenets=True):
    unlock_keychain()
    args = [
        'codesign',
        '--verbose=4',
        '-o', 'runtime',
        '--timestamp',
        '--verify',
        # '--no-strict',
        '--force',
        '-s', CERT_ID,
    ]
    if preserve_entitlemenets:
        args += ['--preserve-metadata=entitlements']
    extra_args = extra_args or []
    if extra_args:
        args.extend(extra_args)

    args.append(path)

    if run_argv(args) != 0:
        error('failed to sign {}'.format(path))

def copy_dmg():
    brand = conf[CONF_BRAND] or 'seafile-client'
    branded_dmg = '{}-{}.dmg'.format(brand, conf[CONF_VERSION])
    src_dmg = os.path.join(BUILDDIR, 'app-{}.dmg'.format(conf[CONF_VERSION]))
    dst_dmg = os.path.join(BUILDDIR, branded_dmg)

    # move msi to outputdir
    must_copy(src_dmg, dst_dmg)

    print '---------------------------------------------'
    print 'The build is successfully. Output is:'
    print '>>\t%s' % dst_dmg
    print '---------------------------------------------'

def notarize_dmg():
    pkg = os.path.join(BUILDDIR, 'app-{}.dmg'.format(conf[CONF_VERSION]))
    info('Try to notarize {}'.format(pkg))
    notarize_script = join(Seafile().projdir, 'scripts/build/notarize.sh')
    cmdline = '{} {}'.format(notarize_script, pkg)
    ret = run(cmdline)
    if ret != 0:
        error('failed to notarize: %s' % cmdline)
    info('Successfully notarized {}'.format(pkg))

def build_and_sign_fsplugin():
    """
    Build and sign the fsplugin. The final output would be "${buildder}/Seafile FinderSync.appex"
    """
    fsplugin = SeafileFinderSyncPlugin()
    fsplugin.build()
    with cd(fsplugin.projdir):
        appex_src = 'fsplugin/{}'.format(FSPLUGIN_APPEX_NAME)
        appex_dst = join(BUILDDIR, basename(appex_src))

        check_remove(appex_dst)
        must_copytree(appex_src, appex_dst)

        entitlements_src = 'fsplugin/seafile-fsplugin.entitlements'
        entitlements_dst = join(BUILDDIR, basename(entitlements_src))

        check_remove(entitlements_dst)
        must_copy(entitlements_src, entitlements_dst)

    do_sign(
        appex_dst,
        extra_args=['--entitlements', entitlements_dst]
    )

def copy_fsplugin(plugins_dir):
    src = join(BUILDDIR, FSPLUGIN_APPEX_NAME)
    dst = join(plugins_dir, FSPLUGIN_APPEX_NAME)
    check_remove(dst)
    must_copytree(src, dst)

def copy_sparkle_framework():
    src = '/usr/local/Sparkle.framework'
    dst = join(SeafileClient().projdir, 'seafile-applet.app/Contents/Frameworks', basename(src))
    check_remove(dst)
    # Here we use the `cp` command instead of shutil to do the copy, because `cp
    # -P` would keep symlinks as is.
    must_run('cp -R -P "{}" "{}"'.format(src, dst))

def build_projects():
    prepare_builddir(BUILDDIR)
    libsearpc = Libsearpc()
    seafile = Seafile()
    seafile_client = SeafileClient()

    libsearpc.build()

    seafile.build()

    seafile_client.build()

    copy_sparkle_framework()

    copy_shared_libs()

def local_workflow():
    build_projects()
    generate_app_tar_gz()

    build_and_sign_fsplugin()
    gen_dmg()
    notarize_dmg()
    copy_dmg()


def generate_app_tar_gz():
    output_app_tgz = join(BUILDDIR, 'seafile-applet.app.tar.gz')
    with cd(SeafileClient().projdir):
        run('tar czf {} seafile-applet.app'.format(output_app_tgz))

def setup_logging(level=logging.INFO):
    kw = {
        'format': '[%(asctime)s][%(module)s]: %(message)s',
        'datefmt': '%m/%d/%Y %H:%M:%S',
        'level': level,
        'stream': sys.stdout
    }

    logging.basicConfig(**kw)
    logging.getLogger('requests.packages.urllib3.connectionpool').setLevel(
        logging.WARNING)

def main():
    setup_logging()
    parse_args()
    # check_cmd_para()
    info('{} script started'.format(abspath(__file__)))
    info('NUM_CPU = {}'.format(NUM_CPU))
    setup_build_env()
    local_workflow()

if __name__ == '__main__':
    main()
