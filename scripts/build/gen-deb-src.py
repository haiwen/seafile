#!/usr/bin/env python
# coding: UTF-8

'''This scirpt builds the seafile debian source tarball. In this tarball,
libsearpc and ccnet is also included.

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
import tempfile
import glob
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
CONF_LIBSEARPC_VERSION  = 'libsearpc_version'
CONF_CCNET_VERSION      = 'ccnet_version'
CONF_SEAFILE_VERSION    = 'seafile_version'
CONF_SEAFILE_CLIENT_VERSION    = 'seafile_client_version'
CONF_SRCDIR             = 'srcdir'
CONF_KEEP               = 'keep'
CONF_BUILDDIR           = 'builddir'
CONF_OUTPUTDIR          = 'outputdir'

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

    info('running %s, cwd=%s' % (' '.join(argv), cwd if cwd else os.getcwd()))
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

def check_targz_src(proj, version, srcdir):
    src_tarball = os.path.join(srcdir, '%s-%s.tar.gz' % (proj, version))
    if not os.path.exists(src_tarball):
        error('%s not exists' % src_tarball)

def remove_unused_files():
    srcdir = os.path.join(conf[CONF_BUILDDIR], 'seafile-%s' % conf[CONF_VERSION])
    web_sh_files = glob.glob(os.path.join(srcdir, 'web', '*.sh'))
    files = [
        os.path.join(srcdir, 'web', 'pygettext.py'),
    ]
    files.extend(web_sh_files)

    for f in files:
        run('rm -f %s' % f)

def gen_tarball():
    output = os.path.join(conf[CONF_OUTPUTDIR], 'seafile-client-latest.tar.gz')
    dirname = 'seafile-%s' % conf[CONF_VERSION]

    ignored_patterns = [
        # windows msvc dlls
        os.path.join(dirname, 'msi', 'bin*'),
    ]

    excludes_list = [ '--exclude=%s' % pattern for pattern in ignored_patterns ]
    argv = [
        'tar',
        'czvf',
        output,
        dirname,
    ]

    argv.append(*excludes_list)

    if run_argv(argv) != 0:
        error('failed to gen %s' % output)

    print '---------------------------------------------'
    print 'The build is successfully. Output is:\t%s' % output
    print '---------------------------------------------'

def uncompress_seafile():
    src = os.path.join(conf[CONF_BUILDDIR], 'seafile-%s' % conf[CONF_SEAFILE_VERSION])
    dst = os.path.join(conf[CONF_BUILDDIR], 'seafile-%s' % conf[CONF_VERSION])

    if os.path.exists(src):
        error('dir %s already exists' % src)
    if os.path.exists(dst):
        error('dir %s already exists' % dst)

    tarball = os.path.join(conf[CONF_SRCDIR], 'seafile-%s.tar.gz' % conf[CONF_SEAFILE_VERSION])
    argv = [ 'tar', 'xf',
             tarball,
             '-C', conf[CONF_BUILDDIR],
         ]

    if run_argv(argv) != 0:
        error('failed to uncompress seafile')

    if conf[CONF_VERSION] != conf[CONF_SEAFILE_VERSION]:
        shutil.move(src, dst)

def uncompress_libsearpc():
    tarball = os.path.join(conf[CONF_SRCDIR], 'libsearpc-%s.tar.gz' % conf[CONF_LIBSEARPC_VERSION])
    dst_dir = os.path.join(conf[CONF_BUILDDIR], 'seafile-%s' % conf[CONF_VERSION], 'libsearpc')
    must_mkdir(dst_dir)
    argv = [ 'tar', 'xf',
             tarball,
             '--strip-components=1',
             '-C', dst_dir,
         ]

    if run_argv(argv) != 0:
        error('failed to uncompress libsearpc')

def uncompress_ccnet():
    tarball = os.path.join(conf[CONF_SRCDIR], 'ccnet-%s.tar.gz' % conf[CONF_CCNET_VERSION])
    dst_dir = os.path.join(conf[CONF_BUILDDIR], 'seafile-%s' % conf[CONF_VERSION], 'ccnet')
    must_mkdir(dst_dir)
    argv = [ 'tar', 'xf',
             tarball,
             '--strip-components=1',
             '-C', dst_dir,
         ]

    if run_argv(argv) != 0:
        error('failed to uncompress ccnet')

def uncompress_seafile_client():
    tarball = os.path.join(conf[CONF_SRCDIR], 'seafile-client-%s.tar.gz' % conf[CONF_SEAFILE_CLIENT_VERSION])
    dst_dir = os.path.join(conf[CONF_BUILDDIR], 'seafile-%s' % conf[CONF_VERSION], 'seafile-client')
    must_mkdir(dst_dir)
    argv = [ 'tar', 'xf',
             tarball,
             '--strip-components=1',
             '-C', dst_dir,
         ]

    if run_argv(argv) != 0:
        error('failed to uncompress ccnet')

def remove_debian_subdir():
    debian_subdir = os.path.join(conf[CONF_BUILDDIR], 'seafile-%s' % conf[CONF_VERSION], 'debian')
    argv = [ 'rm', '-rf', debian_subdir ]
    if run_argv(argv) != 0:
        error('failed to uncompress ccnet')


def parse_args():
    parser = optparse.OptionParser()
    def long_opt(opt):
        return '--' + opt

    parser.add_option(long_opt(CONF_VERSION),
                      dest=CONF_VERSION,
                      nargs=1,
                      help='the version of seafile source. Must be digits delimited by dots, like 1.3.0')

    parser.add_option(long_opt(CONF_SEAFILE_VERSION),
                      dest=CONF_SEAFILE_VERSION,
                      nargs=1,
                      help='the version of seafile. Must be digits delimited by dots, like 1.3.0')

    parser.add_option(long_opt(CONF_LIBSEARPC_VERSION),
                      dest=CONF_LIBSEARPC_VERSION,
                      nargs=1,
                      help='the version of libsearpc as specified in its "configure.ac". Must be digits delimited by dots, like 1.3.0')

    parser.add_option(long_opt(CONF_CCNET_VERSION),
                      dest=CONF_CCNET_VERSION,
                      nargs=1,
                      help='the version of ccnet as specified in its "configure.ac". Must be digits delimited by dots, like 1.3.0')

    parser.add_option(long_opt(CONF_SEAFILE_CLIENT_VERSION),
                      dest=CONF_SEAFILE_CLIENT_VERSION,
                      nargs=1,
                      help='the version of seafile-client. Must be digits delimited by dots, like 1.3.0')

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

    usage = parser.format_help()
    options, remain = parser.parse_args()
    if remain:
        error(usage=usage)

    validate_args(usage, options)

def validate_args(usage, options):
    required_args = [
        CONF_VERSION,
        CONF_SEAFILE_VERSION,
        CONF_LIBSEARPC_VERSION,
        CONF_CCNET_VERSION,
        CONF_SEAFILE_CLIENT_VERSION,
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
        if not re.match('^[0-9](\.[0-9])+$', version):
            error('%s is not a valid version' % version, usage=usage)

    version = get_option(CONF_VERSION)
    libsearpc_version = get_option(CONF_LIBSEARPC_VERSION)
    ccnet_version = get_option(CONF_CCNET_VERSION)
    seafile_version = get_option(CONF_SEAFILE_VERSION)
    seafile_client_version = get_option(CONF_SEAFILE_CLIENT_VERSION)

    check_project_version(version)
    check_project_version(libsearpc_version)
    check_project_version(ccnet_version)
    check_project_version(seafile_version)
    check_project_version(seafile_client_version)

    # [ srcdir ]
    srcdir = get_option(CONF_SRCDIR)
    check_targz_src('libsearpc', libsearpc_version, srcdir)
    check_targz_src('ccnet', ccnet_version, srcdir)
    check_targz_src('seafile', seafile_version, srcdir)
    check_targz_src('seafile-client', seafile_client_version, srcdir)

    # [ builddir ]
    builddir = get_option(CONF_BUILDDIR)
    if not os.path.exists(builddir):
        error('%s does not exist' % builddir, usage=usage)

    builddir = os.path.join(builddir, 'seafile-deb-src')

    # [ outputdir ]
    outputdir = get_option(CONF_OUTPUTDIR)
    if not os.path.exists(outputdir):
        error('outputdir %s does not exist' % outputdir, usage=usage)

    # [ keep ]
    keep = get_option(CONF_KEEP)

    conf[CONF_VERSION] = version
    conf[CONF_LIBSEARPC_VERSION] = libsearpc_version
    conf[CONF_CCNET_VERSION] = ccnet_version
    conf[CONF_SEAFILE_VERSION] = seafile_version
    conf[CONF_SEAFILE_CLIENT_VERSION] = seafile_client_version

    conf[CONF_BUILDDIR] = builddir
    conf[CONF_SRCDIR] = srcdir
    conf[CONF_OUTPUTDIR] = outputdir
    conf[CONF_KEEP] = keep

    prepare_builddir(builddir)
    show_build_info()

def prepare_builddir(builddir):
    must_mkdir(builddir)

    if not conf[CONF_KEEP]:
        def remove_builddir():
            '''Remove the builddir when exit'''
            info('remove builddir before exit')
            shutil.rmtree(builddir, ignore_errors=True)
        atexit.register(remove_builddir)

    os.chdir(builddir)

def show_build_info():
    '''Print all conf information. Confirm before continue.'''
    info('------------------------------------------')
    info('Seafile debian source tarball %s:' % conf[CONF_VERSION])
    info('------------------------------------------')
    info('seafile:          %s' % conf[CONF_SEAFILE_VERSION])
    info('seafile-client:   %s' % conf[CONF_SEAFILE_CLIENT_VERSION])
    info('ccnet:            %s' % conf[CONF_CCNET_VERSION])
    info('libsearpc:        %s' % conf[CONF_LIBSEARPC_VERSION])
    info('builddir:         %s' % conf[CONF_BUILDDIR])
    info('outputdir:        %s' % conf[CONF_OUTPUTDIR])
    info('source dir:       %s' % conf[CONF_SRCDIR])
    info('clean on exit:    %s' % (not conf[CONF_KEEP]))
    info('------------------------------------------')
    info('press any key to continue ')
    info('------------------------------------------')
    dummy = raw_input()

def main():
    parse_args()
    uncompress_seafile()
    uncompress_libsearpc()
    uncompress_ccnet()
    uncompress_seafile_client()
    remove_debian_subdir()
    remove_unused_files()
    gen_tarball()

if __name__ == '__main__':
    main()