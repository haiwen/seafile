#!/usr/bin/env python
# coding: UTF-8

'''This scirpt is used to bundle all needed files into the destdir to
faciliate windows development.

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
import subprocess
import tempfile
import csv

from distutils.core import setup as dist_setup
import py2exe

def usage():
    print '''\
Usage:
    %s <target directory>
'''

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

def info(msg):
    print '[INFO] ' + msg

def error(msg=None, usage=None):
    if msg:
        print '[ERROR] ' + msg
    if usage:
        print usage
    sys.exit(1)

def which(prog):
    '''Return the path of the file <prog>, if exists in PATH'''
    dirs = os.environ['PATH'].split(';')
    for d in dirs:
        if d == '':
            continue
        path = os.path.join(d, prog)
        if os.path.exists(path):
            return path

    return None

def run(cmdline, cwd=None, env=None, suppress_stdout=False, suppress_stderr=False):
    '''Run a program and wait it to finish, and return its exit code. The
    standard output of this program is supressed.

    '''
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

def rmtree(path):
    '''Remove a directory, ignore errors'''
    try:
        shutil.rmtree(path)
    except:
        pass

def must_mkdir(path):
    '''Create a directory, exit on failure'''
    try:
        os.mkdir(path)
    except OSError, e:
        error('failed to create directory %s:%s' % (path, e))

def must_copy(src, dst):
    '''Copy src to dst, exit on failure'''
    try:
        info('copying %s --> %s' % (src, dst))
        shutil.copy(src, dst)
    except Exception, e:
        error('failed to copy %s to %s: %s' % (src, dst, e))

def must_copytree(src, dst):
    '''Copy dir src to dst, exit on failure'''
    try:
        info('copying directory %s --> %s' % (src, dst))
        shutil.copytree(src, dst)
    except Exception, e:
        error('failed to copy dir %s to %s: %s' % (src, dst, e))

def must_move(src, dst):
    '''Move src to dst, exit on failure'''
    try:
        info('moving %s --> %s' % (src, dst))
        shutil.move(src, dst)
    except Exception, e:
        error('failed to move %s to %s: %s' % (src, dst, e))

def web_py2exe():
    webdir = os.path.join(seafile_srcdir, 'web')
    dist_dir = os.path.join(webdir, 'dist')
    build_dir = os.path.join(webdir, 'build')

    rmtree(dist_dir)
    rmtree(build_dir)
    
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

    try:
        dist_setup(name=targetname,
                   options = option,
                   windows=[{"script":targetfile}],
                   data_files=ex_files)
    except Exception as e:
        error('Error when calling py2exe: %s' % e)

    for name in glob.glob('dist/*'):
        must_copy(name, bin_dir)

    must_copytree('i18n', os.path.join(bin_dir, 'i18n'))
    must_copytree('static', os.path.join(bin_dir, 'static'))
    must_copytree('templates', os.path.join(bin_dir, 'templates'))

    rmtree(dist_dir)
    rmtree(build_dir)

    sys.path.pop(0)
    sys.argv = original_argv
    os.chdir(seafile_srcdir)

def parse_depends_csv(path):
    '''parse the output of dependency walker'''
    libs = []
    def should_ingore_lib(lib):
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
            if not should_ingore_lib(lib):
                libs.append(lib)

    return libs

def copy_shared_libs():
    '''Copy shared libs need by libccnet, such as libevent, libsqlite, etc.
    First we use Dependency walker to analyse libccnet-0.dll, and get an
    output file in csv format. Then we parse the csv file to get the list of
    shared libs.

    '''

    tempdir = tempfile.gettempdir()
    output = os.path.join(tempdir, 'depends.csv')
    applet = os.path.join(seafile_srcdir, 'gui', 'win', 'seafile-applet.exe')
    cmd = 'depends.exe -c -f 1 -oc %s %s' % (output, applet)

    # See the manual of Dependency walker
    if run(cmd) > 0x100:
        error('failed to run dependency walker for libccnet')

    if not os.path.exists(output):
        error('failed to run dependency walker for libccnet')

    shared_libs = parse_depends_csv(output)
    for lib in shared_libs:
        must_copy(lib, bin_dir)

    libsqlite3 = which('libsqlite3-0.dll')
    must_copy(libsqlite3, bin_dir)

def copy_dll_exe():
    filelist = [
        'libsearpc-1.dll',
        'libsearpc-json-glib-0.dll',
        'libccnet-0.dll',
        'libseafile-0.dll',
        'ccnet.exe',
        'seaf-daemon.exe',
    ]

    filelist = [ which(f) for f in filelist ]

    applet = os.path.join(seafile_srcdir, 'gui', 'win', 'seafile-applet.exe')
    filelist.append(applet)

    for name in filelist:
        must_copy(name, bin_dir)

    copy_shared_libs()

def main():
    if not os.path.exists(destdir):
        must_mkdir(destdir)
    if not os.path.exists(bin_dir):
        must_mkdir(bin_dir)
    web_py2exe()
    copy_dll_exe()

if __name__ == '__main__':
    if len(sys.argv) != 2:
        usage()
        exit(1)

    seafile_srcdir = os.getcwd()
    destdir = to_win_path(sys.argv[1])
    bin_dir = os.path.join(destdir, 'bin')
    main()
