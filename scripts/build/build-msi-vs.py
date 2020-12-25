#!/usr/bin/env python
# coding: UTF-8

import sys

####################
### Requires Python 3+
####################
if sys.version_info[0] == 2:
    print('Python 2 not be supported, require Python 3. Quit now.')
    sys.exit(1)

import os
import subprocess
import shutil
import time
import glob
import re

BUILDDIR = os.path.join(os.getcwd(), "..\\..\\..\\")

##################
### Configure
##################
# The seafile package project directory
# Directory where the signing certificate is located
CERTFILE = "C:/certs/seafile.pfx"

# Qt library directory
QT_DIR = "C:/Qt/Qt5.15.1/5.15.1/msvc2019_64"

# Wix install directory
WIX_BIN = "C:/wix/bin"

# Openssl lib directory
OPENSSL_DIR = "C:/packagelib"

#####################
# Work path : seafile library and program tmp directory
# and wix build path
#####################
# Package directory
SLNOUTPUTDIR = os.path.join(BUILDDIR, "pack")

# Wix package directory
WIX_PACKAGE_DIR = os.path.join(BUILDDIR, "wix_pack")

####################
### Global variables
###################
RETRY_COUNT = 3
error_exit = False
version = ''

####################
### Common helper functions
###################

def highlight(content, is_error=False):
    '''Add ANSI color to content to get it highlighted on terminal'''
    dummy = is_error
    return content
    # if is_error:
    #     return '\x1b[1;31m%s\x1b[m' % content
    # else:
    #     return '\x1b[1;32m%s\x1b[m' % content

def info(msg):
    print(highlight('[INFO] ') + msg)

def error(msg=None, usage=None):
    if msg:
        print(highlight('[ERROR] ') + msg)
    if usage:
        print(usage)
    sys.exit(1)

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

def run(cmdline, cwd=None, env=None, suppress_stdout=False, suppress_stderr=False):
    '''Specify a command line string'''
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
        if ret != 0:
            global error_exit
            error_exit = True
        return ret

def must_copy(src, dst):
    '''Copy src to dst, exit on failure'''
    try:
        shutil.copy(src, dst)
    except Exception as e:
        error('failed to copy %s to %s: %s' % (src, dst, e))

def must_copytree(src, dst):
    '''Copy dir src to dst, exit on failure'''
    try:
        shutil.copytree(src, dst)
    except Exception as e:
        error('failed to copy dir %s to %s: %s' % (src, dst, e))

def must_rmtree(path):
    '''Recurse rm dir, exit on failure'''
    try:
        shutil.rmtree(path)
    except Exception as e:
        error('failed rm dir %s : %s' % (path, e))

def must_rename(src, dst):
    '''Rename src to dst, exit on failure'''
    try:
        os.rename(src,dst)

    except Exception as e:
        error('failed to rename %s to %s: %s' % (src, dst, e))

def must_mkdir(path):
    '''Creating directories recursively, exit on failure'''
    if os.path.exists(path):
        return
    try:
        os.makedirs(path)
    except OSError as e:
        error('failed to create directory %s:%s' % (path, e))

def dump_env():
    print('Dumping environment variables:')
    for k, v in os.environ.items():
        print('%s: %s' % (k, v)
)

def do_sign(certfile, fn, desc=None):
    info('signing file {} using cert "{}"'.format(fn, certfile))

    if desc:
        desc_flags = '-d "{}"'.format(desc)
    else:
        desc_flags = ''

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

def initworkspace():
    # Clear build file cache
    if os.path.exists(SLNOUTPUTDIR) :
        must_rmtree(SLNOUTPUTDIR)

    # Create a package directory
    must_mkdir(SLNOUTPUTDIR)

def check_project_version(version):
    '''A valid version must be like 1.2.2, 1.3'''
    if not re.match(r'^[0-9]+(\.[0-9]+)+$', version):
        error('%s is not a valid version' % version, usage="vs-build.py 2.0.0")

def check_cmd_para():
    args = sys.argv
    if len(args) != 2:
        error('The number of parameters is incorrect', usage="vs-build.py 2.0.0")
    global version
    version = args[1]
    check_project_version(version)


class Project(object):
    '''Base class for a project'''
    # Probject name, i.e. libseaprc/seafile/seafile-gui
    name = ''

    # A list of shell commands to configure/build the project
    build_commands = []

    def __init__(self):
        self.prefix = BUILDDIR
        self.projdir = os.path.join(self.prefix, self.name)
        self.outdir = os.path.join(self.projdir, 'x64', 'Release')

    def before_build(self):
        '''Hook method to do project-specific stuff before running build commands'''
        pass

    def build(self):
        '''Build the source'''
        self.before_build()
        info('Building %s' % self.name)
        # dump_env()
        for cmd in self.build_commands:
            if run(cmd, cwd=self.projdir) != 0:
                error('error when running command:\n\t%s\n' % cmd)
        self.after_build()

    def after_build(self):
        pass


class Libsearpc(Project):
    name = 'libsearpc'

    def __init__(self):
        Project.__init__(self)
        self.build_commands = [
            'devenv  "%s/libsearpc.sln" /Rebuild "Release|x64"' %(self.projdir),
        ]

    def after_build(self):
        libsearpc_path = os.path.join(self.outdir, 'libsearpc.dll')
        must_copy(libsearpc_path, SLNOUTPUTDIR)


class Seafile(Project):
    name = 'seafile'
    def __init__(self):
        Project.__init__(self)
        self.build_commands = [
            'devenv %s/seafile.sln /Rebuild "Release|x64"' %(self.projdir),
            'devenv %s/msi/custom/seafile_custom.sln /Rebuild "Release|x64"' %(self.projdir),
        ]

    def before_build(self):
        pass

    def after_build(self):

        # Copy seafile dll file to SLNOUTPUTDIR
        dlls = glob.glob(os.path.join(self.outdir, '*.dll'))
        for dll in dlls:
            must_copy(dll, SLNOUTPUTDIR)

        # Copy seafile.exe file to SLNOUTPUTDIR
        must_copy(os.path.join(self.outdir, 'seaf-daemon.exe'), SLNOUTPUTDIR)

        # Generate breakpad symbol
        dump_syms_path = os.path.join(BUILDDIR, 'breakpad', 'src', 'tools', 'windows', 'Release', 'dump_syms.exe')
        pdb_path = os.path.join(self.outdir, 'seaf-daemon.pdb')
        sym_path = os.path.join(self.outdir, 'seaf-daemon.sym')

        cmd = '%s %s > %s' %(dump_syms_path, pdb_path, sym_path)
        if run(cmd, BUILDDIR) != 0:
            error('error when running command:\n\t%s\n' % cmd)


class SeafileGUI(Project):
    name = 'seafile-client'
    target_name = 'seafile-applet.exe'
    def __init__(self):
        Project.__init__(self)
        self.build_commands = [
            'devenv %s/seafile-client.sln /Rebuild "Release|x64"' %(self.projdir) ,
        ]

    def before_build(self):
        pass

    def after_build(self):
        # Copy WinSparkle.dll to SLNOUTPUTDIR
        must_copy(os.path.join(self.projdir, 'third_party', 'WinSparkle-0.5.3', 'x64', 'Release', 'WinSparkle.dll'), SLNOUTPUTDIR)

        # Copy dll to SLNOUTPUTDIR
        dlls = glob.glob(os.path.join(self.outdir, '*.dll'))
        for dll in dlls:
            if not os.path.exists(dll) :
                must_copy(dll, SLNOUTPUTDIR)

        # Copy openssl lib to package dir
        # openssl_lib_path_list = glob.glob(os.path.join(OPENSSL_DIR, '*.dll'))
        # for lib in openssl_lib_path_list :
        #   must_copy(lib, SLNOUTPUTDIR)

        # Copy seafile-applet.exe to SLNOUTPUTDIR
        must_copy(os.path.join(self.outdir, self.target_name), SLNOUTPUTDIR)

        # Use windeloyqt.exe to copy qt resource file and lib
        windeployqt_path = os.path.join(QT_DIR, 'bin', 'windeployqt.exe')
        seafile_exe_path = os.path.join(SLNOUTPUTDIR, self.target_name)
        cmd = "%s --no-compiler-runtime %s" % (windeployqt_path, seafile_exe_path)
        if run(cmd, cwd = SLNOUTPUTDIR) != 0:
            error('error when running command:\n\t%s\n' % cmd)

        # Sign seafile exe
        need_sign_exe = [
            os.path.join(SLNOUTPUTDIR, self.target_name),
            os.path.join(SLNOUTPUTDIR, 'seaf-daemon.exe')
        ]

        for fn in need_sign_exe:
            do_sign(CERTFILE, fn)

        # Generate breakpad symbol
        dump_syms_path = os.path.join(BUILDDIR, 'breakpad', 'src', 'tools', 'windows', 'Release', 'dump_syms.exe')
        pdb_path = os.path.join(self.outdir, 'seafile-applet.pdb')
        sym_path = os.path.join(self.outdir, 'seafile-applet.sym')

        cmd = '%s %s > %s' %(dump_syms_path, pdb_path, sym_path)
        if run(cmd, BUILDDIR) != 0:
            error('error when running command:\n\t%s\n' % cmd)


class SeafileShellExt(Project):
    name = 'seafile-shell-ext'
    def __init__(self):
        Project.__init__(self)
        self.build_commands = [
            'devenv %s/extensions/seafile_ext.sln /Rebuild "Release|x64"' %(self.projdir),
            'devenv %s/shellext-fix/shellext-fix.sln /Rebuild "Release|x64"' %(self.projdir),
        ]
    def before_build(self):
        pass

    def after_build(self):
        # Copy shellext-fix.exe to SLNOUTPUTDIR
        shellext_fix_target = os.path.join(self.projdir, 'shellext-fix', 'x64\\Release', 'shellext-fix.exe')
        must_copy(shellext_fix_target, SLNOUTPUTDIR)

        # Sign seafileext-fix.exe
        do_sign(CERTFILE, os.path.join(SLNOUTPUTDIR, 'shellext-fix.exe'))


def wix_build(language):
    """ Use wix command to build windows msi install package"""

    CULTURE = 'zh-cn'
    LANG_FILE = 'zh_CN.wxl'
    TARGET = 'seafile.msi'

    if language == 'en':
        CULTURE = 'en-us'
        LANG_FILE = 'en_US.wxl'
        TARGET = 'seafile-en.msi'

    CC = '%s/candle.exe' %(WIX_BIN)
    LD = '%s/light.exe' %(WIX_BIN)

    CFLAGS = '-arch "x64" -nologo -ext WixUIExtension -ext WixUtilExtension'
    LDFLAGS  = '-nologo -spdb -ext  WixUIExtension -ext WixUtilExtension' + \
                 ' -loc %s -cultures:%s -sice:ICE80' % (LANG_FILE, CULTURE)


    generator_fragment_cmd = "%s/Paraffin.exe -dir bin -g -alias bin \
        -custom bin fragment.wxs" %(WIX_BIN)
    if run(generator_fragment_cmd, cwd=WIX_PACKAGE_DIR) != 0:
        error('error wherunning command:\n\t%s\n' % generator_fragment_cmd)

    edit_fragment_wxs()

    build_command = [
        '%s %s WixUI_InstallDir_NoLicense.wxs -o WixUI_InstallDir_NoLicense.wixobj'  % (CC, CFLAGS),
        '%s %s MyInstallDirDlg.wxs -o MyInstallDirDlg.wixobj' % (CC, CFLAGS),
        '%s %s fragment.wxs -o fragment.wixobj' % (CC, CFLAGS),
        '%s %s shell.wxs -o shell.wixobj' % (CC, CFLAGS),
        '%s %s seafile.wxs -o seafile.wixobj' % (CC, CFLAGS),
        '%s %s WixUI_InstallDir_NoLicense.wixobj MyInstallDirDlg.wixobj fragment.wixobj shell.wixobj seafile.wixobj -o %s' %(LD, LDFLAGS, TARGET),
    ]
    for cmd in build_command:
        if run(cmd, cwd=WIX_PACKAGE_DIR) != 0:
            error('error when running command:\n\t%s\n' % cmd)

    # Digitally sign the msi package
    msi_path = os.path.join(WIX_PACKAGE_DIR, TARGET)
    signinstaller(msi_path, language)


def prepare_msi():
    if os.path.exists(WIX_PACKAGE_DIR) :
       must_rmtree(WIX_PACKAGE_DIR)


    msi_dir = os.path.join(Seafile().projdir, 'msi')

    # These files are in seafile-shell-ext because they're shared between seafile/seafile
    ext_wxi = os.path.join(SeafileShellExt().projdir, 'msi', 'ext.wxi')
    must_copy(ext_wxi, msi_dir)
    shell_wxs = os.path.join(SeafileShellExt().projdir, 'msi', 'shell.wxs')
    must_copy(shell_wxs, msi_dir)

    # Copy msi to wix package directory
    if not os.path.exists(WIX_PACKAGE_DIR):
        must_copytree(msi_dir, WIX_PACKAGE_DIR)


    wix_pack_bin = os.path.join(WIX_PACKAGE_DIR, 'bin')
    if os.path.exists(wix_pack_bin) :
        os.rmdir(wix_pack_bin)

    # Copy vc runtimer merge module
    must_copy(os.path.join(OPENSSL_DIR, 'Microsoft_VC142_CRT_x64.msm'), SLNOUTPUTDIR)

    must_copytree(SLNOUTPUTDIR, wix_pack_bin)

    # Copy seafile_ext64.dll  to WIX_PACKAGE_DIR/custom
    seafile_extension_target_path = os.path.join(SeafileShellExt().projdir, 'extensions', 'x64\\Release', 'seafile_ext64.dll')
    seafile_extension_dst_path = os.path.join(WIX_PACKAGE_DIR, 'custom')
    must_copy(seafile_extension_target_path, seafile_extension_dst_path)

    # Copy seafile_custom64.dll to WIX_PACKAGE_DIR/custom
    seafile_custom_target_path = os.path.join(Seafile().projdir, 'msi\\custom\\x64\\Release', 'seafile_custom64.dll')
    must_copy(seafile_custom_target_path, seafile_extension_dst_path)


def edit_fragment_wxs():
    '''In the main wxs file(seafile.wxs) we need to reference to the id of
    seafile-applet.exe, which is listed in fragment.wxs. Since fragments.wxs is
    auto generated, the id is sequentially generated, so we need to change the
    id of seafile-applet.exe manually.

    '''
    file_path = os.path.join(WIX_PACKAGE_DIR, 'fragment.wxs')
    new_lines = []
    with open(file_path, 'r', encoding='utf-8') as fp:
        for line in fp:
            if 'seafile-applet.exe' in line:
                # change the id of 'seafile-applet.exe' to 'seafileapplet.exe'
                new_line = re.sub(r'file_bin_[\d]+', 'seafileapplet.exe', line)
                new_lines.append(new_line)
            else:
                new_lines.append(line)

    content = '\r\n'.join(new_lines)
    with open(file_path, 'w', encoding='utf-8') as fp:
        fp.write(content)

def signinstaller(msi_file_path, language):
    global version
    msi_name = ''
    if language != 'cn':
        msi_name = 'seafile-{}-{}.msi' .format(version, language)
    else:
        msi_name = 'seafile-{}.msi' .format(version)
    do_sign(CERTFILE, msi_file_path, msi_name)
    must_rename(msi_file_path, os.path.join(WIX_PACKAGE_DIR, msi_name))


def build_and_sign_msi():
    prepare_msi()

    # Build seafile msi english and chinese version
    wix_build('en')
    wix_build('cn')


def main():
    check_cmd_para()

    # Construct seafile build folder
    initworkspace()

    libsearpc = Libsearpc()
    seafile = Seafile()
    seafile_gui = SeafileGUI()
    seafile_shell_ext = SeafileShellExt()

    # Build Seadrive project
    libsearpc.build()
    seafile.build()
    seafile_gui.build()
    seafile_shell_ext.build()

    # Build seafile msi installer use wix
    build_and_sign_msi()


if __name__ == "__main__":
    main()

