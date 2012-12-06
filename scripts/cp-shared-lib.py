#!/usr/bin/env python

import os
import sys
import shutil

syslibs = ['libsearpc', 'libccnet', 'libseafile', 'libpthread.so', 'libc.so', 'libm.so', 'librt.so', 'libdl.so', 'libselinux.so']

def is_syslib(lib):
    for syslib in syslibs:
        if syslib in lib:
            return True
    return False

if len(sys.argv) < 2:
    print 'usage: %s <dst_dir>' % sys.argv[0]
    sys.exit()

delete = False
if len(sys.argv) == 3 and 'd' in sys.argv[2].lower():
    delete = True

dst_dir = sys.argv[1]

ldd_output = os.popen('ldd `which httpserver`').read()

lines = ldd_output.splitlines()
for line in lines:
    tokens = line.split()
    if len(tokens) != 4:
        continue
    if is_syslib(tokens[0]):
        continue

    if not delete:
        print 'Copying %s' % tokens[2]
        shutil.copy(tokens[2], dst_dir)
    else:
        print 'deleting %s' % tokens[2]
        fn = os.path.join(dst_dir, os.path.basename(tokens[2]))
        os.remove(fn)

