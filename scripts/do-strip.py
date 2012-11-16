#!/usr/bin/env python


import commands
import glob
import os

def do_strip(fn):
    print 'strip:\t', fn
    os.system('strip "%s"' % fn)

def remove_static_lib(fn):
    print 'removing:\t', fn
    os.remove(fn)
    
for parent, dnames, fnames in os.walk("seafile-server/seafile"):
    for fname in fnames:
        fn = os.path.join(parent, fname)
        if os.path.isdir(fn):
            continue

        if os.path.islink(fn):
            continue

        if fn.endswith(".a") or fn.endswith(".la"):
            remove_static_lib(fn)

        finfo = commands.getoutput('file "%s"' % fn)

        if 'not stripped' in finfo:
            do_strip(fn)
            
print 'DONE'            
