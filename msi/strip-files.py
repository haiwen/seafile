import glob
import os


os.chdir('bin')

ignored = []

def do_strip(fn):
    try:
        os.system('strip "%s"' % fn)
    except Exception, e:
        print e
    else:
        print 'strip: ', fn

for dll in glob.glob('*.dll'):
    if dll.startswith('python') or dll.startswith('msvc'):
        ignored.append(dll)
        continue
    else:
        do_strip(dll)

for exe in glob.glob('*.exe'):
    do_strip(exe)
    
print '----------------------------'
print 'ignored:'
for i in ignored:
    print '>> ', i
