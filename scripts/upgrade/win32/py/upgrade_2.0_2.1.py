# coding: UTF-8

import os
import glob
import shutil

from upgrade_common import install_path, seafile_dir, upgrade_db

def copy_template_library():
    src_docs_dir = os.path.join(install_path, 'seafile', 'docs')
    library_template_dir= os.path.join(seafile_dir, 'library-template')
    if not os.path.exists(library_template_dir):
        os.mkdir(library_template_dir)

    for fn in glob.glob(os.path.join(src_docs_dir, '*.doc')):
        shutil.copy(fn, library_template_dir)

def main():
    try:
        upgrade_db('2.1.0')
        copy_template_library()
    except Exception, e:
        print 'Error:\n', e
    else:
        print '\ndone\n'
    finally:
        print '\nprint ENTER to exit\n'
        raw_input()

if __name__ == '__main__':
    main()
