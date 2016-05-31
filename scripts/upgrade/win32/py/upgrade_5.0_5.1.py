# coding: UTF-8

import shutil
import os
import traceback
from os.path import abspath, basename, exists, dirname, join
from upgrade_common import (install_path, seafserv_dir, ccnet_dir, seafile_dir,
                            upgrade_db, run_argv)

def main():
    try:
        upgrade_db('5.1.0')
    except Exception, e:
        traceback.print_exc()
        print 'Error:\n', e
    else:
        print '\ndone\n'
    finally:
        print '\nprint ENTER to exit\n'
        raw_input()


if __name__ == '__main__':
    main()
