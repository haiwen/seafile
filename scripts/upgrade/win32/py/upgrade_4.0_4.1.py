# coding: UTF-8

import os

from upgrade_common import install_path, ccnet_dir, seafile_dir, upgrade_db, run_argv

def main():
    try:
        upgrade_db('4.1.0')
    except Exception, e:
        print 'Error:\n', e
    else:
        print '\ndone\n'
    finally:
        print '\nprint ENTER to exit\n'
        raw_input()

if __name__ == '__main__':
    main()
