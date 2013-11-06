# coding: UTF-8

from upgrade_common import upgrade_db
from add_collate import upgrade_collate

def main():
    try:
        upgrade_db('2.0.0')
        upgrade_collate()
    except Exception, e:
        print 'Error:\n', e
    else:
        print '\ndone\n'
    finally:
        print '\nprint ENTER to exit\n'
        raw_input()

if __name__ == '__main__':
    main()
