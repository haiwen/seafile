#!/usr/bin/env python

import sqlite3
import os
import sys

def usage():
    msg = 'usage: %s <seafile db> <seahub db>' % os.path.basename(sys.argv[0])
    print msg

def alter_seafile_db(seafile_db):
    conn = sqlite3.connect(seafile_db)
    c = conn.cursor()

    try:
        c.execute('SELECT head_id FROM RepoSize')
    except sqlite3.OperationalError:
        c.execute('ALTER TABLE RepoSize ADD COLUMN head_id CHAR(41)')

    conn.commit()

def alter_seahub_db(seahub_db):
    conn = sqlite3.connect(seahub_db)
    c = conn.cursor()

    try:
        c.execute('SELECT last_commit_id FROM base_filecontributors')
    except sqlite3.OperationalError:
        c.execute('ALTER TABLE base_filecontributors ADD COLUMN last_commit_id CHAR(41)')
        c.execute('UPDATE base_filecontributors SET last_commit_id=""')

    conn.commit()

def main():
    seafile_db = sys.argv[1]
    seahub_db = sys.argv[2]

    alter_seafile_db(seafile_db)
    alter_seahub_db(seahub_db)

if __name__ == '__main__':    
    if len(sys.argv) != 3:
        usage()
        sys.exit(1)

    main()

