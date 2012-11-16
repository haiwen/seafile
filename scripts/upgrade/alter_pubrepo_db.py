#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sqlite3
import os
import sys

usage = """Usage: alter_pubrepo_db.py <seaifle data dir>\n
"""

if len(sys.argv) != 2:
    print(usage)
    sys.exit(-1)

seafile_path = sys.argv[1]

seafile_db = os.path.join(seafile_path, 'seafile.db')

def alter_pubrepo_db():
    conn = sqlite3.connect(seafile_db)
    c = conn.cursor()

    try:
        c.execute('SELECT permission FROM InnerPubRepo')
    except sqlite3.OperationalError, e:
        c.execute('ALTER TABLE InnerPubRepo ADD COLUMN permission CHAR(15)')
        c.execute('UPDATE InnerPubRepo SET permission="rw"')

    conn.commit()

if __name__ == '__main__':
    alter_pubrepo_db()
