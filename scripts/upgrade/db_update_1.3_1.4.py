#!/usr/bin/env python

import sqlite3
import os
import sys

def usage():
    msg = 'usage: %s <seahub db>' % os.path.basename(sys.argv[0])
    print msg

def main():
    seahub_db = sys.argv[1]

    conn = sqlite3.connect(seahub_db)
    c = conn.cursor()

    try:
        c.execute('SELECT s_type from share_fileshare')
    except sqlite3.OperationalError:
        # only add this column if not exist yet, so this script is idempotent  
        c.execute('ALTER table share_fileshare add column "s_type" varchar(2) NOT NULL DEFAULT "f"')

    c.execute('CREATE INDEX IF NOT EXISTS "share_fileshare_f775835c" ON "share_fileshare" ("s_type")')
        
    sql = '''CREATE TABLE IF NOT EXISTS "base_dirfileslastmodifiedinfo" (
    "id" integer NOT NULL PRIMARY KEY AUTOINCREMENT,
    "repo_id" varchar(36) NOT NULL,
    "parent_dir" text NOT NULL,
    "parent_dir_hash" varchar(12) NOT NULL,
    "dir_id" varchar(40) NOT NULL,
    "last_modified_info" text NOT NULL,
    UNIQUE ("repo_id", "parent_dir_hash"))'''
    
    c.execute(sql)

    sql = '''CREATE TABLE IF NOT EXISTS "api2_token" (
    "key" varchar(40) NOT NULL PRIMARY KEY,
    "user" varchar(255) NOT NULL UNIQUE,
    "created" datetime NOT NULL)'''
    
    c.execute(sql)

    conn.commit()

if __name__ == '__main__':    
    if len(sys.argv) != 2:
        usage()
        sys.exit(1)

    main()

    
