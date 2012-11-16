#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sqlite3
import os
import sys

usage = """Usage: alter_ccnet_seafile_db.py <ccnet conf dir> <seaifle data dir>\n
This script would update your database from 0.9.5 to 1.0.0.
"""

if len(sys.argv) != 3:
    print(usage)
    sys.exit(-1)

ccnet_path = sys.argv[1]
seafile_path = sys.argv[2]

group_db = os.path.join(ccnet_path, 'GroupMgr/groupmgr.db')
org_db = os.path.join(ccnet_path, 'OrgMgr/orgmgr.db')
user_db = os.path.join(ccnet_path, 'PeerMgr/usermgr.db')
seafile_db = os.path.join(seafile_path, 'seafile.db')

group_db_exists = True
if not os.access(group_db, os.F_OK):
    group_db_exists = False

org_db_exists = True
if not os.access(org_db, os.F_OK):
    org_db_exists = False

user_db_exists = True
if not os.access(user_db, os.F_OK):
    user_db_exists = False

seafile_db_exists = True
if not os.access(seafile_db, os.F_OK):
    seafile_db_exists = False

def alter_group_db():
    ''' Alter Group table'''
    conn = sqlite3.connect(group_db)
    c = conn.cursor()

    # Check data to ensure max group id in Group table and GroupUser table are
    # equal, otherwise may cause unique error when insert to GroupUser.
    c.execute('''SELECT MAX(`group_id`) FROM `Group`''')
    for row in c:
        max_gid = row[0]
    c.execute("DELETE FROM `GroupUser` WHERE `group_id` > %d" % max_gid)

    # Create new group table.
    c.execute('''CREATE TABLE IF NOT EXISTS `Group_new` (`group_id` INTEGER PRIMARY KEY AUTOINCREMENT, `group_name` VARCHAR(255), `creator_name` VARCHAR(255), `timestamp` BIGINT) ''')

    # Dump old group data to new table.
    c.execute('''INSERT INTO `Group_new` (`group_name`, `creator_name`, `timestamp`) SELECT `group_name`, `creator_name`, `timestamp` FROM `Group`''')

    # Drop old group table, and rename new table to `Group`.
    c.execute('''DROP TABLE `Group`''')
    c.execute('''ALTER TABLE `Group_new` RENAME TO `Group`''')

    conn.commit()
    c.close()
    print 'Add `AUTOINCREMENT` to Group table...Done.'

def alter_org_db():
    ''' Alter Oranization table'''
    conn = sqlite3.connect(org_db)
    c = conn.cursor()

    # Create new org table.
    c.execute('''CREATE TABLE Organization_new (org_id INTEGER PRIMARY KEY AUTOINCREMENT, org_name VARCHAR(255), url_prefix VARCHAR(255),  creator VARCHAR(255), ctime BIGINT)''')

    # Dump old org data to new table.
    c.execute('''INSERT INTO Organization_new (org_name, url_prefix, creator, ctime) SELECT org_name, url_prefix, creator, ctime FROM Organization''')

    # Drop old org table, and rename new table to Org.
    c.execute('''DROP TABLE Organization''')
    c.execute('''ALTER TABLE Organization_new RENAME TO Organization''')

    conn.commit()
    c.close()
    print 'Add `AUTOINCREMENT` to Organization table...Done.'

def alter_emailuser():
    ''' Alter EmailUser table'''
    conn = sqlite3.connect(user_db)
    c = conn.cursor()

    # Create new EmailUser table.
    c.execute('''CREATE TABLE EmailUser_new (id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, email TEXT, passwd TEXT, is_staff bool NOT NULL, is_active bool NOT NULL, ctime INTEGER)''')

    # Dump old EmailUser data to new table.
    c.execute('''INSERT INTO EmailUser_new (email, passwd, is_staff, is_active, ctime) SELECT email, passwd, is_staff, is_active, ctime FROM EmailUser''')

    # Drop old EmailUser table, and rename new table to EmailUser.
    c.execute('''DROP TABLE EmailUser''')
    c.execute('''ALTER TABLE EmailUser_new RENAME TO EmailUser''')

    conn.commit()
    c.close()
    print 'Add `AUTOINCREMENT` to EmailUser table...Done.'

    conn = sqlite3.connect(user_db)
    c = conn.cursor()
    c.execute('''DROP INDEX IF EXISTS email_index''')
    try:
        c.execute('''CREATE UNIQUE INDEX IF NOT EXISTS email_index on EmailUser (email)''')
    except sqlite3.IntegrityError:
        print 'Failed in adding unique index for EmailUser, please remove duplicate emails rows in EmailUser.'
        c.close()
    else:
        print 'Add index ...Done'
        conn.commit()
        c.close()

def alter_seafile_db():
    ''' Add index'''
    conn = sqlite3.connect(seafile_db)
    c = conn.cursor()

    c.execute('''CREATE INDEX IF NOT EXISTS repogroup_repoid_index on RepoGroup (repo_id)''')
    c.execute('''CREATE INDEX IF NOT EXISTS repogroup_username_indx on RepoGroup (user_name)''')

    c.execute('''CREATE INDEX IF NOT EXISTS orgrepo_orgid_user_indx on OrgRepo (org_id, user)''')

    conn.commit()
    c.close()

if __name__ == '__main__':
    if group_db_exists:
        alter_group_db()
 
    if org_db_exists:
        alter_org_db()

    if user_db_exists:
        alter_emailuser()

    if seafile_db_exists:
        try:
            alter_seafile_db()
        except:
            pass
