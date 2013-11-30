# coding: UTF-8

'''
Database Upgrade scripts for seafile windows server 2.0.2
'''

import os
import sys
import re
import sqlite3
import logging
import shutil

from upgrade_common import seafserv_dir, ccnet_dir, seafile_dir

# seafserv_dir = '/tmp/haiwen'
# ccnet_dir = os.path.join(seafserv_dir, 'ccnet')
# seafile_dir = os.path.join(seafserv_dir, 'seafile-data')

def error_exit(msg):
    print 'Error: %s' % msg
    sys.exit(1)

class Pattern(object):
    def __init__(self, old, new):
        self.old = old
        self.new = new

class AbstractDBUpdater(object):
    '''Base class to update a database'''

    name = ''
    patterns = []

    def __init__(self, db_path):
        self.db_path = db_path
        self.lines = []
        self.tmp = self.db_path + '.tmp'

        try:
            if os.path.exists(self.tmp):
                os.remove(self.tmp)
        except:
            logging.exception('Error when delete temporary database %s' % self.tmp)
            sys.exit(1)

    def do_update(self):
        print 'updating %s' % self.name
        self.dump_db()
        self.update_schema()
        self.write_db()

    def dump_db(self):
        '''Dump all the schema and data'''
        with sqlite3.connect(self.db_path) as conn:
            for line in conn.iterdump():
                self.lines.append(line.replace('\n', ' '))

    def update_schema(self):
        '''Update schema of tables in this database to add "collate nocase"'''
        new_lines = []
        for line in self.lines:
            new_line = line
            if line.lower().startswith("create table"):
                for pattern in self.patterns:
                    new_line = re.sub(pattern.old, pattern.new, new_line)
            new_lines.append(new_line)

        self.lines = new_lines

    def write_db(self):
        with sqlite3.connect(self.tmp) as conn:
            cursor = conn.cursor()
            for line in self.lines:
                if line.lower().strip().strip(';') in ('begin transaction', 'commit'):
                    continue
                cursor.execute(line)

        shutil.copy(self.tmp, self.db_path)

        try:
            if os.path.exists(self.tmp):
                os.remove(self.tmp)
        except:
            pass

class CcnetUserDBUpdater(AbstractDBUpdater):
    name = 'user database'
    patterns = [
        Pattern(r'(CREATE TABLE EmailUser.*)email TEXT,(.*)',
                r'\1email TEXT COLLATE NOCASE,\2'),

        Pattern(r'(CREATE TABLE Binding.*)email TEXT,(.*)',
                r'\1email TEXT COLLATE NOCASE,\2'),
    ]

    def __init__(self, user_db):
        AbstractDBUpdater.__init__(self, user_db)

class CcnetGroupDBUpdater(AbstractDBUpdater):
    name = 'group database'
    patterns = [
        Pattern(r'(CREATE TABLE `Group`.*)`creator_name` VARCHAR\(255\),(.*)',
                r'\1`creator_name` VARCHAR(255) COLLATE NOCASE,\2'),
        Pattern(r'(CREATE TABLE `GroupUser`.*)`user_name` VARCHAR\(255\),(.*)',
                r'\1`user_name` VARCHAR(255) COLLATE NOCASE,\2'),
    ]

    def __init__(self, group_db):
        AbstractDBUpdater.__init__(self, group_db)

class SeafileDBUpdater(AbstractDBUpdater):
    name = 'seafile database'
    patterns = [
        Pattern(r'(CREATE TABLE RepoOwner.*)owner_id TEXT(.*)',
                r'\1owner_id TEXT COLLATE NOCASE\2'),

        Pattern(r'(CREATE TABLE RepoGroup.*)user_name TEXT,(.*)',
                r'\1user_name TEXT COLLATE NOCASE,\2'),

        Pattern(r'(CREATE TABLE RepoUserToken.*)email VARCHAR\(255\),(.*)',
                r'\1email VARCHAR(255) COLLATE NOCASE,\2'),

        Pattern(r'(CREATE TABLE UserQuota.*)user VARCHAR\(255\),(.*)',
                r'\1user VARCHAR(255) COLLATE NOCASE,\2' ),

        Pattern(r'(CREATE TABLE SharedRepo.*)from_email VARCHAR\(512\), to_email VARCHAR\(512\),(.*)',
                r'\1from_email VARCHAR(512), to_email VARCHAR(512) COLLATE NOCASE,\2'),
    ]

    def __init__(self, seafile_db):
        AbstractDBUpdater.__init__(self, seafile_db)

class SeahubDBUpdater(AbstractDBUpdater):
    name = 'seahub database'
    patterns = [
        Pattern(r'(CREATE TABLE "notifications_usernotification".*)"to_user" varchar\(255\) NOT NULL,(.*)',
                r'\1"to_user" varchar(255) NOT NULL COLLATE NOCASE,\2'),

        Pattern(r'(CREATE TABLE "profile_profile".*)"user" varchar\(75\) NOT NULL UNIQUE,(.*)',
                r'\1"user" varchar(75) NOT NULL UNIQUE COLLATE NOCASE,\2'),

        Pattern(r'(CREATE TABLE "share_fileshare".*)"username" varchar\(255\) NOT NULL,(.*)',
                r'\1"username" varchar(255) NOT NULL COLLATE NOCASE,\2'),

        Pattern(r'(CREATE TABLE "api2_token".*)"user" varchar\(255\) NOT NULL UNIQUE,(.*)',
                r'\1"user" varchar(255) NOT NULL UNIQUE COLLATE NOCASE,\2'),

        Pattern(r'(CREATE TABLE "wiki_personalwiki".*)"username" varchar\(255\) NOT NULL UNIQUE,(.*)',
                r'\1"username" varchar(255) NOT NULL UNIQUE COLLATE NOCASE,\2'),

        Pattern(r'(CREATE TABLE "message_usermessage".*)"from_email" varchar\(75\) NOT NULL,\s*"to_email" varchar\(75\) NOT NULL,(.*)',
                r'\1"from_email" varchar(75) NOT NULL COLLATE NOCASE, "to_email" varchar(75) NOT NULL COLLATE NOCASE,\2'),

        Pattern(r'(CREATE TABLE "avatar_avatar".*)"emailuser" varchar\(255\) NOT NULL,(.*)',
                r'\1"emailuser" varchar(255) NOT NULL COLLATE NOCASE,\2'),
    ]

    def __init__(self, seahub_db):
        AbstractDBUpdater.__init__(self, seahub_db)

def upgrade_collate():
    '''Update database schema to add "COLLATE NOCASE" of email field'''
    user_db = os.path.join(ccnet_dir, 'PeerMgr', 'usermgr.db')
    group_db = os.path.join(ccnet_dir, 'GroupMgr', 'groupmgr.db')
    seafile_db = os.path.join(seafile_dir, 'seafile.db')
    seahub_db = os.path.join(seafserv_dir, 'seahub.db')
    updaters = [
        CcnetUserDBUpdater(user_db),
        CcnetGroupDBUpdater(group_db),
        SeafileDBUpdater(seafile_db),
        SeahubDBUpdater(seahub_db),
    ]

    for updater in updaters:
        updater.do_update()


if __name__ == '__main__':
    upgrade_collate()
