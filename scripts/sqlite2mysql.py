#!/usr/bin/env python

"""Lifted from:
http://stackoverflow.com/questions/18671/quick-easy-way-to-migrate-sqlite3-to-mysql

Run like so:

sqlite3 <your db>.db .dump | python sqlite2mysql.py > <your db>.sql

Then you can import the .sql file into MySql

Note - you need to add foreign key constrains manually since sqlite doesn't actually support them
"""

import re
import fileinput

def this_line_is_useless(line):
    useless_es = [
        'BEGIN TRANSACTION',
        'COMMIT',
        'sqlite_sequence',
        'CREATE UNIQUE INDEX',
        'PRAGMA',
        ]
    for useless in useless_es:
        if re.search(useless, line):
            return True

def has_primary_key(line):
    return bool(re.search(r'PRIMARY KEY', line))

for line in fileinput.input():
    searching_for_end = False
    if this_line_is_useless(line): continue

    # this line was necessary because ''); was getting
    # converted (inappropriately) to \');
    if re.match(r".*, ''\);", line):
        line = re.sub(r"''\);", r'``);', line)

    if re.match(r'^CREATE TABLE.*', line):
        searching_for_end = True

    m = re.search('CREATE TABLE [`"]?(\w*)[`"]?(.*)', line)
    if m:
        name, sub = m.groups()
        sub = sub.replace('"','`')
        line = "DROP TABLE IF EXISTS `%(name)s`;\nCREATE TABLE IF NOT EXISTS `%(name)s`%(sub)s\n"
        line = line % dict(name=name, sub=sub)
    else:
        m = re.search('INSERT INTO "(\w*)"(.*)', line)
        if m:
            name, sub = m.groups()
            line = 'INSERT INTO `%s`%s\n' % m.groups()
            line = line.replace('"', r'\"')
            line = line.replace('"', "'")
    # line = re.sub(r"([^'])'t'(.)", r"\1THIS_IS_TRUE\2", line)
    # line = line.replace('THIS_IS_TRUE', '1')
    # line = re.sub(r"([^'])'f'(.)", r"\1THIS_IS_FALSE\2", line)
    # line = line.replace('THIS_IS_FALSE', '0')

    # Add auto_increment if it's not there since sqlite auto_increments ALL
    # primary keys
    if searching_for_end:
        if re.search(r"integer(?:\s+\w+)*\s*PRIMARY KEY(?:\s+\w+)*\s*,", line, re.I):
            line = line.replace("PRIMARY KEY", "PRIMARY KEY AUTO_INCREMENT")
        # replace " and ' with ` because mysql doesn't like quotes in CREATE commands
        line = line.replace('"', '`').replace("'", '`')

    # And now we convert it back (see above)
    if re.match(r".*, ``\);", line):
        line = re.sub(r'``\);', r"'');", line)

    if searching_for_end and re.match(r'.*\);', line):
        searching_for_end = False

    if re.match(r"CREATE INDEX", line):
        line = re.sub('"', '`', line)

    line = line.replace('"', '`')
    line = line.replace('AUTOINCREMENT', 'AUTO_INCREMENT')
    print line,
