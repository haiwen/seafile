#coding: utf-8

import os
import time
from . import test_util

def test_add_file():
    test_util.mkfile(1, 'a.md', 'add a file')
    test_util.verify_result()

def test_add_file_t():
    test_util.mkfile(2, 'l/m/n/test.md', 'add l/m/n/test.md')
    test_util.verify_result()

def test_add_dir():
    test_util.mkdir(1, 'ad')
    test_util.verify_result()

def test_add_dir_t():
    test_util.mkdir(2, 'tt/ee/st')
    test_util.verify_result()

def test_modify_file():
    test_util.modfile(1, 'a.md', 'modify a.md')
    test_util.verify_result()

def test_rm_file():
    test_util.rmfile(1, 'a.md')
    test_util.verify_result()

def test_rm_dir():
    test_util.rmdir(1, 'ad')
    test_util.verify_result()

def test_rename_file():
    test_util.mkfile(2, 'b.md', 'add b.md')
    time.sleep(1)
    test_util.move(2, 'b.md', 'b_bak.md')
    test_util.verify_result()

def test_rename_dir():
    test_util.mkdir(2, 'ab')
    time.sleep(1)
    test_util.move(2, 'ab', 'ab_bak')
    test_util.verify_result()

def test_each():
    test_util.mkdir(1, 'abc1')
    test_util.mkfile(1, 'abc1/c.md', 'add abc1/c.md')
    time.sleep(1)

    test_util.mkdir(2, 'bcd1')
    test_util.mkfile(2, 'bcd1/d.md', 'add bcd1/d.md')
    test_util.verify_result()

def test_unsync_resync():
    test_util.desync_cli1()
    test_util.rmdir(1, 'abc1')
    test_util.modfile(1, 'bcd1/d.md', 'modify bcd1/d.md to test unsync resync')
    test_util.sync_cli1()

    test_util.verify_result()

    if not os.path.exists(test_util.getpath(1, 'abc1')):
        assert False, 'dir abc1 should be recreated when resync'

    if len(os.listdir(test_util.getpath(1, 'bcd1'))) != 2:
        assert False, 'should generate conflict file for bcd1/d.md when resync'

def test_modify_timestamp():
    test_util.touch(1, 'bcd1/d.md')
    test_util.verify_result()
