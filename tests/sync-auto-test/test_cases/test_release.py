#coding: utf-8

import os
import time
import glob
from threading import Thread
from seaf_op import get_token, urlopen
from . import test_util

'''
Test add-delete-add sequence.
'''
def test_add_delete_add():
    test_util.set_test_root('test_add_delete_add')

    test_util.mkfile(1, 'test/1.txt', 'aaaaaaaa')
    test_util.rmdir(1, 'test')
    test_util.mkfile(1, 'test/1.txt', 'aaaaaaaa')

    test_util.verify_result()

'''
Rename test:
echo 111 > 1.txt; sleep 3; mv 1.txt 2.txt
echo 222 > 3.txt; sleep 3; mv 2.txt 3.txt
echo test > test.txt
mkdir test; echo 444 > 4.txt; sleep 3; mv *.txt test
mkdir test2; mv test test2
mv test2/test .
echo 555 >> test/4.txt; mv test test2
mv test2 test3
'''
def test_rename():
    test_util.set_test_root('test_rename')

    test_util.mkfile(1, '1.txt', '111')
    time.sleep(3)
    test_util.move(1, '1.txt', '2.txt')

    time.sleep(3)

    test_util.mkfile(1, '3.txt', '222')
    time.sleep(3)
    test_util.move(1, '2.txt', '3.txt')

    time.sleep(3)

    test_util.mkfile(1, 'test.txt', 'test')

    time.sleep(3)

    test_util.mkdir(1, 'test')
    test_util.mkfile(1, '4.txt', '444')
    time.sleep(3)
    test_util.batchmove(1, '*.txt', 'test')

    time.sleep(3)

    test_util.mkdir(1, 'test2')
    test_util.move(1, 'test', 'test2')

    time.sleep(3)

    test_util.move(1, 'test2/test', '')

    time.sleep(3)

    test_util.modfile(1, 'test/4.txt', '555')
    test_util.move(1, 'test', 'test2')

    time.sleep(3)

    test_util.move(1, 'test2', 'test3')

    test_util.verify_result()

'''
Create and update test:
echo 111 > test/1.txt
echo 222 >> test/1.txt
copy a dir with multiple levels into test dir
create an empty dir
add file into an empty folder
'''
def test_create_update():
    test_util.set_test_root('test_create_update')

    test_util.mkdir(1, 'test')
    test_util.mkfile(1, 'test/1.txt', '111')

    time.sleep(3)

    test_util.modfile(1, 'test/1.txt', '222')

    time.sleep(3)

    test_util.mkdir(1, '1/2/3/4/5')
    test_util.mkfile(1, '1/1.txt', '111')
    test_util.mkfile(1, '1/2/2.txt', '222')
    test_util.copy(1, '1', 'test/1')

    time.sleep(3)

    test_util.mkdir(1, 'empty')

    time.sleep(3)

    test_util.mkfile(1, 'empty/test.md', 'dddddddddddddddddddddd')

    test_util.verify_result()

'''
Delete test:
echo 222 > 2.txt
rm 2.txt
delete a dir with multiple levels
delete all files under a dir, make it empty.
delete empty dir
'''
def test_delete():
    test_util.set_test_root('test_delete')

    test_util.mkfile(1, '2.txt', '2222')
    time.sleep(3)
    test_util.rmfile(1, '2.txt')

    test_util.mkdir(1, '1/2/3/4/5')
    test_util.mkfile(1, '1/1.txt', '111')
    test_util.mkfile(1, '1/2/2.txt', '222')
    test_util.copy(1, '1', 'test/1')
    time.sleep(3)
    test_util.rmdir(1, '1')

    time.sleep(3)

    test_util.rmdir(1, 'test/1')

    time.sleep(3)

    test_util.rmdir(1, 'test')

    test_util.verify_result()

'''
Case rename test:
rename a dir from 'test' to 'TEST'
disalbe auto sync; rename the dir from 'TEST' to 'test'; enable auto sync.
'''
def test_case_rename():
    test_util.set_test_root('test_case_rename')

    test_util.mkdir(1, 'test')
    test_util.mkfile(1, 'a.txt', 'aaaa')

    time.sleep(3)

    test_util.move(1, 'test', 'TEST')
    test_util.verify_result()

    test_util.desync_cli1()
    test_util.move(1, 'TEST', 'test')
    test_util.sync_cli1()
    test_util.verify_result()

'''
A test set for downloads. The updates are done on cli1 and downloaded on cli2.
Note that these tests are different from upload tests. In upload tests, we deliberately
combine multiple operations into one test; in download tests, we must ensure each
operation be carried out individually on cli2.
'''

# Create a new file
def test_download_1():
    test_util.set_test_root('test_download')

    test_util.mkfile(1, '1.txt', '11111')

    test_util.verify_result()

# Update a file
def test_download_2():
    test_util.set_test_root('test_download')

    test_util.modfile(1, '1.txt', '22222')

    test_util.verify_result()

# Create empty dir
def test_download_3():
    test_util.set_test_root('test_download')

    test_util.mkdir(1, 'dir1')

    test_util.verify_result()

# Rename a file
def test_download_4():
    test_util.set_test_root('test_download')

    test_util.move(1, '1.txt', '2.txt')

    test_util.verify_result()

# Rename empty dir
def test_download_5():
    test_util.set_test_root('test_download')

    test_util.move(1, 'dir1', 'dir2')

    test_util.verify_result()

# Create file in empty dir
def test_download_6():
    test_util.set_test_root('test_download')

    test_util.mkfile(1, 'dir2/1.txt', '1111111')

    test_util.verify_result()

# Rename a non-empty dir
def test_download_7():
    test_util.set_test_root('test_download')

    test_util.move(1, 'dir2', 'dir3')

    test_util.verify_result()

# Remove all files in a non-empty dir
def test_download_8():
    test_util.set_test_root('test_download')

    test_util.rmfile(1, 'dir3/1.txt')

    test_util.verify_result()

# Move a non-empty dir into an empty dir
def test_download_9():
    test_util.set_test_root('test_download')

    test_util.mkfile(1, 'dir4/2.txt', '2222222')
    test_util.verify_result()

    test_util.move(1, 'dir4', 'dir3')

    test_util.verify_result()

# Delete file
def test_download_10():
    test_util.set_test_root('test_download')

    test_util.rmfile(1, '2.txt')

    test_util.verify_result()

# Delete a non-empty dir
def test_download_11():
    test_util.set_test_root('test_download')

    test_util.rmdir(1, 'dir3/dir4')

    test_util.verify_result()

# Delete empty dir
def test_download_12():
    test_util.set_test_root('test_download')

    test_util.rmdir(1, 'dir3')

    test_util.verify_result()

'''
Test cases for download case rename
'''

def test_download_case_rename_1():
    test_util.set_test_root('test_download_case_rename')

    test_util.mkfile(1, 'abc/test/test.txt', 'testtset')
    test_util.verify_result()

    test_util.move(1, 'abc/test', 'abc/TEST')
    test_util.move(1, 'abc', 'ABC')
    test_util.verify_result()

def test_download_case_rename_2():
    test_util.set_test_root('test_download_case_rename')

    test_util.mkfile(1, 'a.txt', 'aaaaaaaaaaaaaaaaaaa')
    test_util.mkfile(1, 'test/b.txt', 'bbbbbbbbbb')
    test_util.verify_result()

    test_util.move(1, 'test', 'TEST')
    test_util.move(1, 'a.txt', 'TEST')
    test_util.verify_result()

'''create cur.md, wait for synced then concurrent modify cur.md
'''
# def mod_file(worktree, fname):
#     test_util.modfile(worktree, fname, test_util.getpath(worktree, fname))

# def test_concurrent_mod():
#     test_util.mkfile(1, 'cur.md', 'curcurcurrrrrrrrrrrrrrrrrrrrr')
#     test_util.verify_result()
#     thread1 = Thread(target=mod_file, args=(1, 'cur.md'))
#     thread2 = Thread(target=mod_file, args=(2, 'cur.md'))
#     thread1.start()
#     thread2.start()
#     test_util.verify_result()
#     files = glob.glob(test_util.getpath(1, 'cur*.md'))
#     assert len(files) ==  2, 'Should generate conflict file'
