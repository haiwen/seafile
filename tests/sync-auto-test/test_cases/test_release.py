#coding: utf-8

import os
import time
import glob
from threading import Thread
from seaf_op import get_token, urlopen
from . import test_util

'''echo 111 > 1.txt; sleep 3; mv 1.txt 2.txt
echo 222 > 3.txt; sleep 3; mv 2.txt 3.txt
echo test > test.txt
mkdir test; echo 444 > 4.txt; sleep 3; mv *.txt test
mkdir test2; mv test test2
mv test2/test .
echo 555 >> test/4.txt; mv test test2
'''
# note this case can't pass on windows
def test_rename():
    test_util.mkfile(1, '1.txt', '111')
    time.sleep(3)
    test_util.move(1, '1.txt', '2.txt')
    test_util.mkfile(1, '3.txt', '222')
    time.sleep(3)
    test_util.move(1, '2.txt', '3.txt')
    test_util.mkfile(1, 'test.txt', 'test')
    test_util.mkdir(1, 'test')
    test_util.mkfile(1, '4.txt', '444')
    time.sleep(3)
    test_util.batchmove(1, '*.txt', 'test')
    test_util.mkdir(1, 'test2')
    test_util.move(1, 'test', 'test2')
    test_util.move(1, 'test2/test', '')
    test_util.modfile(1, 'test/4.txt', '555')
    test_util.move(1, 'test', 'test2')
    test_util.verify_result()

'''mkdir test
echo 111 > test/1.txt
echo 222 >> test/1.txt
copy a dir with multiple levels into test dir
move a dir with multiple levels into test dir
在一个空目录下添加文件，变成非空目录
修改一个文件的时间戳
'''
def test_create_update():
    test_util.mkdir(2, 'test')
    test_util.mkfile(2, 'test/1.txt', '111')
    test_util.modfile(2, 'test/1.txt', '222')
    time.sleep(3)
    test_util.mkdir(2, '1/2/3/4/5')
    test_util.copy(2, '1', '1_cp')
    test_util.mkdir(2, '6/7/8/9/10')
    test_util.move(2, '6', 'test')
    time.sleep(3)
    test_util.mkfile(2, '1/1.md', 'dddddddddddddddddddddd')
    time.sleep(1)
    test_util.touch(2, '1/1.md')
    test_util.verify_result()

'''rm test/1.txt
echo 222 > 2.txt
rm 2.txt
delete a dir with multiple levels
move a dir with multiple levels out of test dir
把一个目录里面的文件全部删除，变成空目录
'''
def test_delete():
    test_util.rmfile(2, 'test/1.txt')
    test_util.mkfile(2, '2.txt', '2222')
    time.sleep(3)
    test_util.rmfile(2, '2.txt')
    test_util.rmdir(2, '1')
    time.sleep(3)
    test_util.move(2, '1_cp/2', '')
    test_util.mkdir(1, 'empty')
    for i in xrange(3):
        test_util.mkfile(1, 'empty/%d.txt' % i, 'dddddddddd')
    time.sleep(3)
    for i in xrange(3):
        test_util.rmfile(1, 'empty/%d.txt' % i)
    test_util.verify_result()

'''修改文件或者目录的名字大小写，如从 test 到 TEST
关闭客户端，执行上述操作，然后启动客户端
'''
def test_rename_case():
    test_util.mkdir(1, 'UPPER')
    test_util.mkfile(2, 'lower.md', 'lowerfffff')
    time.sleep(3)
    test_util.move(1, 'UPPER', 'upper')
    test_util.move(2, 'lower.md', 'LOWER.md')
    test_util.verify_result()
    test_util.desync_cli1()
    test_util.move(1, 'upper', 'UPPER')
    test_util.move(1, 'LOWER.md', 'lower.md')
    test_util.sync_cli1()
    test_util.verify_result()

'''在 web 上把一个有内容的目录 abc 重命名为 ABC
假设有非空目录 abc/test/，先关闭自动同步，在 web 上重命名为 ABC/TEST/，再打开自动同步
假设有非空目录 test，以及文件 a.txt，先关闭自动同步，在 web 上把 test 重命名为 TEST，然后把 a.txt 移动到 TEST 下面，打开自动同步
'''
def test_rename_download():
    test_util.mkdir(1, 'abc/test')
    test_util.mkfile(2, 'a.txt', 'aaaaaaaaaaaaaaaaaaa')
    time.sleep(6)

    token = get_token(test_util.setting.server_url,
                      test_util.setting.user,
                      test_util.setting.password)
    headers = {'Authorization': 'Token %s' % token}

    def rename_on_web(path, newname):
        data = {'operation': 'rename', 'newname': newname}
        urlopen('%s/api2/repos/%s/dir/?p=%s' % \
                (test_util.setting.server_url, test_util.repo_id, path),
                data, headers)

    def move_on_web(dest_path, fname):
        data = {'operation': 'move', 'dst_repo': test_util.repo_id, 'dst_dir': dest_path}
        urlopen('%s/api2/repos/%s/file/?p=%s' % \
                (test_util.setting.server_url, test_util.repo_id, fname),
                data, headers, False)

    rename_on_web('/abc', 'ABC')
    test_util.verify_result()
    if not os.path.exists(test_util.getpath(1, 'ABC')):
        assert False, 'ABC dir should exist in two worktrees'

    test_util.desync_cli2()
    rename_on_web('/ABC/test', 'TEST')
    test_util.sync_cli2()
    test_util.verify_result()
    if not os.path.exists(test_util.getpath(2, 'ABC/TEST')):
        assert False, 'ABC/TEST dir should exit in worktree2'

    test_util.mkdir(1, 'bcd')
    test_util.mkfile(1, 'bcd.md', 'bcddddd')
    time.sleep(6)
    test_util.desync_cli1()
    rename_on_web('/bcd', 'BCD')
    move_on_web('/BCD', '/bcd.md')
    test_util.sync_cli1()
    test_util.verify_result()

'''create cur.md, wait for synced then concurrent modify cur.md
'''
def mod_file(worktree, fname):
    test_util.modfile(worktree, fname, test_util.getpath(worktree, fname))

def test_concurrent_mod():
    test_util.mkfile(1, 'cur.md', 'curcurcurrrrrrrrrrrrrrrrrrrrr')
    test_util.verify_result()
    thread1 = Thread(target=mod_file, args=(1, 'cur.md'))
    thread2 = Thread(target=mod_file, args=(2, 'cur.md'))
    thread1.start()
    thread2.start()
    test_util.verify_result()
    files = glob.glob(test_util.getpath(1, 'cur*.md'))
    assert len(files) ==  2, 'Should generate conflict file'
