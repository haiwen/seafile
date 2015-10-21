#coding: utf-8

import os
import shutil
import time
import subprocess
import glob
from setting import Setting
import seaf_op

def call_process(params):
    with open(os.devnull, 'w') as fd:
        ret = subprocess.check_output(params, stderr=fd)
    return ret

class TestUtil():
    def __init__(self):
        self.setting = Setting()
        self.cli1_dir = os.path.join(os.getcwd(), 'cli1')
        self.cli2_dir = os.path.join(os.getcwd(), 'cli2')
        self.worktree1 = os.path.join(os.getcwd(), 'worktree1')
        self.worktree2 = os.path.join(os.getcwd(), 'worktree2')
        self.enc_repo = False
        try:
            self.enc_repo = bool(os.environ['ENCRYPTED_REPO'])
        except Exception:
            pass
        self.repo_id = None
        self.test_root = ''

    def set_test_root(self, root):
        self.test_root = root

    @staticmethod
    def clean_sync_data(conf):
        try:
            os.remove(os.path.join(conf, 'ccnet.sock'))
            os.remove(os.path.join(conf, 'seafile.ini'))
            shutil.rmtree(os.path.join(conf, 'logs'))
            shutil.rmtree(os.path.join(conf, 'misc'))
            shutil.rmtree(os.path.join(conf, 'seafile'))
            shutil.rmtree(os.path.join(conf, 'seafile-data'))
        except Exception:
            pass

    def init_conf(self):
        self.setting.parse_config()

        if not os.path.exists(self.cli1_dir) or not os.path.exists(self.cli2_dir):
            raise Exception('ccnet conf dir is missing')

        if os.name != 'nt':
            TestUtil.clean_sync_data(self.cli1_dir)
            TestUtil.clean_sync_data(self.cli2_dir)

        if os.path.exists(self.worktree1):
            shutil.rmtree(self.worktree1)
        if os.path.exists(self.worktree2):
            shutil.rmtree(self.worktree2)

        os.mkdir(self.worktree1)
        os.mkdir(self.worktree2)

        seaf_op.seaf_init(self.cli1_dir)
        seaf_op.seaf_init(self.cli2_dir)

    def start_daemon(self):
        seaf_op.seaf_start_all(self.cli1_dir)
        seaf_op.seaf_start_all(self.cli2_dir)

    def create_repo(self):
        self.repo_id = seaf_op.seaf_create(self.cli1_dir, self.setting.server_url,
                                           self.setting.user, self.setting.password,
                                           self.enc_repo)

    def sync_cli1(self):
        seaf_op.seaf_sync(self.cli1_dir, self.setting.server_url, self.repo_id,
                          self.worktree1, self.setting.user, self.setting.password)

    def sync_cli2(self):
        seaf_op.seaf_sync(self.cli2_dir, self.setting.server_url, self.repo_id,
                          self.worktree2, self.setting.user, self.setting.password)

    def sync_repo(self):
        self.sync_cli1()
        self.sync_cli2()

    def desync_cli1(self):
        seaf_op.seaf_desync(self.cli1_dir, self.worktree1)

    def desync_cli2(self):
        seaf_op.seaf_desync(self.cli2_dir, self.worktree2)

    def desync_repo(self):
        self.desync_cli1()
        self.desync_cli2()
        # delete test repo
        seaf_op.seaf_delete(self.cli1_dir, self.setting.server_url,
                            self.setting.user, self.setting.password,
                            self.repo_id)

    def stop_daemon(self):
        seaf_op.seaf_stop(self.cli1_dir)
        seaf_op.seaf_stop(self.cli2_dir)

    def clean(self):
        try:
            if os.name != 'nt':
                TestUtil.clean_sync_data(self.cli1_dir)
                TestUtil.clean_sync_data(self.cli2_dir)
            shutil.rmtree(self.worktree1)
            shutil.rmtree(self.worktree2)
        except Exception:
            pass

    def wait_sync(self):
        while True:
            time.sleep(5)
            repo1 = seaf_op.seaf_get_repo(self.cli1_dir, self.repo_id)
            if repo1 is None:
                continue
            repo2 = seaf_op.seaf_get_repo(self.cli2_dir, self.repo_id)
            if repo2 is None:
                continue
            if repo1.head_cmmt_id == repo2.head_cmmt_id:
                break

    @staticmethod
    def verify_by_rsync(dir1, dir2):
        ret = call_process(['rsync', '-acrin', dir1, dir2])
        if ret:
            for d in ret.split('\n'):
                # omit empty str
                if not d:
                    continue
                # omit directory has almost same result except st_mod
                items = d.split(' ')
                dattr = items[0]
                name = items[1]

                # Output format difference between rsync versions:
                # rsync 3.1.1 : '.d..t.......'
                # rsync 3.0.9 : '.d..t......'

                # On Windows, file timestamp may have 1 second difference
                # between two clients after sync. That's caused by the
                # precision lose when converting Windows timestamp to
                # Unix timestamp. So we don't check timestamp difference
                # for files either.
                if not all([c in ('f', 'd', 't', '.') for c in dattr]):
                    assert False, 'Sync with two client have different result: %s %s' % (dattr, name)

    def verify_result(self, callable=None):
        self.wait_sync()
        if callable:
            callable(self.worktree1, self.worktree2)
        else:
            dir1 = './worktree1/'
            dir2 = './worktree2/'
            TestUtil.verify_by_rsync(dir1, dir2)
            TestUtil.verify_by_rsync(dir2, dir1)

    # worktree: 1(worktree1), 2(worktree2)
    def mkdir(self, worktree, path):
        if worktree == 1:
            os.makedirs(os.path.join(self.worktree1, self.test_root, path))
        elif worktree == 2:
            os.makedirs(os.path.join(self.worktree2, self.test_root, path))

    def rmdir(self, worktree, path):
        if worktree == 1:
            shutil.rmtree(os.path.join(self.worktree1, self.test_root, path))
        elif worktree == 2:
            shutil.rmtree(os.path.join(self.worktree2, self.test_root, path))

    def mkfile(self, worktree, fpath, con=''):
        if worktree == 1:
            pdir = self.worktree1
        elif worktree == 2:
            pdir = self.worktree2
        else:
            return
        abs_path = os.path.join(pdir, self.test_root, fpath)
        dirname = os.path.dirname(abs_path)
        if not os.path.exists(dirname):
            os.makedirs(dirname)
        with open(abs_path, 'w') as fd:
            fd.write(con)

    def rmfile(self, worktree, fpath):
        if worktree == 1:
            os.remove(os.path.join(self.worktree1, self.test_root, fpath))
        elif worktree == 2:
            os.remove(os.path.join(self.worktree2, self.test_root, fpath))

    def modfile(self, worktree, fpath, con=''):
        if worktree == 1:
            pdir = self.worktree1
        elif worktree == 2:
            pdir = self.worktree2
        else:
            return
        abs_path = os.path.join(pdir, self.test_root, fpath)
        with open(abs_path, 'a') as fd:
            fd.write(con)

    def move(self, worktree, org_path, dest_path):
        if worktree == 1:
            shutil.move(os.path.join(self.worktree1, self.test_root, org_path),
                        os.path.join(self.worktree1, self.test_root, dest_path))
        elif worktree == 2:
            shutil.move(os.path.join(self.worktree2, self.test_root, org_path),
                        os.path.join(self.worktree2, self.test_root, dest_path))

    def batchmove(self, worktree, regex, dest_path):
        if worktree == 1:
            pdir = self.worktree1
        elif worktree == 2:
            pdir = self.worktree2
        else:
            return
        files = glob.glob(os.path.join(pdir, self.test_root, regex))
        dest = os.path.join(pdir, self.test_root, dest_path)
        for f in files:
            shutil.move(f, dest)

    def copy(self, worktree, org_path, dest_path):
        if worktree == 1:
            shutil.copytree(os.path.join(self.worktree1, self.test_root, org_path),
                            os.path.join(self.worktree1, self.test_root, dest_path))
        elif worktree == 2:
            shutil.copytree(os.path.join(self.worktree2, self.test_root, org_path),
                            os.path.join(self.worktree2, self.test_root, dest_path))

    def touch(self, worktree, path, time=None):
        if worktree == 1:
            os.utime(os.path.join(self.worktree1, self.test_root, path), time)
        if worktree == 2:
            os.utime(os.path.join(self.worktree2, self.test_root, path), time)

    def getpath(self, worktree, path):
        if worktree == 1:
            return os.path.join(self.worktree1, self.test_root, path)
        elif worktree == 2:
            return os.path.join(self.worktree2, self.test_root, path)
        raise Exception('Invalid worktree')
