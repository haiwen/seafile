from util import TestUtil
import time

test_util = TestUtil()

def setup():
    # init sync related stuff
    test_util.init_conf()
    test_util.start_daemon()
    time.sleep(2)
    test_util.create_repo()
    test_util.sync_repo()
    time.sleep(5)
    print '\n----------------------------------------------------------------------'

def teardown():
    # clean sync related stuf
    print '----------------------------------------------------------------------\n'
    test_util.desync_repo()
    test_util.stop_daemon()
    test_util.clean()
