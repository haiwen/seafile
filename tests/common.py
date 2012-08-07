import sys
#sys.path = ['../../python', '../../python/ccnet/.libs', '../../python/pyccnetevent/.libs', '../python', '../python/seafile/.libs', '../../lib/searpc', '../../lib/searpc/pysearpc/.libs'] + sys.path

from datetime import datetime
import os
import sqlite3

import ccnet

class CcnetDaemon(object):
    
    def __init__(self, confdir):
        self.confdir = confdir
        

    def start(self, *args):
        self.child_pid = os.fork()
        if not self.child_pid:
            # child
            #os.execl("../net/ccnet", "ccnet", "-c", self.confdir,
            #         "-D", "All", "-f", "-")
            os.execl("../../net/ccnet", "ccnet", "-c", self.confdir,
                     "-D", "All", *args)
            
    def stop(self):
        os.kill(self.child_pid, 2)

class SeafileDaemon(object):
    
    def __init__(self, confdir):
        self.confdir = confdir

    def start(self, *args):
        self.child_pid = os.fork()
        if not self.child_pid:
            # child
            #os.execl("../net/ccnet", "ccnet", "-c", self.confdir,
            #         "-D", "All", "-f", "-")
            os.execl("../daemon/seaf-daemon", "seaf-daemon", "-c",
                     self.confdir, *args)
            
    def stop(self):
        os.kill(self.child_pid, 2)


def get_client_sync(confdir):
    client = ccnet.Client()
    client.load_confdir(confdir)
    client.connect_daemon(ccnet.CLIENT_SYNC)
    return client

def get_client_async(confdir):
    client = ccnet.Client()
    client.load_confdir(confdir)
    sockfd = client.connect_daemon(ccnet.CLIENT_ASYNC)
    if sockfd < 0:
        print "Can't connect to daemon"
        exit()
    client.run_synchronizer()
    client.sockfd = sockfd
    return client

def print_cmsg(msg):
    print >>sys.stderr, "[**Control %s] %s" % (
        datetime.now().strftime("%H:%M:%S.%f"), msg)
    
def db_item_exists(dbfile, sql):
    """Check whether `sql` returns any records in sqlite db `dbfile`."""

    conn = sqlite3.connect(dbfile)
    c = conn.cursor()
    c.execute(sql)
    if c.fetchone():
        ret = True
    else:
        ret = False
    conn.close()
    return ret
