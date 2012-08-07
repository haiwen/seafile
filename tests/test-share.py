#!/usr/bin/env python

from datetime import datetime
import os
import time
import shutil

import common
from common import CcnetDaemon, SeafileDaemon, print_cmsg, db_item_exists
import ccnet
from pysearpc import *
import seafile

def cleanup_and_exit():
    os.system("""pkill ccnet""")
#    os.system("""cd basic; ./clean.sh""")
    exit()

ccnet_daemon1 = CcnetDaemon("basic/conf1")
ccnet_daemon1.start("--no-multicast")
ccnet_daemon2 = CcnetDaemon("basic/conf2")
ccnet_daemon2.start("--relay")
ccnet_daemon3 = CcnetDaemon("basic/conf3")
ccnet_daemon3.start("--no-multicast")
ccnet_daemon4 = CcnetDaemon("basic/conf4")
ccnet_daemon4.start("--no-multicast")

print_cmsg("Wait for ccnet daemon starting")
time.sleep(3)

if not os.access("basic/worktree", os.F_OK):
    try:
        os.mkdir("basic/worktree")
    except OSError as e:
        print_cmsg("Failed to create worktree: " + e.strerror)
        cleanup_and_exit()

seaf_daemon1 = SeafileDaemon("basic/conf1")
seaf_daemon1.start("-w", "basic/worktree/wt1")
seaf_daemon2 = SeafileDaemon("basic/conf2")
seaf_daemon2.start("-r")
seaf_daemon3 = SeafileDaemon("basic/conf3")
seaf_daemon3.start("-w", "basic/worktree/wt3")
seaf_daemon4 = SeafileDaemon("basic/conf4")
seaf_daemon4.start("-w", "basic/worktree/wt4")

print_cmsg("sleep")
time.sleep(15)

os.system("""
cd basic;
./seafserv-tool -c conf2 add-server server
./seafserv-tool -c conf2 add-server server2
""")

pool1 = ccnet.ClientPool("basic/conf1")
ccnet_rpc1 = ccnet.CcnetRpcClient(pool1)
seaf_rpc1 = seafile.RpcClient(pool1)
seaf_rpc3 = seafile.RpcClient(ccnet.ClientPool("basic/conf3"))

repo_id = seaf_rpc1.create_repo("test-repo", "test")
if not repo_id:
    print_cmsg("Failed to create repo")
    cleanup_and_exit()

print_cmsg("Created repo " + repo_id)

print_cmsg("Copy data into basic/worktree/wt1")
try:
    if not os.access("basic/worktree/wt1/%s/data" % repo_id, os.F_OK):
        shutil.copytree("basic/data", "basic/worktree/wt1/%s/data" % repo_id)
except OSError as e:
    print_cmsg("Failed to copy data: " + e.strerror)
    cleanup_and_exit()

print_cmsg("Add and commit")

if seaf_rpc1.add(repo_id, "") < 0:
    print_cmsg("Failed to add")
    cleanup_and_exit()

if not seaf_rpc1.commit(repo_id, "commit1"):
    print_cmsg("Failed to commit")
    cleanup_and_exit()

print_cmsg("Get group id")

group_ids = ccnet_rpc1.list_groups()
if not group_ids:
    print_cmsg("No group set up")
    cleanup_and_exit()
test_group_id = ''
for group_id in group_ids.split("\n"):
    if group_id == '':
        break
    group = ccnet_rpc1.get_group(group_id)
    if group.props.name == "ccnet-dev":
        test_group_id = group.props.id
        break
if not test_group_id:
    print_cmsg("Group ccnet-dev cannot be found")
    cleanup_and_exit()

print_cmsg("Share %s to group %s" % (repo_id, test_group_id))

try:
    if seaf_rpc1.share_repo(repo_id, test_group_id) < 0:
        print_cmsg("Failed to share")
        cleanup_and_exit()
except SearpcError as e:
    print >>sys.stderr, "RPC error: %s" % str(e)
    cleanup_and_exit()

print_cmsg("Wait for share info synchronized")
time.sleep(120)

share_info = seaf_rpc3.get_repo_sinfo(repo_id)
if not share_info:
    print_cmsg("Failed to synchronize share info")
    cleanup_and_exit()

cleanup_and_exit()
