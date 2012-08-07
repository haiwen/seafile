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

try:
    seaf_rpc1.add(repo_id, "")
except SearpcError as e:
    print_cmsg("Failed to add: " + str(e))
    cleanup_and_exit()

try:
    seaf_rpc1.commit(repo_id, "commit1")
except SearpcError as e:
    print_cmsg("Failed to commit: " + str(e))
    cleanup_and_exit()

print_cmsg("Start upload")

try:
    upload_tx_id = seaf_rpc1.upload(repo_id, "master", "master");
except SearpcError as e:
    print_cmsg("Failed to start upload: " + str(e))
    cleanup_and_exit()

print_cmsg("Wait for upload")
time.sleep(20)

try:
    fetch_tx_id = seaf_rpc3.fetch(repo_id, "master", "master")
except SearpcError as e:
    print_cmsg("Failed to start fetch: " + str(e))
    cleanup_and_exit()

print_cmsg("Wait for fetch")
time.sleep(20)

print_cmsg("Initial checkout")
try:
    seaf_rpc3.checkout(repo_id, "master")
except SearpcError as e:
    print_cmsg("Failed to check out: " + str(e))
    cleanup_and_exit()

seaf_rpc1.remove_task(upload_tx_id, 1)
seaf_rpc3.remove_task(fetch_tx_id, 0)

cleanup_and_exit()
