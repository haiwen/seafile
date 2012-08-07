#!/bin/bash

CLEANFILE="requirement-db  object-db peer-db group-db \
  user-db GroupMgr PeerMgr ccnet.log \
  seafile-data misc logs"

for d in conf1 conf2 conf3 conf4; do
  for file in $CLEANFILE; do
    rm -rf $d/$file
  done
done

rm -rf conf2/ccnet.db
rm -rf worktree/*
