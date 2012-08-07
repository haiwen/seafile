#!/bin/bash

CLEANFILE="seafile-data"

for d in conf1 conf2 conf3 conf4; do
  for file in $CLEANFILE; do
    rm -rf $d/$file
  done
done

rm -rf worktree/*
