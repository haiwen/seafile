#!/bin/bash

. ../common-conf.sh

testdir=${seafile_dir}/tests/basic

conf1=${testdir}/conf1
conf2=${testdir}/conf2
conf3=${testdir}/conf3
conf4=${testdir}/conf4

debug=Message,Requirement,Other,Peer,Group,Kvitem

if [ ! -d ${conf1}/logs ]; then
    mkdir ${conf1}/logs
fi
if [ ! -d ${conf3}/logs ]; then
    mkdir ${conf3}/logs
fi

gnome-terminal -e "${ccnet} -c ${conf1} -D ${debug} -f -"
sleep 3
gnome-terminal -e "${seaf_daemon} -c ${conf1} -d ${conf1}/seafile-data -w worktree/wt1 -D all -l -"

gnome-terminal -e "${ccnet} -c ${conf3} -D ${debug} -f -"
sleep 3
gnome-terminal -e "${seaf_daemon} -c ${conf3} -d ${conf3}/seafile-data -w worktree/wt3 -D all -l -"
