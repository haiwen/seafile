#!/bin/bash

. ../common-conf.sh

conf1=conf1
conf2=conf2
conf3=conf3
conf4=conf4

debug=Message,Other,Peer

if [ ! -d ${conf1}/logs ]; then
    mkdir ${conf1}/logs
fi
if [ ! -d ${conf3}/logs ]; then
    mkdir ${conf3}/logs
fi
if [ ! -d ${conf4}/logs ]; then
    mkdir ${conf4}/logs
fi

while [ $# -ge 1 ]; do
  case $1 in
    "1" ) 
      gnome-terminal -e "${ccnet} -c ${conf1} -D ${debug} -f -"
      sleep 3
      gnome-terminal -e "${seaf_daemon} -c ${conf1} -d ${conf1}/seafile-data -w worktree/wt1 -D all -l -"
      ;;
    "2" )
      # Use sqlite as database in testing
      ../../tools/seaf-server-init -d ${conf2}/seafile-data > /dev/null

      gnome-terminal -e "${ccnet_server} -c ${conf2} -D ${debug} -f -"
      sleep 3
      gnome-terminal -e "${seaf_server} -c ${conf2}  -d ${conf2}/seafile-data -D all -f -l -"
      ;;
    "3" )
      gnome-terminal -e "${ccnet} -c ${conf3} -D ${debug} -f -"
      sleep 3
      gnome-terminal -e "${seaf_daemon} -c ${conf3} -d ${conf3}/seafile-data -w worktree/wt3 -D all -l -"
      ;;
    "4" )
      gnome-terminal -e "${ccnet} -c ${conf4} -D ${debug} -f -"
      sleep 3
      gnome-terminal -e "${seaf_daemon} -c ${conf4} -d ${conf4}/seafile-data -w worktree/wt4 -D all -l -"
      ;;
  esac
  shift
done
