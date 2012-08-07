#!/bin/bash

. ../common-conf.sh

testdir=${seafile_dir}/tests/basic
conf1=${testdir}/conf1
worktree=/tmp/worktree
seafile_app=${seafile_dir}/app/seafile
repo_name="test-repo"

./clean.sh
./teardown.sh

rm -r ${worktree}/wt1
mkdir -p ${worktree}/wt1
rm ${conf1}/seafile/repo.db
rm -rf /tmp/ccnet1

gnome-terminal -e "${ccnet} -c ${conf1} -D all -f - --no-multicast"
sleep 3
gnome-terminal -e "${seaf_daemon} -c ${conf1} -w ${worktree}/wt1 -l -"
sleep 3

# create a repo
tmp=`${seafile_app} -c ${conf1} create ${repo_name} test /tmp/ccnet1`
repoid1=`echo $tmp | awk '{print $6}' | awk -F. '{print $1}'`
sleep 1

cp README /tmp/ccnet1/

${seafile_app} -c ${conf1} add ${repoid1} >/dev/null
sleep 1
${seafile_app} -c ${conf1} commit ${repoid1} "init" >/dev/null
sleep 1

echo "----"
ls /tmp/ccnet1/
sleep 1

rm -rf /tmp/ccnet1/
sleep 1
${seafile_app} -c ${conf1} checkout ${repoid1} local /tmp/haha/ >/dev/null
sleep 1
echo "----"
ls /tmp/haha
