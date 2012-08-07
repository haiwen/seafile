#!/bin/bash

. ../common-conf.sh

testdir=${seafile_dir}/tests/basic
conf1=${testdir}/conf1
worktree=/tmp/worktree
seafile_app=${seafile_dir}/app/seafile

./clean.sh
./teardown.sh

rm -rf ${worktree}
mkdir -p ${worktree}/wt1

gnome-terminal -e "${ccnet} -c ${conf1} -D all -f - --no-multicast"
sleep 3
gnome-terminal -e "${seaf_daemon} -c ${conf1} -w ${worktree}/wt1 -l -"
sleep 3

# create a repo
${seafile_app} -c ${conf1} create test-repo test > /dev/null
sleep 3
repo_id=`ls ${worktree}/wt1/ | grep -v "checkout-files"`

cp ${top_srcdir}/README ${worktree}/wt1/${repo_id}/
touch -t 191305091843 ${worktree}/wt1/${repo_id}/README
sleep 1

echo "----------------------"
${seafile_app} -c ${conf1} status ${repo_id}
sleep 1

# add a file
${seafile_app} -c ${conf1} add ${repo_id} > /dev/null
sleep 1

echo "----------------------"
${seafile_app} -c ${conf1} status ${repo_id}
sleep 1

# commit
${seafile_app} -c ${conf1} commit ${repo_id} commit1 > /dev/null
sleep 1

echo "----------------------"
${seafile_app} -c ${conf1} status ${repo_id}
