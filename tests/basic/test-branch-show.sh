#!/bin/bash

. ../common-conf.sh

testdir=${seafile_dir}/tests/basic
conf1=${testdir}/conf1
worktree=/tmp/worktree
seafile_app=${seafile_dir}/app/seafile

./clean.sh
./teardown.sh

rm -r ${worktree}/wt1
mkdir -p ${worktree}/wt1

gnome-terminal -e "${ccnet} -c ${conf1} -D all -f - --no-multicast"
sleep 3
gnome-terminal -e "${seaf_daemon} -c ${conf1} -w ${worktree}/wt1 -l -"
sleep 3

# create a repo
${seafile_app} -c ${conf1} create test-repo test > /dev/null
sleep 3
repo_id=`ls ${worktree}/wt1/`

mkdir -p ${worktree}/wt1/${repo_id}/test1/test2
cp ${top_srcdir}/README ${worktree}/wt1/${repo_id}
cp ${top_srcdir}/autogen.sh ${worktree}/wt1/${repo_id}/test1
cp ${top_srcdir}/configure.ac ${worktree}/wt1/${repo_id}/test1/test2
sleep 1

# add a file
${seafile_app} -c ${conf1} add ${repo_id} README > /dev/null
sleep 1

# commit
${seafile_app} -c ${conf1} commit ${repo_id} commit1 > /dev/null
sleep 1

# add branch
${seafile_app} -c ${conf1} branch add ${repo_id} test

# show branch
${seafile_app} -c ${conf1} branch show ${repo_id}
