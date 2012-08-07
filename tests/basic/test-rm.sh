#!/bin/bash

. ../common-conf.sh

testdir=${seafile_dir}/tests/basic
conf1=${testdir}/conf1
worktree=/tmp/worktree
seafile_app=${seafile_dir}/app/seafile

./clean.sh
./teardown.sh

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
${seafile_app} -c ${conf1} add ${repo_id} test1/autogen.sh > /dev/null
${seafile_app} -c ${conf1} add ${repo_id} test1/test2/configure.ac > /dev/null

# commit
${seafile_app} -c ${conf1} commit ${repo_id} commit1 > /dev/null

rm ${worktree}/wt1/${repo_id}/README

${seafile_app} -c ${conf1} rm ${repo_id} README
${seafile_app} -c ${conf1} rm ${repo_id} test1/autogen.sh

${seafile_app} -c ${conf1} status ${repo_id}

${seafile_app} -c ${conf1} commit ${repo_id} commit2

cp ${top_srcdir}/configure.ac ${worktree}/wt1/${repo_id}/test1/test2

${seafile_app} -c ${conf1} status ${repo_id}

echo "hello" >> ${worktree}/wt1/${repo_id}/test1/test2/configure.ac

${seafile_app} -c ${conf1} rm ${repo_id} test1/test2/configure.ac

rm -rf ${worktree}
