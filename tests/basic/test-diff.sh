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

gnome-terminal -e "${ccnet} -c ${conf1} -D all -f - --no-multicast"
sleep 3
gnome-terminal -e "${seaf_daemon} -c ${conf1} -w ${worktree}/wt1 -l -"
sleep 3

# create a repo
${seafile_app} -c ${conf1} create test-repo test > /dev/null
sleep 3
repo_id=`ls ${worktree}/wt1/systems`

# create some files
echo "modify" >> ${worktree}/wt1/works/${repo_name}/modify
echo "remove" >> ${worktree}/wt1/works/${repo_name}/remove
echo "unmerge" >> ${worktree}/wt1/works/${repo_name}/unmerge
sleep 1

# add some files
${seafile_app} -c ${conf1} add ${repo_id} > /dev/null
sleep 1

# commit
${seafile_app} -c ${conf1} commit ${repo_id} commit1 > /dev/null
sleep 1

# add branch
${seafile_app} -c ${conf1} branch add ${repo_id} test
sleep 1

# checkout to test branch
${seafile_app} -c ${conf1} checkout ${repo_id} test
sleep 1

# modify file
echo "add" >> ${worktree}/wt1/works/${repo_name}/add
echo "modify" >> ${worktree}/wt1/works/${repo_name}/modify
rm ${worktree}/wt1/works/${repo_name}/remove
echo "merge conflict" > ${worktree}/wt1/works/${repo_name}/unmerge
sleep 1

# add file
${seafile_app} -c ${conf1} add ${repo_id}
sleep 1

# commit
${seafile_app} -c ${conf1} commit ${repo_id} commit2
sleep 1

# diff
${seafile_app} -c ${conf1} diff ${repo_id} test local
