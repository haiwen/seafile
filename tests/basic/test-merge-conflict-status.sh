#!/bin/bash

. ../common-conf.sh

testdir=${seafile_dir}/tests/basic
conf1=${testdir}/conf1
worktree=/tmp/worktree
seafile_app=${seafile_dir}/app/seafile

./clean.sh
./teardown.sh

rm -rf ${worktree}/wt1
mkdir -p ${worktree}/wt1

gnome-terminal -e "${ccnet} -c ${conf1} -D all -f - --no-multicast"
sleep 3
gnome-terminal -e "${seaf_daemon} -c ${conf1} -w ${worktree}/wt1 -l -"
sleep 3

# create a repo
${seafile_app} -c ${conf1} create test-repo test > /dev/null
sleep 3
repo_id=`ls ${worktree}/wt1/`

cp ${top_srcdir}/README ${worktree}/wt1/${repo_id}
sleep 1

${seafile_app} -c ${conf1} status ${repo_id}

# add a file
${seafile_app} -c ${conf1} add ${repo_id} README > /dev/null
sleep 1

# commit
${seafile_app} -c ${conf1} commit ${repo_id} commit1 > /dev/null
sleep 1

# add two branches
${seafile_app} -c ${conf1} branch add ${repo_id} test1
sleep 1
${seafile_app} -c ${conf1} branch add ${repo_id} test2
sleep 1

# checkout to test1
${seafile_app} -c ${conf1} checkout ${repo_id} test1
sleep 1
# modify file content
echo "test1" >> ${worktree}/wt1/${repo_id}/README
sleep 1
# add README
${seafile_app} -c ${conf1} add ${repo_id}
sleep 1
# commit
${seafile_app} -c ${conf1} commit ${repo_id} test1-commit1
sleep 1

# checkout to test2
${seafile_app} -c ${conf1} checkout ${repo_id} test2
sleep 1
# modify file content
echo "test2" >> ${worktree}/wt1/${repo_id}/README
sleep 1
# add README
${seafile_app} -c ${conf1} add ${repo_id}
sleep 1
# commit
${seafile_app} -c ${conf1} commit ${repo_id} test2-commit2
sleep 1

# status
${seafile_app} -c ${conf1} status ${repo_id}

#
# all above should be OK
#

# merge test1 into test2
${seafile_app} -c ${conf1} merge ${repo_id} test1

# status
${seafile_app} -c ${conf1} status ${repo_id}