#!/bin/bash

. ../common-conf.sh

testdir=${seafile_dir}/tests/basic
conf1=${testdir}/conf1
worktree=/tmp/worktree
seafile_app=${seafile_dir}/app/seafile
repo_name="test-repo"

./clean.sh
./teardown.sh

# create dir
if [ $1 = "create" ]; then
    rm -r ${worktree}/wt1
    mkdir -p ${worktree}/wt1
    rm ${conf1}/seafile/repo.db
fi

gnome-terminal -e "${ccnet} -c ${conf1} -D all -f - --no-multicast"
sleep 3

# for debug
if [ $1 = "debug" ]; then
    read tmp
else
    gnome-terminal -e "${seaf_daemon} -c ${conf1} -w ${worktree}/wt1 -l -"
    sleep 3
fi

# create a repo
if [ $1 = "create" ]
then
    #${seafile_app} -c ${conf1} create ${repo_name} test > /dev/null
    #mkdir /tmp/ccnet-test
    ${seafile_app} -c ${conf1} create ${repo_name} test /tmp/ccnett > /dev/null
fi

repo_id=`ls ${worktree}/wt1/systems`

ls -R ${worktree}

# add file
cp README ${worktree}/wt1/works/${repo_name}/
${seafile_app} -c ${conf1} add ${repo_id} >/dev/null

# commit file
${seafile_app} -c ${conf1} commit ${repo_id} "init" >/dev/null
