#!/bin/bash

. ../common-conf.sh

testdir=${seafile_dir}/tests/basic
conf1=${testdir}/conf1
worktree=/tmp/worktree
seafile_app=${seafile_dir}/app/seafile

function create_repo
{    
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
}

rm -r ${worktree}/wt1
mkdir -p ${worktree}/wt1

gnome-terminal -e "${ccnet} -c ${conf1} -D all -f - --no-multicast"
sleep 3
gnome-terminal -e "${seaf_daemon} -c ${conf1} -w ${worktree}/wt1 -l -"
sleep 3

# find the group id
group_id=`ls ${conf1}/group-db/ | tail -n 1`
if [ -z $group_id ]; then
    echo "no group exists. You may forget to run ./setup.sh"
    exit 1
fi

# find a repo
repo_id=`ls ${worktree}/wt1/`
if [ -z $repo_id ]; then
    create_repo
    repo_id=`ls ${worktree}/wt1/`
fi

echo "repo id is $repo_id"

echo "+++ share item"
item_id=`${seafile_app} -c ${conf1} share ${repo_id} ${group_id}`

echo "+++ unshare item"
${seafile_app} -c ${conf1} unshare ${item_id}
