#!/bin/bash

. ../common-conf.sh

testdir=${seafile_dir}/tests/basic
conf1=${testdir}/conf1
conf3=${testdir}/conf3
worktree=${testdir}/worktree
seafile_app=${seafile_dir}/app/seafile


echo "+++ start seafile"
./seafile.sh 1 2 3 4

repo_id=`ls ${worktree}/wt1/`
if  [ x${repo_id} != x ]; then
    echo "Worktree is not empty, perform ./clean.sh first"
    exit 1
fi

function create_repo
{    
    # create a repo
    ${seafile_app} -c ${conf1} create  --encrypt --passwd=1234 test-repo test > /dev/null
    sleep 3
    repo_id=`ls ${worktree}/wt1/ | tail -n 1`
    if [ -z ${repo_id} ]; then
        echo "create repo failed"
        exit 1
    fi

    mkdir -p ${worktree}/wt1/${repo_id}/test1/test2
    cp ${top_srcdir}/README ${worktree}/wt1/${repo_id}
    cp ${top_srcdir}/autogen.sh ${worktree}/wt1/${repo_id}/test1
    cp ${top_srcdir}/configure.ac ${worktree}/wt1/${repo_id}/test1/test2
    sleep 1

    # add files
    ${seafile_app} -c ${conf1} add ${repo_id} > /dev/null
    sleep 1

    # commit
    ${seafile_app} -c ${conf1} commit ${repo_id} commit1 > /dev/null
}

echo "+++ create repo"
create_repo

repo_id=`ls ${worktree}/wt1/`
echo "+++ upload ${repo_id}"
${seafile_app} -c ${conf1} upload ${repo_id} local master
sleep 10

echo "+++ fetch ${repo_id}"
${seafile_app} -c ${conf3} fetch ${repo_id} master master
sleep 10

echo "+++ checkout"
${seafile_app} -c ${conf3} branch add ${repo_id} local master
${seafile_app} -c ${conf3} set-passwd ${repo_id} 1234
${seafile_app} -c ${conf3} checkout ${repo_id} local

echo "+++ check diff"
if diff ${worktree}/wt3/${repo_id}/test1/test2/configure.ac \
    ${worktree}/wt1/${repo_id}/test1/test2/configure.ac > /dev/null ; then
    echo "+++ Success"
else
    echo "+++ failed"
fi

echo "+++ cleanup"
pkill ccnet