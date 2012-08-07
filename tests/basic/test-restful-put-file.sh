#!/bin/bash

. ../common-conf.sh

testdir=${seafile_dir}/tests/basic
conf1=${testdir}/conf1
worktree=${testdir}/worktree
seafile_app=${seafile_dir}/app/seafile


echo "+++ start seafile"
./seafile.sh 1 2

sleep 1
# create a new repo
res=`${seafile_app} -c ${conf1} create test-repo test ${worktree}/wt1`

# get repo id
repo_id=`echo ${res} | awk '{print $6}' | awk -F. '{print $1}'`

sleep 1
# add some files
mkdir ${worktree}/wt1/1/
cp ${top_srcdir}/configure ${worktree}/wt1/
cp ${top_srcdir}/configure ${worktree}/wt1/1/

sleep 1
# commit
${seafile_app} -c ${conf1} commit ${repo_id} commit1

# start to test put-file API
echo "+++ start to stest put-file API ..."

# success
echo "+++ pass"
${seafile_app} -c ${conf1} put-file ${repo_id} ${top_srcdir}/README ./
sleep 1
${seafile_app} -c ${conf1} put-file ${repo_id} ${top_srcdir}/README /
sleep 1
${seafile_app} -c ${conf1} put-file ${repo_id} ${top_srcdir}/README 1
sleep 1
${seafile_app} -c ${conf1} put-file ${repo_id} ${top_srcdir}/README 1/
sleep 1
${seafile_app} -c ${conf1} put-file ${repo_id} ${top_srcdir}/README /1
sleep 1
${seafile_app} -c ${conf1} put-file ${repo_id} ${top_srcdir}/README /1/
sleep 1
${seafile_app} -c ${conf1} put-file ${repo_id} ${top_srcdir}/README ./1/
sleep 1

# failure
echo "++++ failures
${seafile_app} -c ${conf1} put-file ${repo_id} ${top_srcdir}/README ./1/2
sleep 1
${seafile_app} -c ${conf1} put-file ${repo_id} ${top_srcdir}/README ./1//
sleep 1
${seafile_app} -c ${conf1} put-file ${repo_id} ${top_srcdir}/README ./1/2//
sleep 1
${seafile_app} -c ${conf1} put-file ${repo_id} ${top_srcdir}/README .//1/
sleep 1

echo "+++ cleanup"
pkill ccnet
