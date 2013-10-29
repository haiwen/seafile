#!/bin/sh
#
# This shell script is used to add COLLATE NOCASE to email field to avoid case
# issue in sqlite.
#
# 1. ./add-collate.sh <ccnet_dir> <seafile_dir> <seahub_db>
#

USER_DB='/tmp/user-db.sql'
GROUP_DB='/tmp/group-db.sql'
SEAFILE_DB='/tmp/seafile-db.sql'
SEAHUB_DB='/tmp/seahub-db.sql'

ccnet_dir=$1

########## ccnet
USER_MGR_DB=${ccnet_dir}/PeerMgr/usermgr.db
GRP_MGR_DB=${ccnet_dir}/GroupMgr/groupmgr.db

rm -rf ${USER_DB}
rm -rf ${GROUP_DB}

echo "sqlite3 ${USER_MGR_DB} .dump > ${USER_DB}"
sqlite3 ${USER_MGR_DB} .dump  > ${USER_DB}
echo "sqlite3 ${GRP_MGR_DB} .dump  > ${GROUP_DB}"
sqlite3 ${GRP_MGR_DB} .dump  > ${GROUP_DB}

sed -r 's/(CREATE TABLE EmailUser.*)email TEXT,(.*)/\1email TEXT COLLATE NOCASE,\2/I' ${USER_DB} > ${USER_DB}.tmp && mv ${USER_DB}.tmp ${USER_DB}
sed -r 's/(CREATE TABLE Binding.*)email TEXT,(.*)/\1email TEXT COLLATE NOCASE,\2/I' ${USER_DB} > ${USER_DB}.tmp && mv ${USER_DB}.tmp ${USER_DB}
sed -r 's/(CREATE TABLE `Group`.*)`creator_name` VARCHAR\(255\),(.*)/\1`creator_name` VARCHAR\(255\) COLLATE NOCASE,\2/I' ${GROUP_DB} > ${GROUP_DB}.tmp && mv ${GROUP_DB}.tmp ${GROUP_DB}
sed -r 's/(CREATE TABLE `GroupUser`.*)`user_name` VARCHAR\(255\),(.*)/\1`user_name` VARCHAR\(255\) COLLATE NOCASE,\2/I' ${GROUP_DB} > ${GROUP_DB}.tmp && mv ${GROUP_DB}.tmp ${GROUP_DB}

# backup & restore
mv ${USER_MGR_DB} ${USER_MGR_DB}.`date +"%Y%m%d%H%M%S"`
mv ${GRP_MGR_DB} ${GRP_MGR_DB}.`date +"%Y%m%d%H%M%S"`
sqlite3 ${USER_MGR_DB} < ${USER_DB}
sqlite3 ${GRP_MGR_DB} < ${GROUP_DB}

########## seafile
rm -rf ${SEAFILE_DB}

SEAFILE_DB_FILE=$2/seafile.db
echo "sqlite3 ${SEAFILE_DB_FILE} .dump  > ${SEAFILE_DB}"
sqlite3 ${SEAFILE_DB_FILE} .dump  > ${SEAFILE_DB}

sed -r 's/(CREATE TABLE RepoOwner.*)owner_id TEXT(.*)/\1owner_id TEXT COLLATE NOCASE\2/I' ${SEAFILE_DB} > ${SEAFILE_DB}.tmp && mv ${SEAFILE_DB}.tmp ${SEAFILE_DB}
sed -r 's/(CREATE TABLE RepoGroup.*)user_name TEXT,(.*)/\1user_name TEXT COLLATE NOCASE,\2/I' ${SEAFILE_DB} > ${SEAFILE_DB}.tmp && mv ${SEAFILE_DB}.tmp ${SEAFILE_DB}
sed -r 's/(CREATE TABLE RepoUserToken.*)email VARCHAR\(255\),(.*)/\1email VARCHAR\(255\) COLLATE NOCASE,\2/I' ${SEAFILE_DB} > ${SEAFILE_DB}.tmp && mv ${SEAFILE_DB}.tmp ${SEAFILE_DB}
sed -r 's/(CREATE TABLE UserQuota.*)user VARCHAR\(255\),(.*)/\1user VARCHAR\(255\) COLLATE NOCASE,\2/I' ${SEAFILE_DB} > ${SEAFILE_DB}.tmp && mv ${SEAFILE_DB}.tmp ${SEAFILE_DB}
sed -r 's/(CREATE TABLE SharedRepo.*)from_email VARCHAR\(512\), to_email VARCHAR\(512\),(.*)/\1from_email VARCHAR\(512\), to_email VARCHAR\(512\) COLLATE NOCASE,\2/I' ${SEAFILE_DB} > ${SEAFILE_DB}.tmp && mv ${SEAFILE_DB}.tmp ${SEAFILE_DB}

# backup & restore
mv ${SEAFILE_DB_FILE} ${SEAFILE_DB_FILE}.`date +"%Y%m%d%H%M%S"`
sqlite3 ${SEAFILE_DB_FILE} < ${SEAFILE_DB}

########## seahub
rm -rf ${SEAHUB_DB}

SEAHUB_DB_FILE=$3
echo "sqlite3 ${SEAHUB_DB_FILE} .Dump | tr -d '\n' | sed 's/;/;\n/g' > ${SEAHUB_DB}"
sqlite3 ${SEAHUB_DB_FILE} .dump | tr -d '\n' | sed 's/;/;\n/g' > ${SEAHUB_DB}

sed -r 's/(CREATE TABLE "notifications_usernotification".*)"to_user" varchar\(255\) NOT NULL,(.*)/\1"to_user" varchar\(255\) NOT NULL COLLATE NOCASE,\2/I' ${SEAHUB_DB} > ${SEAHUB_DB}.tmp && mv ${SEAHUB_DB}.tmp ${SEAHUB_DB}
sed -r 's/(CREATE TABLE "profile_profile".*)"user" varchar\(75\) NOT NULL UNIQUE,(.*)/\1"user" varchar\(75\) NOT NULL UNIQUE COLLATE NOCASE,\2/I' ${SEAHUB_DB} > ${SEAHUB_DB}.tmp && mv ${SEAHUB_DB}.tmp ${SEAHUB_DB}
sed -r 's/(CREATE TABLE "share_fileshare".*)"username" varchar\(255\) NOT NULL,(.*)/\1"username" varchar\(255\) NOT NULL COLLATE NOCASE,\2/I' ${SEAHUB_DB} > ${SEAHUB_DB}.tmp && mv ${SEAHUB_DB}.tmp ${SEAHUB_DB}
sed -r 's/(CREATE TABLE "api2_token".*)"user" varchar\(255\) NOT NULL UNIQUE,(.*)/\1"user" varchar\(255\) NOT NULL UNIQUE COLLATE NOCASE,\2/I' ${SEAHUB_DB} > ${SEAHUB_DB}.tmp && mv ${SEAHUB_DB}.tmp ${SEAHUB_DB}
sed -r 's/(CREATE TABLE "wiki_personalwiki".*)"username" varchar\(256\) NOT NULL UNIQUE,(.*)/\1"username" varchar\(256\) NOT NULL UNIQUE COLLATE NOCASE,\2/I' ${SEAHUB_DB} > ${SEAHUB_DB}.tmp && mv ${SEAHUB_DB}.tmp ${SEAHUB_DB}
sed -r 's/(CREATE TABLE "message_usermessage".*)"from_email" varchar\(75\) NOT NULL,\s*"to_email" varchar\(75\) NOT NULL,(.*)/\1"from_email" varchar\(75\) NOT NULL COLLATE NOCASE, "to_email" varchar\(75\) NOT NULL COLLATE NOCASE,\2/I' ${SEAHUB_DB} > ${SEAHUB_DB}.tmp && mv ${SEAHUB_DB}.tmp ${SEAHUB_DB}
sed -r 's/(CREATE TABLE "avatar_avatar".*)"emailuser" varchar\(255\) NOT NULL,(.*)/\1"emailuser" varchar\(255\) NOT NULL COLLATE NOCASE,\2/I' ${SEAHUB_DB} > ${SEAHUB_DB}.tmp && mv ${SEAHUB_DB}.tmp ${SEAHUB_DB}

# backup & restore
mv ${SEAHUB_DB_FILE} ${SEAHUB_DB_FILE}.`date +"%Y%m%d%H%M%S"`
sqlite3 ${SEAHUB_DB_FILE} < ${SEAHUB_DB}

rm -rf ${USER_DB} ${GROUP_DB} ${SEAFILE_DB} ${SEAHUB_DB}
