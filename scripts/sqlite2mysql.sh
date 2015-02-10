#!/bin/sh
#
# This shell script and corresponding sqlite2mysql.py are used to
# migrate Seafile data from SQLite to MySQL.
#
# Setup:
# 
#  1. Move this file and sqlite2mysql.py to the top directory of your Seafile
#     installation path (e.g. /data/haiwen).
#  2. Run: ./sqlite2mysql.sh
#  3. Three files(ccnet-db.sql, seafile-db.sql, seahub-db.sql) are created.
#  4. Loads these files to MySQL
#     (mysql> source ccnet-db.sql)
# 

CCNET_DB='ccnet-db.sql'
SEAFILE_DB='seafile-db.sql'
SEAHUB_DB='seahub-db.sql'

########## ccnet
seafile_path=$(pwd)
if [ -f "${seafile_path}/ccnet/ccnet.conf" ]; then
    USER_MGR_DB=${seafile_path}/ccnet/PeerMgr/usermgr.db
    GRP_MGR_DB=${seafile_path}/ccnet/GroupMgr/groupmgr.db
else
    echo "${seafile_path}/ccnet/ccnet.conf does not exists."
    read -p "Please provide your ccnet.conf path(e.g. /data/haiwen/ccnet/ccnet.conf): " ccnet_conf_path
    if [ -f ${ccnet_conf_path} ]; then
        USER_MGR_DB=$(dirname "${ccnet_conf_path}")/PeerMgr/usermgr.db
        GRP_MGR_DB=$(dirname "${ccnet_conf_path}")/GroupMgr/groupmgr.db
    else
        echo "${ccnet_conf_path} does not exists, quit."
        exit 1
    fi
fi

rm -rf ${CCNET_DB}

echo "sqlite3 ${USER_MGR_DB} .dump | python sqlite2mysql.py > ${CCNET_DB}"
sqlite3 ${USER_MGR_DB} .dump | python sqlite2mysql.py > ${CCNET_DB}
echo "sqlite3 ${GRP_MGR_DB} .dump | python sqlite2mysql.py >> ${CCNET_DB}"
sqlite3 ${GRP_MGR_DB} .dump | python sqlite2mysql.py >> ${CCNET_DB}

# change ctime from INTEGER to BIGINT in EmailUser table
sed 's/ctime INTEGER/ctime BIGINT/g' ${CCNET_DB} > ${CCNET_DB}.tmp && mv ${CCNET_DB}.tmp ${CCNET_DB}

# change email in UserRole from TEXT to VARCHAR(255)
sed 's/email TEXT, role TEXT/email VARCHAR(255), role TEXT/g' ${CCNET_DB} > ${CCNET_DB}.tmp && mv ${CCNET_DB}.tmp ${CCNET_DB}

########## seafile
rm -rf ${SEAFILE_DB}

if [ -f "${seafile_path}/seafile-data/seafile.db" ]; then
    echo "sqlite3 ${seafile_path}/seafile-data/seafile.db .dump | python sqlite2mysql.py > ${SEAFILE_DB}"
    sqlite3 ${seafile_path}/seafile-data/seafile.db .dump | python sqlite2mysql.py > ${SEAFILE_DB}
else
    echo "${seafile_path}/seafile-data/seafile.db does not exists."
    read -p "Please provide your seafile.db path(e.g. /data/haiwen/seafile-data/seafile.db): " seafile_db_path
    if [ -f ${seafile_db_path} ];then
        echo "sqlite3 ${seafile_db_path} .dump | python sqlite2mysql.py > ${SEAFILE_DB}"
        sqlite3 ${seafile_db_path} .dump | python sqlite2mysql.py > ${SEAFILE_DB}
    else
        echo "${seafile_db_path} does not exists, quit."
        exit 1
    fi
fi

# change owner_id in RepoOwner from TEXT to VARCHAR(255)
sed 's/owner_id TEXT/owner_id VARCHAR(255)/g' ${SEAFILE_DB} > ${SEAFILE_DB}.tmp && mv ${SEAFILE_DB}.tmp ${SEAFILE_DB}

# change user_name in RepoGroup from TEXT to VARCHAR(255)
sed 's/user_name TEXT/user_name VARCHAR(255)/g' ${SEAFILE_DB} > ${SEAFILE_DB}.tmp && mv ${SEAFILE_DB}.tmp ${SEAFILE_DB}

########## seahub
rm -rf ${SEAHUB_DB}

if [ -f "${seafile_path}/seahub.db" ]; then
    echo "sqlite3 ${seafile_path}/seahub.db .dump | tr -d '\n' | sed 's/;/;\n/g' | python sqlite2mysql.py > ${SEAHUB_DB}"
    sqlite3 ${seafile_path}/seahub.db .dump | tr -d '\n' | sed 's/;/;\n/g' | python sqlite2mysql.py > ${SEAHUB_DB}
else
    echo "${seafile_path}/seahub.db does not exists."
    read -p "Please prove your seahub.db path(e.g. /data/haiwen/seahub.db): " seahub_db_path
    if [ -f ${seahub_db_path} ]; then
        echo "sqlite3 ${seahub_db_path} .dump | tr -d '\n' | sed 's/;/;\n/g' | python sqlite2mysql.py > ${SEAHUB_DB}"
        sqlite3 ${seahub_db_path} .dump | tr -d '\n' | sed 's/;/;\n/g' | python sqlite2mysql.py > ${SEAHUB_DB}
    else
        echo "${seahub_db_path} does not exists, quit."
        exit 1
    fi
fi

# change username from VARCHAR(256) to VARCHAR(255) in wiki_personalwiki
sed 's/varchar(256) NOT NULL UNIQUE/varchar(255) NOT NULL UNIQUE/g' ${SEAHUB_DB} > ${SEAHUB_DB}.tmp && mv ${SEAHUB_DB}.tmp ${SEAHUB_DB}

# remove unique from contacts_contact
sed 's/,    UNIQUE (`user_email`, `contact_email`)//g' ${SEAHUB_DB} > ${SEAHUB_DB}.tmp && mv ${SEAHUB_DB}.tmp ${SEAHUB_DB}

# remove base_dirfileslastmodifiedinfo records to avoid json string parsing issue between sqlite and mysql
sed '/INSERT INTO `base_dirfileslastmodifiedinfo`/d' ${SEAHUB_DB} > ${SEAHUB_DB}.tmp && mv ${SEAHUB_DB}.tmp ${SEAHUB_DB}

# remove notifications_usernotification records to avoid json string parsing issue between sqlite and mysql
sed '/INSERT INTO `notifications_usernotification`/d' ${SEAHUB_DB} > ${SEAHUB_DB}.tmp && mv ${SEAHUB_DB}.tmp ${SEAHUB_DB}


########## common logic

# add ENGIN=INNODB to create table statment
for sql_file in $CCNET_DB $SEAFILE_DB $SEAHUB_DB
do
    sed -r 's/(CREATE TABLE.*);/\1 ENGINE=INNODB;/g' $sql_file > $sql_file.tmp && mv $sql_file.tmp $sql_file
done

# remove COLLATE NOCASE if possible
for sql_file in $CCNET_DB $SEAFILE_DB $SEAHUB_DB
do
    sed 's/COLLATE NOCASE//g' $sql_file > $sql_file.tmp && mv $sql_file.tmp $sql_file
done

