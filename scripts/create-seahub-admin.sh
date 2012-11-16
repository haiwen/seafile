#!/bin/bash


SCRIPT=$(readlink -f "$0")
INSTALLPATH=$(dirname "${SCRIPT}")
TOPDIR=$(dirname "${INSTALLPATH}")
default_ccnet_conf_dir=${TOPDIR}/ccnet
default_seafile_data_dir=${TOPDIR}/seafile-data
default_seahub_db=${TOPDIR}/seahub.db

function welcome () {
    echo
    echo "-----------------------------------------------------------------"
    echo "This script will help you create a seahub admin account."
    echo "press [ENTER] to continue"
    echo "-----------------------------------------------------------------"
    read dummy
    echo ""
}

function err_and_quit () {
    printf "\n\n\033[33mError occured during execution. \nPlease fix possible problems and run the script again.\033[m\n\n"
}

function check_dependency () {
    if ! which sqlite3 2>/dev/null 1>&2; then
        printf "\033[33msqlite3\033[m is not installed, install it first"
        exit 1;
    fi
}

function ask_question () {
    question=$1
    default=$2
    key=$3
    printf "${question}"
    printf "\n"
    if [[ "${default}" != "" && "${default}" != "nodefault" ]] ; then
        printf "[default: ${default} ] "
    elif [[ "${key}" != "" ]]; then
        printf "[${key}]: "
    fi
}


function get_seahub_admin_email () {
    question="Please specify the email address for seahub admininstrator:"
    ask_question "${question}" "nodefault" "seahub admin email"
    read seahub_admin_email
    if [[ "${seahub_admin_email}" == "" ]]; then
        echo "Seahub admin user name can't be empty."
        get_seahub_admin_email;
    elif [[ ! ${seahub_admin_email} =~ ^.+@.*\..+$ ]]; then
        echo "${seahub_admin_email} is not a valid email address"
        get_seahub_admin_email;
    fi
}

function get_seahub_admin_passwd () {
    echo ""
    question="Please specify the passwd you want to use for seahub admininstrator:"
    ask_question "${question}" "nodefault" "seahub admin password"
    read seahub_admin_passwd
    echo ""
    question="Please ensure the passwd again:"
    ask_question "${question}" "nodefault" "seahub admin password again"
    read seahub_admin_passwd_again
    echo ""
    if [[ "${seahub_admin_passwd}" != "${seahub_admin_passwd_again}" ]]; then
        printf "\033[33mTwo passwords you give mismatch.\033[m"
        get_seahub_admin_passwd;
    elif [[ "${seahub_admin_passwd}" == "" ]]; then
        echo "Passwords can't be empty."
        get_seahub_admin_passwd;
    fi
}

welcome;
check_dependency;
    
get_seahub_admin_email;
sleep .5;
get_seahub_admin_passwd;
seahub_admin_passwd_enc=$(echo -n ${seahub_admin_passwd} | sha1sum | grep -o "[0-9a-f]*")
sleep .5;

printf "\n\n"
echo "This is your seahub admin username/password"
echo ""
printf "admin user name:        \033[33m${seahub_admin_email}\033[m\n"
printf "admin password:         \033[33m${seahub_admin_passwd}\033[m\n\n"

echo ""
echo "If you are OK with these configuration, press [ENTER] to continue."
read dummy


usermgr_db_dir=${default_ccnet_conf_dir}/PeerMgr/
usermgr_db=${usermgr_db_dir}/usermgr.db

# create admin user/passwd entry in ccnet db
if ! mkdir -p "${usermgr_db_dir}" 2>/dev/null 1>&2 ; then
    echo "Failed to create seahub admin."
    err_and_quit;
fi

sql="CREATE TABLE IF NOT EXISTS EmailUser (id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, email TEXT, passwd TEXT, is_staff bool NOT NULL, is_active bool NOT NULL, ctime INTEGER)";

if ! sqlite3 "${usermgr_db}" "${sql}" ; then
    rm -f "${usermgr_db}"
    echo "Failed to create seahub admin."
    err_and_quit;
fi

sql="INSERT INTO EmailUser(email, passwd, is_staff, is_active, ctime) VALUES (\"${seahub_admin_email}\", \"${seahub_admin_passwd_enc}\", 1, 1, 0);"

if ! sqlite3 "${usermgr_db}" "${sql}" ; then
    rm -f "${usermgr_db}"
    echo "Failed to create seahub admin."
    err_and_quit;
fi

# final message
echo ""
echo "Successfully created a seahub admin account for you."
echo ""
