#!/bin/bash

SCRIPT=$(readlink -f "$0")
INSTALLPATH=$(dirname "${SCRIPT}")
TOPDIR=$(dirname "${INSTALLPATH}")
default_ccnet_conf_dir=${TOPDIR}/ccnet
default_seafile_data_dir=${TOPDIR}/seafile-data
default_seahub_db=${TOPDIR}/seahub.db

old_ld_path=$LD_LIBRARY_PATH
new_ld_path=${INSTALLPATH}/seafile/lib/:${LD_LIBRARY_PATH}
export LD_LIBRARY_PATH=$new_ld_path

use_existing_ccnet="false"
use_existing_seafile="false"

server_manual_http="http://wiki.seafile.com.cn/wiki/Server-manual"

function welcome () {
    echo "-----------------------------------------------------------------"
    echo "This script will guide you to config and setup your seafile server."
    echo -e "\nMake sure you have read seafile server manual at \n\n\t${server_manual_http}\n"
    echo "Press [ENTER] to continue"
    echo "-----------------------------------------------------------------"
    read dummy
    echo
}


function err_and_quit () {
    printf "\n\n\033[33mError occured during setup. \nPlease fix possible problems and run the script again.\033[m\n\n"
    exit 1;
}

function on_ctrl_c_pressed () {
    printf "\n\n\033[33mYou have pressed Ctrl-C. Setup is interrupted.\033[m\n\n" 
    exit 1;
}

# clean newly created ccnet/seafile configs when exit on SIGINT 
trap on_ctrl_c_pressed 2

function check_sanity () {
    if ! [[ -d ${INSTALLPATH}/seahub && -d ${INSTALLPATH}/seafile \
        && -d ${INSTALLPATH}/runtime ]]; then
        echo
        echo "The seafile-server diretory doesn't contain all needed files."    
        echo "Please make sure you have extracted all files and folders from tarball."
        err_and_quit;
    fi
}

function read_yes_no () {
    printf "[yes|no] "
    read yesno;
    while [[ "${yesno}" != "yes" && "${yesno}" != "no" ]]
    do
        printf "please answer [yes|no] "
        read yesno;
    done

    if [[ "${yesno}" == "no" ]]; then
        return 1;
    else
        return 0;
    fi
}

function check_root () {
    # -------------------------------------------
    # If running as root, ask the user to ensure it.
    # -------------------------------------------
    username="$(whoami)"
    if [[ "${username}" == "root" ]]; then 
        echo
        echo "You are running this script as ROOT. Are you sure to continue?"

        if ! read_yes_no; then
            echo "You should re-run this script as non-root user."
            echo
            exit 1;
        fi
        echo
    fi
}

function check_existing_ccnet () {
    if [[ -d ${default_ccnet_conf_dir} ]]; then
        echo "It seems you have created a ccnet configuration before. "
        echo "Do you want to use the existing configuration?"

        if ! read_yes_no; then
            echo
            echo "Please remove the existing configuration before continue."
            echo "You can do it by \"rm -rf ${default_ccnet_conf_dir}\""
            echo
            exit 1;
        else
            echo
            echo "Existing ccnet configuration would be used." 
            use_existing_ccnet=true
        fi
    fi
    echo
}

function check_python_module () {
    module=$1 
    name=$2
    hint=$3
    printf "  Checking python module: ${name} ... " 
    if ! python -c "import ${module}" 2>/dev/null 1>&2; then
        echo
        printf "\033[33m ${name} \033[m is not installed, Please install it first.\n"
        if [[ "${hint}" != "" ]]; then
            printf "${hint}"
            echo
        fi
        err_and_quit;
    fi
    echo -e "Done."
}

function check_python () {
    echo "Checking python on this machine ..."
    if ! which python 2>/dev/null 1>&2; then
        echo "No python found on this machine. Please install it first."
        err_and_quit;
    else
        if (python --version 2>&1 | grep "3\\.[0-9].\\.[0-9]") 2>/dev/null 1>&2 ; then
            printf "\033[33m Python version 3.x \033[m detected\n"
            echo "Python 3.x is not supported. Please use python 2.x. Now quit."
            err_and_quit;
        fi
        
        hint="\nOn Debian/Ubntu: apt-get install python-setuptools\nOn CentOS/RHEL: yum install python-setuptools"
        check_python_module pkg_resources setuptools "${hint}"
        hint="\nOn Debian/Ubntu: apt-get install python-simplejson\nOn CentOS/RHEL: yum install python-simplejson"
        check_python_module simplejson python-simplejson "${hint}"
        hint="\nOn Debian/Ubntu: apt-get install python-imaging\nOn CentOS/RHEL: yum install python-imaging"
        check_python_module PIL python-imaging "${hint}"
    fi
    echo
}

function check_sqlite3 () {
    echo -n "Checking for sqlite3 ..."
    if ! which sqlite3 2>/dev/null 1>&2; then
        echo -e "\nSqlite3 is not found. install it first.\n"
        echo "On Debian/Ubuntu:     apt-get install sqlite3"
        echo "On CentOS/RHEL:       yum install sqlite"
        err_and_quit;
    fi
    printf "Done.\n\n"
}

function check_system_dependency () {
    printf "Checking packages needed by seafile ...\n\n"
    check_python;
    check_sqlite3;
    printf "Checking Done.\n\n"
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
    
function get_server_name () {
    question="What do you want to use as the name of this seafile server?\nYour seafile users would see this name in their seafile client."
    hint="You can use a-z, A-Z, 0-9, _ and -, and the length should be 3 ~ 15"
    ask_question "${question}\n${hint}" "nodefault" "server name"
    read server_name
    if [[ "${server_name}" == "" ]]; then
        echo
        echo "server name can not be empty"
        get_server_name
    elif [[ ! ${server_name} =~ ^[a-zA-Z][a-zA-Z0-9_-]{2,14}$ ]]; then
        printf "\n\033[33m${server_name}\033[m is not a valid name.\n"
        get_server_name;
    fi
    echo
}

function get_server_ip_or_domain () {
    question="What is the ip or domain of this server?\nFor example, www.mycompany.com, or, 192.168.1.101" 
    ask_question "${question}\n" "nodefault" "ip or domain"
    read ip_or_domain
    if [[ "${ip_or_domain}" == "" ]]; then
        echo
        echo "ip or domain can not be empty"
        get_server_ip_or_domain
    fi
    echo
}

function get_server_port () {
    question="What tcp port do you want to use for seafile server?" 
    hint="10001 is the recommended port."
    default="10001"
    ask_question "${question}\n${hint}" "${default}"
    read server_port
    if [[ "${server_port}" == "" ]]; then
        server_port="${default}"
    fi
    if [[ ! ${server_port} =~ ^[0-9]+$ ]]; then
        echo "\"${server_port}\" is not a valid port number. "
        get_server_port
    fi
    echo
}

function get_seafile_data_dir () {
    question="Where do you want to put your seafile data?"
    note="The size of seafile data diretory would increase very large, please use a volume with enough free space." 
    default=${default_seafile_data_dir}
    ask_question "${question} \n\033[33mNote: \033[m${note}" "${default}"
    read seafile_data_dir
    if [[ "${seafile_data_dir}" == "" ]]; then
        seafile_data_dir=${default}
    fi

    if [[ -d ${seafile_data_dir} && -f ${seafile_data_dir}/seafile.conf ]]; then
        echo
        echo "It seems you have existing seafile data in ${seafile_data_dir}."
        echo "Do you want to use the existing seafile data?"
        if ! read_yes_no; then
            echo "You choose not to use existing seafile data in ${seafile_data_dir}"
            echo "You need to specify another seafile data directory , or remove ${seafile_data_dir} before continue."
            get_seafile_data_dir
        else
            use_existing_seafile="true"
        fi
    elif [[ -d ${seafile_data_dir} ]] && [[ "$(ls -A $seafile_data_dir)" ]]; then
        echo 
        echo "${seafile_data_dir} is an existing non-empty directory. Please specify another directory"
        echo 
        get_seafile_data_dir
    elif [[ ! ${seafile_data_dir} =~ ^/ ]]; then
        echo 
        echo "\"${seafile_data_dir}\" is not an absolute path. Please specify an absolute path."
        echo 
        get_seafile_data_dir
    elif [[ ! -d $(dirname ${seafile_data_dir}) ]]; then
        echo 
        echo "The path $(dirname ${seafile_data_dir}) does not exist."
        echo 
        get_seafile_data_dir
    fi
    echo
}


# -------------------------------------------
# Main workflow of this script 
# -------------------------------------------

check_root;
sleep .5
check_sanity;
welcome;
sleep .5
check_system_dependency;
sleep .5

check_existing_ccnet;
if [[ ${use_existing_ccnet} != "true" ]]; then
    get_server_name;
    get_server_ip_or_domain;
    get_server_port;
fi

get_seafile_data_dir;
sleep .5

printf "\nThis is your config information:\n\n"

if [[ ${use_existing_ccnet} != "true" ]]; then
    printf "server name:        \033[33m${server_name}\033[m\n"
    printf "server ip/domain:   \033[33m${ip_or_domain}\033[m\n"
    printf "server port:        \033[33m${server_port}\033[m\n"
else
    printf "ccnet config:       use existing config in  \033[33m${default_ccnet_conf_dir}\033[m\n"
fi

if [[ ${use_existing_seafile} != "true" ]]; then
    printf "seafile data dir:     \033[33m${seafile_data_dir}\033[m\n"
else
    printf "seafile data dir:   use existing data in    \033[33m${seafile_data_dir}\033[m\n"
fi

echo
echo "If you are OK with these configuration, press [ENTER] to continue."
read dummy

ccnet_init=${INSTALLPATH}/seafile/bin/ccnet-init
seaf_server_init=${INSTALLPATH}/seafile/bin/seaf-server-init

# -------------------------------------------
# Create ccnet conf 
# -------------------------------------------
if [[ "${use_existing_ccnet}" != "true" ]]; then
    echo "Generating ccnet configuration in ${default_ccnet_conf_dir}..."
    echo
    if ! "${ccnet_init}" -c "${default_ccnet_conf_dir}" --name "${server_name}" \
        --port "${server_port}" --host "${ip_or_domain}" 2>/dev/null 1>&2 ; then
        err_and_quit;
    fi

    echo "Done. "
    echo
fi

sleep 0.5

# -------------------------------------------
# Create seafile conf
# -------------------------------------------
if [[ "${use_existing_seafile}" != "true" ]]; then
    echo "Generating seafile configuration in ${seafile_data_dir} ..."
    echo
    if ! ${seaf_server_init} --seafile-dir "${seafile_data_dir}" 2>/dev/null 1>&2; then
        echo "Failed to generate seafile configuration"
        err_and_quit;
    fi
    
    echo "Done. "
    echo
fi

# -------------------------------------------
# Write seafile.ini
# -------------------------------------------

echo "${seafile_data_dir}" > "${default_ccnet_conf_dir}/seafile.ini"

# -------------------------------------------
# generate seahub/settings.py
# -------------------------------------------
dest_settings_py=${TOPDIR}/seahub_settings.py
seahub_secret_keygen=${INSTALLPATH}/seahub/tools/secret_key_generator.py

HTTP_SERVER_ROOT=http://${ip_or_domain}:8082

if [[ ! -f ${dest_settings_py} ]]; then
    echo "HTTP_SERVER_ROOT = \"${HTTP_SERVER_ROOT}\"" > "${dest_settings_py}"
    echo -n "SECRET_KEY = " >> "${dest_settings_py}"
    key=$(python "${seahub_secret_keygen}")
    echo "\"${key}\"" >> "${dest_settings_py}"
fi

# -------------------------------------------
# Seahub related config
# -------------------------------------------
echo "-----------------------------------------------------------------"
echo "Seahub is the web server for seafile server administaration."
echo "Now let's setup seahub configuration. Press [ENTER] to continue"
echo "-----------------------------------------------------------------"
echo
read dummy

echo "Please specify the email address and password for seahub admininstrator."
echo "You would use them to login as admin on your seahub website."
echo

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
    echo
    question="Please specify the passwd you want to use for seahub admininstrator:"
    ask_question "${question}" "nodefault" "seahub admin password"
    read seahub_admin_passwd
    echo
    question="Please ensure the passwd again:"
    ask_question "${question}" "nodefault" "seahub admin password again"
    read seahub_admin_passwd_again
    echo
    if [[ "${seahub_admin_passwd}" != "${seahub_admin_passwd_again}" ]]; then
        printf "\033[33mTwo passwords you give mismatch.\033[m"
        get_seahub_admin_passwd;
    elif [[ "${seahub_admin_passwd}" == "" ]]; then
        echo "Passwords can't be empty."
        get_seahub_admin_passwd;
    fi
}
    
get_seahub_admin_email;
sleep .5;
get_seahub_admin_passwd;
seahub_admin_passwd_enc=$(echo -n ${seahub_admin_passwd} | sha1sum | grep -o "[0-9a-f]*")
sleep .5;

printf "\n\n"
echo "This is your seahub admin username/password"
echo
printf "admin user name:        \033[33m${seahub_admin_email}\033[m\n"
printf "admin password:         \033[33m${seahub_admin_passwd}\033[m\n\n"

echo
echo "If you are OK with these configuration, press [ENTER] to continue."
read dummy

usermgr_db_dir=${default_ccnet_conf_dir}/PeerMgr/
usermgr_db=${usermgr_db_dir}/usermgr.db

if [[ "${use_existing_ccnet}" != "true" ]]; then
    export LD_LIBRARY_PATH=$old_ld_path
    # create admin user/passwd entry in ccnet db
    if ! mkdir -p "${usermgr_db_dir}" 2>/dev/null 1>&2 ; then
        echo "Failed to create seahub admin."
        err_and_quit;
    fi
    
    sql="CREATE TABLE IF NOT EXISTS EmailUser (id INTEGER NOT NULL PRIMARY KEY, email TEXT, passwd TEXT, is_staff bool NOT NULL, is_active bool NOT NULL, ctime INTEGER)";

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
    export LD_LIBRARY_PATH=$new_ld_path
fi

printf "Now sync seahub database ... "
export PYTHONPATH=${INSTALLPATH}/seafile/lib/python2.7/site-packages:${INSTALLPATH}/seahub/thirdpart:${PYTHONPATH}
manage_py=${INSTALLPATH}/seahub/manage.py
pushd "${INSTALLPATH}/seahub" 2>/dev/null 1>&2
if ! python manage.py syncdb 2>/dev/null 1>&2; then
    popd 2>/dev/null 1>&2
    echo "Failed to sync seahub database."
    err_and_quit;
fi
popd 2>/dev/null 1>&2
printf "Done.\n"

# prepare avatar folder

media_dir=${INSTALLPATH}/seahub/media
orig_avatar_dir=${INSTALLPATH}/seahub/media/avatars
dest_avatar_dir=${TOPDIR}/seahub-data/avatars

if [[ ! -d ${dest_avatar_dir} ]]; then
    mkdir -p "${TOPDIR}/seahub-data"
    mv "${orig_avatar_dir}" "${dest_avatar_dir}"
    ln -s ../../../seahub-data/avatars ${media_dir}
fi

# -------------------------------------------
# final message
# -------------------------------------------

sleep 1

echo
echo "-----------------------------------------------------------------"
echo "Your seafile server configuration has been finished successfully." 
echo "-----------------------------------------------------------------"
echo 
echo "run seafile server:     ./seafile.sh { start | stop | restart }"
echo "run seahub  server:     ./seahub.sh  { start <port> | stop | restart <port> } "
echo
echo -e "When problems occur, Refer to\n"
echo -e "      ${server_manual_http}\n"
echo "for information."
echo
