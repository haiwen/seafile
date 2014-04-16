#!/bin/bash

SCRIPT=$(readlink -f "$0")
INSTALLPATH=$(dirname "${SCRIPT}")
TOPDIR=$(dirname "${INSTALLPATH}")
default_ccnet_conf_dir=${TOPDIR}/ccnet
default_seafile_data_dir=${TOPDIR}/seafile-data
default_seahub_db=${TOPDIR}/seahub.db
default_conf_dir=${TOPDIR}/conf

export SEAFILE_LD_LIBRARY_PATH=${INSTALLPATH}/seafile/lib/:${INSTALLPATH}/seafile/lib64:${LD_LIBRARY_PATH}

use_existing_ccnet="false"
use_existing_seafile="false"

server_manual_http="https://github.com/haiwen/seafile/wiki"

function welcome () {
    echo "-----------------------------------------------------------------"
    echo "This script will guide you to config and setup your seafile server."
    echo -e "\nMake sure you have read seafile server manual at \n\n\t${server_manual_http}\n"
    echo -e "Note: This script will guide your to setup seafile server using sqlite3,"
    echo "which may have problems if your disk is on a NFS/CIFS/USB."
    echo "In these cases, we sugguest you setup seafile server using MySQL."
    echo
    echo "Press [ENTER] to continue"
    echo "-----------------------------------------------------------------"
    read dummy
    echo
}

function err_and_quit () {
    printf "\n\n\033[33mError occured during setup. \nPlease fix possible issues and run the script again.\033[m\n\n"
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
        echo "It seems that you have created a ccnet configuration before. "
        echo "Would you like to use the existing configuration?"

        if ! read_yes_no; then
            echo
            echo "Please remove the existing configuration before continuing."
            echo "You can do it by running \"rm -rf ${default_ccnet_conf_dir}\""
            echo
            exit 1;
        else
            echo
            echo "Existing ccnet configuration is being used." 
            use_existing_ccnet=true
        fi
    fi
    echo
}

function check_python_executable() {
    if [[ "$PYTHON" != "" && -x $PYTHON ]]; then
        return 0
    fi
        
    if which python2.7 2>/dev/null 1>&2; then
        PYTHON=python2.7
    elif which python27 2>/dev/null 1>&2; then
        PYTHON=python27
    elif which python2.6 2>/dev/null 1>&2; then
        PYTHON=python2.6
    elif which python26 2>/dev/null 1>&2; then
        PYTHON=python26
    else
        echo 
        echo "Can't find a python executable of version 2.6 or above in PATH"
        echo "Please install python 2.6+ before continuing."
        echo "If it is installed in a non-standard PATH, please set the PYTHON environment variable"
        echo 
        exit 1
    fi

    echo "Find python: $PYTHON"
    echo
}

function check_python_module () {
    module=$1 
    name=$2
    hint=$3
    printf "  Checking python module: ${name} ... " 
    if ! $PYTHON -c "import ${module}" 2>/dev/null 1>&2; then
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
    check_python_executable
    if ! which $PYTHON 2>/dev/null 1>&2; then
        echo "No $PYTHON found on this machine. Please install it first."
        err_and_quit;
    else
        if ($Python --version 2>&1 | grep "3\\.[0-9].\\.[0-9]") 2>/dev/null 1>&2 ; then
            printf "\033[33m Python version 3.x \033[m detected\n"
            echo "Python 3.x is not supported. Please use python 2.x."
            err_and_quit;
        fi
        
        if [[ $PYTHON == "python2.6" ]]; then
            py26="2.6"
        fi
        hint="\nOn Debian/Ubntu: apt-get install python-setuptools\nOn CentOS/RHEL: yum install python${py26}-distribute"
        check_python_module pkg_resources setuptools "${hint}"
        hint="\nOn Debian/Ubntu: apt-get install python-simplejson\nOn CentOS/RHEL: yum install python${py26}-simplejson"
        check_python_module simplejson python-simplejson "${hint}"
        hint="\nOn Debian/Ubntu: apt-get install python-imaging\nOn CentOS/RHEL: yum install python${py26}-imaging"
        check_python_module PIL python-imaging "${hint}"
        check_python_module sqlite3 python-sqlite3
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
    question="What would you like to use as the name of this seafile server?\nYour seafile users will be able to see the name in their seafile client."
    hint="You can use a-z, A-Z, 0-9, _ and -, and the length should be 3 ~ 15"
    ask_question "${question}\n${hint}" "nodefault" "server name"
    read server_name
    if [[ "${server_name}" == "" ]]; then
        echo
        echo "server name cannot be empty"
        get_server_name
    elif [[ ! ${server_name} =~ ^[a-zA-Z0-9_-]{3,14}$ ]]; then
        printf "\n\033[33m${server_name}\033[m is not a valid name.\n"
        get_server_name;
    fi
    echo
}

function get_server_ip_or_domain () {
    question="What is the ip or domain of this server?\nFor example, www.mycompany.com, or, 192.168.1.101" 
    ask_question "${question}\n" "nodefault" "This server's ip or domain"
    read ip_or_domain
    if [[ "${ip_or_domain}" == "" ]]; then
        echo
        echo "ip or domain cannot be empty"
        get_server_ip_or_domain
    fi
    echo
}

function get_ccnet_server_port () {
    question="What tcp port do you want to use for ccnet server?" 
    hint="10001 is the recommended port."
    default="10001"
    ask_question "${question}\n${hint}" "${default}"
    read server_port
    if [[ "${server_port}" == "" ]]; then
        server_port="${default}"
    fi
    if [[ ! ${server_port} =~ ^[0-9]+$ ]]; then
        echo "\"${server_port}\" is not a valid port number. "
        get_ccnet_server_port
    fi
    echo
}

function get_seafile_server_port () {
    question="What tcp port would you like to use for seafile server?" 
    hint="12001 is the recommended port."
    default="12001"
    ask_question "${question}\n${hint}" "${default}"
    read seafile_server_port
    if [[ "${seafile_server_port}" == "" ]]; then
        seafile_server_port="${default}"
    fi
    if [[ ! ${seafile_server_port} =~ ^[0-9]+$ ]]; then
        echo "\"${seafile_server_port}\" is not a valid port number. "
        get_seafile_server_port
    fi
    echo
}

function get_httpserver_port () {
    question="What tcp port do you want to use for seafile httpserver?" 
    hint="8082 is the recommended port."
    default="8082"
    ask_question "${question}\n${hint}" "${default}"
    read httpserver_port
    if [[ "${httpserver_port}" == "" ]]; then
        httpserver_port="${default}"
    fi
    if [[ ! ${httpserver_port} =~ ^[0-9]+$ ]]; then
        echo "\"${httpserver_port}\" is not a valid port number. "
        get_httpserver_port
    fi
    echo
}


function get_seafile_data_dir () {
    question="Where would you like to store your seafile data?"
    note="Please use a volume with enough free space." 
    default=${default_seafile_data_dir}
    ask_question "${question} \n\033[33mNote: \033[m${note}" "${default}"
    read seafile_data_dir
    if [[ "${seafile_data_dir}" == "" ]]; then
        seafile_data_dir=${default}
    fi

    if [[ -d ${seafile_data_dir} && -f ${seafile_data_dir}/seafile.conf ]]; then
        echo
        echo "It seems that you have already existing seafile data in ${seafile_data_dir}."
        echo "Would you like to use the existing seafile data?"
        if ! read_yes_no; then
            echo "You have chosen not to use existing seafile data in ${seafile_data_dir}"
            echo "You need to specify a different seafile data directory or remove ${seafile_data_dir} before continuing."
            get_seafile_data_dir
        else
            use_existing_seafile="true"
        fi
    elif [[ -d ${seafile_data_dir} && $(ls -A ${seafile_data_dir}) != "" ]]; then
        echo 
        echo "${seafile_data_dir} is an existing non-empty directory. Please specify a different directory"
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

function gen_seafdav_conf () {
    mkdir -p ${default_conf_dir}
    seafdav_conf=${default_conf_dir}/seafdav.conf
    if ! $(cat > ${seafdav_conf} <<EOF
[WEBDAV]
enabled = false
port = 8080
fastcgi = false
share_name = /
EOF
); then
    echo "failed to generate seafdav.conf";
    err_and_quit
fi
}

function copy_user_manuals() {
    src_docs_dir=${INSTALLPATH}/seafile/docs/
    library_template_dir=${seafile_data_dir}/library-template
    mkdir -p ${library_template_dir}
    cp -f ${src_docs_dir}/*.doc ${library_template_dir}
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
    get_ccnet_server_port;
fi

get_seafile_data_dir;
if [[ ${use_existing_seafile} != "true" ]]; then
    get_seafile_server_port
    get_httpserver_port
fi

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
    printf "seafile data dir:   \033[33m${seafile_data_dir}\033[m\n"
    printf "seafile port:       \033[33m${seafile_server_port}\033[m\n"
    printf "httpserver port:    \033[33m${httpserver_port}\033[m\n"
else
    printf "seafile data dir:   use existing data in    \033[33m${seafile_data_dir}\033[m\n"
fi

echo
echo "If you are OK with the configuration, press [ENTER] to continue."
read dummy

ccnet_init=${INSTALLPATH}/seafile/bin/ccnet-init
seaf_server_init=${INSTALLPATH}/seafile/bin/seaf-server-init

# -------------------------------------------
# Create ccnet conf 
# -------------------------------------------
if [[ "${use_existing_ccnet}" != "true" ]]; then
    echo "Generating ccnet configuration in ${default_ccnet_conf_dir}..."
    echo
    if ! LD_LIBRARY_PATH=$SEAFILE_LD_LIBRARY_PATH "${ccnet_init}" -c "${default_ccnet_conf_dir}" --name "${server_name}" --port "${server_port}" --host "${ip_or_domain}"; then
        err_and_quit;
    fi

    echo
fi

sleep 0.5

# -------------------------------------------
# Create seafile conf
# -------------------------------------------
if [[ "${use_existing_seafile}" != "true" ]]; then
    echo "Generating seafile configuration in ${seafile_data_dir} ..."
    echo
    if ! LD_LIBRARY_PATH=$SEAFILE_LD_LIBRARY_PATH ${seaf_server_init} --seafile-dir "${seafile_data_dir}" \
        --port ${seafile_server_port} --httpserver-port ${httpserver_port}; then
        
        echo "Failed to generate seafile configuration"
        err_and_quit;
    fi
    
    echo
fi

# -------------------------------------------
# Write seafile.ini
# -------------------------------------------

echo "${seafile_data_dir}" > "${default_ccnet_conf_dir}/seafile.ini"

# -------------------------------------------
# Generate seafevents.conf
# -------------------------------------------

gen_seafdav_conf;

# -------------------------------------------
# generate seahub/settings.py
# -------------------------------------------
dest_settings_py=${TOPDIR}/seahub_settings.py
seahub_secret_keygen=${INSTALLPATH}/seahub/tools/secret_key_generator.py

if [[ ! -f ${dest_settings_py} ]]; then
    echo -n "SECRET_KEY = " >> "${dest_settings_py}"
    key=$($PYTHON "${seahub_secret_keygen}")
    echo "\"${key}\"" >> "${dest_settings_py}"
fi

# -------------------------------------------
# Seahub related config
# -------------------------------------------
echo "-----------------------------------------------------------------"
echo "Seahub is the web interface for seafile server."
echo "Now let's setup seahub configuration. Press [ENTER] to continue"
echo "-----------------------------------------------------------------"
echo
read dummy

# echo "Please specify the email address and password for the seahub administrator."
# echo "You can use them to login as admin on your seahub website."
# echo

function get_seahub_admin_email () {
    question="Please specify the email address for the seahub administrator:"
    ask_question "${question}" "nodefault" "seahub admin email"
    read seahub_admin_email
    if [[ "${seahub_admin_email}" == "" ]]; then
        echo "Seahub admin user name cannot be empty."
        get_seahub_admin_email;
    elif [[ ! ${seahub_admin_email} =~ ^.+@.*\..+$ ]]; then
        echo "${seahub_admin_email} is not a valid email address"
        get_seahub_admin_email;
    fi
}

function get_seahub_admin_passwd () {
    echo
    question="Please specify the password you would like to use for seahub administrator:"
    ask_question "${question}" "nodefault" "seahub admin password"
    read -s seahub_admin_passwd
    echo
    question="Please enter the password again:"
    ask_question "${question}" "nodefault" "seahub admin password again"
    read -s seahub_admin_passwd_again
    echo
    if [[ "${seahub_admin_passwd}" != "${seahub_admin_passwd_again}" ]]; then
        printf "\033[33mThe passwords didn't match.\033[m"
        get_seahub_admin_passwd;
    elif [[ "${seahub_admin_passwd}" == "" ]]; then
        echo "Password cannot be empty."
        get_seahub_admin_passwd;
    fi
}
    
# get_seahub_admin_email;
# sleep .5;
# get_seahub_admin_passwd;
# seahub_admin_passwd_enc=$(echo -n ${seahub_admin_passwd} | sha1sum | grep -o "[0-9a-f]*")
# sleep .5;

# printf "\n\n"
# echo "This is your seahub admin username/password"
# echo
# printf "admin username:         \033[33m${seahub_admin_email}\033[m\n"
# printf "admin password:         \033[33m**************\033[m\n\n"

# echo
# echo "If you are OK with the configuration, press [ENTER] to continue."
# read dummy

# usermgr_db_dir=${default_ccnet_conf_dir}/PeerMgr/
# usermgr_db=${usermgr_db_dir}/usermgr.db

# if [[ "${use_existing_ccnet}" != "true" ]]; then
#     # create admin user/passwd entry in ccnet db
#     if ! mkdir -p "${usermgr_db_dir}"; then
#         echo "Failed to create seahub admin."
#         err_and_quit;
#     fi
    
#     sql="CREATE TABLE IF NOT EXISTS EmailUser (id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, email TEXT, passwd TEXT, is_staff bool NOT NULL, is_active bool NOT NULL, ctime INTEGER)";

#     if ! sqlite3 "${usermgr_db}" "${sql}" ; then
#         rm -f "${usermgr_db}"
#         echo "Failed to create seahub admin."
#         err_and_quit;
#     fi
    
#     sql="INSERT INTO EmailUser(email, passwd, is_staff, is_active, ctime) VALUES (\"${seahub_admin_email}\", \"${seahub_admin_passwd_enc}\", 1, 1, 0);"

#     if ! sqlite3 "${usermgr_db}" "${sql}" ; then
#         rm -f "${usermgr_db}"
#         echo "Failed to create seahub admin."
#         err_and_quit;
#     fi
# fi

echo "Creating seahub database now... "
echo

export CCNET_CONF_DIR=$default_ccnet_conf_dir
export SEAFILE_CONF_DIR=$seafile_data_dir

export PYTHONPATH=${INSTALLPATH}/seafile/lib/python2.6/site-packages:${INSTALLPATH}/seafile/lib64/python2.6/site-packages:${INSTALLPATH}/seahub/thirdpart:$PYTHONPATH
export PYTHONPATH=${INSTALLPATH}/seafile/lib/python2.7/site-packages:${INSTALLPATH}/seafile/lib64/python2.7/site-packages:$PYTHONPATH

manage_py=${INSTALLPATH}/seahub/manage.py
pushd "${INSTALLPATH}/seahub" 2>/dev/null 1>&2
if ! $PYTHON manage.py syncdb; then
    popd 2>/dev/null 1>&2
    echo "Failed to sync seahub database."
    err_and_quit;
fi
popd 2>/dev/null 1>&2
echo
echo "Done."

# prepare avatar folder

media_dir=${INSTALLPATH}/seahub/media
orig_avatar_dir=${INSTALLPATH}/seahub/media/avatars
dest_avatar_dir=${TOPDIR}/seahub-data/avatars

if [[ ! -d ${dest_avatar_dir} ]]; then
    mkdir -p "${TOPDIR}/seahub-data"
    mv "${orig_avatar_dir}" "${dest_avatar_dir}"
    ln -s ../../../seahub-data/avatars ${media_dir}
fi

# Make a seafile-server symlink, like this:
# /data/haiwen/
#            -- seafile-server-2.0.4
#            -- seafile-server-latest # symlink to 2.0.4
seafile_server_symlink=${TOPDIR}/seafile-server-latest
echo
echo -n "creating seafile-server-latest symbolic link ... "
if ! ln -s $(basename ${INSTALLPATH}) ${seafile_server_symlink}; then
    echo
    echo
    echo "Failed to create symbolic link ${seafile_server_symlink}"
    err_and_quit;
fi
echo "done"
echo

# -------------------------------------------
# copy user manuals to library template
# -------------------------------------------
copy_user_manuals;

# -------------------------------------------
# final message
# -------------------------------------------

sleep 1

echo
echo "-----------------------------------------------------------------"
echo "Your seafile server configuration has been completed successfully." 
echo "-----------------------------------------------------------------"
echo 
echo "run seafile server:     ./seafile.sh { start | stop | restart }"
echo "run seahub  server:     ./seahub.sh  { start <port> | stop | restart <port> }"
echo
echo "-----------------------------------------------------------------"
echo "If the server is behind a firewall, remember to open these tcp ports:"
echo "-----------------------------------------------------------------"
echo
echo "port of ccnet server:         ${server_port}"
echo "port of seafile server:       ${seafile_server_port}"
echo "port of seafile httpserver:   ${httpserver_port}"
echo "port of seahub:               8000"
echo
echo -e "When problems occur, refer to\n"
echo -e "      ${server_manual_http}\n"
echo "for more information."
echo
