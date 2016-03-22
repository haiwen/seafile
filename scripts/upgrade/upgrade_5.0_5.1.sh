#!/bin/bash

SCRIPT=$(readlink -f "$0") # haiwen/seafile-server-1.3.0/upgrade/upgrade_xx_xx.sh
UPGRADE_DIR=$(dirname "$SCRIPT") # haiwen/seafile-server-1.3.0/upgrade/
INSTALLPATH=$(dirname "$UPGRADE_DIR") # haiwen/seafile-server-1.3.0/
TOPDIR=$(dirname "${INSTALLPATH}") # haiwen/
default_ccnet_conf_dir=${TOPDIR}/ccnet
default_conf_dir=${TOPDIR}/conf
seafile_server_symlink=${TOPDIR}/seafile-server-latest
seahub_data_dir=${TOPDIR}/seahub-data
seahub_settings_py=${TOPDIR}/seahub_settings.py

manage_py=${INSTALLPATH}/seahub/manage.py

export CCNET_CONF_DIR=${default_ccnet_conf_dir}
export SEAFILE_CENTRAL_CONF_DIR=${default_conf_dir}
export PYTHONPATH=${INSTALLPATH}/seafile/lib/python2.6/site-packages:${INSTALLPATH}/seafile/lib64/python2.6/site-packages:${INSTALLPATH}/seafile/lib/python2.7/site-packages:${INSTALLPATH}/seahub/thirdpart:$PYTHONPATH
export PYTHONPATH=${INSTALLPATH}/seafile/lib/python2.7/site-packages:${INSTALLPATH}/seafile/lib64/python2.7/site-packages:$PYTHONPATH
export SEAFILE_LD_LIBRARY_PATH=${INSTALLPATH}/seafile/lib/:${INSTALLPATH}/seafile/lib64:${LD_LIBRARY_PATH}

prev_version=5.0
current_version=5.1

echo
echo "-------------------------------------------------------------"
echo "This script would upgrade your seafile server from ${prev_version} to ${current_version}"
echo "Press [ENTER] to contiune"
echo "-------------------------------------------------------------"
echo
read dummy

function check_python_executable() {
    if [[ "$PYTHON" != "" && -x $PYTHON ]]; then
        return 0
    fi

    if which python2.7 2>/dev/null 1>&2; then
        PYTHON=python2.7
    elif which python27 2>/dev/null 1>&2; then
        PYTHON=python27
    else
        echo
        echo "Can't find a python executable of version 2.7 or above in PATH"
        echo "Install python 2.7+ before continue."
        echo "Or if you installed it in a non-standard PATH, set the PYTHON enviroment varirable to it"
        echo
        exit 1
    fi
}

function read_seafile_data_dir () {
    seafile_ini=${default_ccnet_conf_dir}/seafile.ini
    if [[ ! -f ${seafile_ini} ]]; then
        echo "${seafile_ini} not found. Now quit"
        exit 1
    fi
    seafile_data_dir=$(cat "${seafile_ini}")
    if [[ ! -d ${seafile_data_dir} ]]; then
        echo "Your seafile server data directory \"${seafile_data_dir}\" is invalid or doesn't exits."
        echo "Please check it first, or create this directory yourself."
        echo ""
        exit 1;
    fi

    export SEAFILE_CONF_DIR=$seafile_data_dir
}

function ensure_server_not_running() {
    # test whether seafile server has been stopped.
    if pgrep seaf-server 2>/dev/null 1>&2 ; then
        echo
        echo "seafile server is still running !"
        echo "stop it using scripts before upgrade."
        echo
        exit 1
    elif pgrep -f "${manage_py} run_gunicorn" 2>/dev/null 1>&2 \
         || pgrep -f "seahub.wsgi:application" 2>/dev/null 1>&2; then
        echo
        echo "seahub server is still running !"
        echo "stop it before upgrade."
        echo
        exit 1
    elif pgrep -f "${manage_py} runfcgi" 2>/dev/null 1>&2 ; then
        echo
        echo "seahub server is still running !"
        echo "stop it before upgrade."
        echo
        exit 1
    fi
}

function migrate_avatars() {
    echo
    echo "migrating avatars ..."
    echo
    media_dir=${INSTALLPATH}/seahub/media
    orig_avatar_dir=${INSTALLPATH}/seahub/media/avatars
    dest_avatar_dir=${TOPDIR}/seahub-data/avatars

    # move "media/avatars" directory outside
    if [[ ! -d ${dest_avatar_dir} ]]; then
        mkdir -p "${TOPDIR}/seahub-data"
        mv "${orig_avatar_dir}" "${dest_avatar_dir}" 2>/dev/null 1>&2
        ln -s ../../../seahub-data/avatars "${media_dir}"

    elif [[ ! -L ${orig_avatar_dir} ]]; then
        mv "${orig_avatar_dir}"/* "${dest_avatar_dir}" 2>/dev/null 1>&2
        rm -rf "${orig_avatar_dir}"
        ln -s ../../../seahub-data/avatars "${media_dir}"
    fi
    echo "Done"
}

function update_database() {
    echo
    echo "Updating seafile/seahub database ..."
    echo

    db_update_helper=${UPGRADE_DIR}/db_update_helper.py
    if ! $PYTHON "${db_update_helper}" 5.1.0; then
        echo
        echo "Failed to upgrade your database"
        echo
        exit 1
    fi
    echo "Done"
}

function upgrade_seafile_server_latest_symlink() {
    # update the symlink seafile-server to the new server version
    if [[ -L "${seafile_server_symlink}" || ! -e "${seafile_server_symlink}" ]]; then
        echo
        printf "updating \033[33m${seafile_server_symlink}\033[m symbolic link to \033[33m${INSTALLPATH}\033[m ...\n\n"
        echo
        if ! rm -f "${seafile_server_symlink}"; then
            echo "Failed to remove ${seafile_server_symlink}"
            echo
            exit 1;
        fi

        if ! ln -s "$(basename ${INSTALLPATH})" "${seafile_server_symlink}"; then
            echo "Failed to update ${seafile_server_symlink} symbolic link."
            echo
            exit 1;
        fi
    fi
}

function make_media_custom_symlink() {
    media_symlink=${INSTALLPATH}/seahub/media/custom
    if [[ -L "${media_symlink}" ]]; then
        return

    elif [[ ! -e "${media_symlink}" ]]; then
        ln -s ../../../seahub-data/custom "${media_symlink}"
        return


    elif [[ -d "${media_symlink}" ]]; then
        cp -rf "${media_symlink}" "${seahub_data_dir}/"
        rm -rf "${media_symlink}"
        ln -s ../../../seahub-data/custom "${media_symlink}"
    fi

}

function move_old_customdir_outside() {
    # find the path of the latest seafile server folder
    if [[ -L ${seafile_server_symlink} ]]; then
        latest_server=$(readlink -f "${seafile_server_symlink}")
    else
        return
    fi

    old_customdir=${latest_server}/seahub/media/custom

    # old customdir is already a symlink, do nothing
    if [[ -L "${old_customdir}" ]]; then
        return
    fi

    # old customdir does not exist, do nothing
    if [[ ! -e "${old_customdir}" ]]; then
        return
    fi

    # media/custom exist and is not a symlink
    cp -rf "${old_customdir}" "${seahub_data_dir}/"
}

function regenerate_secret_key() {
    regenerate_secret_key_script=$UPGRADE_DIR/regenerate_secret_key.sh
    if ! $regenerate_secret_key_script ; then
        echo "Failed to regenerate the seahub secret key"
        exit 1
    fi
}

# copy ccnet.conf/seafile.conf etc. to conf/ dir, and make the original files read-only
function copy_confs_to_central_conf_dir() {
    local confs=(
        $default_ccnet_conf_dir/ccnet.conf
        $seafile_data_dir/seafile.conf
        $seahub_settings_py
    )
    for conffile in ${confs[*]}; do
        if grep -q "This file has been moved" $conffile; then
            continue
        fi
        cp $conffile $conffile.seafile-5.0.0-bak
        cp -av $conffile $default_conf_dir/
        cat >$conffile<<EOF
# This file has been moved to $default_conf_dir/$(basename $conffile) in seafile 5.0.0
EOF
        chmod a-w $conffile
    done
}

#################
# The main execution flow of the script
################

check_python_executable;
read_seafile_data_dir;
ensure_server_not_running;

update_database;
migrate_avatars;

move_old_customdir_outside;
make_media_custom_symlink;
upgrade_seafile_server_latest_symlink;

echo
echo "-----------------------------------------------------------------"
echo "Upgraded your seafile server successfully."
echo "-----------------------------------------------------------------"
echo
