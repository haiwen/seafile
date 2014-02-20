#!/bin/bash

SCRIPT=$(readlink -f "$0") # haiwen/seafile-server-1.3.0/upgrade/upgrade_xx_xx.sh
UPGRADE_DIR=$(dirname "$SCRIPT") # haiwen/seafile-server-1.3.0/upgrade/
INSTALLPATH=$(dirname "$UPGRADE_DIR") # haiwen/seafile-server-1.3.0/
TOPDIR=$(dirname "${INSTALLPATH}") # haiwen/

echo
echo "-------------------------------------------------------------"
echo "This script would do the minor upgrade for you."
echo "Press [ENTER] to contiune"
echo "-------------------------------------------------------------"
echo
read dummy

media_dir=${INSTALLPATH}/seahub/media
orig_avatar_dir=${INSTALLPATH}/seahub/media/avatars
dest_avatar_dir=${TOPDIR}/seahub-data/avatars
seafile_server_symlink=${TOPDIR}/seafile-server-latest
seahub_data_dir=${TOPDIR}/seahub-data

function migrate_avatars() {
    echo
    echo "------------------------------"
    echo "migrating avatars ..."
    echo
    # move "media/avatars" directory outside
    if [[ ! -d ${dest_avatar_dir} ]]; then
        echo
        echo "Error: avatars directory \"${dest_avatar_dir}\" does not exist" 2>&1
        echo
        exit 1

    elif [[ ! -L ${orig_avatar_dir}} ]]; then
        mv "${orig_avatar_dir}"/* "${dest_avatar_dir}" 2>/dev/null 1>&2
        rm -rf "${orig_avatar_dir}"
        ln -s ../../../seahub-data/avatars "${media_dir}"
    fi
    echo
    echo "DONE"
    echo "------------------------------"
    echo
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

function update_latest_symlink() {
    # update the symlink seafile-server to the new server version
    echo
    echo "updating seafile-server-latest symbolic link to ${INSTALLPATH} ..."
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
}

migrate_avatars;

move_old_customdir_outside;
make_media_custom_symlink;

update_latest_symlink;


echo "DONE"
echo "------------------------------"
echo
