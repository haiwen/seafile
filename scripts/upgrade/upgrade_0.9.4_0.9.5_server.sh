#!/bin/bash

SCRIPT=$(readlink -f "$0")
INSTALLPATH=$(dirname "${SCRIPT}")
TOPDIR=$(dirname "${INSTALLPATH}")
default_seahub_db=${TOPDIR}/seahub.db

prev_version=0.9.4
current_version=0.9.5

echo
echo "-------------------------------------------------------------"
echo "This script would upgrade your seafile server from ${prev_version} to ${current_version}"
echo "Press [ENTER] to contiune"
echo "-------------------------------------------------------------"
echo

read dummy

# test whether seafile server has been stopped.
if pgrep seaf-server 2>/dev/null 1>&2 ; then
    echo 
    echo "seafile server is still running !"
    echo "stop it using scripts before upgrade."
    echo
    exit 1
elif pgrep -f "manage.py run_gunicorn" 2>/dev/null 1>&2 ; then
    echo 
    echo "seahub server is still running !"
    echo "stop it before upgrade."
    echo
    exit 1
fi

# run django syncdb command
echo "------------------------------"
echo "updating seahub database ... "
export PYTHONPATH=${INSTALLPATH}/seafile/lib/python2.7/site-packages:${INSTALLPATH}/seahub/thirdpart:${PYTHONPATH}
manage_py=${INSTALLPATH}/seahub/manage.py
pushd "${INSTALLPATH}/seahub" 2>/dev/null 1>&2
if ! python manage.py syncdb 2>/dev/null 1>&2; then
    echo "failed"
    exit -1
fi
popd 2>/dev/null 1>&2

update_db_py=${INSTALLPATH}/seahub/tools/update-seahub-db_0.9.4_to_0.9.5.py
if ! python "${update_db_py}" "${default_seahub_db}" ; then
    echo "failed"
    exit -1
fi

media_dir=${INSTALLPATH}/seahub/media
orig_avatar_dir=${INSTALLPATH}/seahub/media/avatars
dest_avatar_dir=${TOPDIR}/seahub-data/avatars

# move "media/avatars" directory outside 
if [[ ! -d ${dest_avatar_dir} ]]; then
    mkdir -p "${TOPDIR}/seahub-data"
    mv "${orig_avatar_dir}" "${dest_avatar_dir}" 2>/dev/null 1>&2
    ln -s ../../../seahub-data/avatars ${media_dir}

elif [[ ! -L ${orig_avatar_dir}} ]]; then
    mv ${orig_avatar_dir}/* "${dest_avatar_dir}" 2>/dev/null 1>&2
    rm -rf "${orig_avatar_dir}"
    ln -s ../../../seahub-data/avatars ${media_dir}
fi

rm -rf "${TOPDIR}/ccnet/OrgMgr"

echo "Done"
echo "------------------------------"
echo
