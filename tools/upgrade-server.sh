#!/bin/bash

SCRIPT=$(readlink -f "$0")
INSTALLPATH=$(dirname "${SCRIPT}")
TOPDIR=$(dirname "${INSTALLPATH}")
default_seahub_db=${TOPDIR}/seahub.db

prev_version=0.9.3
current_version=0.9.4

echo
echo "-------------------------------------------------------------"
echo "This script would upgrade your seafile server from ${prev_version} to ${current_version}"
echo "Press [ENTER] to contiune"
echo "-------------------------------------------------------------"
echo

read dummy

# check for python-imaging and python-simplejson

if ! python -c "import simplejson" 2>/dev/null 1>&2; then
    echo "python-simplejson needs to be installed."
    echo "On Debian/Ubntu: apt-get install python-simplejson"
    echo "On CentOS/RHEL: yum install python-simplejson"
    echo
    exit 1
fi

if ! python -c "import PIL" 2>/dev/null 1>&2; then
    echo "python-imaging needs to be installed."
    echo "On Debian/Ubntu: apt-get install python-imaging"
    echo "On CentOS/RHEL: yum install python-imaging"
    echo
    exit 1
fi

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
python manage.py syncdb 2>/dev/null 1>&2 && echo "Done." || echo "Failed."
popd 2>/dev/null 1>&2
echo "------------------------------"

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

seahub_settings=${TOPDIR}/seahub_settings.py

function gen_seahub_secret_key () {
    seahub_secret_keygen=${INSTALLPATH}/seahub/tools/secret_key_generator.py
    echo -n -e "\nSECRET_KEY = " >> "${seahub_settings}"
    key=$(python "${seahub_secret_keygen}")
    echo "\"${key}\"" >> "${seahub_settings}"
}

if ! grep SECRET_KEY "${seahub_settings}" 2>/dev/null 1>&2 ; then
    gen_seahub_secret_key;
fi
    
