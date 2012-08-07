#!/bin/bash

SCRIPT=$(readlink -f "$0")
SCRIPT_PATH=$(dirname "${SCRIPT}")
scriptname=$0

function usage () {
    printf "\nUsage: ${scriptname} <server-pkg-dir>\n\n"
}

if [[ $# != 1 ]]; then
    usage
    exit 1
fi

destdir=$1

if [[ ! -d ${destdir} ]] ; then
    printf "\n\"${destdir}\" is not a valid directory\n\n"
    exit 1
fi

if [[ ! -d ${destdir}/seafile || ! -d ${destdir}/seahub ]]; then
    echo "You should have seafile and seahub dir under ${destdir}"
    exit 1
fi


scripts="setup-seafile.sh seafile.sh seahub.sh"

for file in ${scripts} ; do
    cp -f "${SCRIPT_PATH}/${file}" "${destdir}"
done

runtime_dir=${destdir}/runtime
if [[ ! -d "${runtime_dir}" ]]; then
    mkdir -p "${runtime_dir}"
fi

cp -f "${SCRIPT_PATH}/seahub.conf" "${runtime_dir}"
# copy html files used by seaf-httpserver
cp -f -a "${SCRIPT_PATH}/../server/httpserver/htmls" "${runtime_dir}"

printf "Done.\n\n"
