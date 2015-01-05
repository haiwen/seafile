#!/bin/bash

# This is a wrapper shell script for the real seaf-cli command.
# It prepares necessary environment variables and exec the real script.

# seafile cli client requires python 2.6 or 2.7
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
        echo "Install python 2.6+ before continue."
        echo "Or if you installed it in a non-standard PATH, set the PYTHON enviroment varirable to it"
        echo 
        exit 1
    fi
}

check_python_executable

# seafile cli client requires the argparse module
if ! $PYTHON -c 'import argparse' 2>/dev/null 1>&2; then
    echo
    echo "Python argparse module is required"
    echo "see [https://pypi.python.org/pypi/argparse]"
    echo
    exit 1
fi

SCRIPT=$(readlink -f "$0")
INSTALLPATH=$(dirname "${SCRIPT}")

SEAFILE_BIN_DIR=${INSTALLPATH}/bin
SEAFILE_LIB_DIR=${INSTALLPATH}/lib:${INSTALLPATH}/lib64
SEAFILE_PYTHON_PATH=${INSTALLPATH}/lib/python2.6/site-packages:${INSTALLPATH}/lib64/python2.6/site-packages:${INSTALLPATH}/lib/python2.7/site-packages:${INSTALLPATH}/lib64/python2.7/site-packages

SEAF_CLI=${SEAFILE_BIN_DIR}/seaf-cli.py

PATH=${SEAFILE_BIN_DIR}:${PATH} \
PYTHONPATH=${SEAFILE_PYTHON_PATH}:${PYTHONPATH} \
SEAFILE_LD_LIBRARY_PATH=${SEAFILE_LIB_DIR}:${LD_LIBRARY_PATH} \
exec $PYTHON ${SEAF_CLI} "$@"
