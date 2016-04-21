#!/bin/bash

########
### This script is a wrapper for setup-seafile-mysql.py
########

set -e

SCRIPT=$(readlink -f "$0")
INSTALLPATH=$(dirname "${SCRIPT}")

cd "$INSTALLPATH"

python_script=setup-seafile-mysql.py

function err_and_quit () {
    printf "\n\n\033[33mError occured during setup. \nPlease fix possible problems and run the script again.\033[m\n\n"
    exit 1;
}

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
            echo "Python 3.x is not supported. Please use python 2.x. Now quit."
            err_and_quit;
        fi

        if [[ $PYTHON == "python2.6" ]]; then
            py26="2.6"
        fi
        hint="\nOn Debian/Ubntu: apt-get install python-setuptools\nOn CentOS/RHEL: yum install python${py26}-distribute"
        check_python_module pkg_resources setuptools "${hint}"

        hint="\nOn Debian/Ubntu: apt-get install python-imaging\nOn CentOS/RHEL: yum install python${py26}-imaging"
        check_python_module PIL python-imaging "${hint}"

        hint='\nOn Debian/Ubuntu:\n\nsudo apt-get install python-mysqldb\n\nOn CentOS/RHEL:\n\nsudo yum install MySQL-python'
        check_python_module MySQLdb python-mysqldb "${hint}"
    fi
    echo
}

check_python;

export PYTHON=$PYTHON

exec $PYTHON "$python_script" "$@"
