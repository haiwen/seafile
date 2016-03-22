#!/bin/bash

### BEGIN INIT INFO
# Provides:          seahub
# Required-Start:    $local_fs $remote_fs $network
# Required-Stop:     $local_fs
# Default-Start:     1 2 3 4 5
# Default-Stop:
# Short-Description: Starts Seahub
# Description:       starts Seahub
### END INIT INFO

echo ""

SCRIPT=$(readlink -f "$0")
INSTALLPATH=$(dirname "${SCRIPT}")
TOPDIR=$(dirname "${INSTALLPATH}")
default_ccnet_conf_dir=${TOPDIR}/ccnet
central_config_dir=${TOPDIR}/conf

manage_py=${INSTALLPATH}/seahub/manage.py
gunicorn_conf=${INSTALLPATH}/runtime/seahub.conf
pidfile=${INSTALLPATH}/runtime/seahub.pid
errorlog=${INSTALLPATH}/runtime/error.log
accesslog=${INSTALLPATH}/runtime/access.log
gunicorn_exe=${INSTALLPATH}/seahub/thirdpart/gunicorn


script_name=$0
function usage () {
    echo "Usage: "
    echo
    echo "  $(basename ${script_name}) { start <port> | stop | restart <port> }"
    echo
    echo "To run seahub in fastcgi:"
    echo
    echo "  $(basename ${script_name}) { start-fastcgi <port> | stop | restart-fastcgi <port> }"
    echo
    echo "<port> is optional, and defaults to 8000"
    echo ""
}

# Check args
if [[ $1 != "start" && $1 != "stop" && $1 != "restart" \
    && $1 != "start-fastcgi" && $1 != "restart-fastcgi" && $1 != "clearsessions" ]]; then
    usage;
    exit 1;
fi

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

function validate_ccnet_conf_dir () {
    if [[ ! -d ${default_ccnet_conf_dir} ]]; then
        echo "Error: there is no ccnet config directory."
        echo "Have you run setup-seafile.sh before this?"
        echo ""
        exit -1;
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
}

function validate_seahub_running () {
    if pgrep -f "${manage_py}" 2>/dev/null 1>&2; then
        echo "Seahub is already running."
        exit 1;
    elif pgrep -f "seahub.wsgi:application" 2>/dev/null 1>&2; then
        echo "Seahub is already running."
        exit 1;
    fi
}

function validate_port () {
    if ! [[ ${port} =~ ^[1-9][0-9]{1,4}$ ]] ; then
        printf "\033[033m${port}\033[m is not a valid port number\n\n"
        usage;
        exit 1
    fi
}

if [[ ($1 == "start" || $1 == "restart" || $1 == "start-fastcgi" || $1 == "restart-fastcgi") \
    && ($# == 2 || $# == 1) ]]; then
    if [[ $# == 2 ]]; then
        port=$2
        validate_port
    else
        port=8000
    fi
elif [[ $1 == "stop" && $# == 1 ]]; then
    dummy=dummy
elif [[ $1 == "clearsessions" && $# == 1 ]]; then
    dummy=dummy
else
    usage;
    exit 1
fi

function warning_if_seafile_not_running () {
    if ! pgrep -f "seafile-controller -c ${default_ccnet_conf_dir}" 2>/dev/null 1>&2; then
        echo
        echo "Warning: seafile-controller not running. Have you run \"./seafile.sh start\" ?"
        echo
        exit 1
    fi
}

function prepare_seahub_log_dir() {
    logdir=${TOPDIR}/logs
    if ! [[ -d ${logsdir} ]]; then
        if ! mkdir -p "${logdir}"; then
            echo "ERROR: failed to create logs dir \"${logdir}\""
            exit 1
        fi
    fi
    export SEAHUB_LOG_DIR=${logdir}
}

function before_start() {
    prepare_env;
    warning_if_seafile_not_running;
    validate_seahub_running;
    prepare_seahub_log_dir;
}

function start_seahub () {
    before_start;
    echo "Starting seahub at port ${port} ..."
    check_init_admin;
    $PYTHON $gunicorn_exe seahub.wsgi:application -c "${gunicorn_conf}" -b "0.0.0.0:${port}" --preload

    # Ensure seahub is started successfully
    sleep 5
    if ! pgrep -f "seahub.wsgi:application" 2>/dev/null 1>&2; then
        printf "\033[33mError:Seahub failed to start.\033[m\n"
        echo "Please try to run \"./seahub.sh start\" again"
        exit 1;
    fi
    echo
    echo "Seahub is started"
    echo
}

function start_seahub_fastcgi () {
    before_start;

    # Returns 127.0.0.1 if SEAFILE_FASTCGI_HOST is unset or hasn't got any value,
    # otherwise returns value of SEAFILE_FASTCGI_HOST environment variable
    address=`(test -z "$SEAFILE_FASTCGI_HOST" && echo "127.0.0.1") || echo $SEAFILE_FASTCGI_HOST`

    echo "Starting seahub (fastcgi) at ${address}:${port} ..."
    check_init_admin;
    $PYTHON "${manage_py}" runfcgi host=$address port=$port pidfile=$pidfile \
        outlog=${accesslog} errlog=${errorlog}

    # Ensure seahub is started successfully
    sleep 5
    if ! pgrep -f "${manage_py}" 1>/dev/null; then
        printf "\033[33mError:Seahub failed to start.\033[m\n"
        exit 1;
    fi
    echo
    echo "Seahub is started"
    echo
}

function prepare_env() {
    check_python_executable;
    validate_ccnet_conf_dir;
    read_seafile_data_dir;

    if [[ -z "$LANG" ]]; then
        echo "LANG is not set in ENV, set to en_US.UTF-8"
        export LANG='en_US.UTF-8'
    fi
    if [[ -z "$LC_ALL" ]]; then
        echo "LC_ALL is not set in ENV, set to en_US.UTF-8"
        export LC_ALL='en_US.UTF-8'
    fi

    export CCNET_CONF_DIR=${default_ccnet_conf_dir}
    export SEAFILE_CONF_DIR=${seafile_data_dir}
    export SEAFILE_CENTRAL_CONF_DIR=${central_config_dir}
    export PYTHONPATH=${INSTALLPATH}/seafile/lib/python2.6/site-packages:${INSTALLPATH}/seafile/lib64/python2.6/site-packages:${INSTALLPATH}/seahub:${INSTALLPATH}/seahub/thirdpart:$PYTHONPATH
    export PYTHONPATH=${INSTALLPATH}/seafile/lib/python2.7/site-packages:${INSTALLPATH}/seafile/lib64/python2.7/site-packages:$PYTHONPATH

}

function clear_sessions () {
    prepare_env;

    echo "Start clear expired session records ..."
    $PYTHON "${manage_py}" clearsessions

    echo
    echo "Done"
    echo
}

function stop_seahub () {
    if [[ -f ${pidfile} ]]; then
        pid=$(cat "${pidfile}")
        echo "Stopping seahub ..."
        kill ${pid}
        rm -f ${pidfile}
        return 0
    else
        echo "Seahub is not running"
    fi
}

function check_init_admin() {
    check_init_admin_script=${INSTALLPATH}/check_init_admin.py
    if ! $PYTHON $check_init_admin_script; then
        exit 1
    fi
}

case $1 in
    "start" )
        start_seahub;
        ;;
    "start-fastcgi" )
        start_seahub_fastcgi;
        ;;
    "stop" )
        stop_seahub;
        ;;
    "restart" )
        stop_seahub
        sleep 2
        start_seahub
        ;;
    "restart-fastcgi" )
        stop_seahub
        sleep 2
        start_seahub_fastcgi
        ;;
    "clearsessions" )
        clear_sessions
        ;;
esac

echo "Done."
echo ""
