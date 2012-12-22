#!/bin/bash

echo ""

SCRIPT=$(readlink -f "$0")
INSTALLPATH=$(dirname "${SCRIPT}")
TOPDIR=$(dirname "${INSTALLPATH}")
default_ccnet_conf_dir=${TOPDIR}/ccnet
ccnet_pidfile=${INSTALLPATH}/runtime/ccnet.pid

export PATH=${INSTALLPATH}/seafile/bin:$PATH
export SEAFILE_LD_LIBRARY_PATH=${INSTALLPATH}/seafile/lib/:${INSTALLPATH}/seafile/lib64:${LD_LIBRARY_PATH}

script_name=$0
function usage () {
    echo "usage : "
    echo "$(basename ${script_name}) { start | stop | restart } "
    echo ""
}

# check args
if [[ $# != 1 || ( "$1" != "start" && "$1" != "stop" && "$1" != "restart" ) ]]; then
    usage;
    exit 1;
fi

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

function validate_alreay_running () {
    if pgrep -f "seafile-controller -c ${default_ccnet_conf_dir}" 2>/dev/null 1>&2; then
        echo "Seafile server already running."
        exit 1;
    fi
}

function start_seafile_server () {
    validate_alreay_running;
    validate_ccnet_conf_dir;
    read_seafile_data_dir;

    echo "Starting seafile server, please wait ..."

    seaf_controller="${INSTALLPATH}/seafile/bin/seafile-controller"
    httpserver="${INSTALLPATH}/seafile/bin/httpserver"

    bin_dir="${INSTALLPATH}/seafile/bin"

    LD_LIBRARY_PATH=$SEAFILE_LD_LIBRARY_PATH ${seaf_controller} -c "${default_ccnet_conf_dir}" -d "${seafile_data_dir}"

    sleep 10

    # check if seafile server started successfully
    if ! pgrep -f "seafile-controller -c ${default_ccnet_conf_dir}" 2>/dev/null 1>&2; then
        echo "Failed to start seafile server"
        exit 1;
    fi

    echo "Seafile server started"
    echo

    echo "Starting seafile httpserver, please wait ..."
    LD_LIBRARY_PATH=$SEAFILE_LD_LIBRARY_PATH ${httpserver} -c "${default_ccnet_conf_dir}" -d "${seafile_data_dir}"

    sleep 2
    # Check if httpserver started successfully
    if ! pgrep -f "httpserver -c ${default_ccnet_conf_dir}" 2>/dev/null 1>&2; then
        echo "Failed to start httpserver server"
        # Since we have seaf-server started, kill it on failure
        pkill -SIGTERM -f "seafile-controller -c ${default_ccnet_conf_dir}"
        exit 1;
    fi

    echo "Seafile httpserver started"
}

function stop_seafile_server () {
    if ! pgrep -f "seafile-controller -c ${default_ccnet_conf_dir}" 2>/dev/null 1>&2; then
        echo "seafile server not running yet"
        return 1;
    fi

    echo "Stopping seafile server ..."
    pkill -SIGTERM -f "seafile-controller -c ${default_ccnet_conf_dir}"
    pkill -f "httpserver -c ${default_ccnet_conf_dir}"
    return 0
}

function restart_seafile_server () {
    stop_seafile_server;
    sleep 2
    start_seafile_server;
}

manage_py=${INSTALLPATH}/seahub/manage.py
function check_seahub_running () {
    if pgrep -f "${manage_py} run_gunicorn" 2>/dev/null 1>&2; then
        echo "Seahub is running, please stop it before stop seafile."
        printf "You can stop it by \"\033[33m./seahub.sh stop\033[m\"\n\n"
        exit 1;
    fi
}

case $1 in
    "start" )
        start_seafile_server;
        ;;
    "stop" )
        check_seahub_running;
        stop_seafile_server;
        ;;
    "restart" )
        restart_seafile_server;
esac

echo "Done."
