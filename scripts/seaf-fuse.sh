#!/bin/bash

echo ""

SCRIPT=$(readlink -f "$0")
INSTALLPATH=$(dirname "${SCRIPT}")
TOPDIR=$(dirname "${INSTALLPATH}")
default_ccnet_conf_dir=${TOPDIR}/ccnet
default_conf_dir=${TOPDIR}/conf
seaf_fuse=${INSTALLPATH}/seafile/bin/seaf-fuse

export PATH=${INSTALLPATH}/seafile/bin:$PATH
export SEAFILE_LD_LIBRARY_PATH=${INSTALLPATH}/seafile/lib/:${INSTALLPATH}/seafile/lib64:${LD_LIBRARY_PATH}

script_name=$0
function usage () {
    echo "usage : "
    echo "$(basename ${script_name}) { start <mount-point> | stop | restart <mount-point> } "
    echo ""
}

# check args
if [[ "$1" != "start" && "$1" != "stop" && "$1" != "restart" ]]; then
    usage;
    exit 1;
fi

if [[ ($1 == "start" || $1 == "restart" ) && $# -lt 2 ]]; then
    usage;
    exit 1
fi

if [[ $1 == "stop" && $# != 1 ]]; then
    usage;
    exit 1
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

function validate_already_running () {
    if pid=$(pgrep -f "seaf-fuse -c ${default_ccnet_conf_dir}" 2>/dev/null); then
        echo "seaf-fuse is already running, pid $pid"
        echo
        exit 1;
    fi
}

function warning_if_seafile_not_running () {
    if ! pgrep -f "seafile-controller -c ${default_ccnet_conf_dir}" 2>/dev/null 1>&2; then
        echo
        echo "Warning: seafile-controller not running. Have you run \"./seafile.sh start\" ?"
        echo
    fi
}

function start_seaf_fuse () {
    validate_already_running;
    warning_if_seafile_not_running;
    validate_ccnet_conf_dir;
    read_seafile_data_dir;

    echo "Starting seaf-fuse, please wait ..."

    logfile=${TOPDIR}/logs/seaf-fuse.log

    LD_LIBRARY_PATH=$SEAFILE_LD_LIBRARY_PATH ${seaf_fuse} \
        -c "${default_ccnet_conf_dir}" \
        -d "${seafile_data_dir}" \
        -F "${default_conf_dir}" \
        -l "${logfile}" \
        "$@"

    sleep 2

    # check if seaf-fuse started successfully
    if ! pgrep -f "seaf-fuse -c ${default_ccnet_conf_dir}" 2>/dev/null 1>&2; then
        echo "Failed to start seaf-fuse"
        exit 1;
    fi

    echo "seaf-fuse started"
    echo
}

function stop_seaf_fuse() {
    if ! pgrep -f "seaf-fuse -c ${default_ccnet_conf_dir}" 2>/dev/null 1>&2; then
        echo "seaf-fuse not running yet"
        return 1;
    fi

    echo "Stopping seaf-fuse ..."
    pkill -SIGTERM -f "seaf-fuse -c ${default_ccnet_conf_dir}"
    return 0
}

function restart_seaf_fuse () {
    stop_seaf_fuse
    sleep 2
    start_seaf_fuse $@
}

case $1 in
    "start" )
	shift
        start_seaf_fuse $@;
        ;;
    "stop" )
        stop_seaf_fuse;
        ;;
    "restart" )
	shift
        restart_seaf_fuse $@;
esac

echo "Done."
