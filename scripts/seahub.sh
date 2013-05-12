#!/bin/bash

# seafile combined init job

### BEGIN INIT INFO
# Provides:          seafilehub
# Required-Start:    $local_fs $remote_fs $network seafile
# Required-Stop:     $local_fs
# Default-Start:     1 2 3 4 5
# Default-Stop:
# Short-Description: Starts Seafile
# Description: seafile file syncronization service
### END INIT INFO


# To use this, simply link this file to /etc/init.d/seafile
#   i.e "ln -s /var/www/seafile/seafile.sh /etc/init.d/seafile
# And then insert it into the init.d configuration
#   for Ubuntu/Debian, "update-rc.d seafile defaults"
#
# The program will run as the user owning this script. For Ubuntu/Debian
#   it is advisable to have the directory owned by "www-data"


echo ""

SCRIPT=$(readlink -f "$0")
INSTALLPATH=$(dirname "${SCRIPT}")
TOPDIR=$(dirname "${INSTALLPATH}")
default_ccnet_conf_dir=${TOPDIR}/ccnet
runas=$(stat -c %U ${0//.\//})

manage_py=${INSTALLPATH}/seahub/manage.py
gunicorn_conf=${INSTALLPATH}/runtime/seahub.conf
pidfile=${INSTALLPATH}/runtime/seahub.pid
errorlog=${INSTALLPATH}/runtime/error.log
accesslog=${INSTALLPATH}/runtime/access.log


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
    && $1 != "start-fastcgi" && $1 != "restart-fastcgi" ]]; then
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

function validate_seaf_server_running () {
    if ! pgrep -f "seafile-controller -c ${default_ccnet_conf_dir}" 2>/dev/null 1>&2; then
        echo "seafile server process is not running, please start it by:"
        echo ""
        echo "          ./seafile.sh start"
        echo ""
        exit 1;
    fi
}

function validate_seahub_running () {
    if pgrep -f "${manage_py}" 2>/dev/null 1>&2; then
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
else
    usage;
    exit 1
fi

function before_start() {
    check_python_executable;
    validate_ccnet_conf_dir;
    read_seafile_data_dir;

    validate_seaf_server_running;
    validate_seahub_running;

    export CCNET_CONF_DIR=${default_ccnet_conf_dir}
    export SEAFILE_CONF_DIR=${seafile_data_dir}
    export PYTHONPATH=${INSTALLPATH}/seafile/lib/python2.6/site-packages:${INSTALLPATH}/seafile/lib64/python2.6/site-packages:${INSTALLPATH}/seahub/thirdpart:$PYTHONPATH
    export PYTHONPATH=${INSTALLPATH}/seafile/lib/python2.7/site-packages:${INSTALLPATH}/seafile/lib64/python2.7/site-packages:$PYTHONPATH
}

function start_seahub () {
    before_start;
    echo "Starting seahub http server at port ${port} ..."
    sudo -u ${runas} -E \
	PYTHONPATH=${PYTHONPATH} \
        $PYTHON "${manage_py}" run_gunicorn -c "${gunicorn_conf}" -b "0.0.0.0:${port}"

    # Ensure seahub is started successfully
    sleep 5
    if ! pgrep -f "${manage_py}" 2>/dev/null 1>&2; then
        printf "\033[33mError:Seahub failed to start.\033[m\n"
        echo "Please try to run \"./seafile.sh start\" again"
        exit 1;
    fi
}

function start_seahub_fastcgi () {
    before_start;
    echo "Starting seahub http server (fastcgi) at port ${port} ..."
    sudo -u ${runas} \
	PYTHONPATH=${PYTHONPATH} \
        $PYTHON "${manage_py}" runfcgi host=127.0.0.1 port=$port pidfile=$pidfile \
            outlog=${accesslog} errlog=${errorlog}

    # Ensure seahub is started successfully
    sleep 5
    if ! pgrep -f "${manage_py}" 1>/dev/null; then
        printf "\033[33mError:Seahub failed to start.\033[m\n"
        exit 1;
    fi
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

cmd=$1
if [[ "$0" =~ fastcgi ]]; then
    [ "${1}" == "start" ] && cmd="start-fastgci"
    [ "${1}" == "restart" ] && cmd="restart-fastcgi"
fi

case ${cmd} in
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
esac

echo "Done."
echo ""
