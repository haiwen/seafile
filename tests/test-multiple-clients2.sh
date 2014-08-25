#!/bin/bash
SCRIPT=$(readlink -f "$0")
INSTALLPATH=$(dirname "${SCRIPT}")
TOPDIR=$(dirname "${INSTALLPATH}")
export PYTHONPATH=${INSTALLPATH}/seafile/lib/python2.7/site-packages:${INSTALLPATH}/seafile/lib64/python2.7/site-packages:$PYTHONPATH

set -e

#customize it if you wish to
: ${MAX=100}
BASE_DIR=/tmp
BASE_CCNET_CONF_DIR=ccnet
BASE_SEAFILE_CONF_DIR=seafile-data
BASE_LIBRARY_DIR=library
SEAHUB_URL="http://127.0.0.1:8000"
LIBRARY_NAME="testLIB"
USER="test@test.com"
PASS="testtest"
LIBRARY_ID=""

function start_tests() {
pushd $BASE_DIR

# start daemon 0 and create library
if test "$LIBRARY_ID" == "" ; then
  printf "creating library..."
  CCNET_CONF_DIR="${BASE_CCNET_CONF_DIR}_0"
  SEAFILE_CONF_DIR="${BASE_SEAFILE_CONF_DIR}_0"
  mkdir $SEAFILE_CONF_DIR &>/dev/null
  seaf-cli init -c ${CCNET_CONF_DIR} -d ${SEAFILE_CONF_DIR} &>/dev/null
  seaf-cli start -c ${CCNET_CONF_DIR} &>/dev/null
  LIBRARY_ID=$(seaf-cli create -c ${CCNET_CONF_DIR} -s ${SEAHUB_URL} -n ${LIBRARY_NAME} -t "test purpose" -u ${USER} -p ${PASS})
  seaf-cli stop -c ${CCNET_CONF_DIR} &>/dev/null
  echo "done"
fi

# start daemons
echo "clone is quite slow currently, please be patient"
rm -f *.stamp &>/dev/null
for i in $(seq 1 $MAX) ; do
  if [ -f failed ] ; then
    echo "detected last failure, sleep 30 secs to continue"
    sync
    sleep 30
    rm -f failed
  fi
  CCNET_CONF_DIR="${BASE_CCNET_CONF_DIR}_${i}"
  SEAFILE_CONF_DIR="${BASE_SEAFILE_CONF_DIR}_${i}"
  LIBRARY_DIR="${BASE_LIBRARY_DIR}_${i}"
  mkdir $SEAFILE_CONF_DIR $LIBRARY_DIR &>/dev/null
  printf "starting ${i} of ${MAX}... "
  seaf-cli init -c ${CCNET_CONF_DIR} -d ${SEAFILE_CONF_DIR} &>/dev/null && \
    seaf-cli start -c ${CCNET_CONF_DIR} &>/dev/null && \
    seaf-cli sync -c ${CCNET_CONF_DIR} -l "${LIBRARY_ID}" -s ${SEAHUB_URL} \
    -d "${LIBRARY_DIR}" -u ${USER} -p ${PASS}  &>/dev/null && \
    touch "test_${i}.stamp" && echo "done"
  if [ ! -f "test_${i}.stamp" ] ; then
    touch failed
    echo "failed"
  fi
done

read -p "Press Enter to copy test data"

echo "round 1"
# copy files
for i in $(seq 1 $MAX) ; do
  if [ -f "test_${i}.stamp" ] ; then
    echo "copying ${i} of ${MAX} ..."
    dd if=/dev/urandom "of=${BASE_LIBRARY_DIR}_${i}/test_${i}" bs=128k count=1 &>/dev/null &
  fi
done
printf "waiting to sync..."
sleep 10
echo "done"

echo "round 2"
# copy files
for i in $(seq 1 $MAX) ; do
  if [ -f "test_${i}.stamp" ] ; then
    echo "copying ${i} of ${MAX} ..."
    dd if=/dev/urandom "of=${BASE_LIBRARY_DIR}_${i}/test_${i}" bs=128k count=1 &>/dev/null &
  fi
done
sleep 30

# watch status daemons
read -p "Press Enter to stop all daemons"

#stop daemons
for i in $(seq 1 $MAX) ; do
  if [ -f "test_${i}.stamp" ] ; then
    CCNET_CONF_DIR="${BASE_CCNET_CONF_DIR}_${i}"
    LIBRARY_DIR="${BASE_LIBRARY_DIR}_${i}"
    seaf-cli status -c ${CCNET_CONF_DIR} | awk 'FNR == 2 {print "REPO\t'${i}'\tSTATUS\t"$2}' && \
      seaf-cli desync -c ${CCNET_CONF_DIR} -d "${LIBRARY_DIR}" &>/dev/null && \
      seaf-cli stop -c ${CCNET_CONF_DIR} &>/dev/null &
  fi
done

rm -f *.stamp &>/dev/null

FAIL=0
for job in `jobs -p`
do
  wait $job || let "FAIL+=1"
done

printf "\n"
echo "failed to stop: ${FAIL}"
printf "\n"

popd
}

function start_clean() {
pushd $BASE_DIR
rm -rf ccnet_* seafile-data_* library_*
popd
}


case "$1" in
  "clean" )
    start_clean
    ;;
  "test" )
    start_clean
    start_tests
    ;;
  * )
    start_clean
    start_tests
    ;;
esac
