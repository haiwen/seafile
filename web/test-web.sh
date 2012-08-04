#!/bin/bash

export PYTHONPATH=/opt/lib/python2.6/site-packages

CCNET_DIR=`pwd`/..


while [ $# -ge 1 ]; do
  if [ $1 -ge "1" ]  && [ $1 -le "4" ]; then
      export CCNET_CONF_DIR=$CCNET_DIR/seamsg/tests/basic/conf"$1"
      echo "CCNET_CONF_DIR set to $CCNET_CONF_DIR"
      pushd $CCNET_DIR/seamsg/tests/basic
      ./seamsg.sh $1
      sleep 3
      popd
      python main.py 127.0.0.1:808"$1" &
      sleep 3
      
  fi
  shift
done

