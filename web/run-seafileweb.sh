#!/bin/bash

SEAFILE_DIR=`pwd`/..

export PYTHONPATH=/opt/lib/python2.7/site-packages

export CCNET_CONF_DIR=$SEAFILE_DIR/tests/basic/conf1
python main.py 8081 &

export CCNET_CONF_DIR=$SEAFILE_DIR/tests/basic/conf3
python main.py 8083 &
