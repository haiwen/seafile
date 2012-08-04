#!/bin/bash
CCNET_DIR=`pwd`/..

pushd $CCNET_DIR/seamsg/tests/basic
./setup.sh $@
popd
