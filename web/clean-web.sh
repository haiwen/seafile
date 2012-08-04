#!/bin/bash
CCNET_DIR=`pwd`/..

pushd $CCNET_DIR/seamsg/tests/basic
./clean.sh
git checkout .
popd

