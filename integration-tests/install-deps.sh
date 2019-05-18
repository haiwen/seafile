#!/bin/bash

set -e -x

sudo apt update
sudo apt install -y  autoconf automake libtool libevent-dev libcurl4-openssl-dev \
     libgtk2.0-dev uuid-dev intltool libsqlite3-dev valac libjansson-dev cmake libssl-dev

git clone --depth=1 --branch="master" git://github.com/haiwen/libsearpc.git deps/libsearpc

pushd deps/libsearpc
./autogen.sh && ./configure --disable-fuse --disable-server --enable-client
make -j8 && sudo make install
popd
