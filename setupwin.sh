#! /bin/bash

set -e

TARGET_DIR=/c/pack
if [[ $# != 1 ]] ; then
    echo
    echo "Usage: ./setupwin.sh <target_dir>"
    exit 1;
else
    TARGET_DIR=$1
fi

if [[ ! -d ${TARGET_DIR} ]]; then
    echo 
    echo "${TARGET_DIR} is not a valid directory"
    exit 1;
fi

echo "target directory is" ${TARGET_DIR}

BIN_DIR=${TARGET_DIR}/bin

mkdir -p "${BIN_DIR}"

cp -f `which libsearpc-1.dll` "${BIN_DIR}"
cp -f `which libsearpc-json-glib-0.dll` "${BIN_DIR}"

cp daemon/.libs/seaf-daemon.exe "${BIN_DIR}"

cp lib/.libs/libseafile-0.dll "${BIN_DIR}"

cp -f gui/win/seafile-applet.exe "${BIN_DIR}"

# python related files. This will copy all dlls that it depends on
# (libevent, libssl, libsqlite3)... as well
pushd web
python websetup.py py2exe
cp -rf dist/* "${BIN_DIR}/"
rm -rf dist
rm -rf build
popd

# copy Wix source files and Makefile
cp -rf msi/* "${TARGET_DIR}"

