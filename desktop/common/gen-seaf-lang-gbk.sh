#!/bin/bash

# Edit the utf8 version of seaf-lang.h, and use this script to convert it to
# gbk when done.

SCRIPT=$(readlink -f "$0")
CURDIR=$(dirname "${SCRIPT}")
SRC=${CURDIR}/seaf-lang.h
DEST=${CURDIR}/seaf-lang-gbk.h

iconv -t GBK -f UTF-8 "${SRC}" > "${DEST}"