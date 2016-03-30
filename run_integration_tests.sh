#!/bin/bash
set -e
set -o pipefail
set -x

THISDIR="$(cd "$(dirname "$0")" && pwd)"
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y \
	build-essential \
	ccache \
	curl \
	flex \
	git \
	intltool \
	libarchive-dev \
	libcurl4-openssl-dev \
	libevent-dev \
	libfuse-dev \
	libjansson-dev \
	libmysqlclient-dev \
	libonig-dev \
	libpython-dev \
	libsqlite3-dev \
	libssl-dev \
	libssl1.0.0 \
	libtool \
	mysql-client \
	mysql-server \
	net-tools \
	openssl \
	python \
	python-pip \
	re2c \
	sqlite3 \
	uuid-dev \
	valac \
	wget \
&& true

/etc/init.d/mysql start
ccache -s
export PATH=/usr/lib/ccache:${PATH}

cd "$THISDIR"

./integration-tests/install-deps.sh

./integration-tests/run.py
