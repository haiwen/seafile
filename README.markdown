Introduction
============

Seafile is a distributed file synchronization client/server. A user
first creates a synchronized folder on a server, then sync it with any
local folder. It is distributed in the sense that a client can sync
with any server, public key authentication is used, no login from
client is required.

Feature Summary
================

Seafile can be used to build a full-fledged cloud storage platform. It
has following features:

1. Full web operations like create folders, upload files, move files.
2. Synchronizing on demand (every client can choose what to sync)
3. Sync with existing folders
4. Sharing groups, users can create and join groups. 
5. Full version operation like SyncFolder history, single file history, 
   file restore.
6. Organizations, users can create and join organizations like github.

Seafile uses GIT's version control model, but simplified for automatic
file synchronization. Every synchronized folder is like a
GIT repository. It has its own unique history, which consists of a
list of commits. File history, commit diff, etc., are all supported.

Multiple storage backends can be used to store metadatas and files.

Dependency
==========

The following packages are required to build seafile:

    json-glib >= 0.10.2
    valac >= 0.8
    libsearpc >= 1.0
    libccnet >= 0.9.3
    libmysqlclient-dev
    libzdb >= 2.10.2
    libevhtp >= 0.3.0
    libevent-dev
    uuid-dev
    libsqlite-dev
    libssl-dev

libsearpc tarball can be downloaded from this link:
 https://github.com/downloads/haiwen/libsearpc/libsearpc-1.0.1.tar.gz

libccnet tarball can be downloaded from this link:
 https://github.com/downloads/haiwen/ccnet/ccnet-1.0.0.tar.gz

libzdb tarball can be downloaded from this link:
 http://www.tildeslash.com/libzdb/dist/libzdb-2.10.5.tar.gz

libevhtp tarball can be downloaded from this link:
 https://github.com/downloads/ellzey/libevhtp/libevhtp-0.3.0.tar.gz

Other programs can be installed from apt-get or yum tools in linux.

Compile
=======

To compile the daemon components, just

    ./configure; make; make install

To also compile the server components, use

    ./configure --enable-server

Run
===

Run Client:

Using following command to run seafile client:
$ seafile-applet

If you get following error, please use 'sudo ldconfig -v' to update linker runtime:
'seafile-applet: error while loading shared libraries: libseafile.so.0: cannot open shared object file: No such file or directory'

$ sudo ldconfig -v # update linker rumtime

Run Server:

Please view this page to understand how to configure and run seafile server:
 https://github.com/haiwen/seafile/wiki/Deploy-seafile-server-on-linux
