Introduction [![Build Status](https://secure.travis-ci.org/haiwen/seafile.svg?branch=master)](http://travis-ci.org/haiwen/seafile)
============

Seafile is an open source cloud storage system with features on privacy protection and teamwork. Collections of files are called libraries, and each library can be synced separately. A library can also be encrypted with a user chosen password. Seafile also allows users to create groups and easily sharing files into groups.

Feature Summary
===============

Seafile has the following features:

### File syncing

1. Selective synchronization of file libraries. Each library can be synced separately.
2. Correct handling of file conflicts based on history instead of timestamp.
3. Only transfering contents not in the server, and incomplete transfers can be resumed.
4. Sync with two or more servers.
5. Sync with existing folders.
6. Sync a sub-folder.

### File sharing and collaboration

1. Sharing libraries between users or into groups.
2. Sharing sub-folders between users or into groups.
3. Download links with password protection
4. Upload links
5. Version control with configurable revision number.
6. Restoring deleted files from trash, history or snapshots.

### Privacy protection

1. Library encryption with a user chosen password.
2. Client side encryption when using the desktop syncing.

Internal
========

Seafile's version control model is based on Git, but it is simplified for automatic synchronization does not need Git installed to run Seafile.
Each Seafile library behaves like a Git repository. It has its own unique history, which consists of a list of commits.
A commit points to the root of a file system snapshot. The snapshot consists of directories and files.
Files are further divided into blocks for more efficient network transfer and storage usage.

Differences from Git:

1. Automatic synchronization.
2. Clients do not store file history, thus they avoid the overhead of storing data twice. Git is not efficient for larger files such as images.
3. Files are further divided into blocks for more efficient network transfer and storage usage.
4. File transfer can be paused and resumed.
5. Support for different storage backends on the server side.
6. Support for downloading from multiple block servers to accelerate file transfer.
7. More user-friendly file conflict handling. (Seafile adds the user's name as a suffix to conflicting files.)
8. Graceful handling of files the user modifies while auto-sync is running. Git is not designed to work in these cases.

Build and Run
=============

See <http://manual.seafile.com/develop/README.html>

Internationalization (I18n)
==========

* [Translate seafile web ui](https://github.com/haiwen/seafile/wiki/Seahub-Translation)
* [Translate seafile desktop client](https://github.com/haiwen/seafile-client/#internationalization)

Change Logs
===========

See <https://seacloud.cc/group/3/wiki/home/>


Why Open Source
===============

Our primary goal is to build a first-class product. We think this goal can only be achieved by collaborating with the whole world.


License
=======

Seafile and its desktop and mobile clients are published under the GPLv3.

The Seafile server's web end, i.e. Seahub, is published under the Apache License.

Contact
=======

Twitter: @seafile <https://twitter.com/seafile>

Forum: <https://forum.seafile-server.org>
