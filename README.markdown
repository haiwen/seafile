Introduction
============

Seafile is a next-generation open source cloud storage system, with advanced support for file syncing, privacy protection and teamwork.

Collections of files are called libraries, and each library can be synced separately. A library can be encrypted with a user chosen password. This password is not stored on the server, so even the server admin can't view your file contents.

Seafile lets you create groups with file syncing, wiki, and discussion -- enabling easy collaboration around documents within a team. 

Feature Summary
===============

Seafile is a full-fledged cloud storage platform. It has the following features:

### Complete and advanced file syncing

1. Selective synchronization of file libraries. Each library can be synced separately.
2. Correct handling of file conflicts, based on history instead of timestamp.
3. Efficient bandwidth usage. Only transfer contents not in the server and transfer can be resumed.
4. Sync with two or more servers.
5. Sync with existing folders.
6. Sync a sub-folder.
7. Full version control with configurable revision number.


### Full team collaboration support

1. Groups with file syncing, wiki, discussion.
2. Online file editing and comments.
3. Sharing sub-folders to users/groups
4. Sharing single file between users
5. Sharing link.
6. Personal messages.

### Advanced privacy protection

1. Library encryption with a user chosen password.
2. Client side encryption.
3. Never sends the user's password to the server.

Internal
========

Seafile's version control model is based on Git, but it's simplified for automatic synchronization, and you don't need Git installed to run Seafile. 
Each Seafile library behaves like a Git repository. It has its own unique history, which consists of a list of commits. 
A commit points to the root of a file system snapshot. The snapshot consists of directories and files. 
Files are further divided into blocks for more efficient network transfer and storage usage.

Differences from Git:

1. Automatic synchronization.
2. Clients do not store file history, thus avoids the overhead of storing data twice. Git is not efficient for larger files (such as images).
3. Files are further divided into blocks for more efficient network transfer and storage usage.
4. File transfer can be paused and resumed.
5. Support for different storage backends on the server side.
6. Support for downloading from multiple block servers to accelerate file transfer.
7. More user-friendly file conflict handling (adds user's name as a suffix to conflicted file).
8. Graceful handling of files the user modifies while auto-sync is running. Git is not designed to work in these cases.

Build and Run
=============

See <https://github.com/haiwen/seafile/wiki>

Internationalization (I18n)
==========

See [po/i18n.markdown](https://github.com/haiwen/seafile/blob/master/po/i18n.markdown)

Change Logs
===========

See <https://seacloud.cc/group/3/wiki/home/>


Why Open Source
===============

Our primary goal is to build a first-class level production. Since we are only a small team, we think the goal can only be achieved by collaborating with the whole world.

Seafile is an open and extensible system. A library is a collection of files that could be synced. It can be presented to users as a Wiki, a set of notes, a gallery and so on. We have already write the Wiki module as an example. We need your contributions to make Seafile more versatile. Let's build an awesome system together!

Licence 
=======

Seafile and its desktop and mobile clients are published under GPLv3.

The Seafile server's web end, i.e. Seahub, is published under Apache License.

Contact
=======

Twitter: @seafile <https://twitter.com/seafile>

Google Group: <https://groups.google.com/forum/?fromgroups#!forum/seafile>

IRC: #seafile on freenode
