Introduction
============

Seafile is a professional and reliable private cloud storage. Compared to other cloud storage system, Seafile puts more attention to privacy protection and teamwork.

Seafile managing files into libraries. Each library can be synced separately. A library can be encrypted with a user chosen password. This password is not stored in the server, so even the server admin can't view your file contents.

In Seafile, you can create groups with file syncing, wiki, discussion. It enables you to easily collaborate around documents within a team. 

Feature Summary
===============

Seafile is a full-fledged cloud storage platform. It has following features:

### Complete and Advanced File Syncing

1. Selective sync. Manage files into libraries. Each library can be synced separately.
2. Correctly handling file conflicts based on history instead of timestamp.
3. Efficient bandwidth usage. Only transfer contents not in the server and transfer can be resumed.
4. Sync with two or more servers.
5. Sync with existing folders.
6. Sync a sub-folder.
7. Full version control while the number of revisions is configurable.


### Full team collaboration support

1. Groups with file syncing, wiki, discussion.
2. Online file editing and comments.
3. Sharing sub-folders to users/groups
4. Sharing single file between users
5. Sharing link.
6. Personal Message.

### Advanced Privacy Protection

1. Library encryption with a user chosen password.
2. Client side encryption.
3. Can never send password to the server.

Internal
========

Seafile uses GIT's version control model, but simplified for automatic
synchronization, and doesn't depend on GIT.
Every library is like a GIT repository. It has
its own unique history, which consists of a list of commits.
A commit points to the root of a file system snapshot. The snapshot consists
of directories and files. Files are further divided into blocks
for more efficient network transfer and storage usage.

Differences to GIT:

1. Automatic syncing.
2. Clients do not store file history, thus avoids the overhead of storing data twice. GIT is not efficient for larger files (such as images).
3. Files are further divided into blocks for more efficient network transfer and storage usage.
4. File transfer can be resumed.
5. Support different storage backends on the server side.
6. Support downloading from multiple block servers for accelerating file transfer.
7. More user-friendly file conflicts handling (Add user's name as suffix to conflicted file).
8. Gracefully handles corner cases that user modifies files when auto-sync is running. GIT is not designed to work in these cases.

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
