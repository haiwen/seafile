Introduction
============

Dropbox is good for file syncing and sharing, but is not an ideal place for collaboration. So we build Seafile, a better place for managing documents together. 

In Seafile, you can create groups with file syncing, wiki, discussion and tasks. It enables you to easily collaborate around documents within a team. In addition, it is open source. So you can build a private cloud freely for your organization.

Feature Summary
===============

Seafile is a full-fledged document collaboration platform. It has following features:

1. Groups with file syncing, wiki, discussion and tasks.
2. Managing files into libraries. Each library can be synced separately.
3. Sync with existing folders.
4. File revisions.
5. Library encryption with a user chosen password.

Compared to other open-source Dropbox-like projects, such as
<https://github.com/hbons/SparkleShare>, Seafile has several advantages:

1. Mature, reliable, production-ready file syncing algorithm.
2. Doesn't depend on Git.
3. Not a Dropbox-clone, but a newly designed product for teamwork. 

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
7. More user-friendly file conflicts handling similar to Dropbox (Add user's name as suffix to conflicted file).
8. Gracefully handles corner cases that user modifies files when auto-sync is running. GIT is not designed to work in these cases.

Build and Run
=============

See <https://github.com/haiwen/seafile/wiki>

Change Logs
===========

See <https://seacloud.cc/group/3/wiki/home/>


Why Open Source
===============

Our primary goal is to build a first-class level production. Since we are only a small team, we think the goal can only be achieved by collaborating with the whole world.

Seafile is an open and extensible system. A library is a collection of files that could be synced. It can be presented to users as a Wiki, a set of notes, a gallery and so on. We have already write the Wiki module as an example. We need your contributions to make Seafile more versatile. Let's build an awesome system together!

Licence 
=======

Seafile and its desktop and mobile clients are published under GPLv3 with one exception -- the seafile's logo of desktop and mobile clients must be kept when redistribution.

The Seafile server's web end, i.e. Seahub, is published under Apache License. The seafile logo in Seahub can be changed.

Contact
=======

Twitter: @seafile <https://twitter.com/seafile>

Google Group: <https://groups.google.com/forum/?fromgroups#!forum/seafile>
