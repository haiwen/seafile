Introduction [![Build Status](https://secure.travis-ci.org/haiwen/seafile.svg?branch=master)](http://travis-ci.org/haiwen/seafile)
============

Seafile is an open source cloud storage system with features on privacy protection and teamwork. Collections of files are called libraries, and each library can be synced separately. A library can also be encrypted with a user chosen password. Seafile also allows users to create groups and easily sharing files into groups.

Feature Summary
===============

Seafile has the following features:

### File syncing

1. Selective synchronization for any folder.
2. Correct handling of file conflicts based on history instead of timestamp.
3. Only transfering contents not in the server, and incomplete transfers can be resumed.
4. Sync with two or more servers.
5. Sync with existing folders.


### File sharing and collaboration

1. Sharing folders between users or into groups.
3. Download links with password protection
4. Upload links
5. Version control with configurable revision number.
6. Restoring deleted files from trash, history or snapshots.

### Privacy protection

1. Library encryption with a user chosen password.
2. Client side encryption when using the desktop syncing.

Internal
========

Seafile's version control model is similar to Git, but it is simplified for automatic synchronization.
Each Seafile library behaves like a Git repository. It has its own unique history, which consists of a list of commits.
A commit points to the root of a file system snapshot. The snapshot consists of directories and files.
Files are further divided into blocks for more efficient network transfer and storage usage.


Build and Run
=============

See <http://manual.seafile.com/build_seafile/server.html>

Bug and Feature Request Reports
===============================

Please only submit bugs in GitHub issues (Pro customers should contact us via Email):

* Server and Web interface (Seahub): https://github.com/haiwen/seafile/issues
* Desktop client: https://github.com/haiwen/seafile-client/issues
* Android client: https://github.com/haiwen/seadroid/issues
* iOS client: https://github.com/haiwen/seafile-iOS/issues

Feature requests and installation/usage problem should be asked in the forum https://forum.seafile.com/.

Internationalization (I18n)
===========================

* [Translate Seafile web ui](https://github.com/haiwen/seafile/wiki/Seahub-Translation)
* [Translate Seafile desktop client](https://github.com/haiwen/seafile-client/#internationalization)
* [Translate Seafile Android app](https://github.com/haiwen/seadroid#internationalization)
* [Translate Seafile iOS app](https://github.com/haiwen/seafile-ios#internationalization-i18n)

Change Logs
===========

See <https://seacloud.cc/group/3/wiki/home/#Roadmap-ChangeLogs>


Why Open Source
===============

Our primary goal is to build a first-class product. We think this goal can only be achieved by collaborating with the whole world.


Contributing
===========

For more informations read [Contribution](http://manual.seafile.com/contribution.html).


License
=======

Seafile server and its desktop clients are published under GPLv2.

Mobile clients are published under the GPLv3.

The Seafile server's web end, i.e. Seahub, is published under the Apache License.

Contact
=======

Twitter: @seafile <https://twitter.com/seafile>

Forum: <https://forum.seafile.com>
