## Introduction [![Build Status](https://secure.travis-ci.org/haiwen/seafile.svg?branch=master)](http://travis-ci.org/haiwen/seafile)

Seafile is an open source cloud storage system with privacy protection and teamwork features. Collections of files are called libraries. Each library can be synced separately. A library can also be encrypted with a user chosen password. Seafile also allows users to create groups and easily sharing files into groups.


## Feature Summary

Seafile has the following features:

### File syncing

1. Selective sync for any folder.
2. Correctly handles file conflicts based on history instead of timestamp.
3. Only transfer content delta to the server. Interrupted transfers can be resumed.
4. Sync with two or more servers.
5. Sync with existing folders.


### File sharing and collaboration

1. Sharing folders between users or into groups.
3. Download links with password protection
4. Upload links
5. Version control

### Drive client

* Access all files in the cloud via virtual drive.
* Files are synced on demand.

### Privacy protection

1. Library encryption with a user chosen password.
2. Client side encryption when using the desktop syncing.

### Online documents and knowledge management (New)

* Online Markdown editing in WYSIWYG way
* A draft review workflow for online documents
* Metadata management, including
  * File labels
  * Related documents
* Wiki mode
* Realtime notifications


## Source repositories for Seafile components


Each component of Seafile has its own source code repository on Github.

* Sync client daemon (this repository): https://github.com/haiwen/seafile
* Sync client GUI: https://github.com/haiwen/seafile-client
* Server core: https://github.com/haiwen/seafile-server
* Server web UI: https://github.com/haiwen/seahub
* iOS app: https://github.com/haiwen/seafile-iOS
* Android app: https://github.com/haiwen/seadroid
* WebDAV: https://github.com/haiwen/seafdav

Before version 6.0, the source code of "sync client daemon" and "server core" was mixed together in https://github.com/haiwen/seafile.
But after 6.0 version, the server core is separated into its own repository.
For this reason, the sync client daemon repository is still the "front page" for Seafile project on Github.

Build and Run
=============

See <http://manual.seafile.com/build_seafile/server.html>

Bug and Feature Request Reports
===============================

Please only submit bugs in GitHub issues (Pro customers should contact us via Email):

* Server, Web interface (Seahub) and desktop clients: https://github.com/haiwen/seafile/issues
* Android client: https://github.com/haiwen/seadroid/issues
* iOS client: https://github.com/haiwen/seafile-iOS/issues

Feature requests can be made and installation/usage problems can be discussed in the forum https://forum.seafile.com/.

Internationalization (I18n)
===========================

* [Translate Seafile web ui](https://github.com/haiwen/seafile/wiki/Seahub-Translation)
* [Translate Seafile desktop client](https://github.com/haiwen/seafile-client/#internationalization)
* [Translate Seafile Android app](https://github.com/haiwen/seadroid#internationalization)
* [Translate Seafile iOS app](https://github.com/haiwen/seafile-ios#internationalization-i18n)

Change Logs
===========

See <https://manual.seafile.com/changelog/server-changelog/>


Why Open Source
===============

Our primary goal is to build a first-class product. We think this goal can only be achieved by collaborating with the whole world.


Contributing
===========

For more information read [Contribution](http://manual.seafile.com/contribution.html).


License
=======

- Seafile iOS client: Apache License v2
- Seafile Android client: GPLv3
- Desktop syncing client (this repository): GPLv2
- Seafile Server core: AGPLv3
- Seahub (Seafile server Web UI): Apache License v2

Contact
=======

Twitter: @seafile <https://twitter.com/seafile>

Forum: <https://forum.seafile.com>
