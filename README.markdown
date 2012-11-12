Introduction
============

Seafile enables you to build private cloud for file sharing and collaboration among team members in your company/organization. 

First you create a file library in the web and upload files to
it. Then you share it into a team or with another user.

File libraries can also be synchronized among computers and mobile
devices. You download a library to your PC. Whenever you add, delete
or edit a file, the latest version be uploaded to the server
automatically and then be synchronized to everyone's computer.

Feature Summary
===============

Seafile can be used to build a full-fledged cloud storage platform. It
has following features:

1. Each library can be synced separately.
2. Sync with existing folders.
3. Groups, users can create and join groups. 
4. File revisions.
5. File comments, event notifications, 
6. Library encryption with a user chosen password.

Internal
========

Seafile uses GIT's version control model, but simplified for automatic
synchronization. Every library is like a GIT repository. It has
its own unique history, which consists of a list of commits.
A commit points to the root of a file system. A file system consists
of directories and files. Files are further divided into blocks
for easy transferring and storing.

Differences from GIT:

1. Clients do not store file history.
2. Files are further divided into blocks for easy transporting and storing.
3. File transferring can be resumed.
4. Support different storage backends in the server side.
5. Support downloading from multiple block servers for accelerating file transferring.

Build and Run
=============

See <https://github.com/haiwen/seafile/wiki>
