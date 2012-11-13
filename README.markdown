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
synchronization, and doesn't depend on GIT.
Every library is like a GIT repository. It has
its own unique history, which consists of a list of commits.
A commit points to the root of a file system snapshot. The snapshot consists
of directories and files. Files are further divided into blocks
for more efficient network transfer and storage usage.

Differences from GIT:

1. Automatic syncing.
2. Clients do not store file history, thus avoids the overhead of storing data twice.
3. Files are further divided into blocks for more efficient network transfer and storage usage.
4. File transfer can be resumed.
5. Support different storage backends on the server side.
6. Support downloading from multiple block servers for accelerating file transfer.

Build and Run
=============

See <https://github.com/haiwen/seafile/wiki>
