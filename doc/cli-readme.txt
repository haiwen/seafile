                         Seafile command line client
                         ===========================

For the full manual about seafile CLI client, see [https://github.com/haiwen/seafile/wiki/Seafile-CLI-client]

Table of Contents
=================
1 Requirement:
2 Get Started
    2.1 Initialize
    2.2 Start seafile client
    2.3 Download a library from a server
    2.4 stop seafile client
3 Uninstall


1 Requirement:
---------------

  - python 2.6/2.7

  - If you use python 2.6, you need to install python "argparse" module

    see [https://pypi.python.org/pypi/argparse]


2 Get Started
--------------


2.1 Initialize
===============

  mkdir ~/seafile-client
  ./seaf-cli init -d ~/seafile-client


2.2 Start seafile client
=========================



  ./seaf-cli start



2.3 Download a library from a server
=====================================

   First retrieve the library id by browsing on the server -> it's in the url after "/repo/"

   Then:

   seaf-cli download -l "the id of the library" -s  "the url + port of server" -d "the folder where the library folder will be downloaded" -u "username on server" [-p "password"]

   seaf-cli status  # check status of ongoing downloads

   # Name  Status  Progress
   # Apps    downloading     9984/10367, 9216.1KB/s


2.4 stop seafile client
========================

  ./seaf-cli stop

3 Uninstall
------------

  First stop the client:

  seaf-cli stop

  Then remove the data:


  rm -rf ~/.seafile-client

  rm -rf ~/.ccnet   # note this should not be erased if you run the server on the same host

  rm -rf seafile-cli-1.5.3

