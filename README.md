Certificate Manager
===========

Description
-----------
certificate management of used in app or service

Prerequisites
=============
This codes are tested under Ubuntu 18.04 64bit LTS.

Building
========
Basic Build

    $ cd build
    $ cmake ..
    $ make

Debug Build

    $ cd build
    $ cmake -DCMAKE_BUILD_TYPE=Debug ..
    $ make

Release Build

    $ cd build
    $ cmake -DCMAKE_BUILD_TYPE=Release ..
    $ make


Cleaning
========
before uploading codes to remote repository, remove contents in build directory

    $ cd build
    $ rm -rf ./*