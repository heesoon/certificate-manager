certificate-manager
============================

Summary
-------
certificate-manager is to update system certificates and keep their intergrity

Description
-----------
The service downloads certificates package from remote SDP server. 
Server provides trusted CA list as bunch of files digitally signed which is 
to be downloaded, unpacked, verified and put into device CA directory. 

Notes
-----
Use 'create_ca.sh' script to create a certificates bundle and sign it
Use 'create_url_override.sh' script to create an url override setting file

Dependencies
------------

Below are the tools and libraries required to build filecache:

* luna-service2++-3
* glib-2.0
* PmLogLib
* libarchive
* zlib

Copyright and License Information
---------------------------------

Unless otherwise specified, all content, including all source code files and
documentation files in this repository are:

Copyright (c) 2007-2019 LG Electronics, Inc.

Unless otherwise specified or set forth in the NOTICE file, all content,
including all source code files and documentation files in this repository are:
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this content except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

