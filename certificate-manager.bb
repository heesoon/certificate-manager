# Copyright (c) 2013-2014 LG Electronics, Inc.
SUMMARY = "Certificate Manager"
AUTHOR = "Hee-Soon, Kim<heesoon.kim@lge.com>"
LICENSE = "CLOSED"
 
WEBOS_VERSION = "0.1.0-1_41f301a1c40d10ac506c1473bd8939691a946c2e"
PR = "r0"
inherit webos_component
inherit webos_public_repo
inherit webos_enhanced_submissions
inherit webos_cmake
 
#SRC_URI = "file://git"
#SRC_URI = "file://src"
S = "${WORKDIR}/git"
