# Copyright (c) 2021 LG Electronics, Inc.

SUMMARY = "webOS component aimed at obtaining and preparing certificates bundle"
AUTHOR = "Hee-Soon Kim <heesoon.kim@lge.com>"
SECTION = "webos/base"
LICENSE = "CLOSED"

DEPENDS = "glib-2.0 luna-service2 openssl pmloglib libpbnjson db8"

RDEPENDS_${PN} = ""

WEBOS_VERSION = "1.0.0-8_728d37a6a04e06a76a0f09bf940eada16e47f6c0"
PR = "r0"

inherit webos_component
inherit webos_enhanced_submissions
inherit webos_cmake
inherit webos_system_bus
inherit webos_daemon

#SRC_URI = "${WEBOS_PRO_GIT_REPO_COMPLETE}"
S = "${WORKDIR}/git"

do_install_append() {
    install -d "${D}${webos_servicesdir}/${BPN}"
}

FILES_${PN} += "${webos_servicesdir}"