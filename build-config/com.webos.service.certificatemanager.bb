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

SERVICEDIR = "${D}${webos_servicesdir}/${BPN}"

do_install_append() {
	# install scripts files
    install -d ${SERVICEDIR}
	install -d ${SERVICEDIR}/scripts

	#cp -R --no-dereference --preserve=mode,links -v ${S}/files/scripts/* ${SERVICEDIR}/scripts/
	install -m 0644 ${S}/files/scripts/* ${SERVICEDIR}/scripts/
	
    # install 
    install -d ${D}${webos_sysconfdir}/db/kinds
    install -d ${D}${webos_sysconfdir}/db/permissions
    #cp -vrf ${S}/db/kinds/* ${D}${webos_sysconfdir}/db/kinds/ 2> /dev/null || true
    #cp -vrf ${S}/db/permissions/* ${D}${webos_sysconfdir}/db/permissions/ 2> /dev/null || true
	install -m 0644 ${S}/files/db8/kinds/* ${D}${webos_sysconfdir}/db/kinds/
	install -m 0644 ${S}/files/db8/permissions/* ${D}${webos_sysconfdir}/db/permissions/
}

FILES_${PN} += "${webos_servicesdir}"