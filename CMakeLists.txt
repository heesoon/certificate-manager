# Copyright (c) 2008-2018 LG Electronics, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 2.8.7)
project(com.webos.service.certificatemanager CXX C)

include(webOS/webOS)
webos_modules_init(1 0 0)
webos_component(1 0 0)

include(FindPkgConfig)

pkg_check_modules(GLIB2 REQUIRED glib-2.0)
include_directories(${GLIB2_INCLUDE_DIRS})
webos_add_compiler_flags(ALL ${GLIB2_CFLAGS_OTHER})

pkg_check_modules(GTHREAD2 REQUIRED gthread-2.0)
include_directories(${GTHREAD2_INCLUDE_DIRS})
webos_add_compiler_flags(ALL ${GTHREAD2_CFLAGS_OTHER})

pkg_check_modules(LS2 REQUIRED luna-service2)
include_directories(${LS2_INCLUDE_DIRS})
webos_add_compiler_flags(ALL ${LS2_CFLAGS_OTHER})

pkg_check_modules(PBNJSON_CPP REQUIRED pbnjson_cpp)
include_directories(${PBNJSON_CPP_INCLUDE_DIRS})
webos_add_compiler_flags(ALL ${PBNJSON_CPP_CFLAGS_OTHER})

pkg_check_modules(PMLOG REQUIRED PmLogLib)
include_directories(${PMLOG_INCLUDE_DIRS})
webos_add_compiler_flags(ALL ${PMLOG_CFLAGS_OTHER})

pkg_check_modules(DB8 REQUIRED db8)
include_directories(${DB8_INCLUDE_DIRS})
webos_add_compiler_flags(ALL ${DB8_CFLAGS_OTHER})

pkg_check_modules(OPENSSL REQUIRED openssl)
include_directories(${OPENSSL_INCLUDE_DIRS})
webos_add_compiler_flags(ALL ${OPENSSL_CFLAGS_OTHER})

include_directories(
	${CMAKE_SOURCE_DIR}
	${CMAKE_SOURCE_DIR}/include
	${CMAKE_SOURCE_DIR}/include/ls-utils
	${CMAKE_SOURCE_DIR}/include/adapters
)

#webos_add_compiler_flags(ALL -DMOJ_LINUX -std=c++11 -fno-exceptions -Wall -Werror)
webos_add_compiler_flags(ALL -std=c++11 -Wall)

set(SOURCES
	${CMAKE_SOURCE_DIR}/src/OpensslBioWrapper.cpp
	${CMAKE_SOURCE_DIR}/src/OpensslConfWrapper.cpp
	${CMAKE_SOURCE_DIR}/src/OpensslRsaKeyWrapper.cpp
	${CMAKE_SOURCE_DIR}/src/OpensslCertWrapper.cpp
	${CMAKE_SOURCE_DIR}/src/OpensslCsrWrapper.cpp
	${CMAKE_SOURCE_DIR}/src/OpensslCaWrapper.cpp
	${CMAKE_SOURCE_DIR}/src/CertificateManager.cpp
	${CMAKE_SOURCE_DIR}/src/main.cpp
	${CMAKE_SOURCE_DIR}/src/ls-utils/errors.cpp
	${CMAKE_SOURCE_DIR}/src/ls-utils/jsonutils.cpp
	${CMAKE_SOURCE_DIR}/src/ls-utils/logging.cpp
	${CMAKE_SOURCE_DIR}/src/ls-utils/lunaservice_client.cpp
	${CMAKE_SOURCE_DIR}/src/ls-utils/lunaservice_utils.cpp
	${CMAKE_SOURCE_DIR}/src/ls-utils/lunasubscription.cpp
	${CMAKE_SOURCE_DIR}/src/adapters/adapter_asm.cpp
)

add_executable(${PROJECT_NAME} ${SOURCES})
target_link_libraries (${PROJECT_NAME}
	${GLIB2_LDFLAGS}
	${GTHREAD2_LDFLAGS}
	${LS2_LDFLAGS}
	${PMLOG_LDFLAGS}
	${PBNJSON_CPP_LDFLAGS}
	${DB8_LDFLAGS}
	${OPENSSL_LDFLAGS}
	pthread
)

#webos_build_program(NAME ${PROJECT_NAME} ADMIN)
install(TARGETS ${PROJECT_NAME} DESTINATION ${WEBOS_INSTALL_SBINDIR})
webos_build_system_bus_files()
webos_build_configured_file(files/systemd/com.webos.service.certificatemanager.service SYSCONFDIR systemd/system)
# for pmlog
webos_build_configured_file(files/conf/pmlog/com.webos.service.certificatemanager.conf SYSCONFDIR pmlog.d)
#webos_build_db8_files()

file(GLOB_RECURSE SCHEMAS files/schema/*.schema)
install(FILES ${SCHEMAS} DESTINATION ${WEBOS_INSTALL_WEBOS_SYSCONFDIR}/schemas/com.web.service.certificatemanager)

#file(GLOB_RECURSE SCRIPTS files/scripts/*)
#install(FILES ${SCRIPTS} DESTINATION ${WEBOS_INSTALL_WEBOS_SERVICESDIR}/scripts/com.web.service.certificatemanager)
