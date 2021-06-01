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
webos_add_compiler_flags(ALL ${GLIB2_CFLAGS})

pkg_check_modules(LUNASERVICE2 REQUIRED luna-service2)
webos_add_compiler_flags(ALL ${LUNASERVICE2_CFLAGS})

pkg_check_modules(PMLOG REQUIRED PmLogLib)
include_directories(${PMLOG_INCLUDE_DIRS})
webos_add_compiler_flags(ALL ${PMLOG_CFLAGS_OTHER})

pkg_check_modules(PBNJSON_CPP REQUIRED pbnjson_cpp)
include_directories(${PBNJSON_CPP_INCLUDE_DIRS})
webos_add_compiler_flags(ALL ${PBNJSON_CPP_CFLAGS_OTHER})

pkg_check_modules(DB8 REQUIRED db8)
include_directories(${DB8_INCLUDE_DIRS})
webos_add_compiler_flags(ALL ${DB8_CFLAGS_OTHER})

pkg_check_modules(OPENSSL REQUIRED openssl)
include_directories(${OPENSSL_INCLUDE_DIRS})
webos_add_compiler_flags(ALL ${OPENSSL_CFLAGS_OTHER})

include_directories(${CMAKE_SOURCE_DIR})
include_directories(${CMAKE_SOURCE_DIR}/include)

#webos_add_compiler_flags(ALL -DMOJ_LINUX -std=c++11 -fno-exceptions -Wall -Werror)
webos_add_compiler_flags(ALL -std=c++11 -Wall)

set(SOURCES
	"src/Log.cpp"
	"src/OpensslBioWrapper.cpp"
	"src/OpensslConfWrapper.cpp"
	"src/OpensslRsaKeyWrapper.cpp"
	"src/OpensslCertWrapper.cpp"
	"src/OpensslCsrWrapper.cpp"
	"src/OpensslCaWrapper.cpp"
	"src/CertificateManager.cpp"
	"src/main.cpp"
)

add_executable(${PROJECT_NAME} ${SOURCES})
target_link_libraries (${PROJECT_NAME}
	${GLIB2_LDFLAGS}
	${LUNASERVICE2_LDFLAGS}
	${PMLOG_LDFLAGS}	
	${PBNJSON_CPP_LDFLAGS}
	${DB8_LDFLAGS}
	${OPENSSL_LDFLAGS}
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
