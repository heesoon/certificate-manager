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

project(com.webos.service.certificateManager)

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

set(SOURCES
	"Log.cpp"
	"OpensslBioWrapper.cpp"
	"OpensslConfWrapper.cpp"
	"OpensslRsaKeyWrapper.cpp"
	"OpensslCertWrapper.cpp"
	"OpensslCsrWrapper.cpp"
	"OpensslCaWrapper.cpp"
	"CertificateManager.cpp"
	"JUtil.cpp"
	"Utils.cpp"
	"Singleton.cpp"
	"main.cpp"
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

webos_build_program(NAME ${PROJECT_NAME} ADMIN)
webos_build_system_bus_files()
#webos_build_db8_files()

# add bin file /usr/bin/certificate-manager
#install (TARGETS ${PROJECT_NAME} RUNTIME DESTINATION bin)

# for pmlog
#webos_build_configured_file(files/conf/pmlog/certificate-manager.conf SYSCONFDIR pmlog.d)

# add dbus and lunaservice2 from  files/sysbus/*
#install(FILES ../files/sysbus/certificate-manager.json DESTINATION share/ls2/roles/pub)
#install(FILES ../files/sysbus/certificate-manager.json DESTINATION share/ls2/roles/prv)
#install(FILES ../files/sysbus/certificate-manager.service DESTINATION share/dbus-1/services)
#install(FILES ../files/sysbus/certificate-manager.service DESTINATION share/dbus-1/system-services)
