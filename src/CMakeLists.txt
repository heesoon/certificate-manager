cmake_minimum_required(VERSION 3.10)
project(certificateManager)

set(ENSRCS
	${CMAKE_SOURCE_DIR}/src/opensslengine/opensslEngine.cpp
)

set(SRCS
	${CMAKE_SOURCE_DIR}/src/opensslwrapper/OpensslBioWrapper.cpp
	${CMAKE_SOURCE_DIR}/src/opensslwrapper/OpensslConfWrapper.cpp
	${CMAKE_SOURCE_DIR}/src/opensslwrapper/OpensslRsaKeyWrapper.cpp
	${CMAKE_SOURCE_DIR}/src/opensslwrapper/OpensslCertWrapper.cpp
	${CMAKE_SOURCE_DIR}/src/opensslwrapper/OpensslCsrWrapper.cpp
	${CMAKE_SOURCE_DIR}/src/opensslwrapper/OpensslCaWrapper.cpp
	${CMAKE_SOURCE_DIR}/src/Log.cpp
	${CMAKE_SOURCE_DIR}/src/CertificateManager.cpp
)

add_executable(${PROJECT_NAME}
	${SRCS}
)

add_library(opensslEngine SHARED
	${ENSRCS}
)

add_library(crypto
	SHARED
	IMPORTED
)

set_target_properties(crypto
	PROPERTIES IMPORTED_LOCATION
	#${CMAKE_SOURCE_DIR}/lib/openssl/libs/libcrypto.so
	${CMAKE_SOURCE_DIR}/lib/openssl/libs/libcrypto.so.3
)

include_directories(
	${CMAKE_SOURCE_DIR}/lib/openssl/include
	${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(${PROJECT_NAME} PRIVATE
	crypto
	opensslEngine
)