cmake_minimum_required(VERSION 3.10)
project(CertificateManager)

set(SRCS
	"Log.cpp"
	"OpensslBioWrapper.cpp"
	"OpensslConfWrapper.cpp"
	"OpensslRsaKeyWrapper.cpp"
	"OpensslCertWrapper.cpp"
	"OpensslCsrWrapper.cpp"
	"OpensslCaWrapper.cpp"
	"CertificateManager.cpp"
)

add_executable(${PROJECT_NAME}
	${SRCS}
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

target_link_libraries(
	${PROJECT_NAME} PRIVATE
	crypto
)