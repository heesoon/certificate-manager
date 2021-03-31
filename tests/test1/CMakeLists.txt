project(test1)
cmake_minimum_required(VERSION 3.10)

set(SRCS
	"test.cpp"
)

add_executable(${PROJECT_NAME}
	${SRCS}
)

find_library(
	LIB_OPENSSL_CRYPTO
	libcrypto.so
	PATHS ${CMAKE_SOURCE_DIR}/openssl/libs
	REQUIRED
)

if(${LIB_OPENSSL_CRYPTO} EQUAL "LIB_OPENSSL_CRYPTO-NOTFOUND")
#	message("Err : Couldn't find openssl crypto library")
else()
#	message("SUC : find openssl crypto library")
	
	include_directories(${CMAKE_SOURCE_DIR}/openssl/include)
	target_link_libraries(
		${PROJECT_NAME} PRIVATE
		${LIB_OPENSSL_CRYPTO}
	)	
endif()