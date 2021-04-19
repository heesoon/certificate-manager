project(loadKeywrapper)
cmake_minimum_required(VERSION 3.10)

set(SRCS
	"loadKeyWrapper.cpp"
	"loadKeyWrapper_test.cpp"
)

#add_compile_definitions(__DEBUG__)
#target_compile_definitions(${PROJECT_NAME} PRIVATE __DEBUG__)
#set( CMAKE_CXX_FLAGS "-D__DEBUG__" )

add_executable(${PROJECT_NAME}
	${SRCS}
)

#find_library(
#	LIB_OPENSSL_CRYPTO
#	libcrypto.so
#	PATHS ${CMAKE_SOURCE_DIR}/openssl/libs
#	NAMES crypto
#	HINTS "${CMAKE_SOURCE_DIR}/openssl/libs"
#	REQUIRED
#)

add_library(crypto
	SHARED
	IMPORTED
)

add_library(libBioWrapper
	SHARED
	${CMAKE_SOURCE_DIR}/tests/test2/biowrapper/bioWrapper.cpp
)

set_target_properties(crypto
	PROPERTIES IMPORTED_LOCATION
	${CMAKE_SOURCE_DIR}/openssl/libs/libcrypto.so
)

include_directories(
	${CMAKE_SOURCE_DIR}/openssl/include
	${CMAKE_SOURCE_DIR}/tests/test2/biowrapper
)
#link_directories(${CMAKE_SOURCE_DIR}/openssl/libs)
target_link_libraries(
	${PROJECT_NAME} PRIVATE
	crypto
	libBioWrapper
)
