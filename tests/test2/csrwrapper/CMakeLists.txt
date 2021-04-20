project(Csrwrapper)
cmake_minimum_required(VERSION 3.10)

set(SRCS
	"CsrWrapper.cpp"
	"CsrWrapper_test.cpp"
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

add_library(biowrapper4Csr
	SHARED
	${CMAKE_SOURCE_DIR}/tests/test2/biowrapper/bioWrapper.cpp
)

add_library(cnfwrapper4Csr
	SHARED
	${CMAKE_SOURCE_DIR}/tests/test2/cnfwrapper/CnfWrapper.cpp
)

set_target_properties(crypto
	PROPERTIES IMPORTED_LOCATION
	${CMAKE_SOURCE_DIR}/openssl/libs/libcrypto.so
)

include_directories(
	${CMAKE_SOURCE_DIR}/openssl/include
	${CMAKE_SOURCE_DIR}/tests/test2/biowrapper
	${CMAKE_SOURCE_DIR}/tests/test2/cnfwrapper
)
#link_directories(${CMAKE_SOURCE_DIR}/openssl/libs)
target_link_libraries(
	${PROJECT_NAME} PRIVATE
	crypto
	biowrapper4Csr
	cnfwrapper4Csr
)
