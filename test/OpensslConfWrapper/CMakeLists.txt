cmake_minimum_required(VERSION 3.10)
project(OpensslConfWrapper)

set(SRCS
	${CMAKE_SOURCE_DIR}/src/Log.cpp
	${CMAKE_SOURCE_DIR}/src/OpensslBioWrapper.cpp
	${CMAKE_SOURCE_DIR}/src/OpensslConfWrapper.cpp
	"OpensslConfWrapperTest.cpp"
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

add_library(gtest
	STATIC
	IMPORTED
)

set_target_properties(gtest
	PROPERTIES IMPORTED_LOCATION
	${CMAKE_SOURCE_DIR}/lib/gtest/libs/libgtest.a
)

include_directories(
	${CMAKE_SOURCE_DIR}/include
	${CMAKE_SOURCE_DIR}/lib/openssl/include
	${CMAKE_SOURCE_DIR}/lib/gtest/include	
)

target_link_libraries(
	${PROJECT_NAME} PRIVATE
	crypto
	gtest
	pthread	
)