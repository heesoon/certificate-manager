project(OpensslKeyWrapper)
cmake_minimum_required(VERSION 3.10)

set(SRCS
	${CMAKE_SOURCE_DIR}/src/Log.cpp
	${CMAKE_SOURCE_DIR}/src/OpensslBioWrapper.cpp
	${CMAKE_SOURCE_DIR}/src/OpensslRsaKeyWrapper.cpp
	"OpensslRsaKeyWrapperTest.cpp"
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
	${CMAKE_SOURCE_DIR}/include
	${CMAKE_SOURCE_DIR}/lib/openssl/include
)

target_link_libraries(
	${PROJECT_NAME} PRIVATE
	crypto
)