#cmake_minimum_required(VERSION 3.10)

set(SRCS
	"test.cpp"
)

include_directories(${CMAKE_SOURCE_DIR}/openssl/include)
link_directories(${CMAKE_SOURCE_DIR}/openssl/libs)

add_executable(test1
 ${SRCS}
 )
 
target_link_libraries(
	test1
	crypto
	ssl
)