cmake_minimum_required(VERSION 3.10)

project(test1)

set(SRCS
	"test.cpp"
)

#include_directories(${CMAKE_SOURCE_DIR}/openssl/include)
#link_directories(${CMAKE_SOURCE_DIR}/openssl/libs)

add_executable(${PROJECT_NAME}
 ${SRCS}
 )

target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/openssl/include)
target_link_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/openssl/libs)
target_link_libraries(
	${PROJECT_NAME} PRIVATE
	crypto
	ssl
)