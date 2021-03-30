cmake_minimum_required(VERSION 3.10)

set(SRCS
	"test.cpp"
)

include_directories(${CMAKE_SOURCE_DIR}/openssl/include)
link_directories(${CMAKE_SOURCE_DIR}/openssl/libs)

add_executable(${PROJECT_NAME}
 ${SRCS}
 )
 
target_link_libraries(
	${PROJECT_NAME}
	crypto
	ssl
)
