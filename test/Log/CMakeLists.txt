cmake_minimum_required(VERSION 3.10)
project(logTest)

set(SRCS
	${CMAKE_SOURCE_DIR}/src/Log.cpp
	"LogTest.cpp"
)

add_executable(${PROJECT_NAME}
	${SRCS}
)

include_directories(
	${CMAKE_SOURCE_DIR}/include
)