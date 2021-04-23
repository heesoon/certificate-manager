project(log)
cmake_minimum_required(VERSION 3.10)

set(SRCS
	"log.cpp"
	"log_test.cpp"
)

add_executable(${PROJECT_NAME}
	${SRCS}
)

include_directories(
)