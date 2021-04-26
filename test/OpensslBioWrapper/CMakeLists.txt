project(OpensslBioWrapper)
cmake_minimum_required(VERSION 3.10)

set(SRCS
	${CMAKE_SOURCE_DIR}/src/OpensslBioWrapper.cpp
	"OpensslBioWrapperTest.cpp"
)

add_executable(${PROJECT_NAME}
	${SRCS}
)

include_directories(
	${CMAKE_SOURCE_DIR}/include
)