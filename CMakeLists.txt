cmake_minimum_required(VERSION 3.10)

# set the project name
project(certificate-manager) 	# PROJECT_NAME is certificate-manager

# set makefile verbose enable
SET(CMAKE_VERBOSE_MAKEFILE ON)

add_subdirectory(src)

# add library (default static library)
#add_library(
#	myhellow STATIC	# library name for executable
#	myhellow		# library name for executable
#	myhellow.hpp 
#	myhellow.cpp
#)

# add the executable
#add_executable("${PROJECT_NAME}" tutorial2.cpp)

# set path for libary
#target_link_libraries(
#	"${PROJECT_NAME}" PRIVATE
#	myhellow
#)
