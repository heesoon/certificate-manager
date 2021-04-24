cmake_minimum_required(VERSION 3.10)

set(CMAKE_CXX_STANDARD 11 ) 
set(CMAKE_CXX_FLAGS "-O1 -Wall" ) 
set(CMAKE_CXX_FLAGS_DEBUG "-O0 -g -DLOG_PRINT" ) 
set(CMAKE_CXX_FLAGS_RELEASE "-O2" ) 
set(CMAKE_CXX_FLAGS_MINSIZEREL "-Os" ) 

add_subdirectory(src)
add_subdirectory(test)