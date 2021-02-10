cmake_minimum_required(VERSION 3.10)

project(quizRandom)
#set(Boost_USE_STATIC_LIBS OFF) 
#set(Boost_USE_MULTITHREADED ON)  
#set(Boost_USE_STATIC_RUNTIME OFF) 
#find_package(Boost 1.45.0 COMPONENTS *boost libraries h) 

#if(Boost_FOUND)
#    include_directories(${Boost_INCLUDE_DIRS})
#find_package(unofficial-sqlite3

set(CMAKE_CXX_STANDARD 11)

include_directories(${PROJECT_SOURCE_DIR})
include_directories(${PROJECT_SOURCE_DIR}/libraries)
include_directories(${PROJECT_SOURCE_DIR}/libraries/ssl/include/crypto/)
include_directories(${PROJECT_SOURCE_DIR}/libraries/sqlite/build)

add_subdirectory("libraries")
add_executable(${PROJECT_NAME} 
src/trial.cpp 
headers/crypto.cpp)

